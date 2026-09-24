"""地理定位缓存 —— 带持久化、批量、限流。

⚠ 为什么必须做限流和缓存

ip-api 免费版是 **45 请求/分钟**。一个正常的浏览器开几个标签页就会连
几十个不同 IP，如果每个 IP 都实时查一次：
  1. 几秒内就把配额打爆
  2. 之后所有查询都返回失败
  3. 界面上表现为"地图上一个点都没有"—— 看起来像功能坏了，其实是配额用光了

所以这里的策略：
  - 内存缓存 + 落盘缓存（`geo_cache.json`），命中直接返回，不占配额
  - 每轮只解析有限个（`budget`），其余的排队等下一轮
  - 失败的条目也记缓存（带较短 TTL），避免反复撞墙
  - 内网 / 保留地址不查（本来就没有地理信息）
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
import urllib.request
from pathlib import Path

# 内网与保留段：不查，直接给个本地标签
_LOCAL_LABELS = [
    ("198.18.0.0/15", "隧道内部"),
    ("10.0.0.0/8", "内网"),
    ("172.16.0.0/12", "内网"),
    ("192.168.0.0/16", "内网"),
    ("169.254.0.0/16", "链路本地"),
    ("127.0.0.0/8", "本机"),
    ("100.64.0.0/10", "运营商内网"),
    ("224.0.0.0/4", "组播"),
]

OK_TTL = 7 * 24 * 3600      # 成功的记录存 7 天（IP 归属很少变）
FAIL_TTL = 900              # 失败的记录存 15 分钟（别反复撞墙）
MAX_CACHE = 4000            # 缓存上限，超了丢最旧的


def local_label(ip: str) -> str | None:
    """内网 / 保留地址返回中文标签，否则 None。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "无效地址"
    if a.is_loopback:
        return "本机"
    if a.is_link_local:
        return "链路本地"
    if a.is_multicast:
        return "组播"
    if a.is_unspecified:
        return "未指定"
    for cidr, label in _LOCAL_LABELS:
        try:
            if a in ipaddress.ip_network(cidr, strict=False):
                return label
        except ValueError:
            continue
    if a.is_private:
        return "内网"
    return None


class GeoCache:
    """IP -> 地理位置，带缓存与限流。"""

    def __init__(self, data_dir: Path, per_round: int = 12,
                 round_seconds: float = 20.0):
        self.path = Path(data_dir) / "geo_cache.json"
        self.per_round = per_round          # 每轮最多解析几个新 IP
        self.round_seconds = round_seconds  # 轮次间隔（限流窗口）
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._pending: list[str] = []
        self._last_round = 0.0
        self._dirty = False
        self._load()

    # ---- 持久化 -------------------------------------------------------
    def _load(self) -> None:
        try:
            if self.path.exists():
                d = json.loads(self.path.read_text(encoding="utf-8-sig"))
                if isinstance(d, dict):
                    self._cache = d
        except Exception:
            self._cache = {}

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            with self._lock:
                # 超上限时按时间戳丢最旧的
                if len(self._cache) > MAX_CACHE:
                    items = sorted(self._cache.items(),
                                   key=lambda kv: kv[1].get("ts", 0),
                                   reverse=True)[:MAX_CACHE]
                    self._cache = dict(items)
                snap = dict(self._cache)
                self._dirty = False
            tmp = self.path.with_name("geo_cache.json.tmp")
            tmp.write_text(json.dumps(snap, ensure_ascii=False),
                           encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception:
            pass

    # ---- 查询 ---------------------------------------------------------
    def lookup(self, ip: str, queue: bool = True) -> dict:
        """查一个 IP。命中缓存直接返回；否则入队并返回 pending。"""
        lab = local_label(ip)
        if lab:
            return {"ip": ip, "local": True, "label": lab,
                    "country": "", "city": "", "isp": "", "lat": None,
                    "lon": None}

        now = time.time()
        with self._lock:
            rec = self._cache.get(ip)
            if rec:
                ttl = OK_TTL if rec.get("ok") else FAIL_TTL
                if now - float(rec.get("ts") or 0) < ttl:
                    return dict(rec)
            if queue and ip not in self._pending:
                self._pending.append(ip)
        return {"ip": ip, "pending": True, "country": "", "city": "",
                "isp": "", "lat": None, "lon": None}

    def resolve_pending(self, timeout: float = 6.0) -> int:
        """按配额解析待办队列。返回本轮解析了几个。

        限流：两轮之间至少间隔 `round_seconds`，每轮最多 `per_round` 个。
        这样最多是 per_round/round_seconds 个/秒，远低于 45/分钟。
        """
        now = time.time()
        if now - self._last_round < self.round_seconds:
            return 0
        with self._lock:
            batch = self._pending[:self.per_round]
            del self._pending[:len(batch)]
            self._last_round = now
        if not batch:
            return 0

        done = 0
        # ip-api 的批量接口一次能查 100 个，但免费版限制更严；
        # 用单条接口逐个查，失败不影响其他
        for ip in batch:
            rec = self._fetch_one(ip, timeout)
            with self._lock:
                self._cache[ip] = rec
                self._dirty = True
            if rec.get("ok"):
                done += 1
        self.save()
        return done

    @staticmethod
    def _fetch_one(ip: str, timeout: float) -> dict:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,regionName,city,"
               f"isp,org,as,lat,lon&lang=zh-CN")
        rec = {"ip": ip, "ts": time.time(), "ok": False,
               "country": "", "city": "", "isp": "", "org": "",
               "lat": None, "lon": None, "error": ""}
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "EgressGuard/1.3"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            if d.get("status") == "success":
                rec.update({
                    "ok": True,
                    "country": d.get("country") or "",
                    "country_code": d.get("countryCode") or "",
                    "region": d.get("regionName") or "",
                    "city": d.get("city") or "",
                    "isp": d.get("isp") or "",
                    "org": d.get("org") or "",
                    "as": d.get("as") or "",
                    "lat": d.get("lat"),
                    "lon": d.get("lon"),
                })
            else:
                rec["error"] = str(d.get("message") or d.get("status"))
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
        return rec

    # ---- 维护 ---------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            n_ok = sum(1 for v in self._cache.values() if v.get("ok"))
            return {"cached": len(self._cache), "resolved": n_ok,
                    "pending": len(self._pending),
                    "last_round_ago_s": round(time.time() - self._last_round, 1)
                    if self._last_round else None,
                    "per_round": self.per_round,
                    "round_seconds": self.round_seconds}

    def clear(self) -> int:
        with self._lock:
            n = len(self._cache)
            self._cache = {}
            self._dirty = True
        self.save()
        return n
