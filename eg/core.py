"""守护主循环 + 本地 API。

主循环的节奏
------------
  250ms   枚举连接表 -> 判定 -> 处置           （热路径，纯 ctypes，无子进程）
  8s      刷新网卡态势 -> 网卡级判定           （含 IPv6 旁路、DNS 泄漏）
  60s     主动探测出口 IP -> 出口级判定        （走网络，慢）
  按需     本地 API 响应仪表盘与"被掐程序"的查询

三种运行档位
------------
  观察档  enabled=False           只记录、只报告，不动任何连接
  演练档  enabled=True,dry_run=True 判定+通知，但仍不动连接
  实弹档  enabled=True,dry_run=False 判定+通知+掐断+隔离

为什么默认是观察档：这类工具最危险的失败模式是"误判把正常网络掐了"，
先让用户看着判定跑一阵、确认没有误报，再上实弹。
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import socket
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import __version__
from . import netinfo as NI
from . import winapi as W
from .config import Config, ensure_dirs, DATA_DIR
# ⚠ 必须同时导入 _run_ps。
#   我第一版只写了 `from .enforce import Enforcer`，然后在 core.py 里
#   直接调 `_run_ps(...)` —— 每一处都抛 NameError，而外面包着
#   `except Exception: pass`，于是**启动自检的残留路由清理、IPv6 规则感知检查
#   全都静默失效**，看起来像"功能正常"。
#   这和验收脚本里漏 `from eg import netinfo as NI` 是同一类错误。
from .enforce import Enforcer, _run_ps
from .logbus import LogBus
from .notify import Notifier
from .policy import Code, Finding, PolicyEngine, SEV_RANK

START_TS = time.time()

# --------------------------------------------------------------------------
# 状态型判定 vs 事件型判定
#
# 反馈指出的问题：DNS 泄漏是"WLAN 3 配的是国内 DNS"这个**配置事实**，不会自己变；
# IPv6 旁路同理。但原来它们按事件流反复报（每 reannounce_s 一条），
# 结果把真正的**一次性事件**（某个程序裸奔了）淹没在噪音里。
#
# 现在区分开：
#   状态型（下面这些）—— 只在**状态发生变化时**发一条事件；
#                        持续期间常驻在仪表盘的体检条 / 活跃判定里。
#   事件型（连接类）—— 照常按事件报，因为每一次都是独立发生的动作。
# --------------------------------------------------------------------------
STATE_CODES = {
    Code.IPV6_GLOBAL_EXPOSED,
    Code.DNS_LEAK,
    Code.TUNNEL_DOWN,
}


# --------------------------------------------------------------------------
# 守护核心
# --------------------------------------------------------------------------

class GuardCore:
    def __init__(self, cfg: Config | None = None):
        ensure_dirs()
        self.cfg = cfg or Config()
        self.bus = LogBus()
        self.net = NI.NetInfo(self.cfg.snapshot())
        self.policy = PolicyEngine(self.cfg, self.net, self.bus)
        self.enforcer = Enforcer(self.cfg, self.bus)
        self.notifier = Notifier(self.cfg, self.bus)

        self._stop = threading.Event()
        self._lock = threading.RLock()
        # key -> (last_seen_ts, Finding, first_seen_ts, 命中次数)
        self._active: dict[tuple, tuple[float, Finding, float, int]] = {}
        self._announce: dict[tuple, float] = {}
        self._active_ttl = 25.0
        self._counters = {"findings": 0, "finding_hits": 0, "blocked": 0,
                          "killed": 0, "quarantined": 0, "notices": 0,
                          "probes": 0, "probe_fail": 0, "history": 0,
                          "dropped_actions": 0, "blocked_targets": 0}
        # 隔离 + 通知的工作队列。热循环只管往里放，绝不等它。
        self._action_q: queue.Queue = queue.Queue(maxsize=500)
        # 状态型判定的"上一轮内容"快照，用于只在变化时发事件
        self._state_snapshot: dict[tuple, str] = {}
        # 自动修复的冷却：key -> 上次修复时间。防抖，避免每轮都去改系统配置。
        self._remediated: dict[str, float] = {}
        self._state_seen_round: set[tuple] = set()
        self._last_probe: dict = {}
        self._last_probe_ts = 0.0
        self._tunnel_ok: bool | None = None
        self._adapters: list[NI.Adapter] = []
        self._last_adapter_ts = 0.0
        self._api_server = None
        self._static_installed = False
        self._fail_closed = False
        self._fw_cache: dict = {}
        self._fw_cache_ts = 0.0
        self._fw_ttl = 15.0

        # 自己和自己的父进程必须放行，否则守护进程会把自己掐掉
        for pid in {os.getpid(), os.getppid()}:
            if pid > 0:
                self.policy.allow_runtime(pid)

        self.bus.state(severity="info", code="BOOT",
                       title="EgressGuard 守护已启动",
                       detail=f"版本 {__version__}｜管理员={'是' if W.is_admin() else '否'}"
                              f"｜模式={'实弹' if (self.cfg.enabled and not self.cfg.dry_run) else ('演练' if self.cfg.enabled else '观察')}")

    # ---- 对外状态 -----------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            act = sorted(
                ({"ts": t, "first_seen": fs, "hits": n,
                  "first_seen_str": time.strftime("%H:%M:%S", time.localtime(fs)),
                  **f.to_dict()}
                 for t, f, fs, n in self._active.values()),
                key=lambda x: (-SEV_RANK.get(x["severity"], 0), -x["ts"]))
            counters = dict(self._counters)
            last_probe = dict(self._last_probe)
            tunnel_ok = self._tunnel_ok
            adapters = [a.to_dict() for a in self._adapters]

        mode = ("实弹" if (self.cfg.enabled and not self.cfg.dry_run)
                else ("演练" if self.cfg.enabled else "观察"))
        probe_iv = float(self.cfg.get("probe_interval_s", 60) or 60)
        return {
            "version": __version__,
            "uptime_s": round(time.time() - START_TS, 1),
            "mode": mode,
            "enabled": self.cfg.enabled,
            "dry_run": self.cfg.dry_run,
            "action": self.cfg.get("action"),
            "effective_action": self.cfg.effective_action,
            "poll_interval_ms": self.cfg.get("poll_interval_ms"),
            "probe_interval_s": self.cfg.get("probe_interval_s"),
            "is_admin": W.is_admin(),
            "tunnel_ok": tunnel_ok,
            "adapters": adapters,
            "tunnels": [a for a in adapters if a.get("is_tunnel")],
            "physical": [a for a in adapters if not a.get("is_tunnel")
                         and a.get("status", "").lower() == "up"],
            "egress": last_probe,
            "next_probe_in": max(0, round(probe_iv - (time.time() - self._last_probe_ts), 1)),
            "counters": counters,
            "active_findings": act,
            "policy": self.policy.summary(),
            "firewall": self._firewall_cached(),
            "static_rules_installed": self._static_installed,
            "fail_closed": self._fail_closed,
            "fail_closed_on_tunnel_loss": bool(
                self.cfg.get("fail_closed_on_tunnel_loss", True)),
            "events_file": str(self.bus.path),
            "api_port": int(self.cfg.get("api", {}).get("port", 47821)),
        }

    def _firewall_cached(self) -> dict:
        """防火墙状态带 15 秒缓存。

        为什么要缓存：查防火墙状态要起一个 PowerShell 子进程（1~3 秒），
        而仪表盘每 2 秒就拉一次 /api/status。
        不缓存的话每次刷新都卡住，界面会像死了一样。
        """
        now = time.time()
        with self._lock:
            if self._fw_cache and now - self._fw_cache_ts < self._fw_ttl:
                return self._fw_cache
        st = self.enforcer.firewall_state()
        with self._lock:
            self._fw_cache = st
            self._fw_cache_ts = time.time()
        return st

    # ---- 处置 ---------------------------------------------------------

    def handle_findings(self, findings: list[Finding], where: str = "guard") -> list[dict]:
        """接收判定，决定要不要播报、要不要动手。

        三层去重，缺一不可：
          1. 记录层：同一条连接每个轮询周期都会被重新判定，但只算"一个"判定，
             仪表盘上不会堆成几千条。
          2. 播报层：同一条判定在 reannounce_s 秒内只往事件流写一次，
             否则事件流会被 250ms 一次的重复内容淹掉。
          3. 处置层：同一条判定只处置一次（policy.already_handled）。
        """
        out: list[dict] = []
        now = time.time()
        reannounce = float(self.cfg.get("reannounce_s", 60) or 60)

        for f in findings:
            key = f.dedup_key()
            actionable = f.rank >= SEV_RANK["medium"]

            # 状态型判定：内容没变就不重复发事件。
            # 变了（DNS 换了服务器、IPv6 地址变了）才发一条。
            if f.code in STATE_CODES:
                skey = self._state_key(f)
                with self._lock:
                    prev_state = self._state_snapshot.get(skey)
                    self._state_snapshot[skey] = f.detail
                    self._state_seen_round.add(skey)
                if prev_state == f.detail:
                    # 状态没变：只刷新活跃区的时间戳，不写事件
                    if actionable:
                        with self._lock:
                            p = self._active.get(key)
                            self._active[key] = (now, f, p[2] if p else now,
                                                 (p[3] + 1) if p else 1)
                    continue
                if prev_state is not None:
                    self.bus.state(severity="info", code=f.code + "_CHANGED",
                                   title=f"状态变化：{f.title}",
                                   detail=f"从「{prev_state[:60]}」变为「{f.detail[:60]}」",
                                   reason=f.detail)

            with self._lock:
                prev = self._active.get(key) if actionable else None
                is_new = prev is None
                if is_new and actionable:
                    # 只对"需要你注意"的判定计数。
                    # 低级别（已死连接/内核持有）每轮都是新 key，如果也计数，
                    # 仪表盘上的"判定数"会被历史痕迹灌成几百条，完全失真。
                    self._counters["findings"] += 1
                first_seen = prev[2] if prev else now
                count = (prev[3] + 1) if prev else 1
                if actionable:
                    self._active[key] = (now, f, first_seen, count)
                last_announce = self._announce.get(key, 0.0)

            self._counters["finding_hits"] = self._counters.get("finding_hits", 0) + 1

            # 低级别：只进事件流，5 分钟最多写一次
            if not actionable:
                if now - last_announce < 300:
                    continue
                with self._lock:
                    self._announce[key] = now
                self._counters["history"] = self._counters.get("history", 0) + 1
                self.bus.finding(severity=f.severity, code=f.code, title=f.title,
                                 detail=f.detail, pid=f.pid, process=f.process,
                                 exe=f.exe, local=f.local, remote=f.remote,
                                 proto=f.proto, reason=f.detail,
                                 extra={"iface": f.iface, "evidence": f.evidence,
                                        "where": where, "enforceable": False})
                continue

            # 中等以上：新出现就播报，之后按 reannounce 节奏补播
            if not is_new and now - last_announce < reannounce:
                pass
            else:
                with self._lock:
                    self._announce[key] = now
                self.bus.finding(
                    severity=f.severity, code=f.code, title=f.title,
                    detail=f.detail, pid=f.pid, process=f.process,
                    exe=f.exe, local=f.local, remote=f.remote,
                    proto=f.proto, reason=f.detail,
                    extra={"iface": f.iface, "evidence": f.evidence,
                           "where": where, "enforceable": f.enforceable,
                           "first_seen": time.strftime("%H:%M:%S", time.localtime(first_seen)),
                           "hits": count, "new": is_new})

            if not self.cfg.enabled:
                continue
            if not f.enforceable or f.rank < SEV_RANK["high"]:
                continue
            if self.policy.already_handled(f):
                continue

            act = self.cfg.effective_action
            steps: list[str] = []

            if act == "notify_only":
                steps.append("演练：未做任何阻断")
            else:
                # 掐断是纯 ctypes 调用（SetTcpEntry），微秒级，就地做没问题。
                # 而且越早掐越好，不该排到队列后面去。
                if act in ("block_and_kill", "block_kill_proc") \
                        and self.cfg.get("kill_established", True) and f.proto == "tcp":
                    r = self.enforcer.kill_connection(f)
                    if r.ok:
                        self._counters["killed"] += 1
                    steps.append(f"掐断连接：{r.detail}")

            # 隔离 + 通知全部丢给工作线程。
            #
            # ⚠ 这是实测踩到的第二个同类阻塞 bug：
            #   原来这里直接调 enforcer.quarantine_program()（起 PowerShell，最长 30s）
            #   和 notifier.notify()（起控制台注入/事件日志/Toast 子进程，各带 10~25s 超时），
            #   全部内联在热循环里。结果是"检测到一次泄漏 → 热循环被通知阻塞十几秒 →
            #   这期间新出现的泄漏完全看不见"。
            #   实测现象：一条只活了 1 秒的 ESTAB 泄漏连接被漏掉，
            #   守护只在它退化成 CLOSE_WAIT 之后才抓到。
            #   现在热循环只负责"发现 + 掐断"，慢活全部异步化。
            if act != "notify_only":
                self._enqueue_action(f, act, steps)

            out.append({"finding": f.to_dict(), "steps": steps,
                        "queued": act != "notify_only"})
        return out

    @staticmethod
    def _state_key(f: Finding) -> tuple:
        """状态型判定的身份：同一网卡上的同一类问题算同一个状态。"""
        ev = f.evidence or {}
        v6 = str(ev.get("ipv6") or "")[:24]
        return (f.code, f.iface, ev.get("if_index"), v6)

    def _enqueue_action(self, f: Finding, act: str, steps: list[str]) -> None:
        """把隔离与通知排进工作队列。队列满了就丢弃并记一条错误，绝不阻塞热循环。"""
        try:
            self._action_q.put_nowait((f, act, list(steps)))
        except Exception:
            self._counters["dropped_actions"] = \
                self._counters.get("dropped_actions", 0) + 1
            self.bus.error(severity="high", code="ACTION_QUEUE_FULL",
                           title="处置队列已满，丢弃一项",
                           detail=f"{f.process}({f.pid}) {f.code}")

    def _action_loop(self) -> None:
        """处置工作线程：隔离程序 + 发通知。慢就慢，不拖累热循环。"""
        while not self._stop.is_set():
            try:
                item = self._action_q.get(timeout=0.5)
            except Exception:
                continue
            if item is None:
                break
            f, act, steps = item
            try:
                if act in ("block_new", "block_and_kill", "block_kill_proc"):
                    target = f.exe or ""
                    remote_ip = ""
                    if f.remote:
                        remote_ip = f.remote.rsplit(":", 1)[0]

                    if not target or "\\" not in target:
                        # 拿不到全路径（多为提权进程）—— 建不了任何防火墙规则。
                        # 但连接已经在热循环里掐掉了，而且它再裸奔会再被掐，
                        # 所以这不是"没防护"，只是"没有持久化规则"。
                        steps.append(
                            f"拿不到 {f.process or '该程序'} 的全路径，建不了防火墙规则；"
                            f"已掐断当前连接，它若再次裸奔会继续被掐")
                    elif not remote_ip:
                        steps.append("没有远端地址，无法建目标级规则；已掐断当前连接")
                    else:
                        # 默认动作：封杀「程序 → 目标」，不是封杀整个程序。
                        # 这样"某个 python 脚本裸奔"不会变成"所有 python 程序断网"。
                        r = self.enforcer.block_target(
                            target, remote_ip, reason=f.detail,
                            port=int(f.remote.rsplit(":", 1)[1])
                            if ":" in f.remote else 0,
                            proto=f.proto or "tcp")
                        if r.ok:
                            self._counters["blocked_targets"] = \
                                self._counters.get("blocked_targets", 0) + 1
                        steps.append(f"封杀目标：{r.detail}")

                        # 惯犯才升级到整程序封杀；共用宿主与自身永不升级
                        esc, why = self.enforcer.should_escalate(target)
                        if esc:
                            r2 = self.enforcer.quarantine_program(
                                target, reason=f.detail + "（惯犯升级）")
                            if r2.ok:
                                self._counters["quarantined"] += 1
                            steps.append(f"升级为整程序封杀：{r2.detail}")
                        else:
                            steps.append(f"不升级为整程序封杀（{why}）")

                if act == "block_kill_proc" and f.pid > 0:
                    r = self.enforcer.kill_process(f.pid, reason=f.detail)
                    steps.append(f"终结进程：{r.detail}")

                action_text = "；".join(steps) if steps else "仅记录"
                channels = self.notifier.notify(f, action_text)
                self._counters["notices"] += 1
                self.bus.action(severity=f.severity, code=f.code + "_HANDLED",
                                title=f"已处置：{f.process or f.iface}",
                                detail=f"{action_text}｜通知通道：{channels}",
                                pid=f.pid, process=f.process, exe=f.exe,
                                local=f.local, remote=f.remote, proto=f.proto,
                                reason=f.detail,
                                extra={"channels": channels, "steps": steps})
            except Exception:
                self.bus.error(severity="high", code="ACTION_LOOP",
                               title="处置线程异常",
                               detail=traceback.format_exc()[-700:])

    # ---- 探测 ---------------------------------------------------------

    def probe_egress(self) -> dict:
        cfg = self.cfg
        to = float(cfg.get("probe_timeout_s", 6) or 6)
        rep: dict = {"ts": time.time(), "time": time.strftime("%H:%M:%S"),
                     "stage": "probing"}

        # 先把"正在探测"发布出去，界面立刻有反馈，
        # 不用等物理网卡那几次注定超时的探测跑完（那要十几秒）。
        with self._lock:
            self._last_probe = dict(rep)
            self._last_probe_ts = time.time()

        # 主探测：走系统默认路由（正常应等于隧道落地）
        g = self.net.probe_egress(None, timeout=to)
        self._counters["probes"] += 1
        rep["default"] = g.to_dict()
        if not g.ok:
            self._counters["probe_fail"] += 1

        f = self.policy.evaluate_egress(g, "默认路由出口")
        if f:
            self.handle_findings([f], where="probe")
        rep["verdict"] = ("泄漏：" + f.title) if f else ("正常" if g.ok else "探测失败")
        rep["stage"] = "main-done"

        # 主结果一出来就发布，旁证探测慢慢补
        with self._lock:
            self._last_probe = dict(rep)
            self._last_probe_ts = time.time()

        # 旁证探测：绑定物理网卡，看绕过隧道会露出什么。
        # 隧道在 IP 层劫持默认路由时这里会超时，超时本身也是有用信息
        # （说明"绑物理网卡出不去"），所以给一个短超时，不拖慢整体。
        side: list[dict] = []
        for a in self.net.physical(force=True):
            for ip in a.ipv4[:1]:
                g2 = self.net.probe_egress(ip, timeout=min(to, 3.0))
                side.append({"bind": ip, "iface": a.alias, **g2.to_dict()})
        rep["physical_bind"] = side

        # 旁证探测：绑定隧道网卡
        for a in self.net.tunnels(force=True):
            if a.ipv4:
                g3 = self.net.probe_egress(a.ipv4[0], timeout=to)
                rep["tunnel_bind"] = {"bind": a.ipv4[0], "iface": a.alias, **g3.to_dict()}
                f3 = self.policy.evaluate_egress(g3, f"隧道 {a.alias}")
                if f3:
                    self.handle_findings([f3], where="probe-tunnel")
                break

        rep["stage"] = "done"
        with self._lock:
            self._last_probe = rep
            self._last_probe_ts = time.time()
        return rep

    def calibrate(self) -> dict:
        """标定本机真实出口 IP，写进 blocked_ips。

        两种情形：
          - 隧道没开：默认路由探测拿到的就是真实出口，直接记。
          - 隧道开着：默认路由拿不到真实出口，只能从"绑定物理网卡的探测"里取。
        两个都试，把拿到的都记进去。
        """
        found: list[str] = []
        details: list[str] = []

        g = self.net.probe_egress(None, timeout=6)
        if g.ok and g.ip:
            geo_foreign = g.country_code and g.country_code.upper() != "CN"
            if not geo_foreign:
                found.append(g.ip)
                details.append(f"默认路由出口 {g.ip}（{g.country}{g.region}{g.city} {g.isp}）"
                               "—— 看起来就是本机真实出口")
            else:
                details.append(f"默认路由出口 {g.ip} 在境外（{g.country}），"
                               "说明隧道正在生效，这条路拿不到真实出口")

        for a in self.net.physical(force=True):
            for ip in a.ipv4[:1]:
                g2 = self.net.probe_egress(ip, timeout=5)
                if g2.ok and g2.ip:
                    found.append(g2.ip)
                    details.append(f"绑定物理网卡 {ip}（{a.alias}）→ 出口 {g2.ip}"
                                   f"（{g2.country}{g2.region}{g2.city} {g2.isp}）")
                else:
                    details.append(f"绑定物理网卡 {ip}（{a.alias}）→ 出不去"
                                   f"（{g2.error}）——隧道在 IP 层劫持了默认路由，这是好事")

        cur = list(self.cfg.get("blocked_ips") or [])
        added = [ip for ip in found if ip not in cur]
        if added:
            self.cfg.update({"blocked_ips": cur + added})
            self.bus.action(severity="medium", code="CALIBRATE",
                            title="已标定本机真实出口",
                            detail=f"新增封杀 {added}")
        else:
            self.bus.action(severity="info", code="CALIBRATE",
                            title="标定完成（无新增）", detail="；".join(details) or "无结果")

        return {"found": found, "added": added, "blocked_ips": cur + added,
                "details": details}

    def leak_test(self) -> dict:
        """一键泄漏体检。给仪表盘上的「测试泄漏」按钮用。"""
        rep: dict = {"ts": time.time(), "items": []}
        adapters = self.net.adapters(force=True)
        phys_ips = {ip: a.alias for a in adapters
                    if not a.is_tunnel and a.is_up and not a.alias.lower().startswith("loopback")
                    for ip in a.ipv4}

        g = self.net.probe_egress(None, timeout=6)
        rep["items"].append({
            "name": "默认路由出口",
            "ok": g.ok,
            "value": f"{g.ip} · {g.country}{g.region}{g.city} · {g.isp}" if g.ok else g.error,
            "verdict": "pass" if (g.ok and not self.policy.evaluate_egress(g)) else
                       ("fail" if g.ok else "unknown"),
        })

        tun = [a for a in adapters if a.is_tunnel and a.is_up]
        rep["items"].append({
            "name": "隧道在线",
            "ok": bool(tun),
            "value": ", ".join(f"{a.alias}({','.join(a.ipv4)})" for a in tun) or "没有隧道网卡",
            "verdict": "pass" if tun else "fail",
        })

        v6 = [(a.alias, a.ipv6_global) for a in adapters
              if not a.is_tunnel and a.is_up and a.ipv6_global]
        rep["items"].append({
            "name": "IPv6 旁路",
            "ok": not v6,
            "value": "; ".join(f"{al}: {','.join(ips)}" for al, ips in v6) or "无全局 IPv6",
            "verdict": "fail" if v6 else "pass",
        })

        conns = W.list_tcp() + W.list_udp()
        # ⚠ 必须走和白名单一样的判定，否则会把隧道客户端自己的外层传输
        # （iKuuuVPNCore -> 27.44.127.109:808）也算成"绕过隧道" ——
        # 实测报了 50 条假阳性。那 50 条恰恰是隧道赖以工作的连接，
        # 报出来只会误导用户去"处理"一个绝对不能动的东西。
        leaked = []
        for c in conns:
            if not (c.is_outbound and c.local_addr in phys_ips):
                continue
            name, exe = self.policy.procs.get(c.pid)
            if self.policy._is_allowlisted_process(c.pid, exe, name):
                continue
            if self.policy._is_vpn_peer(c.remote_addr):
                continue
            leaked.append(f"{name}({c.pid}) {c.local_addr} -> {c.remote_addr}:{c.remote_port}")
        rep["items"].append({
            "name": "绕过隧道的连接",
            "ok": not leaked,
            "value": f"{len(leaked)} 条" + (("：" + "; ".join(leaked[:5])) if leaked else ""),
            "verdict": "fail" if leaked else "pass",
        })

        dns_leak = []
        tun_dns = {d for a in tun for d in a.dns}
        for a in adapters:
            if a.is_tunnel or not a.is_up or a.alias.lower().startswith("loopback"):
                continue
            for d in a.dns:
                if d not in tun_dns:
                    dns_leak.append(f"{a.alias}->{d}")
        rep["items"].append({
            "name": "DNS 泄漏",
            "ok": not dns_leak,
            "value": ", ".join(dns_leak) or "无",
            "verdict": "fail" if dns_leak else "pass",
        })

        needles = self.policy.needles()
        rep["items"].append({
            "name": "指纹素材",
            "ok": True,
            "value": f"已监控 {len(needles)} 项：" +
                     ", ".join(f"{n['kind']}={n['value']}" for n in needles[:6]),
            "verdict": "pass",
        })

        fw = self.enforcer.firewall_state()
        fw_on = all(v.get("enabled") for v in fw.values() if isinstance(v, dict)) if fw else False
        rep["items"].append({
            "name": "Windows 防火墙",
            "ok": fw_on,
            "value": json.dumps(fw, ensure_ascii=False)[:200],
            "verdict": "pass" if fw_on else "fail",
        })

        rep["pass"] = sum(1 for i in rep["items"] if i["verdict"] == "pass")
        rep["fail"] = sum(1 for i in rep["items"] if i["verdict"] == "fail")
        self.bus.action(severity="info", code="LEAK_TEST", title="泄漏体检完成",
                        detail=f"{rep['pass']} 项通过 / {rep['fail']} 项不通过")
        return rep

    # ---- 主循环 -------------------------------------------------------

    # ---- 心跳状态文件（给集成方判断"没装"还是"在重启"）---------------
    #
    # 反馈里的问题：守护重启的窗口期，集成方调 /api/status 得到"连接被拒绝"，
    # 无法区分"闸门没装"和"闸门正在重启"，只能瞎猜。
    #
    # 解决办法：守护每 5 秒往统一数据目录写一份 state.json 心跳。
    # 集成方判据：
    #   /api/health 通了                      -> 运行中
    #   连不上，但 state.json 心跳在 30 秒内   -> 正在重启（不是没装）
    #   state.json 里 state=="stopped"        -> 被主动停掉了
    #   文件不存在 / 心跳过期                  -> 没在跑
    def _write_state(self, state: str = "running") -> None:
        try:
            st = self.status()
            now = time.time()
            payload = {
                "state": state,
                "version": __version__,
                "pid": os.getpid(),
                "started_at": START_TS,
                "started_str": time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(START_TS)),
                "last_heartbeat": now,
                "last_heartbeat_str": time.strftime("%Y-%m-%d %H:%M:%S",
                                                    time.localtime(now)),
                "mode": st.get("mode"),
                "enabled": st.get("enabled"),
                "dry_run": st.get("dry_run"),
                "tunnel_ok": st.get("tunnel_ok"),
                "api_port": st.get("api_port"),
                "counters": st.get("counters"),
                "hint": ("心跳在 30 秒内说明守护活着；"
                         "HTTP 连不上但心跳新鲜 = 正在重启，不是没装"),
            }
            p = DATA_DIR / "state.json"
            tmp = p.with_name("state.json.tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            os.replace(tmp, p)
        except Exception:
            pass

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            self._write_state("running")
            self._stop.wait(5.0)

    def _startup_selfcheck(self) -> None:
        """启动自检：清理上一次异常退出留下的痕迹。

        反馈建议：「崩溃兜底（死亡开关）已有了，建议再加一条
        启动时自检残留路由/规则并自动清理。」

        为什么需要：验收测试会真加主机路由、真建防火墙规则。
        脚本中途崩了或被强杀，这些痕迹就留在系统上，而用户不知道是谁留的。
        """
        try:
            # 1. 测试用的主机路由（RFC 5737 文档保留段）—— 一定是测试残留，直接删
            ok, out, err = _run_ps(
                "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                "Where-Object { $_.DestinationPrefix -like '203.0.113.*' -or "
                "                $_.DestinationPrefix -like '198.51.100.*' -or "
                "                $_.DestinationPrefix -like '192.0.2.*' } | "
                "ForEach-Object { $_.DestinationPrefix }; Write-Output '---'",
                timeout=40)
            leftovers = [x.strip() for x in (out or "").splitlines()
                         if x.strip() and x.strip() != "---"]
            if leftovers:
                for pref in leftovers:
                    _run_ps(f"route delete {pref.split('/')[0]} 2>$null | Out-Null; "
                            f"Write-Output 'OK'", timeout=20)
                self.bus.state(
                    severity="medium", code="SELFTEST_CLEANUP",
                    title=f"已清理 {len(leftovers)} 条自测残留路由",
                    detail=f"上一次验收测试没有正常收尾，留下了这些主机路由："
                           f"{', '.join(leftovers[:6])}。已删除 —— "
                           f"它们会把本该走隧道的流量带到物理网卡上。")

            # 1b. 把**隧道段地址**指向物理网卡的路由 —— 一定是脏状态
            #
            # 实测抓到过一条真实的：198.18.0.107/32 -> WLAN 3（下一跳 192.168.0.1）。
            # 那是早期验收测试崩溃时留下的 —— 它把本该进隧道的 fake-IP 流量
            # 送到了物理网卡上，等于凭空造出一条泄漏路径。
            # 这类路由不可能是正常配置：隧道段地址没有任何理由走物理网卡。
            tun_cidrs = list(self.cfg.get("tunnel_cidrs") or ["198.18.0.0/15"])
            tun_idx = {a.if_index for a in self._adapters if a.is_tunnel}
            ok3, out3, _ = _run_ps(
                "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                "Where-Object { $_.NextHop -ne '0.0.0.0' } | "
                "ForEach-Object { [PSCustomObject]@{ Dest=$_.DestinationPrefix; "
                "  IfIndex=$_.InterfaceIndex; Alias=$_.InterfaceAlias; "
                "  Next=$_.NextHop } } | ConvertTo-Json -Compress", timeout=40)
            dirty = []
            try:
                import ipaddress as _ip
                rs = json.loads(out3) if (out3 or "").strip() else []
                rs = rs if isinstance(rs, list) else [rs]
                nets = [_ip.ip_network(x, strict=False) for x in tun_cidrs]
                for r in rs:
                    if int(r.get("IfIndex") or 0) in tun_idx:
                        continue
                    dest = (r.get("Dest") or "").split("/")[0]
                    try:
                        addr = _ip.ip_address(dest)
                    except ValueError:
                        continue
                    if any(addr in n for n in nets):
                        dirty.append(r)
            except Exception:
                dirty = []
            if dirty:
                for r in dirty:
                    _run_ps(f"route delete {(r.get('Dest') or '').split('/')[0]} "
                            f"2>$null | Out-Null; Write-Output 'OK'", timeout=20)
                self.bus.state(
                    severity="high", code="LEAK_ROUTE_CLEANED",
                    title=f"已清理 {len(dirty)} 条把隧道段地址指向物理网卡的路由",
                    detail="；".join(f"{r.get('Dest')}→{r.get('Alias')}"
                                     f"(下一跳 {r.get('Next')})" for r in dirty[:5])
                    + "。这类路由不可能是正常配置 —— 它把本该进隧道的流量"
                      "送到了物理网卡上，等于凭空造出一条泄漏路径。")

            # 2. 残留的 TARGET 规则 —— 只报告，不自动删
            #    （它们是真实防护，删了等于放开；只是重启后升级计数会重置）
            ok2, out2, _ = _run_ps(
                "(Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction "
                "SilentlyContinue | Where-Object { $_.Name -like "
                "'EgressGuard::TARGET::*' } | Measure-Object).Count", timeout=30)
            try:
                n = int((out2 or "0").strip() or 0)
            except Exception:
                n = 0
            if n > 0:
                self.bus.state(
                    severity="info", code="TARGET_RULES",
                    title=f"检测到 {n} 条「程序→目标」封杀规则（上个会话留下的）",
                    detail="这些规则仍然生效。重启会让「惯犯升级」的计数重置，"
                           "但规则本身是真实防护，不会自动删除。"
                           "要清理请用仪表盘上的「清空规则」。")

            # 3. 白名单粒度警告
            #
            # 反馈指出的问题：allow_processes 是按 exe 名匹配的，
            # 把 python.exe 加进白名单 = 放行全机所有 Python 程序。
            # 这个粒度和隔离粒度是同一个病根，配置层面同样存在。
            # 检测到就明确警告，别让用户以为"我只放行了那一个脚本"。
            from .enforce import SHARED_HOST_EXES
            bad = [str(x) for x in (self.cfg.get("allow_processes") or [])
                   if x and "\\" not in x
                   and os.path.basename(x).lower() in SHARED_HOST_EXES]
            if bad:
                self.bus.state(
                    severity="high", code="ALLOWLIST_GRANULARITY",
                    title="白名单里有共用宿主：" + ", ".join(bad),
                    detail="白名单是按 exe 名匹配的，加共用宿主等于放行**全机所有**"
                           "同类程序（比如所有 Python 脚本），不只是你想放行的那一个。"
                           "要精确放行请填**完整路径**（带反斜杠的条目按全路径精确匹配）。")
        except Exception as e:
            self.bus.error(severity="low", code="SELFCHECK",
                           title="启动自检失败（不影响主功能）", detail=str(e))

    def _refresh_adapters(self) -> None:
        try:
            ads = self.net.adapters(force=True)
        except Exception as e:
            self.bus.error(severity="high", code="ADAPTER_REFRESH",
                           title="网卡态势刷新失败", detail=str(e))
            return
        self._adapters = ads
        self._last_adapter_ts = time.time()

        tun = [a for a in ads if a.is_tunnel and a.is_up]
        ok = bool(tun)
        changed = (self._tunnel_ok is not None and self._tunnel_ok != ok)
        if changed:
            self.bus.state(severity="critical" if not ok else "info",
                           code="TUNNEL_CHANGE",
                           title="隧道状态变化",
                           detail=("隧道已断开 —— 现在所有出站流量都是裸奔"
                                   if not ok else f"隧道已恢复：{tun[0].alias}"))
        self._tunnel_ok = ok

        # 隧道断开 -> 自动熔断；恢复 -> 自动解除。
        # 这是比"手动严格模式"更有价值的用法：它消灭的是
        # "VPN 掉了但程序还在往外发"的那个窗口，而不是长期全局拒绝。
        if changed and self.cfg.enabled and self.cfg.get("fail_closed_on_tunnel_loss", True):
            self._set_fail_closed(not ok, reason="隧道状态变化")

        # 状态型判定按"轮"处理：本轮开始清空 seen，评估完把没再出现的
        # 视为"状态已恢复"，发一条恢复事件。
        with self._lock:
            self._state_seen_round.clear()
        for f in self.policy.evaluate_adapters(ads):
            self.handle_findings([f], where="adapters")
        with self._lock:
            gone = set(self._state_snapshot) - self._state_seen_round
            for k in gone:
                self._state_snapshot.pop(k, None)
        for k in gone:
            self.bus.state(severity="info", code=str(k[0]) + "_RESOLVED",
                           title=f"已恢复：{k[0]}",
                           detail=f"网卡 {k[1]} 上的该状态已消失，不再判定为泄漏")

        # ---- 结构性泄漏自动修复（v1.1.0）----
        #
        # 只在本轮**实际看到了**这些状态时才修，而且必须 enabled=True。
        # 观察档（enabled=False）不动系统任何东西 —— 那是它的契约。
        # 零泄漏自检会明确告诉你"检测到 N 项结构性泄漏，闸门未启用所以没修"。
        if self.cfg.enabled and self.cfg.get("auto_remediate", True):
            self._auto_remediate(ads)

    def _auto_remediate(self, ads: list) -> None:
        """对结构性泄漏做自动修复。带冷却，防抖。"""
        cd = float(self.cfg.get("remediate_cooldown_s", 300) or 300)
        now = time.time()
        physical = [a for a in ads if not a.is_tunnel and a.is_up
                    and not a.alias.lower().startswith("loopback")]
        tunnels = [a for a in ads if a.is_tunnel and a.is_up]
        tun_dns = next((t.dns[0] for t in tunnels if t.dns), "")

        def cooled(key: str) -> bool:
            last = self._remediated.get(key, 0.0)
            if now - last < cd:
                return True
            self._remediated[key] = now
            return False

        # IPv6 旁路
        if self.cfg.get("auto_remediate_ipv6", True):
            bad = [a for a in physical if a.ipv6_global]
            if bad and not cooled("ipv6"):
                aliases = [a.alias for a in bad]
                r = self.enforcer.remediate_ipv6(aliases)
                self.bus.action(
                    severity="high" if r.ok else "critical",
                    code="AUTO_REMEDIATE_IPV6",
                    title=("已自动封堵 IPv6 旁路" if r.ok
                           else "IPv6 旁路自动封堵失败"),
                    detail=f"网卡 {", ".join(aliases)} 上有全局 IPv6 地址 —— "
                           f"隧道只承载 IPv4，这些地址是完整的旁路通道。{r.detail}")

        # 非隧道 DNS
        if self.cfg.get("auto_remediate_dns", True) and tun_dns:
            for a in physical:
                leaked = [d for d in a.dns if d != tun_dns]
                if not leaked:
                    continue
                if cooled(f"dns:{a.alias}"):
                    continue
                r = self.enforcer.remediate_dns(a.alias, tun_dns, a.dns)
                if not r.ok:
                    self.bus.error(severity="high", code="AUTO_REMEDIATE_DNS",
                                   title=f"{a.alias} 的 DNS 自动修复失败",
                                   detail=r.detail)

    def _set_fail_closed(self, on: bool, reason: str = "") -> None:
        """隧道断开时熔断 / 恢复时解除。同一状态不重复下发。"""
        with self._lock:
            if self._fail_closed == on:
                return
        progs = self._tunnel_program_paths()
        r = self.enforcer.fail_closed(on, progs)
        with self._lock:
            self._fail_closed = on if r.ok else self._fail_closed
        if not r.ok:
            self.bus.error(severity="critical", code="FAILCLOSED_FAIL",
                           title="熔断动作失败（网络可能仍在裸奔）",
                           detail=f"{r.detail}；触发原因：{reason}")

    def _tunnel_program_paths(self) -> list[str]:
        """把隧道相关程序的 exe 全路径找出来，给熔断白名单用。

        熔断时只放行这些，隧道程序才连得出去重连。
        路径来自配置的进程名 + 已学到的隧道对端所属进程。
        """
        import glob
        names = [str(x).lower() for x in (self.cfg.get("allow_processes") or [])]
        paths: list[str] = []
        roots = [
            r"C:\Program Files\ikuuu_vpn\app",
            r"C:\Program Files\ikuuu_vpn",
            r"C:\Program Files (x86)\ikuuu_vpn\app",
        ]
        for root in roots:
            try:
                for p in glob.glob(os.path.join(root, "*.exe")):
                    if os.path.basename(p).lower() in names:
                        paths.append(p)
            except Exception:
                continue
        if not paths:
            for root in roots:
                try:
                    paths += glob.glob(os.path.join(root, "*.exe"))
                except Exception:
                    continue
        # 兜底：用进程名反查路径
        if not paths:
            for pid, nm in self.policy.procs.names_snapshot().items():
                if nm.lower() in names:
                    p = self.policy.procs._path(pid)
                    if p:
                        paths.append(p)
        return list(dict.fromkeys(paths))

    def _hot_loop(self) -> None:
        """热循环：只做连接枚举 + 判定 + 处置。**绝不在这里做慢操作。**

        实测踩到的大坑：原来这里会顺手调 `_refresh_adapters()`，
        而刷新网卡要起 PowerShell 子进程（优化前 5~10 秒）。
        结果是热循环每隔 8 秒就被阻塞十几秒，判定节奏从 250ms 恶化到十几秒 ——
        一条"发完请求就走"的快泄漏会在这个窗口里完全溜掉。
        实测就是这样漏掉了一个已经 ESTAB 的连接，只在 CLOSE_WAIT 阶段才抓到。

        现在网卡刷新挪到 _adapter_loop 独立线程，这里只读缓存。
        """
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                phys = {ip: a.alias for a in self._adapters
                        if not a.is_tunnel and a.is_up
                        and not a.alias.lower().startswith("loopback")
                        for ip in a.ipv4}
                if phys:
                    conns = W.list_tcp() + W.list_udp()
                    findings = self.policy.evaluate_connections(conns, phys)
                    if findings:
                        self.handle_findings(findings, where="connections")
            except Exception:
                self.bus.error(severity="high", code="HOT_LOOP",
                               title="热循环异常", detail=traceback.format_exc()[-800:])

            # 过期判定清掉：连接消失后 TTL 秒，它就从仪表盘上退场
            with self._lock:
                now = time.time()
                self._active = {k: v for k, v in self._active.items()
                                if now - v[0] < self._active_ttl}

            iv = max(0.05, float(self.cfg.get("poll_interval_ms", 250) or 250) / 1000.0)
            slack = iv - (time.monotonic() - t0)
            self._stop.wait(max(0.0, slack))

    def _adapter_loop(self) -> None:
        """网卡态势刷新：独立线程，慢也没关系，不拖累热循环。"""
        while not self._stop.is_set():
            try:
                self._refresh_adapters()
            except Exception:
                self.bus.error(severity="high", code="ADAPTER_LOOP",
                               title="网卡刷新线程异常",
                               detail=traceback.format_exc()[-500:])
            self._stop.wait(max(2.0, float(self.cfg.get("adapter_refresh_s", 8) or 8)))

    def _slow_loop(self) -> None:
        # 启动先来一次探测
        self._stop.wait(2.0)
        while not self._stop.is_set():
            if self.cfg.get("check_egress_ip", True):
                try:
                    self.probe_egress()
                except Exception:
                    self.bus.error(severity="medium", code="PROBE",
                                   title="出口探测异常",
                                   detail=traceback.format_exc()[-500:])
            iv = float(self.cfg.get("probe_interval_s", 60) or 60)
            self._stop.wait(max(5.0, iv))

    # ---- 本地 API -----------------------------------------------------

    def start_api(self) -> int:
        core = self

        class Handler(BaseHTTPRequestHandler):
            server_version = f"EgressGuard/{__version__}"
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            # ---- 工具 ----
            def _send(self, code: int, obj) -> None:
                body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "*")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _auth(self, q: dict) -> bool:
                tok = core.cfg.api_token
                got = (self.headers.get("X-EG-Token")
                       or (q.get("token", [""])[0] if q else ""))
                return bool(tok) and got == tok

            def _query(self) -> dict:
                return parse_qs(urlparse(self.path).query)

            # ---- GET ----
            def do_GET(self):
                try:
                    path = urlparse(self.path).path.rstrip("/") or "/"
                    q = self._query()

                    if path in ("/", "/ui", "/dashboard"):
                        # 仪表盘页面本身从本地 API 端口发出，
                        # 这样页面和 API 同源，不需要处理 CORS 与 file:// 的各种坑。
                        # 用 paths.resource()：冻结后 ui.html 在解包目录里，
                        # 源码运行时在 eg/ 目录里，两种情况都能找到。
                        from .paths import resource
                        html = resource("eg/ui.html").read_bytes()
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(html)))
                        self.send_header("Cache-Control", "no-store")
                        self.end_headers()
                        self.wfile.write(html)
                        return

                    if path == "/api/health" or path == "/api/ping":
                        return self._send(200, {"ok": True, "version": __version__,
                                                "uptime_s": round(time.time() - START_TS, 1)})

                    # 「告诉那个程序」的端点：**不需要 token**，
                    # 因为被掐断的程序要能匿名问"我为什么被掐了"。
                    #
                    # ⚠ 语义必须严格：blocked 只反映**这个 pid 自己**有没有被处置过。
                    #
                    # 曾经的错误做法：查不到该 pid 的记录就退回"全局最近一条拦截"。
                    # 后果是任何从没被拦过的程序来问，都会收到
                    #   {"blocked": true, "reason": "DNS 泄漏 ..."}
                    # —— 一个程序问"我被掐了吗"，得到"是的你被掐了，原因是 DNS 泄漏"，
                    # 但它根本没被掐。集成方会据此误判该重试还是该改配置。
                    # 这是接口语义错误，不是小毛病。
                    if path == "/api/why":
                        pid = int((q.get("pid", ["0"])[0] or "0"))
                        rec = core.notifier.violation_for_pid(pid) if pid else None
                        if rec is None:
                            return self._send(200, {
                                "blocked": False,
                                "pid": pid,
                                "message": "这个进程没有被 EgressGuard 拦截过的记录",
                                "hint": "要查全局最近一次拦截，请用 /api/last_violation",
                            })
                        return self._send(200, {
                            "blocked": True,
                            "code": rec.get("code"),
                            "reason": rec.get("detail"),
                            "title": rec.get("title"),
                            "time": rec.get("time"),
                            "age_s": round(time.time() - float(rec.get("ts") or 0), 1),
                            # PID 会被回收复用。给出进程名 + 时间，
                            # 让调用方能自己判断这条记录是不是"它自己"的。
                            "process": rec.get("process"),
                            "pid": rec.get("pid"),
                            "remote": rec.get("remote"),
                            "iface": rec.get("iface"),
                            "action": rec.get("action"),
                            "explain": ("本机启用了 EgressGuard 闸门：不允许昆明 IP 与"
                                        "本机指纹从本机泄漏。该连接满足泄漏条件，"
                                        "已被主动切断。"),
                        })

                    # 全局最近一次拦截 —— 和 /api/why 分开，避免语义混淆
                    if path == "/api/last_violation":
                        lv = core.notifier.last_violation()
                        if not lv:
                            return self._send(200, {"blocked": False,
                                                    "message": "还没有任何拦截记录"})
                        lv = dict(lv)
                        lv["blocked"] = True
                        lv["age_s"] = round(time.time() - float(lv.get("ts") or 0), 1)
                        return self._send(200, lv)

                    if path == "/api/status":
                        return self._send(200, core.status())

                    if path == "/api/events":
                        n = int((q.get("n", ["200"])[0] or "200"))
                        ms = (q.get("min_severity", ["info"])[0] or "info")
                        kinds = q.get("kind")
                        return self._send(200, {"events": core.bus.tail(n, ms, kinds),
                                                "stats": core.bus.stats()})

                    if path == "/api/connections":
                        return self._send(200, core.connections_view())

                    if path == "/api/rules":
                        if not self._auth(q):
                            return self._send(403, {"error": "需要 token"})
                        return self._send(200, {"rules": core.enforcer.list_rules()})

                    if path == "/api/config":
                        if not self._auth(q):
                            return self._send(403, {"error": "需要 token"})
                        return self._send(200, core.cfg.snapshot())

                    return self._send(404, {"error": "not found", "path": path})

                except Exception as e:
                    return self._send(500, {"error": str(e),
                                            "trace": traceback.format_exc()[-600:]})

            # ---- POST ----
            def do_POST(self):
                try:
                    path = urlparse(self.path).path.rstrip("/") or "/"
                    q = self._query()
                    ln = int(self.headers.get("Content-Length") or 0)
                    raw = self.rfile.read(ln) if ln else b"{}"
                    try:
                        body = json.loads(raw.decode("utf-8") or "{}")
                    except Exception:
                        body = {}

                    if path == "/api/login":
                        if not self._auth(q) and body.get("token") != core.cfg.api_token:
                            return self._send(403, {"error": "token 不正确"})
                        return self._send(200, {"ok": True})

                    if not self._auth(q):
                        return self._send(403, {"error": "需要 token"})

                    if path == "/api/config":
                        core.cfg.update(body)
                        core.net._cfg = core.cfg.snapshot()
                        core.bus.state(severity="info", code="CONFIG",
                                       title="配置已更新",
                                       detail=", ".join(sorted(body.keys()))[:300])
                        return self._send(200, {"ok": True, "config": core.cfg.snapshot()})

                    if path == "/api/toggle":
                        patch = {}
                        if "enabled" in body:
                            patch["enabled"] = bool(body["enabled"])
                        if "dry_run" in body:
                            patch["dry_run"] = bool(body["dry_run"])
                        if patch:
                            core.cfg.update(patch)
                        core.bus.state(
                            severity="medium" if core.cfg.enabled else "info",
                            code="TOGGLE", title="闸门状态变更",
                            detail=f"启用={core.cfg.enabled} 演练={core.cfg.dry_run}")
                        return self._send(200, {"ok": True, "enabled": core.cfg.enabled,
                                                "dry_run": core.cfg.dry_run})

                    if path == "/api/action":
                        act = body.get("action", "")
                        if act == "panic":
                            r = core.enforcer.panic_restore()
                        elif act == "install_static":
                            aliases = [a.alias for a in core._adapters
                                       if not a.is_tunnel and a.is_up
                                       and not a.alias.lower().startswith("loopback")]
                            res = core.enforcer.install_static_rules(aliases)
                            core._static_installed = all(x.ok for x in res)
                            r = {"ok": core._static_installed,
                                 "detail": "；".join(x.detail for x in res)}
                        elif act == "clear_rules":
                            r = core.enforcer.remove_all_rules()
                        elif act == "calibrate":
                            r = core.calibrate()
                        elif act == "leak_test":
                            r = core.leak_test()
                        elif act == "probe":
                            r = core.probe_egress()
                        elif act == "enable_firewall":
                            r = core.enforcer.enable_firewall()
                        elif act == "disable_ipv6":
                            alias = body.get("alias", "")
                            r = core.enforcer.disable_ipv6_on_adapter(alias)
                        elif act == "enable_ipv6":
                            alias = body.get("alias", "")
                            r = core.enforcer.restore_ipv6_on_adapter(alias)
                        elif act == "neutralize_hostname":
                            r = core.enforcer.neutralize_dhcp_hostname(
                                body.get("name", "HOST"))
                        elif act == "set_system_proxy":
                            r = core.enforcer.set_system_proxy(
                                body.get("server") or None)
                        elif act == "clear_system_proxy":
                            r = core.enforcer.clear_system_proxy()
                        elif act == "list_bypass":
                            rs = core.enforcer.list_bypass_routes(
                                [a.if_index for a in core._adapters if a.is_tunnel])
                            r = {"ok": True,
                                 "detail": (f"发现 {len(rs)} 条绕过隧道的路由："
                                            + "; ".join(
                                                f"{x.get('Dest')}→{x.get('Alias')}"
                                                for x in rs[:8]))
                                 if rs else "没有发现绕过隧道的路由",
                                 "routes": rs}
                        elif act == "clear_bypass":
                            r = core.enforcer.remove_all_bypass_routes(
                                [a.if_index for a in core._adapters if a.is_tunnel])
                        elif act == "guide_target":
                            r = core.enforcer.guide_target_to_tunnel(
                                body.get("ip", ""),
                                [a.if_index for a in core._adapters if a.is_tunnel])
                        elif act == "detect_proxy":
                            srv = core.enforcer.detect_tunnel_proxy()
                            r = {"ok": bool(srv),
                                 "detail": (f"探测到隧道代理端口 {srv}"
                                            if srv else
                                            "没探测到隧道客户端的本地代理端口")}
                        elif act == "block_target":
                            r = core.enforcer.block_target(
                                body.get("exe", ""), body.get("ip", ""),
                                reason=body.get("reason", "手动封杀目标"),
                                port=int(body.get("port") or 0))
                        elif act == "quarantine":
                            r = core.enforcer.quarantine_program(
                                body.get("exe", ""), body.get("reason", "手动隔离"))
                        elif act == "release":
                            r = core.enforcer.release_program(body.get("exe", ""))
                        elif act == "strict_on":
                            allow = [a.get("exe", "") for a in core._adapters]  # 占位
                            progs = list(core.cfg.get("allow_programs_full") or [])
                            r = core.enforcer.strict_kill_switch(True, progs)
                        elif act == "strict_off":
                            r = core.enforcer.strict_kill_switch(False, [])
                        else:
                            return self._send(400, {"error": f"未知动作 {act}"})
                        d = r.to_dict() if hasattr(r, "to_dict") else r
                        return self._send(200, d)

                    return self._send(404, {"error": "not found", "path": path})

                except Exception as e:
                    return self._send(500, {"error": str(e),
                                            "trace": traceback.format_exc()[-600:]})

        host = self.cfg.get("api", {}).get("host", "127.0.0.1")
        port = int(self.cfg.get("api", {}).get("port", 47821))
        last_err = None
        for p in range(port, port + 12):
            try:
                srv = ThreadingHTTPServer((host, p), Handler)
                srv.daemon_threads = True
                self._api_server = srv
                threading.Thread(target=srv.serve_forever, daemon=True,
                                 name="eg-api").start()
                if p != port:
                    self.cfg.update({"api": {"port": p}})
                self.bus.state(severity="info", code="API",
                               title="本地 API 已就绪",
                               detail=f"http://{host}:{p}/api/status")
                return p
            except OSError as e:
                last_err = e
                continue
        self.bus.error(severity="high", code="API",
                       title="本地 API 启动失败", detail=str(last_err))
        return 0

    # ---- 连接视图（给仪表盘）------------------------------------------

    def connections_view(self, limit: int = 300) -> dict:
        phys = {ip: a.alias for a in self._adapters
                if not a.is_tunnel and a.is_up
                and not a.alias.lower().startswith("loopback")
                for ip in a.ipv4}
        try:
            conns = W.list_tcp() + W.list_udp()
        except Exception as e:
            return {"error": str(e), "rows": []}

        rows = []
        for c in conns:
            if not c.is_outbound:
                continue
            name, exe = self.policy.procs.get(c.pid)
            in_tunnel = c.local_addr not in phys and c.local_addr != "0.0.0.0"
            allowed = self.policy._is_allowlisted_process(c.pid, exe, name)
            vpn_peer = self.policy._is_vpn_peer(c.remote_addr)
            if vpn_peer:
                verdict, sev = "隧道外层(放行)", "info"
            elif c.local_addr in phys and allowed:
                verdict, sev = "隧道外层(放行)", "info"
            elif c.local_addr in phys:
                verdict, sev = "裸奔泄漏", "critical"
            elif c.local_addr == "0.0.0.0":
                verdict, sev = "未绑定(监听)", "low"
            else:
                verdict, sev = "经隧道", "info"
            rows.append({
                "pid": c.pid, "process": name, "exe": exe,
                "proto": c.proto, "family": c.family, "state": c.state_name,
                "local": f"{c.local_addr}:{c.local_port}",
                "remote": f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "(广播/无远端)",
                "local_addr": c.local_addr, "iface": phys.get(c.local_addr, ""),
                "verdict": verdict, "severity": sev, "tunnel": in_tunnel,
            })
        rows.sort(key=lambda r: (0 if r["severity"] == "critical" else 1, r["process"]))
        return {"rows": rows[:limit], "total": len(rows),
                "physical_ips": phys}

    # ---- 生命周期 -----------------------------------------------------

    def start(self) -> None:
        """启动顺序很重要：**先起 API，再刷网卡**。

        刷网卡要起 PowerShell 子进程（实测 1~2 秒，优化前 5~10 秒）。
        如果先刷网卡再起 API，这段时间里仪表盘连不上端口，
        界面会显示"连不上守护"，用户会以为工具坏了。
        先起 API，界面立刻能打开并显示"正在初始化"。

        三个线程各司其职，互不阻塞：
          eg-hot     250ms 连接判定（只读缓存，绝不碰慢操作）
          eg-adapter 8s 网卡态势刷新（慢，但独立）
          eg-slow    60s 出口探测（要联网，更慢，也独立）
        """
        self.start_api()
        # 启动自检：清理上一次异常退出留下的自测残留（主机路由等）
        threading.Thread(target=self._heartbeat_loop, daemon=True,
                         name="eg-heartbeat").start()
        threading.Thread(target=self._startup_selfcheck, daemon=True,
                         name="eg-selfcheck").start()
        threading.Thread(target=self._adapter_loop, daemon=True,
                         name="eg-adapter").start()
        threading.Thread(target=self._hot_loop, daemon=True, name="eg-hot").start()
        threading.Thread(target=self._slow_loop, daemon=True, name="eg-slow").start()
        threading.Thread(target=self._action_loop, daemon=True,
                         name="eg-action").start()
        # 再起一个处置线程。
        #
        # 为什么需要两个：通知通道要 spawn 子进程（控制台注入 / 事件日志 / Toast），
        # 一次通知实测要 5~8 秒。单线程串行处理时，一波泄漏里后面的要排队等，
        # 实测出现过"守护 16:05:58 就掐断了，通知却 16:06:09 才发出去"——
        # 用户感知上就是"掐了但没告诉我为什么"。
        # 两个线程足够摊平常见的小规模并发，又不会因为并发太高让规则互相打架。
        threading.Thread(target=self._action_loop, daemon=True,
                         name="eg-action2").start()

    def _initial_refresh(self) -> None:
        try:
            self._refresh_adapters()
        except Exception:
            self.bus.error(severity="high", code="INIT",
                           title="首次网卡刷新失败",
                           detail=traceback.format_exc()[-600:])

    def run_forever(self) -> None:
        self.start()
        self.bus.state(severity="info", code="READY", title="守护进入运行态",
                       detail=f"模式 {self.status()['mode']}")
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        # 主动退出要留个明确标记：集成方看到 state=stopped 就知道
        # "是被人停掉了"，而不是"崩了"或"没装"。
        self._write_state("stopped")
        self.bus.state(severity="info", code="STOP", title="守护正在退出")
        if self._api_server:
            try:
                self._api_server.shutdown()
            except Exception:
                pass
        self.bus.close()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# 闸门状态判定（给集成方用）
#
# 反馈里的问题：守护重启窗口内，集成方调 API 得到"连接被拒绝"，
# 分不清"闸门没装"和"闸门正在重启"。
#
# 这个函数把判定逻辑固化下来，集成方不用自己拼：
#   运行中     /api/health 通了
#   正在重启   连不上，但 state.json 心跳在 30 秒内
#   已停止     连不上，state.json 里 state=="stopped"
#   未运行     连不上，也没有新鲜的心跳
# --------------------------------------------------------------------------

HEARTBEAT_FRESH_S = 30.0


# --------------------------------------------------------------------------
# 零泄漏自检（v1.1.0）
#
# 用户的目标就一句话：**不泄露**。
# 所以需要一个东西能直接回答"现在到底有没有在漏"，而不是让人自己
# 从仪表盘上十几个指标里拼结论。
#
# 这个函数把"零泄漏"拆成可判定的项，逐项给依据，最后给一个总判定：
#   zero_leak = true   当前所有项都过
#   zero_leak = false  有项不过，blocking 里列出是哪几项、为什么
#
# 分两类：
#   结构型（IPv6 旁路 / DNS 泄漏 / 隧道在线 / 绕过路由）—— 常驻状态，最危险
#   动态型（裸奔连接 / 出口 IP）—— 瞬时状态，可能只是恰好没抓到
# --------------------------------------------------------------------------

def zero_leak_report(core=None) -> dict:
    from . import winapi as _W

    own = core is None
    if own:
        ensure_dirs()
        cfg = Config()
        core = GuardCore(cfg)
    # ⚠ **无论 core 是不是外面传进来的，都必须刷新网卡。**
    #   我第一版把刷新放在 `if own:` 里面，于是从 main() 调进来时
    #   core._adapters 是空的 —— 自检直接报"没有隧道网卡"，
    #   而实际上隧道好好地在跑。这种假阴性比假阳性更危险：
    #   它会让人以为"零泄漏检查说没问题"或者反过来白白恐慌。
    #   自检是诊断命令，多花几秒刷新完全值得。
    core._refresh_adapters()

    cfg = core.cfg
    ads = core._adapters
    physical = [a for a in ads if not a.is_tunnel and a.is_up
                and not a.alias.lower().startswith("loopback")]
    tunnels = [a for a in ads if a.is_tunnel and a.is_up]
    tun_ips = {ip for t in tunnels for ip in t.ipv4}
    tun_dns = {d for t in tunnels for d in t.dns}

    checks: list[dict] = []

    def add(name: str, ok: bool, kind: str, detail: str, fix: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "kind": kind,
                       "detail": detail, "fix": fix})

    # ---- 结构型 ----
    add("隧道在线", bool(tunnels), "结构",
        ", ".join(f"{t.alias}({','.join(t.ipv4)})" for t in tunnels) or "没有隧道网卡",
        "启动 VPN 客户端")

    # ⚠ 这个检查项必须**规则感知**，不能只看"网卡上有没有 IPv6 地址"。
    #
    # 装了封堵规则之后，地址还在（防火墙不移除地址），但流量已经出不去。
    # 第一版只看地址存不存在，于是自动修复明明生效了、检查项还在报"有泄漏" ——
    # 这会让人误判成"修了没用"。
    #
    # 正确语义：地址存在 **且没有规则挡着** 才算泄漏。
    v6 = [(a.alias, a.ipv6_global) for a in physical if a.ipv6_global]
    v6_blocked = False
    if v6:
        try:
            okq, outq, _ = _run_ps(
                "Get-NetFirewallRule -Group 'EgressGuard' -ErrorAction SilentlyContinue | "
                "Where-Object { $_.DisplayName -like '*IPv6*' -and "
                "$_.Action.ToString() -eq 'Block' -and [bool]$_.Enabled } | "
                "ForEach-Object { $af = $_ | Get-NetFirewallAddressFilter; "
                "($af.RemoteAddress) -join '|' }", timeout=30)
            v6_blocked = "2000::/3" in (outq or "")
        except Exception:
            v6_blocked = False
    if not v6:
        add("无 IPv6 旁路", True, "结构", "物理网卡上没有全局 IPv6",
            "仪表盘「关闭物理网卡 IPv6」或打开自动修复（auto_remediate_ipv6）")
    elif v6_blocked:
        add("无 IPv6 旁路", True, "结构",
            "; ".join(f"{al}: {','.join(ips[:2])}" for al, ips in v6)
            + " —— 地址还在（防火墙不移除地址），但已被规则封杀 2000::/3，出不去",
            "已封堵。想彻底去掉地址：仪表盘「关闭物理网卡 IPv6」")
    else:
        add("无 IPv6 旁路", False, "结构",
            "; ".join(f"{al}: {','.join(ips[:2])}" for al, ips in v6)
            + " —— 且没有封堵规则，这些流量能直接出去",
            "仪表盘「关闭物理网卡 IPv6」或打开自动修复（auto_remediate_ipv6）")

    dns_bad = [(a.alias, [d for d in a.dns if d not in tun_dns])
               for a in physical if [d for d in a.dns if d not in tun_dns]]
    add("无 DNS 泄漏", not dns_bad, "结构",
        "; ".join(f"{al}->{','.join(ds)}" for al, ds in dns_bad) or "物理网卡的 DNS 都在隧道内",
        "仪表盘「引导系统代理到隧道」旁的 DNS 修复，或打开 auto_remediate_dns")

    # ---- 动态型 ----
    phys_ips = {ip for a in physical for ip in a.ipv4}
    leaked, hist = [], []
    try:
        conns = _W.list_tcp() + _W.list_udp()
        # ⚠ 必须先"学一遍隧道对端"，再判。
        #   不学的话，隧道客户端自己的外层传输（内核以 PID 0 持有的那些条目，
        #   对端是 27.44.127.109 之类）会被当成裸奔 —— 实测报出 100+ 条假阳性。
        #   那是隧道赖以工作的连接，报出来只会让人白白恐慌。
        core.policy.learn_vpn_peers(conns, phys_ips)
        for c in conns:
            if not (c.is_outbound and c.local_addr in phys_ips):
                continue
            name, exe = core.policy.procs.get(c.pid)
            if core.policy._is_allowlisted_process(c.pid, exe, name):
                continue
            if core.policy._is_vpn_peer(c.remote_addr):
                continue
            line = f"{name}({c.pid}) {c.local_addr}->{c.remote_addr}:{c.remote_port}"
            # 分三档：
            #   ESTAB/SYN_*  现在正在漏 -> 计入泄漏
            #   CLOSE_WAIT   已经漏过了、socket 还开着 -> 也计入（快泄漏只能抓到这一帧）
            #   TIME_WAIT 等 纯历史痕迹 -> 只作提示，不算"现在在漏"
            if c.is_live or c.state_name == "CLOSE_WAIT":
                leaked.append(line)
            else:
                hist.append(line)
    except Exception as e:
        import traceback as _tb
        print(f"[零泄漏自检] 连接枚举失败：{type(e).__name__}: {e}", file=sys.stderr)
        _tb.print_exc()
        leaked = [f"枚举失败：{e}"]
    detail = (f"{len(leaked)} 条正在/刚刚绕过隧道：" + "; ".join(leaked[:4])
              if leaked else "没有连接绕过隧道")
    if hist:
        detail += f"（另有 {len(hist)} 条已结束的历史痕迹，不算当前泄漏）"
    add("无裸奔连接", not leaked, "动态", detail,
        "闸门启用后会自动掐断；共用宿主只掐连接不封程序")

    bypass = []
    try:
        bypass = core.enforcer.list_bypass_routes(
            [t.if_index for t in tunnels])
    except Exception:
        pass
    add("无绕过隧道的路由", not bypass, "结构",
        f"{len(bypass)} 条：" + "; ".join(
            f"{r.get('Dest')}->{r.get('Alias')}" for r in bypass[:4]) if bypass
        else "没有把流量带出隧道的具体路由",
        "仪表盘「清掉绕过路由（导回隧道）」")

    blocking = [c for c in checks if not c["ok"]]
    zero = not blocking
    hard = [c for c in blocking if c["kind"] == "结构"]

    if zero:
        verdict = "零泄漏：全部检查项通过"
    elif hard:
        verdict = (f"有泄漏：{len(hard)} 项结构性问题 + "
                   f"{len(blocking) - len(hard)} 项动态问题")
    else:
        verdict = f"有泄漏：{len(blocking)} 项动态问题（结构上是干净的）"

    auto = bool(cfg.enabled and cfg.get("auto_remediate", True))
    return {
        "zero_leak": zero,
        "verdict": verdict,
        "enabled": cfg.enabled,
        "dry_run": cfg.dry_run,
        "auto_remediate": auto,
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": checks,
        "blocking": [c["name"] for c in blocking],
        "note": ("闸门未启用，所以结构性泄漏不会自动修 —— 打开闸门即可"
                 if (blocking and not cfg.enabled) else
                 ("自动修复已开启" if auto else "自动修复关闭")),
    }


def probe_gateway(port: int | None = None, timeout: float = 2.0) -> dict:
    import urllib.request

    cfg = Config()
    api_port = int(port or cfg.get("api", {}).get("port", 47821))
    token = cfg.api_token
    out = {"api_port": api_port, "state_file": str(DATA_DIR / "state.json")}

    # 1. HTTP 探活
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{api_port}/api/health",
            headers={"X-EG-Token": token})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            h = json.loads(r.read().decode("utf-8"))
        if h.get("ok"):
            out.update(status="running", alive=True,
                       message=f"闸门运行中（已运行 {h.get('uptime_s')} 秒）",
                       health=h)
            # 顺带带上完整状态，省一次调用
            try:
                req2 = urllib.request.Request(
                    f"http://127.0.0.1:{api_port}/api/status",
                    headers={"X-EG-Token": token})
                with urllib.request.urlopen(req2, timeout=timeout) as r2:
                    out["status_detail"] = json.loads(r2.read().decode("utf-8"))
            except Exception:
                pass
            return out
    except Exception as e:
        out["http_error"] = f"{type(e).__name__}: {e}"

    # 2. HTTP 不通 -> 看心跳
    sf = DATA_DIR / "state.json"
    if not sf.exists():
        out.update(status="not_running", alive=False,
                   message="闸门没在跑（也没有任何历史状态文件 —— "
                           "多半是没装过）",
                   advice="要装：双击 安装_右键管理员运行.bat")
        return out
    # ⚠ 用 utf-8-sig 读：状态文件是我们自己写的（无 BOM），
    #   但用户/脚本可能用 PowerShell 的 Out-File 改过它，那会带 BOM，
    #   而带 BOM 的 JSON 用普通 utf-8 解会直接抛异常 —— 实测踩到过。
    #   读状态文件这种"尽力而为"的场景，宁可宽容。
    try:
        st = json.loads(sf.read_text(encoding="utf-8-sig"))
    except Exception as e:
        out.update(status="unknown", alive=False,
                   message=f"状态文件读不出来：{e}",
                   advice=f"可以直接删掉 {sf} 让它重建")
        return out

    age = time.time() - float(st.get("last_heartbeat") or 0)
    out["state"] = st.get("state")
    out["heartbeat_age_s"] = round(age, 1)
    out["last_heartbeat_str"] = st.get("last_heartbeat_str")
    out["last_mode"] = st.get("mode")

    if st.get("state") == "stopped":
        out.update(status="stopped", alive=False,
                   message=f"闸门被主动停掉了（{st.get('last_heartbeat_str')}）",
                   advice="要恢复：双击 启动仪表盘.bat 打开闸门，"
                          "或重新跑一次安装脚本")
    elif age <= HEARTBEAT_FRESH_S:
        out.update(status="restarting", alive=False,
                   message=f"闸门正在重启（心跳 {age:.0f} 秒前，仍新鲜）"
                           f"—— 不是没装",
                   advice=f"等几秒重试；守护由计划任务拉起，通常 10 秒内回来")
    else:
        out.update(status="not_running", alive=False,
                   message=f"闸门没在跑（最后心跳 {age/60:.1f} 分钟前）",
                   advice="检查计划任务 EgressGuard 是否还在："
                          "Get-ScheduledTask -TaskName EgressGuard")
    return out


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # ⚠ 必须在 argparse **之前**处理 --out。
    # 打包成 --windowed exe 后 sys.stdout 是 None，argparse 的 --help 输出会直接消失。
    # 把 stdout 提前重定向到 --out 指定的文件，--help / 错误信息 / JSON 结果
    # 就全都落进同一个文件，不需要为 help 单独开一条路。
    out_path = None
    if "--out" in argv:
        i = argv.index("--out")
        if i + 1 < len(argv):
            out_path = argv[i + 1]
    if out_path:
        try:
            fh = open(out_path, "w", encoding="utf-8", errors="replace", buffering=1)
            sys.stdout = fh
            sys.stderr = fh
        except Exception:
            pass

    ap = argparse.ArgumentParser("egcore", description="EgressGuard 守护进程")
    ap.add_argument("--once", action="store_true", help="只跑一轮判定然后退出")
    ap.add_argument("--probe", action="store_true", help="立刻做一次出口探测然后退出")
    ap.add_argument("--leak-test", action="store_true", help="做一次泄漏体检然后退出")
    ap.add_argument("--calibrate", action="store_true", help="标定本机真实出口 IP")
    ap.add_argument("--status", action="store_true", help="打印当前状态 JSON")
    ap.add_argument("--assert", dest="assert_zero", action="store_true",
                    help="零泄漏自检：给出「当前是否零泄漏」的明确结论与逐项依据。"
                         "退出码 0=零泄漏，1=有泄漏 —— 可以直接用在脚本里当门禁")
    ap.add_argument("--check", action="store_true",
                    help="判断闸门状态：运行中/正在重启/已停止/未运行。"
                         "集成方在开工前调这个，不用自己拼判定逻辑")
    ap.add_argument("--enable", action="store_true", help="打开总开关（并关闭演练）")
    ap.add_argument("--disable", action="store_true", help="关闭总开关")
    ap.add_argument("--json", action="store_true", help="机器可读输出")
    ap.add_argument("--out", default=None,
                    help="把结果写到这个文件（打包成窗口化 exe 后，stdout 无法被"
                         "管道捕获，写文件是唯一可靠的取结果方式）")
    args = ap.parse_args(argv)

    def emit(text: str) -> None:
        try:
            print(text)
        except Exception:
            # 窗口化 exe 且没有父控制台、又没给 --out 时，stdout 不可用，属正常
            pass

    core = GuardCore()

    if args.enable:
        core.cfg.update({"enabled": True, "dry_run": False})
    if args.disable:
        core.cfg.update({"enabled": False})
    if args.enable or args.disable:
        emit(json.dumps({"enabled": core.cfg.enabled, "dry_run": core.cfg.dry_run},
                        ensure_ascii=False))
        if not (args.status or args.once or args.leak_test or args.probe
                or args.calibrate):
            return 0

    if args.assert_zero:
        rep = zero_leak_report(core)
        emit(json.dumps(rep, ensure_ascii=False, indent=2, default=str))
        # 退出码即结论：0=零泄漏，1=有泄漏。脚本里可直接 if 判断。
        return 0 if rep["zero_leak"] else 1

    if args.check:
        emit(json.dumps(probe_gateway(), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.status:
        # 必须先把网卡态势刷出来再读状态。
        # 不刷的话 self._adapters 是空的，输出里"网卡/隧道/出口"全是空 ——
        # 用户会以为工具坏了。这里多花 5~6 秒（PowerShell 采集）是值得的。
        core._refresh_adapters()
        emit(json.dumps(core.status(), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.calibrate:
        emit(json.dumps(core.calibrate(), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.leak_test:
        emit(json.dumps(core.leak_test(), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.probe:
        emit(json.dumps(core.probe_egress(), ensure_ascii=False, indent=2, default=str))
        return 0

    if args.once:
        core._refresh_adapters()
        phys = {ip: a.alias for a in core._adapters
                if not a.is_tunnel and a.is_up
                and not a.alias.lower().startswith("loopback")
                for ip in a.ipv4}
        conns = W.list_tcp() + W.list_udp()
        fs = core.policy.evaluate_connections(conns, phys)
        fs += core.policy.evaluate_adapters(core._adapters)
        emit(json.dumps({"connections": len(conns),
                         "findings": [f.to_dict() for f in fs]},
                        ensure_ascii=False, indent=2))
        return 0

    core.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
