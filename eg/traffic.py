"""流量采样器 —— 把"现在网络上正在发生什么"变成可以画出来的数据。

采集三类东西：

  1. **网卡字节计数**（GetIfEntry2，64 位）→ 真实的上/下行速率（字节/秒）
     这是**真数据**，不是估算。

  2. **连接表采样**（GetExtendedTcpTable/UdpTable）→ 每个进程的
     活跃连接数、新建连接速率、目的地集合。

  3. **时间线历史** → 每个进程在每个采样刻度上的活动强度，环形缓冲。

⚠ 一个必须说清楚的诚实边界

**每个进程的字节数是拿不到的。** 试过三条路：
  - `GetPerTcpConnectionEStats` —— 这台机器上返回 1784（ERROR_INVALID_USER_BUFFER），
    这个 API 属于可选特性，很多系统上根本没实现
  - ETW（Microsoft-Windows-Kernel-Network）—— **可行**，10 秒产生 5.6 MB CSV，
    也就是 33 MB/分钟。做一次性分析可以，做常驻监控太重
  - 逐连接字节数 —— Windows 不通过任何用户态 API 暴露

所以"谁在控制流量"这一栏用的是**连接活动度**（活跃连接数 + 新建速率），
不是字节数。界面上会**明确标注这是活动度**，不会假装成流量。
总速率那一栏是真的字节数。
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
from collections import deque
from ctypes import wintypes

from . import winapi as W

# ---------------------------------------------------------------------------
# GetIfEntry2 —— 拿每张网卡的 64 位收发字节计数
# ---------------------------------------------------------------------------


class _NET_LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_ulonglong)]


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _MIB_IF_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", _NET_LUID),
        ("InterfaceIndex", wintypes.ULONG),
        ("InterfaceGuid", _GUID),
        ("Alias", wintypes.WCHAR * 257),
        ("Description", wintypes.WCHAR * 257),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", wintypes.ULONG),
        ("Type", ctypes.c_uint),
        ("TunnelType", ctypes.c_uint),
        ("MediaType", ctypes.c_uint),
        ("PhysicalMediumType", ctypes.c_uint),
        ("AccessType", ctypes.c_uint),
        ("DirectionType", ctypes.c_uint),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", ctypes.c_uint),
        ("AdminStatus", ctypes.c_uint),
        ("MediaConnectState", ctypes.c_uint),
        ("NetworkGuid", _GUID),
        ("ConnectionType", ctypes.c_uint),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


_EXPECTED_ROW2 = 1352   # MSDN 上 MIB_IF_ROW2 的大小（x64）


def _row2_usable() -> bool:
    """结构体定义对不对，先自检。布局错了会读出垃圾数字。"""
    n = ctypes.sizeof(_MIB_IF_ROW2)
    # 不同 SDK 版本略有差异，给一个宽容区间；差太多说明布局错了
    return abs(n - _EXPECTED_ROW2) <= 8


def if_counters(only: set[int] | None = None) -> dict[int, dict]:
    """{ifIndex: {in, out, alias}} —— 64 位字节计数。失败返回空 dict。

    ⚠ `only` 这个过滤是必须的。
    Windows 上同一张物理网卡会挂好几个过滤驱动层
    （QoS Packet Scheduler / WFP Native MAC / Virtual WiFi Filter / …），
    GetIfEntry2 对**每一层**都返回一份**完全相同**的计数。
    实测这台机器上 45 个接口里有 40 个是这种重复层 ——
    不过滤的话界面上会列出 40 多行一模一样的速率，还把它们加起来当总流量，
    数字直接虚高好几倍。
    """
    if not _row2_usable():
        return {}
    out: dict[int, dict] = {}
    try:
        iphlpapi = ctypes.windll.iphlpapi
        for idx in range(1, 512):
            row = _MIB_IF_ROW2()
            row.InterfaceIndex = idx
            row.InterfaceLuid = _NET_LUID()
            # GetIfEntry2 需要 Index 或 Luid 有一个有效；用 Index 时 Luid 置 0
            rc = iphlpapi.GetIfEntry2(ctypes.byref(row))
            if rc != 0:
                continue
            idx2 = int(row.InterfaceIndex)
            if only is not None and idx2 not in only:
                continue
            out[idx2] = {
                "alias": str(row.Alias),
                "in": int(row.InOctets),
                "out": int(row.OutOctets),
                "oper": int(row.OperStatus),
            }
    except Exception:
        return out
    return out


def _fmt_rate(bps: float) -> str:
    if bps < 1024:
        return f"{bps:.0f} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    return f"{bps / 1048576:.2f} MB/s"


class TrafficMonitor:
    """流量采样与时间线。

    每秒 `sample()` 一次；API 通过 `snapshot()` / `timeline()` 取数。
    """

    def __init__(self, cfg, policy, geo, tick_s: float = 1.0, history_s: int = 900):
        self.cfg = cfg
        self.policy = policy
        self.geo = geo
        self.tick_s = tick_s
        self.history_s = history_s          # 时间线保留 15 分钟
        self._lock = threading.Lock()

        self._ticks: deque[dict] = deque(maxlen=int(history_s / tick_s))
        self._prev_if: dict[int, dict] = {}
        self._prev_if_ts = 0.0
        self._prev_conns: dict[tuple, float] = {}   # 连接身份 -> 首次出现时刻
        self._rates: deque[dict] = deque(maxlen=300)  # 最近 5 分钟的总速率
        self._last_conns: list = []
        self._last_sample_ts = 0.0
        self._by_proc_cache: dict = {}

    # ---- 采样 ---------------------------------------------------------
    def sample(self, adapters=None) -> None:
        now = time.time()
        with self._lock:
            # 1. 网卡字节计数 -> 速率
            #    只取 NetInfo 认得的那些网卡（物理 + 隧道），
            #    过滤掉同一张卡的 QoS/WFP/Filter 驱动层（它们报的是同一份计数）
            only = {a.if_index for a in (adapters or [])}
            cur_if = if_counters(only or None)
            dt = now - self._prev_if_ts if self._prev_if_ts else 0.0
            rates = {}
            if cur_if and self._prev_if and 0.2 < dt < 30:
                for idx, cur in cur_if.items():
                    prev = self._prev_if.get(idx)
                    if not prev:
                        continue
                    din = cur["in"] - prev["in"]
                    dout = cur["out"] - prev["out"]
                    # 计数器回绕（换网卡/重置）时会是负数，丢掉这一帧
                    if din < 0 or dout < 0:
                        continue
                    rates[idx] = {
                        "alias": cur["alias"],
                        "in_bps": din / dt,
                        "out_bps": dout / dt,
                    }
            self._prev_if = cur_if
            self._prev_if_ts = now
            self._rates.append({"ts": now, **{
                f"if{i}": (v["in_bps"] + v["out_bps"]) for i, v in rates.items()}})

            # 2. 连接表 -> 每进程活动
            try:
                conns = W.list_tcp() + W.list_udp()
            except Exception:
                conns = []
            self._last_conns = conns

            # ⚠ 必须先学一遍隧道对端，再判 leaked。
            #   不学的话 policy._is_vpn_peer 永远是 False，
            #   隧道自己的外层传输会被全部标成"裸奔"。
            try:
                phys0 = {ip for a in (adapters or []) if not a.is_tunnel
                         for ip in a.ipv4}
                self.policy.learn_vpn_peers(conns, phys0)
            except Exception:
                pass

            phys_ips = set()
            tun_ips = set()
            for a in (adapters or []):
                if a.is_tunnel:
                    tun_ips.update(a.ipv4)
                else:
                    phys_ips.update(a.ipv4)

            now_ids = {}
            per_proc: dict[str, dict] = {}
            for c in conns:
                if not c.is_outbound:
                    continue
                # PID 0 = 内核持有的连接（隧道客户端的外层传输、
                # 系统 DNS、时间同步等）。它们**不能按进程归属**，
                # 单独归一类，不要混进具体程序里 —— 否则
                # 「System 有 2833 条连接」这种数字会把界面淹掉。
                if c.pid in (0, 4):
                    name, _exe = "内核/系统（无法归属）", ""
                else:
                    name, _exe = self.policy.procs.get(c.pid)
                    name = name or f"pid {c.pid}"
                ident = (c.pid, c.local_port, c.remote_addr, c.remote_port,
                         c.proto)
                first = self._prev_conns.get(ident, now)
                now_ids[ident] = first
                p = per_proc.setdefault(name, {
                    "pid": c.pid, "name": name, "conns": 0, "new": 0,
                    "live": 0, "leaked": 0, "kernel_held": 0,
                    "dests": set(), "tcp": 0, "udp": 0,
                })
                p["conns"] += 1
                if first >= now - self.tick_s * 1.5:
                    p["new"] += 1
                if c.is_live:
                    p["live"] += 1
                p[c.proto] = p.get(c.proto, 0) + 1
                # 「裸奔」的判定必须和闸门用**同一套逻辑**：
                #   1. 白名单里的程序（隧道客户端自身、本工具）不算
                #   2. 隧道对端（learn 出来的）不算
                #   3. 内核持有且指向隧道对端的也不算
                # 只按"本地地址在物理网卡上"判会把隧道自己的外层传输
                # 全标成裸奔 —— 实测报出 220 条假阳性，那恰恰是隧道赖以工作的连接。
                if c.local_addr in phys_ips:
                    # ⚠ 内核持有的连接（PID 0/4）**单独统计，不算泄漏**。
                    #
                    # 实测：PID 0 名下有 3900+ 条从物理网卡出去的连接
                    # （隧道客户端的外层传输、系统 DNS 等由内核代持）。
                    # 它们无法归属到任何程序，所以：
                    #   算成"泄漏" -> 数字巨大且无从处置，纯噪音
                    #   完全不显示 -> 用户不知道有这些东西存在
                    # 所以单独一栏，说清楚"看不到归属"。
                    if c.pid in (0, 4):
                        p["kernel_held"] = p.get("kernel_held", 0) + 1
                        continue
                    allowed = False
                    try:
                        allowed = bool(self.policy._is_allowlisted_process(
                            c.pid, _exe, name))
                        if not allowed and self.policy._is_vpn_peer(c.remote_addr):
                            allowed = True
                    except Exception:
                        allowed = False
                    if not allowed:
                        p["leaked"] += 1
                if c.remote_addr and not c.remote_addr.startswith(
                        ("127.", "0.0.0.0")):
                    p["dests"].add(c.remote_addr)
            self._prev_conns = now_ids

            # 活动度打分：活跃连接 + 新建连接加权。
            # ⚠ 这是**活动度**，不是字节数 —— 界面上会这么标。
            for p in per_proc.values():
                p["activity"] = p["live"] + p["new"] * 4
            self._by_proc_cache = per_proc

            self._ticks.append({
                "ts": now,
                "rates": rates,
                "procs": {k: {"activity": v["activity"], "conns": v["conns"],
                              "new": v["new"], "live": v["live"],
                              "leaked": v["leaked"],
                              "kernel_held": v.get("kernel_held", 0),
                              "pid": v["pid"]}
                          for k, v in per_proc.items()},
                "total_in": sum(v["in_bps"] for v in rates.values()),
                "total_out": sum(v["out_bps"] for v in rates.values()),
            })
            self._last_sample_ts = now

        # 地理队列推进放在锁外：它要发网络请求，不能占着采样锁。
        # 限流在 GeoCache 内部（每 20 秒最多 12 个），这里每 tick 调一次是安全的。
        try:
            self.geo.resolve_pending()
        except Exception:
            pass

    # ---- 取数 ---------------------------------------------------------
    def snapshot(self, top: int = 40) -> dict:
        with self._lock:
            ticks = list(self._ticks)
            per_proc = {k: dict(v) for k, v in self._by_proc_cache.items()}
            rates = dict(ticks[-1]["rates"]) if ticks else {}

        total_in = sum(v["in_bps"] for v in rates.values())
        total_out = sum(v["out_bps"] for v in rates.values())

        procs = []
        for name, p in per_proc.items():
            dests = sorted(p["dests"])
            geo_dests = []
            for ip in dests[:6]:
                g = self.geo.lookup(ip)
                geo_dests.append({
                    "ip": ip,
                    "country": g.get("country") or g.get("label") or "",
                    "city": g.get("city") or "",
                    "isp": g.get("isp") or "",
                    "lat": g.get("lat"), "lon": g.get("lon"),
                    "pending": bool(g.get("pending")),
                    "local": bool(g.get("local")),
                })
            procs.append({
                "pid": p["pid"], "name": name,
                "conns": p["conns"], "live": p["live"], "new": p["new"],
                "leaked": p["leaked"],
                "kernel_held": p.get("kernel_held", 0),
                "activity": p["activity"],
                "tcp": p.get("tcp", 0), "udp": p.get("udp", 0),
                "dest_count": len(dests), "destinations": geo_dests,
            })
        procs.sort(key=lambda x: (-x["leaked"], -x["activity"], -x["conns"]))

        return {
            "ts": time.time(),
            "total": {"in_bps": total_in, "out_bps": total_out,
                      "in_h": _fmt_rate(total_in), "out_h": _fmt_rate(total_out)},
            "adapters": [{"if_index": i, **v, "in_h": _fmt_rate(v["in_bps"]),
                          "out_h": _fmt_rate(v["out_bps"])}
                         for i, v in rates.items()],
            "processes": procs[:top],
            "process_count": len(procs),
            "connection_count": len(self._last_conns),
            "leaked_connections": sum(p["leaked"] for p in per_proc.values()),
            "kernel_held_connections": sum(p.get("kernel_held", 0)
                                           for p in per_proc.values()),
            "metric_note": ("每进程显示的是**连接活动度**（活跃连接 + 新建速率），"
                            "不是字节数 —— Windows 不通过用户态 API 暴露每进程字节。"
                            "总速率是真字节数。"),
            "geo": self.geo.stats(),
        }

    def timeline(self, seconds: int = 300, buckets: int = 120) -> dict:
        """时间线：每进程在每个时间桶里的活动强度。"""
        with self._lock:
            ticks = list(self._ticks)
        if not ticks:
            return {"buckets": [], "series": [], "seconds": seconds}
        now = ticks[-1]["ts"]
        start = now - seconds
        ticks = [t for t in ticks if t["ts"] >= start]
        if not ticks:
            return {"buckets": [], "series": [], "seconds": seconds}

        width = max(0.5, seconds / buckets)
        edges = [start + i * width for i in range(buckets + 1)]

        # 每个进程一条泳道
        names = set()
        for t in ticks:
            names.update(t["procs"].keys())
        series = []
        for name in names:
            cells = [0.0] * buckets
            leaked_cells = [False] * buckets
            for t in ticks:
                p = t["procs"].get(name)
                if not p:
                    continue
                bi = int((t["ts"] - start) / width)
                if 0 <= bi < buckets:
                    cells[bi] += p["activity"]
                    if p["leaked"]:
                        leaked_cells[bi] = True
            if not any(cells):
                continue
            series.append({
                "name": name,
                "pid": next((t["procs"][name]["pid"] for t in reversed(ticks)
                             if name in t["procs"]), 0),
                "cells": [round(c, 1) for c in cells],
                "leaked": leaked_cells,
                "total": round(sum(cells), 1),
            })
        series.sort(key=lambda s: -s["total"])

        # 总速率的折线
        rate_cells = [0.0] * buckets
        for t in ticks:
            bi = int((t["ts"] - start) / width)
            if 0 <= bi < buckets:
                rate_cells[bi] = max(rate_cells[bi], t["total_in"] + t["total_out"])

        return {
            "seconds": seconds,
            "bucket_seconds": round(width, 2),
            "start": start, "end": now,
            "buckets": [round(e, 2) for e in edges[:-1]],
            "rate": [round(r, 1) for r in rate_cells],
            "series": series[:24],
            "series_count": len(series),
            "metric_note": "泳道深浅 = 该进程的网络活动度（连接数加权），不是字节数",
        }

    def rates(self, seconds: int = 120) -> list[dict]:
        with self._lock:
            rs = list(self._rates)
        now = time.time()
        return [r for r in rs if now - r["ts"] <= seconds]
