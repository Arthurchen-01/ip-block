"""判定引擎：把"网络态势快照"翻译成"泄漏判定"。

五类泄漏
--------
1. PHYSICAL_EGRESS      连接绑定了物理网卡 —— 真实 IP 直接暴露给对方。
                        判据 = 连接的 LocalAddr 落在物理网卡 IP 集合里。
                        （不是路由表，见 winapi 模块 docstring 里的解释）

2. EGRESS_IP_*          出口 IP 落在昆明/云南/大陆/本机真实出口。
                        判据 = 主动探测 + 地理/ASN 查询。

3. IPV6_*               非隧道网卡上存在全局 IPv6 地址，或有 IPv6 出站连接。
                        隧道只承载 IPv4 时，IPv6 是完整的旁路通道。

4. DNS_LEAK             DNS 解析发往非隧道的解析器，泄漏的是"你在访问什么"。

5. FINGERPRINT_*        指纹信道（NetBIOS/mDNS/LLMNR/SMB/SSDP）或
                        出站内容里含主机名/MAC/MachineGuid/用户名。
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import re
import socket
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import netinfo as NI
from . import winapi as W
from .config import Config
from .logbus import LogBus

# --------------------------------------------------------------------------
# 判定码
# --------------------------------------------------------------------------

class Code:
    PHYSICAL_EGRESS = "PHYSICAL_EGRESS"
    EGRESS_IP_KUNMING = "EGRESS_IP_KUNMING"
    EGRESS_IP_DOMESTIC = "EGRESS_IP_DOMESTIC"
    EGRESS_IP_REAL = "EGRESS_IP_REAL"
    IPV6_GLOBAL_EXPOSED = "IPV6_GLOBAL_EXPOSED"
    IPV6_EGRESS = "IPV6_EGRESS"
    DNS_LEAK = "DNS_LEAK"
    FINGERPRINT_CHANNEL = "FINGERPRINT_CHANNEL"
    FINGERPRINT_PAYLOAD = "FINGERPRINT_PAYLOAD"
    TUNNEL_DOWN = "TUNNEL_DOWN"


# code -> (严重度, 短名, 一句话原因模板)
CODE_META: dict[str, tuple[str, str, str]] = {
    Code.PHYSICAL_EGRESS: (
        "critical", "裸奔出站",
        "这条连接绑定在物理网卡 {iface} 上，没有走隧道。对方看到的会是你的真实地址，"
        "而不是 VPN 落地。"),
    Code.EGRESS_IP_KUNMING: (
        "critical", "出口在昆明/云南",
        "出口 IP {ip} 归属 {region}{city}（{isp}），是昆明本地地址。"),
    Code.EGRESS_IP_DOMESTIC: (
        "critical", "出口在中国大陆",
        "出口 IP {ip} 归属中国大陆 {region}{city}（{isp}），"
        "按当前策略要求出口必须落在境外。"),
    Code.EGRESS_IP_REAL: (
        "critical", "出口=本机真实出口",
        "出口 IP {ip} 与标定出的本机真实出口一致，说明隧道没生效或流量绕过了隧道。"),
    Code.IPV6_GLOBAL_EXPOSED: (
        "high", "IPv6 旁路存在",
        "网卡 {iface} 上有全局 IPv6 地址 {ip}，且有 IPv6 默认路由。"
        "隧道只承载 IPv4，任何走 IPv6 的连接都会绕过隧道。"),
    Code.IPV6_EGRESS: (
        "critical", "IPv6 出站绕隧道",
        "存在 IPv6 出站连接，隧道不承载 IPv6，该流量未经代理。"),
    Code.DNS_LEAK: (
        "high", "DNS 泄漏",
        "网卡 {iface} 配置了非隧道 DNS {dns}。域名解析会走这条路径，"
        "上游能看到你在访问哪些域名。"),
    Code.FINGERPRINT_CHANNEL: (
        "high", "指纹信道外发",
        "程序正在使用 {proto} 端口 {port}（{proto_name}）在物理网卡上通信，"
        "这类协议会广播主机名/工作组/设备信息。"),
    Code.FINGERPRINT_PAYLOAD: (
        "critical", "内容含本机指纹",
        "出站内容里出现了本机指纹「{needle_kind}: {needle}」，会被对端记录。"),
    Code.TUNNEL_DOWN: (
        "critical", "隧道已断",
        "隧道接口不可用，此时任何出站流量都是裸奔，必须全部阻断。"),
}

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    code: str
    detail: str
    severity: str = "high"
    pid: int = 0
    process: str = ""
    exe: str = ""
    local: str = ""
    remote: str = ""
    proto: str = ""
    iface: str = ""
    evidence: dict = field(default_factory=dict)
    # 是否允许对它动手（掐断/隔离）。历史痕迹与不可归因的条目一律 False。
    enforceable: bool = True

    @property
    def title(self) -> str:
        return CODE_META.get(self.code, ("", self.code, ""))[1]

    @property
    def rank(self) -> int:
        return SEV_RANK.get(self.severity, 0)

    def dedup_key(self) -> tuple:
        """同一条连接上的同一个判定只应触发一次处置。"""
        return (self.code, self.pid, self.local, self.remote, self.proto)

    def to_dict(self) -> dict:
        return {
            "code": self.code, "title": self.title, "severity": self.severity,
            "detail": self.detail, "pid": self.pid, "process": self.process,
            "exe": self.exe, "local": self.local, "remote": self.remote,
            "proto": self.proto, "iface": self.iface, "evidence": self.evidence,
            "enforceable": self.enforceable,
        }


# --------------------------------------------------------------------------
# 进程信息
# --------------------------------------------------------------------------

_kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
_kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class ProcessTable:
    """PID -> (进程名, 完整路径)。

    两层缓存：
      - 名字：整表快照（Toolhelp32），每 name_ttl 秒刷一次。不需要权限，
        提权进程也能拿到名字。热循环里查字典，零系统调用。
      - 路径：按需 OpenProcess，成功/失败都缓存，避免反复失败重试。
        提权进程拿不到路径是正常的，此时路径为空串，白名单退化为按名字匹配。
    """

    def __init__(self, name_ttl: float = 5.0, path_ttl: float = 300.0):
        self._name_ttl = name_ttl
        self._path_ttl = path_ttl
        self._lock = threading.RLock()
        self._names: dict[int, str] = {}
        self._names_ts = 0.0
        self._paths: dict[int, tuple[float, str]] = {}

    def _refresh_names(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._names_ts < self._name_ttl and self._names:
            return
        names = W.list_process_names()
        with self._lock:
            if names:
                self._names = names
                self._names_ts = now

    def get(self, pid: int) -> tuple[str, str]:
        if pid <= 0:
            return ("System", "")
        self._refresh_names()
        with self._lock:
            name = self._names.get(pid, "")
        if not name:
            self._refresh_names(force=True)
            with self._lock:
                name = self._names.get(pid, "")
        if not name:
            name = f"pid:{pid}"
        return (name, self._path(pid))

    def _path(self, pid: int) -> str:
        now = time.monotonic()
        with self._lock:
            hit = self._paths.get(pid)
            if hit and now - hit[0] < self._path_ttl:
                return hit[1]
        h = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        path = ""
        if h:
            try:
                size = wintypes.DWORD(1024)
                buf = ctypes.create_unicode_buffer(size.value)
                if _kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                    path = buf.value
            finally:
                _kernel32.CloseHandle(h)
        with self._lock:
            self._paths[pid] = (now, path)
        return path

    def names_snapshot(self) -> dict[int, str]:
        self._refresh_names()
        with self._lock:
            return dict(self._names)

    def forget(self, pid: int) -> None:
        with self._lock:
            self._names.pop(pid, None)
            self._paths.pop(pid, None)


# --------------------------------------------------------------------------
# 指纹素材
# --------------------------------------------------------------------------

def collect_fingerprint_needles() -> list[dict]:
    """把本机可被远程识别的指纹素材收出来。

    这些字符串一旦出现在出站内容里，就等于把本机身份递了出去。
    """
    out: list[dict] = []

    def add(kind: str, value: str, why: str):
        v = (value or "").strip()
        if v and len(v) >= 4:
            out.append({"kind": kind, "value": v, "why": why,
                        "value_lower": v.lower()})

    # 主机名 / 计算机名
    add("主机名", os.environ.get("COMPUTERNAME", ""), "任何协议里带上它，对端就能把你和别的会话串起来")
    add("主机名", socket.gethostname(), "同上")

    # 用户名
    add("用户名", os.environ.get("USERNAME", ""), "出现在 UA / 路径 / 日志里就是身份泄漏")

    # 网卡 MAC
    try:
        for a in NI.NetInfo({}).adapters(force=True):
            if a.mac and a.mac not in ("", "00-00-00-00-00-00-00-E0"):
                add("网卡MAC", a.mac.replace("-", ":"), "MAC 是硬件唯一标识，且能定位到厂商")
                add("网卡MAC", a.mac, "同上")
    except Exception:
        pass

    # MachineGuid / SMBIOS UUID
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as k:
            add("MachineGuid", winreg.QueryValueEx(k, "MachineGuid")[0],
                "Windows 安装唯一标识，跨重装会话可追踪")
    except Exception:
        pass
    try:
        import subprocess
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
            capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        add("主板UUID", (p.stdout or "").strip(), "硬件唯一序列号")
    except Exception:
        pass

    # 域 / 工作组
    for var in ("USERDOMAIN", "USERDNSDOMAIN"):
        add("域/工作组", os.environ.get(var, ""), "能暴露组织归属")

    # 去重（同一个值只留一条，保留最先出现的 kind）
    seen: set[str] = set()
    uniq: list[dict] = []
    for n in out:
        if n["value_lower"] in seen:
            continue
        seen.add(n["value_lower"])
        uniq.append(n)
    return uniq


# --------------------------------------------------------------------------
# 判定引擎
# --------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, cfg: Config, net: NI.NetInfo, bus: LogBus):
        self.cfg = cfg
        self.net = net
        self.bus = bus
        self.procs = ProcessTable()
        self._needles: list[dict] = []
        self._needles_ts = 0.0
        self._needle_ttl = 300.0
        self._vpn_peers: dict[str, float] = {}   # 学到的隧道外层对端 IP -> 学到的时间
        self._peer_ttl = 1800.0
        self._handled: dict[tuple, float] = {}   # 已处置过的连接指纹
        self._handled_ttl = 3600.0
        self._allow_runtime: set[int] = set()    # 运行时放行的 PID（含自己）
        self._networks_cache: list | None = None
        self._networks_raw: list[str] = []

    # ---- 指纹 ---------------------------------------------------------

    def needles(self) -> list[dict]:
        now = time.monotonic()
        if now - self._needles_ts > self._needle_ttl or not self._needles:
            manual = [{"kind": "手动", "value": s, "value_lower": s.lower(),
                       "why": "配置里手动加入"}
                      for s in (self.cfg.get("fingerprint_needles") or []) if s]
            auto = collect_fingerprint_needles() if self.cfg.get("auto_fingerprint_needles") else []
            self._needles = auto + manual
            self._needles_ts = now
        return self._needles

    # ---- 放行 ---------------------------------------------------------

    def allow_runtime(self, pid: int) -> None:
        self._allow_runtime.add(pid)

    def _networks(self) -> list:
        raw = list(self.cfg.get("allow_remote_cidrs") or [])
        if self._networks_cache is None or raw != self._networks_raw:
            nets = []
            for c in raw:
                try:
                    nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    continue
            self._networks_cache = nets
            self._networks_raw = raw
        return self._networks_cache

    def _is_allowlisted_process(self, pid: int, exe: str, name: str) -> bool:
        if pid in self._allow_runtime:
            return True
        entries = [str(x) for x in (self.cfg.get("allow_processes") or [])]
        exe_l = (exe or "").lower()
        name_l = (name or "").lower()
        for e in entries:
            el = e.strip().lower()
            if not el:
                continue
            if "\\" in el or "/" in el:
                if exe_l and exe_l == el:
                    return True
            else:
                if name_l and name_l == el:
                    return True
        return False

    def _is_remote_allowed(self, remote: str) -> bool:
        try:
            ip = ipaddress.ip_address(remote.split("%")[0])
        except ValueError:
            return False
        for n in self._networks():
            try:
                if ip in n:
                    return True
            except TypeError:
                continue
        return False

    def _is_tunnel_internal(self, remote: str) -> bool:
        """隧道内部的假地址（198.18.x.x 之类），不是外发，不用管。"""
        try:
            ip = ipaddress.ip_address(remote.split("%")[0])
        except ValueError:
            return False
        for c in (self.cfg.get("tunnel_cidrs") or ["198.18.0.0/15"]):
            try:
                if ip in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def note_vpn_peer(self, ip: str) -> None:
        """记下隧道自身的外层对端，之后连到这些 IP 一律放行。

        为什么需要这个：隧道进程建立连接时，内核（PID 0）也会在连接表里留下
        TIME_WAIT / 半开条目，这些条目没有可用的进程名，无法靠白名单匹配。
        按"对端 IP"放行能一并覆盖。
        """
        if ip:
            self._vpn_peers[ip] = time.monotonic()

    def _is_vpn_peer(self, ip: str) -> bool:
        t = self._vpn_peers.get(ip)
        if t is None:
            return False
        if time.monotonic() - t > self._peer_ttl:
            self._vpn_peers.pop(ip, None)
            return False
        return True

    # ---- 主判定 -------------------------------------------------------

    def learn_vpn_peers(self, conns: Iterable[W.Conn],
                        physical_ips: dict[str, str]) -> list[str]:
        """第一遍：把隧道自身在物理网卡上的对端 IP 学出来。

        必须单独跑一遍，否则启动瞬间会有一波误报：
        隧道进程刚建连时，内核（PID 0）也会在连接表里留下 TIME_WAIT / 半开条目，
        这些条目没有进程名可匹配，只能靠"对端 IP 已知"来放行。
        """
        learned: list[str] = []
        for c in conns:
            if c.local_addr not in physical_ips:
                continue
            if not c.remote_addr or self._is_remote_allowed(c.remote_addr):
                continue
            name, exe = self.procs.get(c.pid)
            if self._is_allowlisted_process(c.pid, exe, name):
                if not self._is_vpn_peer(c.remote_addr):
                    learned.append(c.remote_addr)
                self.note_vpn_peer(c.remote_addr)
        return learned

    def evaluate_connections(self, conns: Iterable[W.Conn],
                             physical_ips: dict[str, str],
                             ) -> list[Finding]:
        """physical_ips: 物理网卡 IP -> 网卡别名

        两遍扫描：先学隧道外层对端，再判定。见 learn_vpn_peers 的说明。
        """
        conns = list(conns)
        self.learn_vpn_peers(conns, physical_ips)

        findings: list[Finding] = []
        cfg = self.cfg
        check_phys = cfg.get("check_physical_egress", True)
        check_fp = cfg.get("check_fingerprint_channels", True)
        check_v6 = cfg.get("check_ipv6", True)

        for c in conns:
            if not c.is_outbound:
                continue
            if self._is_remote_allowed(c.remote_addr):
                continue
            if self._is_tunnel_internal(c.remote_addr):
                continue

            name, exe = self.procs.get(c.pid)
            allowed_proc = self._is_allowlisted_process(c.pid, exe, name)

            # 隧道自身的外层传输：放行（对端已在第一遍学掉）
            if allowed_proc and c.local_addr in physical_ips:
                continue

            # 「隧道对端 IP 放行」必须加归因条件，否则是个安全漏洞。
            #
            # 为什么要按对端放行：隧道进程的连接结束后，TCB 会归到内核
            # （PID 0/4），这些残留条目没有可匹配的进程名，不放行就会天天误报。
            #
            # 为什么不能无条件按对端放行：本机实测 iKuuu 客户端会用 223.5.5.5、
            # 223.6.6.6、1.12.12.12 等做 DoT/DNS。一旦这些 IP 进了放行集，
            # **任何程序**连这些 IP 都会被免检 —— 包括一个明明绑在物理网卡上
            # 裸奔的程序。那就等于在闸门上开了一个洞。
            #
            # 所以：只有当这条连接**无法归因到某个具体且非白名单的程序**时，
            # 才按对端放行。有明确 PID 且该进程不在白名单 -> 照常判违规。
            if self._is_vpn_peer(c.remote_addr):
                if (not c.is_attributable) or allowed_proc:
                    continue

            # ---- 1. 物理网卡裸奔 ----
            if check_phys and c.local_addr in physical_ips:
                iface = physical_ips[c.local_addr]

                # 定级：三档。
                #
                #  critical + 可处置：ESTAB / SYN_SENT / SYN_RCVD —— 正在传数据，真在漏
                #
                #  high + 可处置：CLOSE_WAIT —— 对端已关闭，但**本地 socket 还开着**，
                #      程序仍然能往里写。更重要的是：一个"发一个请求就走"的快泄漏，
                #      250ms 轮询很可能只抓到 CLOSE_WAIT 这一帧。
                #      如果把它判成不可处置，工具对快泄漏就等于完全瞎了 ——
                #      而这恰恰是最需要拦的一类（短连接、打完就跑）。
                #      处置动作（隔离该程序）在 CLOSE_WAIT 下同样正确。
                #
                #  low + 不可处置：TIME_WAIT / FIN_WAIT / LAST_ACK / CLOSING ——
                #      纯历史痕迹，只剩统计意义。TIME_WAIT 数量极大（隧道自身的
                #      连接结束后都落这里），必须压到最低档，否则仪表盘全是噪音。
                if not c.is_attributable:
                    sev, enf = "low", False
                    why = "由内核/System 持有，无法归因到具体程序，也无法安全阻断"
                elif c.is_live:
                    sev, enf = "critical", True
                    why = ""
                elif c.state == W.MIB_TCP_STATE_CLOSE_WAIT:
                    sev, enf = "high", True
                    why = ("连接处于 CLOSE_WAIT：对端已关闭但本机 socket 仍开着，"
                           "程序仍可写入；快泄漏常只能抓到这一帧，故照常处置")
                else:
                    sev, enf = "low", False
                    why = f"连接状态 {c.state_name}，已不再传数据（历史痕迹）"

                if c.family == "ipv6":
                    if check_v6:
                        findings.append(Finding(
                            code=Code.IPV6_EGRESS, severity=sev, enforceable=enf,
                            detail=CODE_META[Code.IPV6_EGRESS][2] + (f"（{why}）" if why else ""),
                            pid=c.pid, process=name, exe=exe,
                            local=f"{c.local_addr}:{c.local_port}",
                            remote=f"{c.remote_addr}:{c.remote_port}",
                            proto=c.proto, iface=iface,
                            evidence={"state": c.state_name, "live": c.is_live,
                                      "attributable": c.is_attributable, "note": why},
                        ))
                else:
                    tmpl = CODE_META[Code.PHYSICAL_EGRESS][2]
                    findings.append(Finding(
                        code=Code.PHYSICAL_EGRESS, severity=sev, enforceable=enf,
                        detail=tmpl.format(iface=iface) + (f"（{why}）" if why else ""),
                        pid=c.pid, process=name, exe=exe,
                        local=f"{c.local_addr}:{c.local_port}",
                        remote=f"{c.remote_addr}:{c.remote_port}",
                        proto=c.proto, iface=iface,
                        evidence={"state": c.state_name, "local_addr": c.local_addr,
                                  "live": c.is_live, "attributable": c.is_attributable,
                                  "note": why},
                    ))
                continue

            # ---- 5. 指纹信道 ----
            # TCP：看远端端口；UDP：连接表里没有远端，只能看本地端口
            # （NetBIOS 名称服务、mDNS、LLMNR 都是本地固定端口发出）
            if c.proto == "tcp":
                port = c.remote_port
            else:
                port = c.local_port
            if check_fp and port in NI.FINGERPRINT_PORTS:
                findings.append(Finding(
                    code=Code.FINGERPRINT_CHANNEL, severity="high",
                    detail=CODE_META[Code.FINGERPRINT_CHANNEL][2].format(
                        proto=c.proto.upper(), port=port,
                        proto_name=NI.FINGERPRINT_PORTS[port]),
                    pid=c.pid, process=name, exe=exe,
                    local=f"{c.local_addr}:{c.local_port}",
                    remote=f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "(广播)",
                    proto=c.proto, iface=physical_ips.get(c.local_addr, ""),
                    evidence={"port": port, "proto_name": NI.FINGERPRINT_PORTS[port]},
                ))

        return findings

    def evaluate_adapters(self, adapters: list[NI.Adapter]) -> list[Finding]:
        """网卡级别的判定：IPv6 旁路、DNS 泄漏、隧道是否在线。"""
        findings: list[Finding] = []
        cfg = self.cfg
        tunnels = [a for a in adapters if a.is_tunnel and a.is_up]
        physical = [a for a in adapters if not a.is_tunnel and a.is_up
                    and not a.alias.lower().startswith("loopback")]

        if not tunnels:
            findings.append(Finding(
                code=Code.TUNNEL_DOWN, severity="critical",
                detail=CODE_META[Code.TUNNEL_DOWN][2],
                iface="", evidence={"tunnel_count": 0},
            ))

        tun_dns: set[str] = set()
        for t in tunnels:
            tun_dns.update(t.dns)

        for a in physical:
            if cfg.get("check_ipv6", True) and a.ipv6_global and a.has_default_route:
                findings.append(Finding(
                    code=Code.IPV6_GLOBAL_EXPOSED, severity="high",
                    detail=CODE_META[Code.IPV6_GLOBAL_EXPOSED][2].format(
                        iface=a.alias, ip=a.ipv6_global[0]),
                    iface=a.alias,
                    evidence={"ipv6": a.ipv6_global, "if_index": a.if_index},
                ))

            if cfg.get("check_dns", True) and a.dns:
                leaked = [d for d in a.dns if d not in tun_dns]
                if leaked:
                    findings.append(Finding(
                        code=Code.DNS_LEAK, severity="high",
                        detail=CODE_META[Code.DNS_LEAK][2].format(
                            iface=a.alias, dns=", ".join(leaked)),
                        iface=a.alias,
                        evidence={"dns": leaked, "tunnel_dns": sorted(tun_dns),
                                  "if_index": a.if_index},
                    ))
        return findings

    def evaluate_egress(self, geo: NI.GeoInfo, label: str = "隧道出口") -> Finding | None:
        """出口 IP 判定。label 说明这次探测是从哪条路径出去的。"""
        if not geo.ok or not geo.ip:
            return None
        cfg = self.cfg

        blocked = [str(x) for x in (cfg.get("blocked_ips") or [])]
        if geo.ip in blocked:
            return Finding(
                code=Code.EGRESS_IP_REAL, severity="critical",
                detail=CODE_META[Code.EGRESS_IP_REAL][2].format(ip=geo.ip),
                iface=label, evidence=geo.to_dict(),
            )

        hit = NI.in_cidr_list(geo.ip, list(cfg.get("blocked_cidrs") or []))
        if hit:
            return Finding(
                code=Code.EGRESS_IP_KUNMING, severity="critical",
                detail=f"出口 IP {geo.ip} 落在封杀段 {hit}（{geo.country} {geo.region}{geo.city} {geo.isp}）",
                iface=label, evidence=dict(geo.to_dict(), matched_cidr=hit),
            )

        regions = [str(x).lower() for x in (cfg.get("blocked_regions") or [])]
        blob = f"{geo.region} {geo.city}".lower()
        for kw in regions:
            if kw and kw in blob:
                return Finding(
                    code=Code.EGRESS_IP_KUNMING, severity="critical",
                    detail=CODE_META[Code.EGRESS_IP_KUNMING][2].format(
                        ip=geo.ip, region=geo.region, city=geo.city, isp=geo.isp),
                    iface=label, evidence=dict(geo.to_dict(), matched_region=kw),
                )

        cc = [str(x).upper() for x in (cfg.get("blocked_countries") or [])]
        if geo.country_code and geo.country_code.upper() in cc:
            return Finding(
                code=Code.EGRESS_IP_DOMESTIC, severity="critical",
                detail=CODE_META[Code.EGRESS_IP_DOMESTIC][2].format(
                    ip=geo.ip, region=geo.region, city=geo.city, isp=geo.isp),
                iface=label, evidence=geo.to_dict(),
            )

        if cfg.get("require_foreign_egress") and geo.country_code and geo.country_code.upper() == "CN":
            return Finding(
                code=Code.EGRESS_IP_DOMESTIC, severity="critical",
                detail=CODE_META[Code.EGRESS_IP_DOMESTIC][2].format(
                    ip=geo.ip, region=geo.region, city=geo.city, isp=geo.isp),
                iface=label, evidence=geo.to_dict(),
            )
        return None

    # ---- 内容指纹扫描 --------------------------------------------------

    def scan_payload(self, blob: bytes | str, where: str,
                     pid: int = 0, remote: str = "") -> list[Finding]:
        """在出站内容里找本机指纹。给清洗代理和抓包用。"""
        if not blob or not self.cfg.get("check_fingerprint_payload", True):
            return []
        if isinstance(blob, bytes):
            try:
                text = blob.decode("utf-8", "replace")
            except Exception:
                return []
        else:
            text = blob
        low = text.lower()
        name, exe = self.procs.get(pid) if pid else ("", "")
        out: list[Finding] = []
        for n in self.needles():
            if n["value_lower"] in low:
                idx = low.find(n["value_lower"])
                ctx = text[max(0, idx - 40): idx + len(n["value"]) + 40]
                out.append(Finding(
                    code=Code.FINGERPRINT_PAYLOAD, severity="critical",
                    detail=CODE_META[Code.FINGERPRINT_PAYLOAD][2].format(
                        needle_kind=n["kind"], needle=n["value"]),
                    pid=pid, process=name, exe=exe, remote=remote,
                    iface=where,
                    evidence={"needle_kind": n["kind"], "needle": n["value"],
                              "context": ctx, "where": where},
                ))
                break   # 一条内容命中一次就够，别刷屏
        return out

    # ---- 去重 ---------------------------------------------------------

    def already_handled(self, f: Finding) -> bool:
        now = time.monotonic()
        if len(self._handled) > 20000:
            self._handled = {k: v for k, v in self._handled.items()
                             if now - v < self._handled_ttl}
        k = f.dedup_key()
        t = self._handled.get(k)
        if t is not None and now - t < 60.0:
            return True
        self._handled[k] = now
        return False

    # ---- 状态摘要（给仪表盘）------------------------------------------

    def summary(self) -> dict:
        return {
            "vpn_peers": sorted(self._vpn_peers.keys()),
            "needles": [{"kind": n["kind"], "value": n["value"], "why": n["why"]}
                        for n in self.needles()],
            "allow_processes": list(self.cfg.get("allow_processes") or []),
        }
