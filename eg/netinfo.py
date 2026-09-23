"""网络态势采集：网卡、隧道识别、出口 IP 探测、地理归属判定。

设计要点
--------
1. 网卡信息来自 PowerShell（`Get-NetAdapter` / `Get-NetIPAddress` / `Get-DnsClientServerAddress`），
   带 TTL 缓存。热循环（250ms）不碰它，只读缓存。

2. 隧道识别是**启发式 + 可配置**的。本机实测：iKuuu 客户端起了一个 wintun 网卡，
   名字 `iKuuuVPN`，IPv4 是 `198.18.0.1/16`（RFC2544 基准测试段，clash/mihomo TUN 的惯用假地址）。
   判定优先级：
     a) 配置里显式指定的接口名 / IP 段
     b) 接口 IP 落在 198.18.0.0/15（TUN 假地址惯例）
     c) 接口描述里含 tunnel / wintun / tap / wireguard / utun / sing-box 等关键词
   命中任意一条即视为隧道。

3. 出口 IP 探测是**绑定源地址**的：可以指定从隧道 IP 出去、或从物理网卡 IP 出去。
   这两种探测回答的是完全不同的问题：
     绑定隧道 IP   -> "我的正常出口是什么"（应等于 VPN 落地）
     绑定物理网卡IP -> "如果流量绕过隧道，对方会看到什么"（这就是泄漏实锤）
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import winapi as W

# --------------------------------------------------------------------------
# 快速预筛用的"云南/昆明"地址段
#
# ⚠ 这只是**加速预筛**，不是权威判据。权威判据是运行时对出口 IP 做地理/ASN 查询
#   （见 GeoInfo / Policy）。这里列的是运营商在云南的公开分配段，用于在还没拿到
#   地理结果时就能立刻拦截。可在配置里覆盖。
# --------------------------------------------------------------------------
YUNNAN_CIDRS: list[str] = [
    # 中国电信 云南
    "222.172.0.0/16", "220.163.0.0/16", "116.52.0.0/14", "182.240.0.0/13",
    "106.56.0.0/14", "113.16.0.0/13", "218.62.0.0/16", "61.166.0.0/16",
    # 中国移动 云南
    "112.112.0.0/14", "183.224.0.0/12", "39.128.0.0/12", "117.136.128.0/17",
    # 中国联通 云南
    "42.242.0.0/15", "119.62.0.0/16", "116.248.0.0/14", "27.40.0.0/13",
    # 云南教育网 / 其他
    "218.194.0.0/16", "219.221.0.0/16",
    # IPv6：中国联通 / 电信 / 移动 三大段（本机 WLAN 上的 2408:896e:... 就落在第一条里）
    "2408:8000::/20", "240e::/20", "2409::/20",
]

# 隧道网卡描述里的关键词
TUNNEL_KEYWORDS = (
    "tunnel", "wintun", "tap-", "tap ", "wireguard", "utun", "sing-box",
    "clash", "mihomo", "openvpn", "proton", "nordlynx", "warp",
    "iKuuuVPN".lower(), "virtual ethernet adapter",
)

# 指纹信道端口：这些协议会把主机名/工作组/设备型号广播出去
FINGERPRINT_PORTS = {
    137: "NetBIOS 名称服务（广播主机名）",
    138: "NetBIOS 数据报（广播主机名/工作组）",
    139: "NetBIOS 会话（SMB over NetBIOS，带主机名）",
    445: "SMB 直连（主机名 + 工作组 + 系统版本）",
    5353: "mDNS（广播主机名 .local + 服务列表）",
    5355: "LLMNR（广播主机名）",
    1900: "SSDP/UPnP（设备型号 + 序列号）",
    3702: "WS-Discovery（设备类型 + 主机名）",
}

PS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def _ps_json(script: str, timeout: float = 30.0) -> Any:
    """跑一段 PowerShell 并解析 JSON 输出。

    编码：必须强制 PowerShell 用 UTF-8 输出。
    否则中文系统上它按控制台代码页(936/GBK)吐字节，Python 按 UTF-8 解，
    所有中文（网卡名、接口描述）都会变成乱码。
    """
    prologue = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
                "$OutputEncoding=[System.Text.Encoding]::UTF8;"
                "$ProgressPreference='SilentlyContinue';")
    cmd = PS + [f"$ErrorActionPreference='SilentlyContinue'; "
                f"{prologue}{script} | ConvertTo-Json -Depth 5 -Compress"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        return None
    txt = (p.stdout or b"").decode("utf-8", "replace").strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        return None


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------

@dataclass
class Adapter:
    alias: str
    if_index: int
    description: str = ""
    status: str = ""
    mac: str = ""
    media: str = ""
    ipv4: list[str] = field(default_factory=list)
    ipv6_global: list[str] = field(default_factory=list)
    ipv6_linklocal: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    gateway: str = ""
    is_tunnel: bool = False
    has_default_route: bool = False

    @property
    def is_up(self) -> bool:
        return self.status.lower() == "up"

    def to_dict(self) -> dict:
        return {
            "alias": self.alias, "if_index": self.if_index,
            "description": self.description, "status": self.status,
            "mac": self.mac, "ipv4": self.ipv4, "ipv6_global": self.ipv6_global,
            "dns": self.dns, "gateway": self.gateway,
            "is_tunnel": self.is_tunnel, "has_default_route": self.has_default_route,
        }


@dataclass
class GeoInfo:
    ip: str
    ok: bool = False
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# --------------------------------------------------------------------------
# 采集器
# --------------------------------------------------------------------------

class NetInfo:
    """带缓存的网络态势采集。线程安全。"""

    def __init__(self, cfg: dict | None = None, cache_ttl: float = 8.0):
        self._lock = threading.RLock()
        self._ttl = cache_ttl
        self._ts = 0.0
        self._adapters: list[Adapter] = []
        self._cfg = cfg or {}
        self._geo_cache: dict[str, tuple[float, GeoInfo]] = {}
        self._geo_ttl = 600.0

    # ---- 网卡 ----------------------------------------------------------

    def adapters(self, force: bool = False) -> list[Adapter]:
        with self._lock:
            now = time.monotonic()
            if force or now - self._ts > self._ttl or not self._adapters:
                try:
                    self._adapters = self._collect()
                    self._ts = now
                except Exception:
                    if not self._adapters:
                        raise
            return list(self._adapters)

    def _collect(self) -> list[Adapter]:
        cfg = self._cfg
        tun_names = {s.lower() for s in cfg.get("tunnel_interfaces", [])}
        tun_cidrs = [ipaddress.ip_network(c, strict=False)
                     for c in cfg.get("tunnel_cidrs", ["198.18.0.0/15"])]

        # ⚠ 一次 PowerShell 调用把所有信息取回来，不要分 6 次。
        #
        # 实测教训：原来每类信息各起一个 PowerShell 子进程（网卡/IPv4/IPv6/DNS/
        # 路由v4/路由v6），一次刷新要 5~10 秒。守护进程的热循环如果同步等它，
        # 就会整整十几秒不做任何判定 —— 一次"发完请求就走"的快泄漏
        # 会在这个窗口里完全溜掉（实测就是这样漏掉了一个 ESTAB 连接）。
        # 合并成一次调用后，刷新成本降到 1~2 秒，再配合独立线程，
        # 热循环的 250ms 节奏就不受影响了。
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$nic = @(Get-NetAdapter | ForEach-Object { "
            "  [PSCustomObject]@{ Name=$_.Name; idx=$_.InterfaceIndex; "
            "    Desc=$_.InterfaceDescription; Status=$_.Status; "
            "    Mac=$_.MacAddress; Media=$_.MediaType } });"
            "$ip4 = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
            "  [PSCustomObject]@{ idx=$_.InterfaceIndex; IP=$_.IPAddress } });"
            "$ip6 = @(Get-NetIPAddress -AddressFamily IPv6 | ForEach-Object { "
            "  [PSCustomObject]@{ idx=$_.InterfaceIndex; IP=$_.IPAddress } });"
            "$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { "
            "  [PSCustomObject]@{ idx=$_.InterfaceIndex; "
            "    Servers=@($_.ServerAddresses) } });"
            "$r4 = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
            "| ForEach-Object { [PSCustomObject]@{ idx=$_.InterfaceIndex; "
            "    Next=$_.NextHop } });"
            "$r6 = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' "
            "| ForEach-Object { [PSCustomObject]@{ idx=$_.InterfaceIndex; "
            "    Next=$_.NextHop } });"
            "[PSCustomObject]@{ nic=$nic; ip4=$ip4; ip6=$ip6; dns=$dns; "
            "  r4=$r4; r6=$r6 }"
        )
        # 注意：这里不要自己再 ConvertTo-Json —— _ps_json 会在外面统一加一次。
        # 加两次会变成"JSON 字符串的 JSON"，解析出来是个 str 而不是 dict。
        blob = _ps_json(script, timeout=45) or {}
        if isinstance(blob, str):
            try:
                blob = json.loads(blob)
            except Exception:
                blob = {}

        nic = _as_list(blob.get("nic"))
        ips4 = _as_list(blob.get("ip4"))
        ips6 = _as_list(blob.get("ip6"))
        dns = _as_list(blob.get("dns"))
        routes = _as_list(blob.get("r4")) + _as_list(blob.get("r6"))

        by_idx: dict[int, Adapter] = {}
        for n in nic:
            idx = n.get("idx")
            if idx is None:
                continue
            a = Adapter(
                alias=n.get("Name") or "",
                if_index=int(idx),
                description=n.get("Desc") or "",
                status=n.get("Status") or "",
                mac=n.get("Mac") or "",
                media=str(n.get("Media") or ""),
            )
            by_idx[a.if_index] = a

        for row in ips4:
            idx = row.get("idx")
            a = by_idx.get(int(idx)) if idx is not None else None
            if a is None:
                continue
            ip = row.get("IP") or ""
            if ip and not ip.startswith("169.254."):
                a.ipv4.append(ip)

        for row in ips6:
            idx = row.get("idx")
            a = by_idx.get(int(idx)) if idx is not None else None
            if a is None:
                continue
            ip = (row.get("IP") or "").split("%")[0]
            if not ip:
                continue
            try:
                obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if obj.is_link_local:
                a.ipv6_linklocal.append(ip)
            elif not obj.is_loopback and not obj.is_multicast:
                a.ipv6_global.append(ip)

        for row in dns:
            idx = row.get("idx")
            a = by_idx.get(int(idx)) if idx is not None else None
            if a is None:
                continue
            for s in _as_list(row.get("Servers")):
                if s:
                    a.dns.append(str(s))

        for row in routes:
            idx = row.get("idx")
            a = by_idx.get(int(idx)) if idx is not None else None
            if a is None:
                continue
            a.has_default_route = True
            if not a.gateway and row.get("Next"):
                a.gateway = str(row["Next"])

        # ---- 隧道判定 ----
        for a in by_idx.values():
            a.is_tunnel = self._is_tunnel(a, tun_names, tun_cidrs)

        return sorted(by_idx.values(), key=lambda x: x.if_index)

    @staticmethod
    def _is_tunnel(a: Adapter, tun_names: set[str], tun_cidrs: list) -> bool:
        if a.alias.lower() in tun_names:
            return True
        for ip in a.ipv4:
            try:
                obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            for net in tun_cidrs:
                if obj in net:
                    return True
        blob = f"{a.alias} {a.description}".lower()
        if any(k in blob for k in TUNNEL_KEYWORDS):
            return True
        return False

    # ---- 派生视图 ------------------------------------------------------

    def tunnels(self, force: bool = False) -> list[Adapter]:
        return [a for a in self.adapters(force) if a.is_tunnel]

    def physical(self, force: bool = False) -> list[Adapter]:
        """物理出口网卡：非隧道、非回环、有全局地址、处于 Up。"""
        out = []
        for a in self.adapters(force):
            if a.is_tunnel or not a.is_up:
                continue
            if a.alias.lower().startswith("loopback"):
                continue
            if a.ipv4 or a.ipv6_global:
                out.append(a)
        return out

    def tunnel_ip_set(self, force: bool = False) -> set[str]:
        return {ip for a in self.tunnels(force) for ip in a.ipv4}

    def physical_ip_set(self, force: bool = False) -> set[str]:
        """**这是泄漏判定的核心集合**：任何出站连接的 LocalAddr 落在这里 = 绕过隧道。"""
        return {ip for a in self.physical(force) for ip in a.ipv4}

    def ip_to_ifindex(self, force: bool = False) -> dict[str, int]:
        m: dict[str, int] = {}
        for a in self.adapters(force):
            for ip in a.ipv4:
                m[ip] = a.if_index
        return m

    # ---- 出口 IP 探测 --------------------------------------------------

    def probe_egress(self, bind_ip: str | None = None, timeout: float = 6.0) -> GeoInfo:
        """探测出口 IP。bind_ip 指定源地址：
             None            -> 走系统默认路由
             隧道 IP          -> 强制走隧道
             物理网卡 IP      -> 强制绕过隧道（泄漏实锤探测）
        """
        ip = self._fetch_echo(bind_ip, timeout)
        if not ip:
            return GeoInfo(ip="", ok=False, error="所有回显服务均不可达")
        return self.geo(ip, timeout=timeout)

    @staticmethod
    def _fetch_echo(bind_ip: str | None, timeout: float) -> str | None:
        import socket
        import ssl

        targets = [
            ("ip-api.com", 80, "/line/?fields=query", False),
            ("api.ipify.org", 80, "/", False),
            ("icanhazip.com", 80, "/", False),
            ("ifconfig.me", 80, "/ip", False),
            ("ipinfo.io", 443, "/ip", True),
            ("api.ip.sb", 443, "/ip", True),
        ]
        ipre = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{6,}\b")

        for host, port, path, use_tls in targets:
            try:
                fam = socket.AF_INET
                try:
                    infos = socket.getaddrinfo(host, port, fam, socket.SOCK_STREAM)
                    if not infos:
                        continue
                    dst = infos[0][4]
                except socket.gaierror:
                    continue
                s = socket.socket(fam, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if bind_ip:
                    s.bind((bind_ip, 0))
                s.connect(dst)
                if use_tls:
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=host)
                req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: EgressGuard-probe\r\nAccept: */*\r\n"
                       f"Connection: close\r\n\r\n")
                s.sendall(req.encode())
                chunks = []
                while True:
                    b = s.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
                    if sum(len(c) for c in chunks) > 16384:
                        break
                s.close()
                body = b"".join(chunks).decode("utf-8", "replace")
                body = body.split("\r\n\r\n", 1)[-1].strip()
                m = ipre.search(body)
                if m:
                    cand = m.group(0)
                    try:
                        ipaddress.ip_address(cand)
                        return cand
                    except ValueError:
                        continue
            except Exception:
                continue
        return None

    # ---- 地理 / ASN ----------------------------------------------------

    def geo(self, ip: str, timeout: float = 6.0) -> GeoInfo:
        with self._lock:
            hit = self._geo_cache.get(ip)
            if hit and time.monotonic() - hit[0] < self._geo_ttl:
                return hit[1]

        g = self._lookup_geo(ip, timeout)
        with self._lock:
            if g.ok:
                self._geo_cache[ip] = (time.monotonic(), g)
        return g

    @staticmethod
    def _lookup_geo(ip: str, timeout: float) -> GeoInfo:
        import urllib.request

        def http_json(url: str) -> dict | None:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "EgressGuard/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return json.loads(r.read().decode("utf-8", "replace"))
            except Exception:
                return None

        d = http_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                      f"regionName,city,isp,org,as,query")
        if d and d.get("status") == "success":
            return GeoInfo(
                ip=ip, ok=True,
                country=d.get("country", ""), country_code=d.get("countryCode", ""),
                region=d.get("regionName", ""), city=d.get("city", ""),
                isp=d.get("isp", ""), org=d.get("org", ""), asn=d.get("as", ""),
            )

        d = http_json(f"https://ipwho.is/{ip}")
        if d and d.get("success"):
            conn = d.get("connection") or {}
            return GeoInfo(
                ip=ip, ok=True,
                country=d.get("country", ""), country_code=d.get("country_code", ""),
                region=d.get("region", ""), city=d.get("city", ""),
                isp=conn.get("isp", ""), org=conn.get("org", ""),
                asn=str(conn.get("asn", "")),
            )

        d = http_json(f"https://api.ip.sb/geoip/{ip}")
        if d and d.get("ip"):
            return GeoInfo(
                ip=ip, ok=True,
                country=d.get("country", ""), country_code=d.get("country_code", ""),
                region=d.get("region", ""), city=d.get("city", ""),
                isp=d.get("isp", ""), org=d.get("organization", ""),
                asn=str(d.get("asn", "")),
            )

        return GeoInfo(ip=ip, ok=False, error="地理查询失败（三个服务均不可用）")


# --------------------------------------------------------------------------
# 云南/昆明 快速预筛
# --------------------------------------------------------------------------

def in_cidr_list(ip: str, cidrs: list[str]) -> str | None:
    """IP 是否落在给定 CIDR 列表内，返回命中的那一条。"""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for c in cidrs:
        try:
            if obj in ipaddress.ip_network(c, strict=False):
                return c
        except ValueError:
            continue
    return None


def looks_kunming(geo: GeoInfo) -> str | None:
    """地理结果是否指向昆明/云南/中国大陆运营商。返回命中的理由，否则 None。

    这是**权威判据**，比 CIDR 预筛可靠：运营商分配段经常调整，
    但地理库会跟着更新。两者一起用：CIDR 负责快，地理负责准。
    """
    if not geo.ok:
        return None
    region = f"{geo.region}{geo.city}".lower()
    for kw in ("yunnan", "kunming", "云南", "昆明"):
        if kw in region:
            return f"地理归属命中「{geo.region}/{geo.city}」"
    if geo.country_code == "CN":
        return f"出口在中国大陆（{geo.region}{geo.city} / {geo.isp}）"
    return None
