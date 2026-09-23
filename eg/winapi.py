"""底层 Windows API 封装（纯 ctypes，不依赖第三方库）。

EgressGuard 只用到最小的一小面 Windows 网络 API：

  枚举层（普通用户权限即可）
    GetExtendedTcpTable / GetExtendedUdpTable  ->  按 PID 枚举连接，拿到"这条连接真实绑定的本地地址"
    GetIpAddrTable                             ->  本机所有 IPv4 地址 -> 接口索引

  掐断层（需要管理员）
    SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)      ->  强制删除一条 TCP 连接，即"掐断"

  ⚠ 关键设计事实（本工具成立的基石）
  ------------------------------------------------------------------
  Windows 上判断"一条连接走没走隧道"，不能用路由表（Find-NetRoute / GetBestRoute），
  因为 TUN 型代理（clash/mihomo/wintun 等）会把默认路由整条劫持到隧道上，
  路由表查询会对"代理自己绑定物理网卡去连上游服务器"的连接也回答"走隧道"，
  从而给出完全相反的结论。

  唯一权威的判据是 GetExtendedTcpTable 返回的 dwLocalAddr —— 这条连接真正绑定在哪个本地 IP 上：
      本地地址 = 隧道接口 IP（如 198.18.0.1）  ->  确实在隧道里
      本地地址 = 物理网卡 IP（如 192.168.0.101）->  裸奔，真实 IP 暴露

  本模块的 poll_* 系列就是把这个权威判据取出来。
"""

from __future__ import annotations

import ctypes
import socket
import struct
from ctypes import wintypes
from dataclasses import dataclass

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

AF_INET = 2
AF_INET6 = 23

# TCP_TABLE_CLASS
TCP_TABLE_BASIC_LISTENER = 0
TCP_TABLE_BASIC_CONNECTIONS = 1
TCP_TABLE_BASIC_ALL = 2
TCP_TABLE_OWNER_PID_LISTENER = 3
TCP_TABLE_OWNER_PID_CONNECTIONS = 4
TCP_TABLE_OWNER_PID_ALL = 5
TCP_TABLE_OWNER_MODULE_LISTENER = 6
TCP_TABLE_OWNER_MODULE_CONNECTIONS = 7
TCP_TABLE_OWNER_MODULE_ALL = 8

# UDP_TABLE_CLASS
UDP_TABLE_BASIC = 0
UDP_TABLE_OWNER_PID = 1
UDP_TABLE_OWNER_MODULE = 2

# MIB_TCP_STATE
MIB_TCP_STATE_CLOSED = 1
MIB_TCP_STATE_LISTEN = 2
MIB_TCP_STATE_SYN_SENT = 3
MIB_TCP_STATE_SYN_RCVD = 4
MIB_TCP_STATE_ESTAB = 5
MIB_TCP_STATE_FIN_WAIT1 = 6
MIB_TCP_STATE_FIN_WAIT2 = 7
MIB_TCP_STATE_CLOSE_WAIT = 8
MIB_TCP_STATE_CLOSING = 9
MIB_TCP_STATE_LAST_ACK = 10
MIB_TCP_STATE_TIME_WAIT = 11
MIB_TCP_STATE_DELETE_TCB = 12

TCP_STATE_NAME = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTAB",
    6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0

# 内存块结构体尺寸（来自 winsock2.h / iphlpapi.h，已逐个核对）
SZ_MIB_TCPROW_OWNER_PID = 24      # state, localAddr, localPort, remoteAddr, remotePort, pid
SZ_MIB_TCP6ROW_OWNER_PID = 56     # localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
SZ_MIB_UDPROW_OWNER_PID = 12      # localAddr, localPort, pid
SZ_MIB_UDP6ROW_OWNER_PID = 28     # localAddr[16], localScope, localPort, pid
SZ_MIB_IPADDRROW = 24             # addr, index, mask, bcast, reasm, unused1, unused2
SZ_MIB_TCPROW = 20                # state, localAddr, localPort, remoteAddr, remotePort  (给 SetTcpEntry 用)

# --------------------------------------------------------------------------
# DLL
# --------------------------------------------------------------------------

_iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)

_iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
]
_iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

_iphlpapi.GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, ctypes.c_int, wintypes.ULONG,
]
_iphlpapi.GetExtendedUdpTable.restype = wintypes.DWORD

_iphlpapi.GetIpAddrTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
]
_iphlpapi.GetIpAddrTable.restype = wintypes.DWORD

_iphlpapi.SetTcpEntry.argtypes = [ctypes.c_void_p]
_iphlpapi.SetTcpEntry.restype = wintypes.DWORD

_iphlpapi.GetBestInterfaceEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
_iphlpapi.GetBestInterfaceEx.restype = wintypes.DWORD


# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Conn:
    """一条出站连接（TCP 或 UDP）。local_addr 是权威的绑定地址。"""
    proto: str          # "tcp" / "udp"
    family: str         # "ipv4" / "ipv6"
    state: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    pid: int

    @property
    def state_name(self) -> str:
        return TCP_STATE_NAME.get(self.state, str(self.state))

    @property
    def is_outbound(self) -> bool:
        """非监听、非回环、有真实远端。"""
        if self.proto == "tcp" and self.state == MIB_TCP_STATE_LISTEN:
            return False
        if self.remote_addr in ("0.0.0.0", "::", ""):
            return False
        if self.remote_port == 0:
            return False
        if self.remote_addr.startswith("127.") or self.remote_addr == "::1":
            return False
        if self.local_addr.startswith("127.") or self.local_addr == "::1":
            return False
        return True

    @property
    def is_live(self) -> bool:
        """这条连接现在还能传数据吗？

        为什么必须区分：TIME_WAIT / CLOSE_WAIT / FIN_WAIT* 这些状态下的条目
        已经不会再发数据了，它们是**历史痕迹**。把它们当成实弹泄漏去掐，
        既没意义（掐了也没用），又会让仪表盘被噪音淹掉，
        更糟的是会诱导用户去"隔离"一个其实早就结束了的程序。

        真正的实弹只有：ESTAB / SYN_SENT / SYN_RCVD，以及 UDP（无连接，一律算活）。
        """
        if self.proto == "udp":
            return True
        return self.state in (MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_SYN_SENT,
                              MIB_TCP_STATE_SYN_RCVD)

    @property
    def is_attributable(self) -> bool:
        """这条连接能不能归因到某个具体程序？

        PID 0 是 System Idle、PID 4 是 System —— 内核代表别人持有 TCB
        （典型场景：隧道进程的连接刚结束，TCB 归了内核）。
        这类条目：
          - 无法隔离（没有 exe 路径）
          - 无法终结（不能杀 System）
          - 也无法安全地整体阻断（会打断整个操作系统）
        所以只报告、不处置。
        """
        return self.pid not in (0, 4)

    @property
    def key(self) -> tuple:
        return (self.proto, self.local_addr, self.local_port,
                self.remote_addr, self.remote_port, self.pid)


@dataclass(frozen=True, slots=True)
class LocalIp:
    addr: str
    if_index: int
    mask: str


# --------------------------------------------------------------------------
# 内部工具
# --------------------------------------------------------------------------

def _port(dw: int) -> int:
    """dwLocalPort/dwRemotePort 低 16 位是网络字节序，要翻一下。"""
    return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)


def _ntoa(ipv4_dw: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", ipv4_dw))


def _v6_ntoa(raw: bytes, scope: int = 0) -> str:
    addr = socket.inet_ntop(socket.AF_INET6, raw)
    return f"{addr}%{scope}" if scope else addr


def _grow_table(call, ul_af: int, table_class: int) -> bytes | None:
    """两次调用式取表：先问大小，再取内容。"""
    size = wintypes.DWORD(0)
    rc = call(None, ctypes.byref(size), False, ul_af, table_class, 0)
    if rc != ERROR_INSUFFICIENT_BUFFER:
        # 表为空时会直接返回 NO_ERROR 且 size=0
        if rc == NO_ERROR:
            return None
        raise OSError(f"取表尺寸失败 rc={rc}")
    buf = ctypes.create_string_buffer(size.value)
    rc = call(buf, ctypes.byref(size), False, ul_af, table_class, 0)
    if rc != NO_ERROR:
        raise OSError(f"取表内容失败 rc={rc}")
    return buf.raw


# --------------------------------------------------------------------------
# 枚举
# --------------------------------------------------------------------------

def list_tcp(include_listen: bool = False) -> list[Conn]:
    """枚举 TCP 连接（含 IPv4 + IPv6），按 PID 归属。"""
    out: list[Conn] = []
    table_class = TCP_TABLE_OWNER_PID_ALL if include_listen else TCP_TABLE_OWNER_PID_CONNECTIONS

    raw = _grow_table(_iphlpapi.GetExtendedTcpTable, AF_INET, table_class)
    if raw:
        n = struct.unpack_from("<I", raw, 0)[0]
        for i in range(n):
            off = 4 + i * SZ_MIB_TCPROW_OWNER_PID
            state, la, lp, ra, rp, pid = struct.unpack_from("<IIIIII", raw, off)
            out.append(Conn("tcp", "ipv4", state, _ntoa(la), _port(lp),
                            _ntoa(ra), _port(rp), pid))

    raw6 = _grow_table(_iphlpapi.GetExtendedTcpTable, AF_INET6, table_class)
    if raw6:
        n = struct.unpack_from("<I", raw6, 0)[0]
        for i in range(n):
            off = 4 + i * SZ_MIB_TCP6ROW_OWNER_PID
            la = raw6[off:off + 16]
            lscope, lp = struct.unpack_from("<II", raw6, off + 16)
            ra = raw6[off + 24:off + 40]
            rscope, rp = struct.unpack_from("<II", raw6, off + 40)
            state, pid = struct.unpack_from("<II", raw6, off + 48)
            out.append(Conn("tcp", "ipv6", state, _v6_ntoa(la, lscope), _port(lp),
                            _v6_ntoa(ra, rscope), _port(rp), pid))
    return out


def list_udp() -> list[Conn]:
    """枚举 UDP 端点。UDP 是无连接，只有本地地址+端口，远端为空。"""
    out: list[Conn] = []

    raw = _grow_table(_iphlpapi.GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID)
    if raw:
        n = struct.unpack_from("<I", raw, 0)[0]
        for i in range(n):
            off = 4 + i * SZ_MIB_UDPROW_OWNER_PID
            la, lp, pid = struct.unpack_from("<III", raw, off)
            out.append(Conn("udp", "ipv4", 0, _ntoa(la), _port(lp), "", 0, pid))

    raw6 = _grow_table(_iphlpapi.GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID)
    if raw6:
        n = struct.unpack_from("<I", raw6, 0)[0]
        for i in range(n):
            off = 4 + i * SZ_MIB_UDP6ROW_OWNER_PID
            la = raw6[off:off + 16]
            lscope, lp, pid = struct.unpack_from("<III", raw6, off + 16)
            out.append(Conn("udp", "ipv6", 0, _v6_ntoa(la, lscope), _port(lp), "", 0, pid))
    return out


def local_ipv4_table() -> list[LocalIp]:
    """本机所有 IPv4 地址及其所属接口索引。"""
    size = wintypes.ULONG(0)
    rc = _iphlpapi.GetIpAddrTable(None, ctypes.byref(size), False)
    if rc != ERROR_INSUFFICIENT_BUFFER:
        raise OSError(f"GetIpAddrTable 取尺寸失败 rc={rc}")
    buf = ctypes.create_string_buffer(size.value)
    rc = _iphlpapi.GetIpAddrTable(buf, ctypes.byref(size), False)
    if rc != NO_ERROR:
        raise OSError(f"GetIpAddrTable 取内容失败 rc={rc}")
    raw = buf.raw
    n = struct.unpack_from("<I", raw, 0)[0]
    out: list[LocalIp] = []
    for i in range(n):
        off = 4 + i * SZ_MIB_IPADDRROW
        addr, index, mask = struct.unpack_from("<III", raw, off)
        out.append(LocalIp(_ntoa(addr), index, _ntoa(mask)))
    return out


def best_interface_index(remote_ip: str) -> int | None:
    """路由表层面的出口接口索引。**仅作辅助参考，不是权威判据**（见模块 docstring）。"""
    try:
        if ":" in remote_ip:
            sa = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            packed = socket.inet_pton(socket.AF_INET6, remote_ip.split("%")[0])
            # sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4)
            raw = struct.pack("<HH", socket.AF_INET6, 0) + b"\x00" * 4 + packed + b"\x00" * 4
        else:
            sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packed = socket.inet_aton(remote_ip)
            raw = struct.pack("<HH", socket.AF_INET, 0) + packed + b"\x00" * 8
        del sa
        buf = ctypes.create_string_buffer(raw, len(raw))
        idx = wintypes.DWORD(0)
        rc = _iphlpapi.GetBestInterfaceEx(buf, ctypes.byref(idx))
        return idx.value if rc == NO_ERROR else None
    except Exception:
        return None


# --------------------------------------------------------------------------
# 掐断
# --------------------------------------------------------------------------

def kill_tcp_connection(local_addr: str, local_port: int,
                        remote_addr: str, remote_port: int) -> tuple[bool, str]:
    """强制删除一条 IPv4 TCP 连接（把 TCB 置为 DELETE_TCB）。

    这是 Windows 上唯一能在用户态真正"掐断一条已建立连接"的手段，
    效果等同连接被立刻复位。**需要管理员权限**（否则返回 rc=5 拒绝访问）。

    返回 (是否成功, 说明)。
    """
    try:
        la = struct.unpack("<I", socket.inet_aton(local_addr))[0]
        ra = struct.unpack("<I", socket.inet_aton(remote_addr))[0]
    except OSError:
        return False, "IPv6 连接不支持 SetTcpEntry 强杀（需靠防火墙规则阻断）"

    # 端口要转回网络字节序存放
    lp = ((local_port & 0xFF) << 8) | ((local_port >> 8) & 0xFF)
    rp = ((remote_port & 0xFF) << 8) | ((remote_port >> 8) & 0xFF)

    row = struct.pack("<IIIII", MIB_TCP_STATE_DELETE_TCB, la, lp, ra, rp)
    buf = ctypes.create_string_buffer(row, SZ_MIB_TCPROW)
    rc = _iphlpapi.SetTcpEntry(buf)
    if rc == NO_ERROR:
        return True, "已强制删除 TCP 连接"
    if rc == 5:
        return False, "拒绝访问：掐断连接需要管理员权限（请用『安装』脚本装好提权守护）"
    if rc == 317:  # ERROR_MR_MID_NOT_FOUND
        return False, "连接已不存在"
    return False, f"SetTcpEntry 失败 rc={rc}"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# --------------------------------------------------------------------------
# 进程名枚举（Toolhelp32）
#
# 为什么不用 OpenProcess + QueryFullProcessImageName：
#   提权进程（本机的 iKuuuVPNCore.exe 就是）对普通权限进程拒绝
#   PROCESS_QUERY_LIMITED_INFORMATION，导致取不到名字，
#   白名单失效 -> 把 VPN 自己判成泄漏源 -> 整个工具自杀。
#   CreateToolhelp32Snapshot 枚举进程名**不需要**任何特殊权限，
#   这是唯一可靠的取名字方式。全路径仍然需要 OpenProcess，
#   所以路径是"能拿就拿，拿不到就用名字匹配"。
# --------------------------------------------------------------------------

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


_kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_kernel32.Process32FirstW.restype = wintypes.BOOL
_kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
_kernel32.Process32NextW.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def list_process_names() -> dict[int, str]:
    """一次性取全部 PID -> 进程名（含提权进程）。失败返回空字典。"""
    out: dict[int, str] = {}
    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return out
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = _kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out[int(entry.th32ProcessID)] = entry.szExeFile
            ok = _kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snap)
    return out


def is_ipv4(s: str) -> bool:
    return ":" not in s


def is_private_ipv4(ip: str) -> bool:
    """10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10(CGNAT) 以及
    198.18.0.0/15（RFC2544 基准测试段 —— clash/mihomo TUN 的惯用假地址段）。"""
    try:
        a, b, c, _ = (int(x) for x in ip.split("."))
    except Exception:
        return False
    if a == 10 or a == 127:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    if a == 198 and 18 <= b <= 19:
        return True
    return False
