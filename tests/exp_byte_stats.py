"""探测：能不能拿到每条 TCP 连接的字节数？

这决定了「流量时间线」是画**真实流量**还是只能画连接数 —— 差别很大。

Windows 提供 GetPerTcpConnectionEStats(TcpConnectionEstatsData)，
返回 TCP_ESTATS_DATA_ROD_v0，里面有 DataBytesOut / DataBytesIn。
先实测它在这台机器上能不能用、要不要先 SetPerTcpConnectionEStats 打开采集。
"""

import ctypes
import io
import socket
import sys
import time
from ctypes import wintypes

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")

from eg import winapi as W  # noqa: E402

iphlpapi = ctypes.windll.iphlpapi

AF_INET = 2
TCP_ESTATS_DATA_ROD_TI_CTL = 0
TcpConnectionEstatsData = 1


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD),
                ("dwLocalAddr", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD),
                ("dwRemoteAddr", wintypes.DWORD),
                ("dwRemotePort", wintypes.DWORD)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    _fields_ = [
        ("DataBytesOut", ctypes.c_ulonglong),
        ("DataSegsOut", ctypes.c_ulonglong),
        ("DataBytesIn", ctypes.c_ulonglong),
        ("DataSegsIn", ctypes.c_ulonglong),
        ("SegsOut", ctypes.c_ulonglong),
        ("SegsIn", ctypes.c_ulonglong),
        ("SoftErrors", wintypes.DWORD),
        ("SoftErrorReason", wintypes.DWORD),
        ("SndUna", wintypes.DWORD),
        ("SndNxt", wintypes.DWORD),
        ("SndMax", wintypes.DWORD),
        ("ThruBytesAcked", ctypes.c_ulonglong),
        ("RcvNxt", wintypes.DWORD),
        ("ThruBytesReceived", ctypes.c_ulonglong),
    ]


def to_row(c) -> MIB_TCPROW:
    r = MIB_TCPROW()
    r.dwState = c.state
    r.dwLocalAddr = int.from_bytes(socket.inet_aton(c.local_addr), "little")
    r.dwLocalPort = ((c.local_port & 0xFF) << 8) | (c.local_port >> 8)
    r.dwRemoteAddr = int.from_bytes(socket.inet_aton(c.remote_addr), "little")
    r.dwRemotePort = ((c.remote_port & 0xFF) << 8) | (c.remote_port >> 8)
    return r


def enable(estats_type: int, row: MIB_TCPROW) -> int:
    """打开某个 estats 类别的采集。返回 0 表示成功。"""
    # SetPerTcpConnectionEStats(Row, EstatsType, Rw, RwVersion, RwSize, Offset)
    rw = (ctypes.c_ubyte * 4)()
    return iphlpapi.SetPerTcpConnectionEStats(
        ctypes.byref(row), estats_type, ctypes.byref(rw), 0, 4, 0)


def read(estats_type: int, row: MIB_TCPROW):
    rod = TCP_ESTATS_DATA_ROD_v0()
    sz = wintypes.ULONG(ctypes.sizeof(rod))
    rc = iphlpapi.GetPerTcpConnectionEStats(
        ctypes.byref(row), estats_type,
        None, 0, 0,          # rw
        None, 0, 0,          # ros
        ctypes.byref(rod), 0, ctypes.byref(sz))
    return rc, rod, sz.value


def main():
    print("=" * 70)
    print("  能不能拿到每条 TCP 连接的字节数？")
    print("=" * 70)

    conns = [c for c in W.list_tcp() if c.is_outbound and c.is_live]
    print(f"  当前活连接 {len(conns)} 条")
    if not conns:
        print("  没有活连接，先建一条再测")
        return

    # 挑一条 ESTAB 的
    target = next((c for c in conns if c.state_name == "ESTAB"), conns[0])
    print(f"  取样连接: {target.local_addr}:{target.local_port} -> "
          f"{target.remote_addr}:{target.remote_port} [{target.state_name}] "
          f"pid={target.pid}")
    row = to_row(target)

    print("\n--- 1. 不打开采集，直接读 ---")
    rc, rod, sz = read(TcpConnectionEstatsData, row)
    print(f"  GetPerTcpConnectionEStats rc={rc} 结构大小={sz}")
    if rc == 0:
        print(f"    DataBytesOut={rod.DataBytesOut}  DataBytesIn={rod.DataBytesIn}")
    else:
        print(f"    （rc={rc}，可能是 ERROR_NOT_SUPPORTED=50 / 需要先 enable）")

    print("\n--- 2. 先 SetPerTcpConnectionEStats 打开采集，再读 ---")
    erc = enable(TcpConnectionEstatsData, row)
    print(f"  SetPerTcpConnectionEStats rc={erc}")
    time.sleep(1)
    rc2, rod2, sz2 = read(TcpConnectionEstatsData, row)
    print(f"  GetPerTcpConnectionEStats rc={rc2}")
    if rc2 == 0:
        print(f"    DataBytesOut={rod2.DataBytesOut}  DataBytesIn={rod2.DataBytesIn}")
        print("    => ✅ 能拿到字节数，时间线可以画真实流量")
    else:
        print(f"    => ❌ 拿不到（rc={rc2}）")

    print("\n--- 3. 退路：网卡级字节计数器（GetIfEntry2）---")
    try:
        from eg import netinfo as NI
        from eg.config import Config
        net = NI.NetInfo(Config().snapshot())
        for a in net.adapters(force=True):
            print(f"    {a.alias!r:12} idx={a.if_index}")
    except Exception as e:
        print(f"    {e}")
    import subprocess
    p = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-NetAdapterStatistics | Select-Object Name,"
                        "ReceivedBytes,SentBytes | ConvertTo-Json -Compress"],
                       capture_output=True, text=True)
    print("    Get-NetAdapterStatistics:")
    print("     ", (p.stdout or "").strip()[:400])

    print("\n--- 4. 再退一步：按连接数采样（一定能用）---")
    print("    每秒采样一次连接表，统计每个进程的新建连接数/活跃连接数")
    print("    这不是字节数，但足以画出「谁在什么时候活动」的时间线")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
