"""实测：能不能把裸奔流量"引导"回隧道（VPN 出口）？

要回答的问题是：一个程序从物理网卡裸奔出去，
我们能不能把它改道到 iKuuu 的 TUN 里、让它从 VPN 出口出去？

答案取决于 Windows 的一个语义细节，必须实测：

  A. 程序**按路由表走**（没显式 bind）
     -> 路由表指向哪个接口，源地址就是哪个接口的地址。
        把路由改到 TUN，它重连就进隧道了。**可引导。**

  B. 程序**显式 bind 了物理网卡地址**
     -> 包必须从拥有该地址的接口发出。用户态没有任何 API 能改道。
        **不可引导**，只能掐断。

本脚本把两种情况都测出来。
"""

import ctypes
import io
import socket
import struct
import subprocess
import sys
import time
from ctypes import wintypes

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")
from eg import winapi as W  # noqa: E402

TEST_IP = "203.0.113.7"        # RFC 5737 文档保留段，永不会被路由
PHYS_GW = "192.168.0.1"
PHYS_IF = "24"
TUN_IF = "30"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def route_add_via_phys():
    run(["route", "delete", TEST_IP])
    run(["route", "add", TEST_IP, "mask", "255.255.255.255", PHYS_GW,
         "metric", "1", "if", PHYS_IF])


def route_del():
    run(["route", "delete", TEST_IP])


def iface_for(ip):
    p = run(["powershell", "-NoProfile", "-Command",
             f"(Find-NetRoute -RemoteIPAddress {ip} | Select-Object -First 1)"
             f".InterfaceAlias"])
    return (p.stdout or "").strip()


def src_for(ip):
    p = run(["powershell", "-NoProfile", "-Command",
             f"(Find-NetRoute -RemoteIPAddress {ip} | Select-Object -First 1)"
             f".IPAddress"])
    return (p.stdout or "").strip()


def probe(ip, bind_ip=None, timeout=4.0):
    """起一条连接，返回 (本地地址, 状态)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if bind_ip:
            s.bind((bind_ip, 0))
        try:
            s.connect((ip, 443))
        except Exception:
            pass
        la = s.getsockname()[0]
        lp = s.getsockname()[1]
        # 从内核连接表取权威状态
        st = ""
        for c in W.list_tcp():
            if c.local_port == lp and c.remote_addr == ip:
                st = c.state_name
                la = c.local_addr
                break
        return la, st
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    print("=" * 74)
    print("  实验：裸奔流量能不能被引导回隧道（VPN 出口）")
    print("=" * 74)
    print(f"  测试 IP        : {TEST_IP}（RFC 5737 文档保留段）")
    print(f"  物理网卡       : WLAN 3  (ifIndex {PHYS_IF}, 网关 {PHYS_GW})")
    print(f"  隧道网卡       : iKuuuVPN (ifIndex {TUN_IF})")
    print()

    # ---- 基线：不加任何路由时，这个 IP 走哪 ----
    route_del()
    time.sleep(0.5)
    print("--- 0. 基线：不干预时 ---")
    print(f"  路由判定接口 = {iface_for(TEST_IP)}")
    print(f"  路由判定源址 = {src_for(TEST_IP)}")
    la, st = probe(TEST_IP)
    print(f"  实际连接     = 本地 {la}  状态 {st}")
    print(f"  => 这个 IP 默认就走隧道" if la.startswith("198.18") else
          f"  => 这个 IP 默认走物理网卡")
    print()

    # ---- 情况 A：不 bind，但路由被改到物理网卡 ----
    print("--- A. 路由被改到物理网卡，程序【不 bind】---")
    route_add_via_phys()
    time.sleep(0.5)
    print(f"  路由判定接口 = {iface_for(TEST_IP)}")
    la, st = probe(TEST_IP)
    print(f"  实际连接     = 本地 {la}  状态 {st}")
    leak_a = not la.startswith("198.18")
    print(f"  => {'裸奔了（源地址=物理网卡）' if leak_a else '仍在隧道内'}")
    print()

    # ---- 情况 A 的引导：删掉那条路由，重连 ----
    print("--- A-引导：删掉那条物理网卡路由，让程序重连 ---")
    route_del()
    time.sleep(0.5)
    la2, st2 = probe(TEST_IP)
    print(f"  实际连接     = 本地 {la2}  状态 {st2}")
    guided = la2.startswith("198.18")
    print(f"  => {'✅ 已回到隧道！源地址变成 ' + la2 if guided else '❌ 仍在裸奔'}")
    print()

    # ---- 情况 B：显式 bind 物理网卡 ----
    print("--- B. 程序【显式 bind 物理网卡地址】---")
    la3, st3 = probe(TEST_IP, bind_ip="192.168.0.101")
    print(f"  实际连接     = 本地 {la3}  状态 {st3}")
    print(f"  => 即使路由指向隧道，源地址仍是 {la3}")
    print()

    print("--- B-引导尝试：路由指向隧道 + 显式 bind 物理网卡 ---")
    # 让路由明确指向 TUN（其实默认就是），再看显式 bind 的效果
    route_del()
    time.sleep(0.5)
    la4, st4 = probe(TEST_IP, bind_ip="192.168.0.101")
    print(f"  实际连接     = 本地 {la4}  状态 {st4}")
    still_leak = not la4.startswith("198.18")
    print(f"  => {'❌ 依然用物理网卡地址，用户态无法改道' if still_leak else '✅ 居然进了隧道'}")
    print()

    # ---- 当前真实泄漏目标的判定 ----
    print("--- C. 当前真实裸奔目标的路由判定 ---")
    phys = {a.alias for a in __import__("eg.netinfo", fromlist=["NetInfo"])
            .NetInfo({}).physical(force=True)}
    seen = []
    for c in W.list_tcp():
        if (c.is_outbound and c.local_addr == "192.168.0.101"
                and not c.remote_addr.startswith(("127.", "192.168.", "169.254.",
                                                  "224.", "255."))
                and c.remote_addr not in seen):
            seen.append(c.remote_addr)
        if len(seen) >= 5:
            break
    for ip in seen:
        print(f"  {ip:18s} 路由判定={iface_for(ip):12s} 源址={src_for(ip)}")
    if not seen:
        print("  （当前没有裸奔连接）")
    print()
    print("  解读：如果某条裸奔连接的路由判定是 iKuuuVPN，")
    print("        那它就是**显式 bind 了物理网卡**，属于情况 B，只能掐断。")
    print("        如果路由判定是 WLAN 3，那是路由把它带出去的，属于情况 A，可以引导。")

    route_del()
    print()
    print("=" * 74)


if __name__ == "__main__":
    main()
