"""受控泄漏靶子：故意从物理网卡直连外网，用来端到端验收 EgressGuard。

它做的事就是"一个真实泄漏程序会做的事"：
  1. 把 socket 显式绑定到物理网卡 IP（如 192.168.0.101），绕过隧道
  2. 连一个外网地址并**保持长连接**（TLS + SNI，连接稳定停在 ESTABLISHED）
  3. **自己查内核连接表**，看自己那条连接什么时候从表里消失
  4. 全程写日志到文件（外部可据此验证"连接是什么时候被掐的"）
  5. 可选开一个 Tkinter 窗口（用来验证"归属弹窗"通道）
  6. 控制台持续输出（用来验证"控制台红字"通道）

为什么"自己查内核连接表"是唯一可靠的感知方式
--------------------------------------------
第一版靶子靠 `sendall(b"")` 判断连接是否还活着 —— **这是错的**：
零字节 send 是个空操作，即使 TCB 已被 SetTcpEntry 删掉也照样"成功"，
所以靶子永远感知不到自己被掐。

第二版想靠 recv/select，但 TLS 层和半关闭状态会让判据变得很绕。

最硬的判据是回到源头：**看内核的连接表里还有没有这条连接**。
EgressGuard 掐断的手段就是 SetTcpEntry(DELETE_TCB)，
它一执行，这一行就会从 GetExtendedTcpTable 里消失。
所以靶子直接查这张表，就能给出"我确实被掐了"的第一手证据。

用法：
    python leak_target.py --bind 192.168.0.101 --remote 218.30.118.6:443 \
        --tls --sni www.cnnic.cn --log D:\\...\\leak_target.log --gui --hold 60
"""

import argparse
import ctypes
import os
import socket
import ssl
import struct
import sys
import threading
import time
from ctypes import wintypes

LOG_PATH = None
LOCK = threading.Lock()

# --------------------------------------------------------------------------
# 内联的 GetExtendedTcpTable（不依赖 eg 包，靶子要能独立跑）
# --------------------------------------------------------------------------

_iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
_iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
_iphlpapi.GetExtendedTcpTable.restype = wintypes.DWORD

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
ROW_SZ = 24
ERROR_INSUFFICIENT_BUFFER = 122
NO_ERROR = 0


def _port(dw: int) -> int:
    return ((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF)


def tcp_table() -> list[tuple]:
    """返回 [(local_addr, local_port, remote_addr, remote_port, state, pid), ...]"""
    size = wintypes.DWORD(0)
    rc = _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False,
                                       AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != ERROR_INSUFFICIENT_BUFFER:
        return []
    buf = ctypes.create_string_buffer(size.value)
    rc = _iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False,
                                       AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != NO_ERROR:
        return []
    raw = buf.raw
    n = struct.unpack_from("<I", raw, 0)[0]
    out = []
    for i in range(n):
        off = 4 + i * ROW_SZ
        st, la, lp, ra, rp, pid = struct.unpack_from("<IIIIII", raw, off)
        out.append((socket.inet_ntoa(struct.pack("<I", la)), _port(lp),
                    socket.inet_ntoa(struct.pack("<I", ra)), _port(rp), st, pid))
    return out


def conn_alive(laddr: str, lport: int, raddr: str, rport: int) -> tuple[bool, str]:
    """查内核表：这条连接还在吗？返回 (是否还在, 状态名)。"""
    names = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTAB",
             6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
             10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}
    for la, lp, ra, rp, st, _pid in tcp_table():
        if la == laddr and lp == lport and ra == raddr and rp == rport:
            return True, names.get(st, str(st))
    return False, ""


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with LOCK:
        print(line, flush=True)
        if LOG_PATH:
            try:
                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
            except Exception:
                pass


def main() -> int:
    global LOG_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--remote", required=True)
    ap.add_argument("--sni", default=None)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--http", action="store_true",
                    help="发一个 HTTP 请求（默认不发：发了可能被服务端主动关闭，"
                         "连接会掉到 CLOSE_WAIT，不利于验证掐断）")
    ap.add_argument("--log", default=None)
    ap.add_argument("--gui", action="store_true")
    ap.add_argument("--hold", type=float, default=60.0)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--linger", type=float, default=30.0,
                    help="被掐断后进程继续存活的秒数。必须 >0，否则通知送到时"
                         "进程已经退出，控制台/弹窗两个通道拿不到目标。")
    args = ap.parse_args()

    LOG_PATH = args.log
    if LOG_PATH:
        open(LOG_PATH, "w", encoding="utf-8").close()

    host, port = args.remote.rsplit(":", 1)
    port = int(port)
    sni = args.sni or host

    log(f"靶子启动 pid={os.getpid()}  bind={args.bind}  remote={host}:{port}  "
        f"tls={args.tls} sni={sni}")

    if args.gui:
        try:
            import tkinter as tk
            win = tk.Tk()
            win.title("EGTESTTARGET 泄漏靶子")
            win.geometry("540x200+240+180")
            tk.Label(win, text=f"我是故意泄漏的程序\n绑定 {args.bind} -> {host}:{port}",
                     font=("Microsoft YaHei UI", 12)).pack(expand=True)
            win.after(int(args.hold * 1000) + 8000, win.destroy)
            threading.Thread(target=win.mainloop, daemon=True).start()
            time.sleep(1.2)
            log("GUI 窗口已创建")
        except Exception as e:
            log(f"GUI 创建失败（不影响主流程）：{e}")

    # ---- 连接（带重试）----
    #
    # ⚠ 必须重试，不能一次失败就退出。
    #
    # 实测教训：EgressGuard 的判定周期是 250ms，它可能在 TCP 握手还没完成的
    # SYN_SENT 阶段就把这条泄漏连接掐掉（SetTcpEntry 删 TCB）。
    # 于是靶子的 connect() 收到 `WinError 10053 你的主机中的软件中止了一个已建立的连接`，
    # 然后靶子一 return，进程就没了 —— 验收脚本看到的是"靶子没建立连接"，
    # 误判成失败。其实守护干得完全正确，是靶子太脆。
    #
    # 真实泄漏程序遇到连接失败也会重试，所以这里就按真实行为来：
    # 在整个 hold 期间不断重连，每次失败都记一笔，并标注是被掐的还是别的原因。
    s = None
    laddr = lport = raddr = rport = None
    deadline = time.time() + args.hold
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(6.0)
        try:
            raw.bind((args.bind, 0))
        except Exception as e:
            log(f"BIND FAILED: {type(e).__name__}: {e}")
            return 3
        la, lp = raw.getsockname()
        if attempts == 1:
            log(f"已绑定本地地址 {la}:{lp}  <-- 关键：源地址是物理网卡，绕过隧道")
        try:
            raw.connect((host, port))
            laddr, lport = la, lp
            raddr, rport = raw.getpeername()
            log(f"第{attempts}次 TCP CONNECTED  local={raw.getsockname()}  "
                f"peer={raw.getpeername()}")
            s = raw
            break
        except Exception as e:
            code = getattr(e, "winerror", None)
            tag = ""
            if code == 10053:
                tag = ("  <-- 连接已被掐断：本机软件中止（EgressGuard 在 SYN 阶段"
                       "就把 TCB 删了）")
            elif code == 10054:
                tag = "  <-- 对端强制关闭"
            log(f"第{attempts}次 CONNECT 失败：{type(e).__name__}"
                f"{f' WinError {code}' if code else ''}: {e}{tag}")
            try:
                raw.close()
            except Exception:
                pass
            time.sleep(0.8)

    if s is None:
        log(f"保持期结束仍未建立连接（共尝试 {attempts} 次）—— "
            f"如果每次都报 WinError 10053，说明闸门在 SYN 阶段就拦住了，"
            f"这本身就是防护生效的证据")
        return 4

    # ---- TLS ----
    if args.tls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=sni)
            log(f"TLS 握手完成  version={s.version()}  cipher={s.cipher()[0]}")
        except Exception as e:
            log(f"TLS 握手失败（连接仍在，对验收依然有效）：{type(e).__name__}: {e}")

    if args.http:
        try:
            req = (f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                   f"User-Agent: EgressGuard-TestTarget/1.0\r\n"
                   f"Accept: */*\r\nConnection: keep-alive\r\n\r\n")
            s.sendall(req.encode())
            log("已发送 HTTP 请求")
        except Exception as e:
            log(f"HTTP 请求失败：{e}")

    # ---- 关键：靠内核连接表感知被掐，而不是靠 sendall(b"") ----
    alive, st = conn_alive(laddr, lport, raddr, rport)
    log(f"内核连接表自检：{laddr}:{lport} -> {raddr}:{rport}  "
        f"存在={alive} 状态={st}")

    deadline = time.time() + args.hold
    n = 0
    killed_at = None
    while time.time() < deadline:
        n += 1
        # 只查内核连接表，**不往 socket 里发任何东西**。
        # 实测教训：之前每轮发 1 个字节（NUL）探活，结果把服务端惹毛了 ——
        # 360 DNS / CNNIC 收到非法数据后主动关闭连接，连接掉到 CLOSE_WAIT，
        # 而 CLOSE_WAIT 按设计是"不可处置"的告警档，验收就永远拿不到掐断判定。
        # 查内核表既准确又零副作用：SetTcpEntry 一执行，这一行就消失。
        alive, st = conn_alive(laddr, lport, raddr, rport)
        if not alive:
            killed_at = time.strftime("%H:%M:%S")
            log(f"!!! 连接已被掐断 !!!  内核连接表里已经没有这条连接了。"
                f"自检第 {n} 次  时刻={killed_at}")
            break
        time.sleep(args.interval)
    else:
        alive, st = conn_alive(laddr, lport, raddr, rport)
        log(f"保持结束（自检 {n} 次，连接一直没被掐；末次 存在={alive} 状态={st}）")

    # 被掐之后**不能立刻退出**，必须再活一段时间。
    #
    # 为什么：EgressGuard 的处置顺序是「掐断连接 → 隔离程序 → 通知该程序」，
    # 后两步要起 PowerShell、建防火墙规则，耗时几秒。
    # 如果靶子一发现连接没了就 return，进程在通知送达之前就没了，
    # 于是"控制台红字"找不到控制台、"归属弹窗"找不到窗口 —— 验收假失败。
    # 而且真实程序也不会因为一条连接断了就立刻自杀。
    if killed_at and args.linger > 0:
        log(f"连接已被掐断，但进程继续存活 {args.linger:.0f} 秒，"
            f"以便接收 EgressGuard 的切断通知（真实程序也是这个行为）")
        time.sleep(args.linger)
        log("存活宽限期结束，准备退出")

    try:
        s.close()
    except Exception:
        pass
    log(f"靶子退出 pid={os.getpid()}  被掐={bool(killed_at)}  时刻={killed_at}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
