"""独立的控制台注入器：**必须在子进程里跑**。

为什么不能在本进程里做
----------------------
往目标程序的控制台写红字，标准做法是：

    AttachConsole(target_pid) -> CreateFile("CONOUT$") -> WriteConsoleW

但 AttachConsole 要求**本进程当前没有控制台**。如果本进程已经有控制台
（比如守护进程是从命令行启动的、或者验收脚本继承了 PowerShell 的控制台），
AttachConsole 会失败，于是很自然地会先 `FreeConsole()` 让出来再附加。

问题就出在这个 FreeConsole：它摘掉的是**本进程自己的**控制台。
摘掉之后本进程的 stdout 句柄失效，下一次 `print()` 直接抛
`OSError: [WinError 6] 句柄无效`。

实测后果：验收脚本跑到"通知靶子"这一步整个进程崩掉，
exit code 1，报告没写出来，连 finally 里的清理都没跑完。

所以正确的做法是：**把这段脏活扔进一个短命子进程**。
子进程爱怎么 FreeConsole 就怎么 FreeConsole，父进程的控制台毫发无损。
"""

from __future__ import annotations

import ctypes
import json
import sys
from ctypes import wintypes

_kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_kernel32.AttachConsole.argtypes = [wintypes.DWORD]
_kernel32.FreeConsole.argtypes = []
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.WriteConsoleW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
_kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
_kernel32.SetConsoleTextAttribute.argtypes = [wintypes.HANDLE, wintypes.WORD]
_kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
_kernel32.GetStdHandle.restype = wintypes.HANDLE

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value
STD_OUTPUT_HANDLE = -11

CONSOLE_RED = 0x0004 | 0x0008
CONSOLE_DEFAULT = 0x0007


def inject(pid: int, title: str, body: str) -> str:
    """把红字写进 pid 的控制台。返回人类可读的结果说明。"""
    k = _kernel32
    attached = bool(k.AttachConsole(pid))
    if not attached:
        # 本进程（子进程）可能有继承来的控制台，先让出去再附加
        k.FreeConsole()
        attached = bool(k.AttachConsole(pid))
    if not attached:
        return "目标进程没有控制台（GUI 程序正常现象），已走弹窗/事件日志通道"

    try:
        h = k.CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                          OPEN_EXISTING, 0, None)
        if not h or h == INVALID_HANDLE:
            h = k.GetStdHandle(STD_OUTPUT_HANDLE)
        if not h or h == INVALID_HANDLE:
            return "拿不到目标控制台的输出句柄"

        text = (
            "\r\n"
            "========================================================\r\n"
            "  EgressGuard 已切断本程序的网络连接\r\n"
            "--------------------------------------------------------\r\n"
            f"  {title}\r\n"
            "\r\n"
            + "".join("  " + ln + "\r\n" for ln in body.splitlines())
            + "--------------------------------------------------------\r\n"
            "  以上为拦截原因，不是程序自身的错误。\r\n"
            f"  查询接口：http://127.0.0.1:47821/api/why?pid={pid}\r\n"
            "========================================================\r\n"
        )
        written = wintypes.DWORD(0)
        k.SetConsoleTextAttribute(h, CONSOLE_RED)
        ok = k.WriteConsoleW(h, text, len(text), ctypes.byref(written), None)
        k.SetConsoleTextAttribute(h, CONSOLE_DEFAULT)
        if ok and written.value > 0:
            return f"已用红字写入目标控制台（{written.value} 字符）"

        # WriteConsoleW 在"控制台被重定向成管道/文件"时必然失败，
        # 这时退化为普通字节写入。
        try:
            raw = text.encode("gbk", "replace")
            n = wintypes.DWORD(0)
            if k.WriteFile(h, raw, len(raw), ctypes.byref(n), None):
                return f"控制台已重定向，已按字节写入（{n.value} 字节）"
        except Exception:
            pass
        return "WriteConsoleW 失败（控制台可能被重定向，或已被别的进程占用）"
    finally:
        k.FreeConsole()


def run_from_stdin() -> int:
    """从 stdin 读 JSON 任务并执行。子进程入口。"""
    try:
        raw = sys.stdin.read()
        job = json.loads(raw)
    except Exception as e:
        sys.stdout.write(f"参数解析失败：{e}")
        return 2
    result = inject(int(job.get("pid", 0)),
                    str(job.get("title", "")),
                    str(job.get("body", "")))
    sys.stdout.write(result)
    return 0


if __name__ == "__main__":
    sys.exit(run_from_stdin())
