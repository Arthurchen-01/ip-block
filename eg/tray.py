"""系统托盘常驻图标 —— 让 EgressGuard 有"软件"的存在感。

为什么需要：原来的形态是"两个 exe + 一个 bat"，用户要看状态得主动打开仪表盘。
闸门是常驻防护，但它本身没有任何常驻的可见入口 —— 托盘图标就是那个入口：
  - 图标颜色一眼看出当前是否零泄漏（绿=干净，红=有泄漏，黄=闸门没开）
  - 悬停显示一句话结论
  - 右键菜单：打开仪表盘 / 零泄漏自检 / 开关闸门 / 打开数据目录 / 退出
  - 发现泄漏时弹气泡通知

实现选择：**用 win32gui 直接调 Shell_NotifyIconW，不引入 pystray**。
本机实测有 pywin32（win32gui/win32api）但没有 pystray；
为一个托盘图标多背一个第三方依赖不划算，而且托盘 API 本身很简单。

线程模型：托盘有自己的消息循环，必须跑在**非主线程**里
（主线程留给 pywebview 的窗口循环）。
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

try:
    import win32api
    import win32con
    import win32gui
    _HAS_WIN32 = True
except Exception:  # pragma: no cover
    _HAS_WIN32 = False

from .paths import app_root, data_dir, resource

# ---- Shell_NotifyIcon 常量 ------------------------------------------------
WM_TRAY = win32con.WM_USER + 20 if _HAS_WIN32 else 0x0400 + 20
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
NIIF_INFO, NIIF_WARNING, NIIF_ERROR = 0x1, 0x2, 0x3

# 菜单项 id
ID_OPEN, ID_CHECK, ID_TOGGLE, ID_DATA, ID_LOGS, ID_EXIT = 1001, 1002, 1003, 1004, 1005, 1099


def _log(msg: str) -> None:
    """把托盘内部的动作写进日志文件。

    ⚠ 为什么必须这样：windowed exe 没有控制台，托盘跑在自己的线程里，
    线程里的异常只会在进程退出时打印 —— 而 GUI 进程往往一直活着，
    于是"托盘就是不出现"变成一个没有任何线索的现象。实测卡了很久。
    """
    try:
        from .paths import data_dir
        p = data_dir() / "logs" / "dashboard.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} [tray] {msg}\n")
    except Exception:
        pass


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
    ]


class TrayApp:
    """托盘图标。状态每 3 秒刷新一次，颜色随状态变。"""

    def __init__(self, cfg=None, on_open_dashboard=None, on_exit=None):
        self.cfg = cfg
        self.on_open_dashboard = on_open_dashboard
        self.on_exit = on_exit
        self.hwnd = None
        self._nid = None
        self._icons = {}
        self._state = "unknown"
        self._verdict = "正在启动…"
        self._last_balloon = 0.0
        self._last_selfcheck = 0.0
        self._thread = None
        self._stop = threading.Event()

    # ---- 图标 ---------------------------------------------------------
    def _load_icons(self) -> None:
        """加载三态图标。优先用 .ico；没有就现画。"""
        ico = resource("assets", "egressguard.ico")
        if not ico.exists():
            ico = app_root() / "assets" / "egressguard.ico"
        if not ico.exists():
            ico = resource("assets", "icon_ok.png")
        for st in ("ok", "leak", "off"):
            path = ico if ico.suffix.lower() == ".ico" else ico
            try:
                # LR_LOADFROMFILE + LR_DEFAULTSIZE
                h = win32gui.LoadImage(0, str(path), win32con.IMAGE_ICON,
                                       0, 0, win32con.LR_LOADFROMFILE |
                                       win32con.LR_DEFAULTSIZE)
                if h:
                    self._icons[st] = h
            except Exception:
                pass
        if not self._icons:
            h = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
            for st in ("ok", "leak", "off"):
                self._icons[st] = h

    # ---- 状态 ---------------------------------------------------------
    def _api(self, path: str, timeout: float = 2.0):
        cfg = self.cfg
        port = int((cfg.get("api", {}) or {}).get("port", 47821)) if cfg else 47821
        token = getattr(cfg, "api_token", "") if cfg else ""
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                     headers={"X-EG-Token": token})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def _refresh_state(self) -> None:
        """刷新状态。

        ⚠ 两条路径的代价差很多，不能一视同仁：
          - 问守护的 API：毫秒级，可以每 3 秒问一次
          - 自己跑零泄漏自检：要采集网卡、查防火墙、列路由，**6 秒起步**
        第一版不分青红皂白，守护不在时就每 3 秒跑一次完整自检 ——
        等于托盘自己一直在满负荷转。现在自己跑的那条路降到 30 秒一次。
        """
        try:
            rep = self._api("/api/zero_leak")
            zero = bool(rep.get("zero_leak"))
            self._verdict = str(rep.get("verdict") or "")
            enabled = bool(rep.get("enabled"))
            self._last_selfcheck = time.time()
        except Exception:
            # 守护没在跑。自己算一次，但不要每次都算。
            if time.time() - self._last_selfcheck < 30:
                if self._state == "unknown":
                    self._state = "off"
                    self._verdict = "守护没在跑（等待重试）"
                    self._update_icon()
                return
            self._last_selfcheck = time.time()
            try:
                from .core import zero_leak_report
                rep = zero_leak_report()
                zero = bool(rep.get("zero_leak"))
                self._verdict = str(rep.get("verdict") or "")
                enabled = bool(rep.get("enabled"))
            except Exception as e:
                self._state = "off"
                self._verdict = f"守护没在跑（{type(e).__name__}）"
                self._update_icon()
                return

        if not enabled:
            self._state = "off"
            self._verdict = "闸门未启用（观察档）—— " + self._verdict
        elif zero:
            self._state = "ok"
        else:
            self._state = "leak"

        self._update_icon()
        if self._state == "leak":
            self._balloon("检测到泄漏", self._verdict, NIIF_WARNING)

    def _update_icon(self) -> None:
        if not self._nid or not self.hwnd:
            return
        nid = self._nid
        nid.uFlags = NIF_ICON | NIF_TIP
        nid.hIcon = self._icons.get(self._state) or self._icons.get("ok")
        tip = f"EgressGuard · {self._verdict}"
        nid.szTip = tip[:120]
        try:
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    def _balloon(self, title: str, text: str, flags: int = NIIF_INFO) -> None:
        # 气泡别刷屏：同一状态 60 秒内只弹一次
        now = time.time()
        if now - self._last_balloon < 60:
            return
        self._last_balloon = now
        if not self._nid:
            return
        nid = self._nid
        nid.uFlags = NIF_INFO
        nid.szInfoTitle = title[:60]
        nid.szInfo = text[:250]
        nid.dwInfoFlags = flags
        try:
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    # ---- 菜单 ---------------------------------------------------------
    def _show_menu(self) -> None:
        menu = win32gui.CreatePopupMenu()
        label = {"ok": "✓ 零泄漏", "leak": "✗ 有泄漏", "off": "○ 闸门未启用"}[self._state]
        win32gui.AppendMenu(menu, win32con.MF_STRING | win32con.MF_GRAYED, 0, label)
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_OPEN, "打开仪表盘")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_CHECK, "零泄漏自检")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_TOGGLE, "启用 / 停用闸门")
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_DATA, "打开数据目录")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_LOGS, "打开事件日志")
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        win32gui.AppendMenu(menu, win32con.MF_STRING, ID_EXIT, "退出")

        pos = win32gui.GetCursorPos()
        # 必须 SetForegroundWindow，否则菜单点了不消失（Windows 的老规矩）
        win32gui.SetForegroundWindow(self.hwnd)
        cmd = win32gui.TrackPopupMenu(
            menu, win32con.TPM_LEFTALIGN | win32con.TPM_RIGHTBUTTON
            | win32con.TPM_RETURNCMD, pos[0], pos[1], 0, self.hwnd, None)
        win32gui.PostMessage(self.hwnd, win32con.WM_NULL, 0, 0)
        win32gui.DestroyMenu(menu)
        if cmd:
            self._on_menu(cmd)

    def _on_menu(self, cmd: int) -> None:
        if cmd == ID_OPEN:
            if self.on_open_dashboard:
                try:
                    self.on_open_dashboard()
                except Exception:
                    pass
        elif cmd == ID_CHECK:
            self._show_check()
        elif cmd == ID_TOGGLE:
            self._toggle()
        elif cmd == ID_DATA:
            os.startfile(str(data_dir()))
        elif cmd == ID_LOGS:
            p = data_dir() / "events.jsonl"
            if p.exists():
                subprocess.Popen(["notepad.exe", str(p)],
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                os.startfile(str(data_dir()))
        elif cmd == ID_EXIT:
            self.stop()
            if self.on_exit:
                try:
                    self.on_exit()
                except Exception:
                    pass

    def _show_check(self) -> None:
        """跑一次零泄漏自检并把结果弹出来。"""
        try:
            from .core import zero_leak_report
            rep = zero_leak_report()
            lines = [f"{'✓' if c['ok'] else '✗'} {c['name']}：{c['detail'][:60]}"
                     for c in rep["checks"]]
            body = "\n".join(lines)
            win32api.MessageBox(
                0, f"{rep['verdict']}\n\n{body}\n\n{rep['note']}",
                "EgressGuard 零泄漏自检", win32con.MB_ICONINFORMATION)
        except Exception as e:
            win32api.MessageBox(0, f"自检失败：{e}",
                                "EgressGuard", win32con.MB_ICONERROR)

    def _toggle(self) -> None:
        try:
            self._api("/api/toggle", timeout=5)
            self._refresh_state()
        except Exception:
            pass

    # ---- 窗口过程 -----------------------------------------------------
    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAY:
            if lparam in (win32con.WM_RBUTTONUP, win32con.WM_CONTEXTMENU):
                self._show_menu()
            elif lparam == win32con.WM_LBUTTONDBLCLK:
                if self.on_open_dashboard:
                    try:
                        self.on_open_dashboard()
                    except Exception:
                        pass
            return 0
        if msg == win32con.WM_DESTROY:
            win32gui.PostQuitMessage(0)
            return 0
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    # ---- 生命周期 -----------------------------------------------------
    def _run(self) -> None:
        _log("=== 托盘线程启动 ===")
        self._load_icons()
        _log(f"图标加载完成：{len(self._icons)} 个 {list(self._icons.keys())}")
        wc = win32gui.WNDCLASS()
        wc.lpfnWndProc = self._wndproc
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.lpszClassName = "EgressGuardTray"
        try:
            win32gui.RegisterClass(wc)
            _log("RegisterClass OK")
        except Exception as e:
            _log(f"RegisterClass 失败（可能已注册）：{type(e).__name__}: {e}")
        self.hwnd = win32gui.CreateWindow(
            wc.lpszClassName, "EgressGuard", 0, 0, 0, 0, 0, 0, 0,
            wc.hInstance, None)
        _log(f"CreateWindow -> hwnd={self.hwnd}")
        # 把 hwnd 落盘：外部进程可以拿它做 IsWindow 校验，
        # 不用靠 FindWindow 去猜（FindWindow 在冻结形态下查不到，原因未明）
        try:
            from .paths import data_dir
            (data_dir() / "tray_hwnd.txt").write_text(str(int(self.hwnd)),
                                                      encoding="utf-8")
        except Exception:
            pass

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = self._icons.get("ok")
        nid.szTip = "EgressGuard · 正在启动…"
        rc = ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        _log(f"Shell_NotifyIcon(NIM_ADD) -> {rc}（1=成功）")
        self._nid = nid

        # 状态轮询线程
        def poll():
            # 先给一次"启动中"的气泡，让用户知道它活着
            time.sleep(1.5)
            self._balloon("EgressGuard 已启动",
                          "右键这个图标可以查看零泄漏状态、开关闸门。", NIIF_INFO)
            _log("气泡通知已发（启动提示）")
            last = None
            n = 0
            while not self._stop.is_set():
                n += 1
                try:
                    self._refresh_state()
                except Exception as e:
                    _log(f"刷新状态异常：{type(e).__name__}: {e}")
                if self._state != last:
                    _log(f"状态 -> {self._state}  「{self._verdict}」")
                    last = self._state
                elif n % 20 == 0:
                    _log(f"心跳 #{n}  state={self._state}")
                self._stop.wait(3.0)
            _log("轮询线程退出")

        threading.Thread(target=poll, daemon=True, name="eg-tray-poll").start()

        _log("进入消息循环 PumpMessages")
        try:
            win32gui.PumpMessages()
        finally:
            _log("!! 消息循环已退出（托盘图标会被删掉）")
            try:
                ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE,
                                                        ctypes.byref(nid))
            except Exception:
                pass

    def start(self) -> None:
        """在后台线程启动托盘（主线程要留给 webview）。"""
        if not _HAS_WIN32:
            _log("start() 跳过：_HAS_WIN32 为假")
            return

        def _wrapped():
            try:
                self._run()
            except Exception:
                import traceback
                _log("托盘线程异常：\n" + traceback.format_exc())

        self._thread = threading.Thread(target=_wrapped, daemon=True,
                                        name="eg-tray")
        self._thread.start()
        _log(f"托盘线程已启动 tid={self._thread.ident}")

    def stop(self) -> None:
        self._stop.set()
        if self.hwnd:
            try:
                win32gui.PostMessage(self.hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass


def main() -> int:
    """独立跑托盘（调试用）。"""
    if not _HAS_WIN32:
        print("需要 pywin32", file=sys.stderr)
        return 1
    from .config import Config
    app = TrayApp(Config())
    app._run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
