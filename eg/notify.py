"""通知层：把"为什么掐你"送到那个程序手里。

用户的硬要求是「要告诉那个程序是这个原因导致的」，所以这里做了**七条通道**，
不是只写个日志了事。每条通道单独 try，任何一条挂了不影响其他条。

  1. 落盘事件        data/events.jsonl（永久留痕）
  2. 原因卡          程序所在会话的桌面 + data/notices/<pid>.json（机器可读）
  3. 控制台注入       AttachConsole(pid) + WriteConsoleW —— 直接打进它的黑框
  4. 归属弹窗         MessageBox 挂在**目标程序自己的窗口**上，
                     视觉上就是那个程序在告诉你原因，而不是系统在弹
  5. Windows 事件日志  eventcreate，事件源 EgressGuard，事件 ID 900
  6. 系统 Toast       Windows.UI.Notifications，右下角横幅
  7. 可查询接口       本地 API /api/why?pid=N 与命名管道（由 core 提供）

冷却：同一个程序 + 同一个原因，notify_cooldown_s 秒内不重复打扰。
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import threading
import time
from ctypes import wintypes
from pathlib import Path

from .config import Config, DATA_DIR
from .logbus import LogBus
from .policy import Finding

_user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

_user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
_user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_user32.IsWindowVisible.argtypes = [wintypes.HWND]
_user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
_user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
_user32.MessageBoxTimeoutW.argtypes = [
    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
    wintypes.UINT, wintypes.WORD, wintypes.DWORD]
_user32.MessageBoxTimeoutW.restype = ctypes.c_int
_user32.MessageBoxW.argtypes = [
    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
_user32.MessageBoxW.restype = ctypes.c_int

_kernel32.AttachConsole.argtypes = [wintypes.DWORD]
_kernel32.FreeConsole.argtypes = []
_kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
_kernel32.GetStdHandle.restype = wintypes.HANDLE
_kernel32.WriteConsoleW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.SetConsoleTextAttribute.argtypes = [wintypes.HANDLE, wintypes.WORD]
_kernel32.GetConsoleScreenBufferInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
_kernel32.WriteFile.restype = wintypes.BOOL

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
STD_ERROR_HANDLE = -12
STD_OUTPUT_HANDLE = -11
MB_OK = 0x0
MB_ICONERROR = 0x10
MB_TOPMOST = 0x40000
MB_SETFOREGROUND = 0x10000
MB_SYSTEMMODAL = 0x1000

# 控制台红色（FOREGROUND_RED = 4，加亮 = 8）
CONSOLE_RED = 0x0004 | 0x0008
CONSOLE_DEFAULT = 0x0007

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE = ctypes.c_void_p(-1).value

_PSEXE = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]


def find_main_window(pid: int) -> int:
    """找目标进程的可见顶层窗口（有标题的那个）。找不到返回 0。"""
    found = [0]

    def cb(hwnd, _lparam):
        if not _user32.IsWindowVisible(hwnd):
            return True
        wpid = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if wpid.value != pid:
            return True
        n = _user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        found[0] = hwnd
        return False

    try:
        _user32.EnumWindows(WNDENUMPROC(cb), 0)
    except Exception:
        pass
    return found[0]


class Notifier:
    def __init__(self, cfg: Config, bus: LogBus):
        self.cfg = cfg
        self.bus = bus
        self._lock = threading.RLock()
        self._last: dict[tuple, float] = {}
        self._dialogs_open = 0
        self._max_dialogs = 3
        self._last_violation: dict = {}

    # ---- 冷却 ---------------------------------------------------------

    def _cool(self, key: tuple) -> bool:
        """True = 还在冷却期，别打扰。"""
        cd = float(self.cfg.get("notify_cooldown_s", 20) or 0)
        now = time.monotonic()
        with self._lock:
            t = self._last.get(key)
            if t is not None and now - t < cd:
                return True
            self._last[key] = now
            if len(self._last) > 5000:
                self._last = {k: v for k, v in self._last.items() if now - v < cd * 10}
        return False

    # ---- 文案 ---------------------------------------------------------

    def compose(self, f: Finding, action_text: str, target_label: str) -> tuple[str, str]:
        """(标题, 正文)。正文要让人一眼看懂"为什么被掐"。"""
        title = f"EgressGuard 已切断：{target_label}（{f.title}）"
        lines = [
            f"程序：{f.process or '未知'}" + (f"（PID {f.pid}）" if f.pid else ""),
            f"判定：{f.title}  [{f.code}]",
            f"原因：{f.detail}",
        ]
        if f.remote:
            lines.append(f"连接：{f.local} -> {f.remote}（{f.proto.upper()}）")
        if f.iface:
            lines.append(f"网卡：{f.iface}")
        lines.append(f"处置：{action_text}")
        lines.append("")
        lines.append("为什么必须掐断：你的要求是昆明 IP 和本机指纹不得从本机泄漏。")
        lines.append("这条连接满足泄漏条件，所以在造成后果之前被切掉了。")
        lines.append("查询接口：http://127.0.0.1:%d/api/why?pid=%d" %
                     (int(self.cfg.get("api", {}).get("port", 47821)), f.pid))
        return title, "\n".join(lines)

    # ---- 主入口 -------------------------------------------------------

    def notify(self, f: Finding, action_text: str,
               target_label: str | None = None) -> dict:
        """发通知。返回各通道的结果，方便仪表盘显示"通知送到了哪里"。"""
        n = self.cfg.get("notify", {}) or {}
        # 网卡级判定（IPv6 旁路 / DNS 泄漏 / 隧道断开）没有归属程序，
        # 用「本机网络配置」当标签，而不是「PID 0」这种看了反而更糊涂的东西。
        is_system_level = f.pid <= 0
        if target_label:
            label = target_label
        elif is_system_level:
            label = f"本机网络配置（{f.iface}）" if f.iface else "本机网络配置"
        else:
            label = f.process or f"PID {f.pid}"
        title, body = self.compose(f, action_text, label)

        # 自测标记：验收测试跑的时候打开 selftest_mode，
        # 所有通知和事件都会显著标出"这是自测，不是真实泄漏"。
        #
        # 为什么需要：反馈里提到，另一个工作区曾经撞上"闸门正在跑验收测试"
        # 的窗口期，那几分钟里 python.exe 被真封杀，他们完全没法联网，
        # 而且不知道是谁干的。标出来至少能让人一眼看懂发生了什么。
        selftest = bool(self.cfg.get("selftest_mode")) or bool(f.evidence.get("selftest"))
        if selftest:
            title = "【自测流量，不是真实泄漏】" + title
            body = "⚠ 这是 EgressGuard 自己的验收测试制造的流量，不是真实泄漏。\n" + body

        rec = {
            "ts": time.time(), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "code": f.code, "title": title, "body": body,
            "pid": f.pid, "process": f.process or ("本机网络配置" if is_system_level else ""),
            "exe": f.exe,
            "severity": f.severity, "detail": f.detail,
            "local": f.local, "remote": f.remote, "proto": f.proto,
            "iface": f.iface, "evidence": f.evidence,
            "action": action_text, "system_level": is_system_level,
            "selftest": selftest,
        }
        with self._lock:
            self._last_violation = rec

        results: dict[str, str] = {}

        # 1. 落盘（永远做）
        try:
            self._write_files(rec)
            results["file"] = "ok"
        except Exception as e:
            results["file"] = f"失败：{e}"

        key = (f.pid, f.code)
        if self._cool(key):
            results["cooldown"] = "冷却中，跳过交互式通知"
            self.bus.notice(severity=f.severity, code=f.code, title=title,
                            detail="（冷却中，仅落盘）" + f.detail,
                            pid=f.pid, process=f.process, exe=f.exe,
                            local=f.local, remote=f.remote, proto=f.proto,
                            reason=f.detail)
            return results

        # 2. 原因卡（放桌面，最直观）
        if n.get("desktop_file", True):
            try:
                results["desktop_file"] = self._desktop_card(rec)
            except Exception as e:
                results["desktop_file"] = f"失败：{e}"

        # 3. 控制台注入 —— 只对"有归属程序"的判定做。
        #    往 PID 0 的控制台写没意义（那是 System，而且它没有控制台）。
        if n.get("console", True) and f.pid > 0:
            try:
                results["console"] = self._console_inject(f.pid, title, body)
            except Exception as e:
                results["console"] = f"失败：{e}"
        elif is_system_level:
            results["console"] = "网卡级判定无归属程序，跳过控制台注入"

        # 4. 归属弹窗 —— 同上
        if n.get("messagebox", True) and f.pid > 0:
            try:
                results["messagebox"] = self._messagebox(f.pid, title, body)
            except Exception as e:
                results["messagebox"] = f"失败：{e}"
        elif is_system_level:
            results["messagebox"] = "网卡级判定无归属程序，跳过弹窗（见桌面原因卡）"

        # 5. 事件日志
        if n.get("eventlog", True):
            try:
                results["eventlog"] = self._eventlog(title, body)
            except Exception as e:
                results["eventlog"] = f"失败：{e}"

        # 6. Toast
        if n.get("toast", True):
            try:
                results["toast"] = self._toast(title, f.detail)
            except Exception as e:
                results["toast"] = f"失败：{e}"

        self.bus.notice(severity=f.severity, code=f.code, title=title,
                        detail=f.detail, pid=f.pid, process=f.process, exe=f.exe,
                        local=f.local, remote=f.remote, proto=f.proto,
                        reason=f.detail, extra={"channels": results})
        return results

    # ---- 通道实现 -----------------------------------------------------

    def _write_files(self, rec: dict) -> None:
        (DATA_DIR / "notices").mkdir(parents=True, exist_ok=True)
        blob = json.dumps(rec, ensure_ascii=False, indent=2)
        if rec["pid"]:
            (DATA_DIR / "notices" / f"pid_{rec['pid']}.json").write_text(
                blob, encoding="utf-8")
        (DATA_DIR / "last_violation.json").write_text(blob, encoding="utf-8")

    def _desktop_card(self, rec: dict) -> str:
        """往桌面写一张纯文本"原因卡"。

        ⚠ 三个实测踩到的坑，都要靠这里的写法避开：

        1. **文件名撞名会把内容撕碎。**
           原来文件名是 `..._<程序>_<秒级时间戳>.txt`。同一秒内发生多次拦截
           （比如 svchost + DNS + IPv6 挤在一起）就会撞到同一个文件名，
           多个写入方用 "w" 打开同一个文件，内容交错，
           用户看到的就是"标题重复了十几遍、正文被挤到后面"。

        2. **必须原子写。** 先写临时文件再 os.replace，
           这样任何时刻读到的都是一份完整内容，不会读到半截。

        3. **必须自动收敛。** 跑一阵子桌面会堆满卡片。
           这里每个程序只保留最近 keep_per_program 张。
        """
        desktop = Path(os.path.expanduser("~")) / "Desktop"
        if not desktop.exists():
            desktop = Path(os.environ.get("USERPROFILE", ".")) / "Desktop"
        desktop.mkdir(parents=True, exist_ok=True)

        stamp = time.strftime("%m%d_%H%M%S")
        safe = "".join(ch for ch in (rec["process"] or "unknown")
                       if ch.isalnum() or ch in "._-")[:40] or "unknown"
        pid = int(rec.get("pid") or 0)
        # pid 进文件名：同一秒内不同程序/不同进程不会撞名
        path = desktop / f"EgressGuard_已掐断_{safe}_{pid}_{stamp}.txt"

        selftest = "【自测流量，不是真实泄漏】\n\n" if rec.get("selftest") else ""
        text = (
            "=" * 66 + "\n"
            "  EgressGuard 切断通知 —— 这不是报错，是主动拦截\n"
            "=" * 66 + "\n\n"
            + selftest
            + f"时间：{rec['time']}\n"
            f"程序：{rec['process']}（PID {rec['pid']}）\n"
            f"判定：{rec['title']}\n\n"
            f"原因：{rec['detail']}\n\n"
            f"连接：{rec['local']} -> {rec['remote']}（{rec['proto'].upper()}）\n"
            f"网卡：{rec['iface']}\n"
            f"处置：{rec['action']}\n\n"
            "证据：\n"
            + json.dumps(rec.get("evidence") or {}, ensure_ascii=False, indent=2) + "\n\n"
            "为什么必须掐断：\n"
            "  你的要求是昆明 IP 与本机指纹不得从本机泄漏。这条连接满足泄漏条件，\n"
            "  所以在造成后果之前被切断。\n\n"
            "想知道为什么被掐，程序可以调：\n"
            f"  http://127.0.0.1:{int(self.cfg.get('api', {}).get('port', 47821))}"
            f"/api/why?pid={rec['pid']}\n"
            "  （blocked=true 表示**这个 pid 自己**被拦截过；\n"
            "    查全局最近一次拦截请用 /api/last_violation）\n\n"
            "全部事件：\n"
            f"  {DATA_DIR / 'events.jsonl'}\n"
        )
        # 原子写：临时文件 + replace，避免并发写把内容撕碎
        tmp = path.with_name(path.name + ".tmp")
        try:
            tmp.write_text(text, encoding="utf-8-sig")
            os.replace(tmp, path)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
            path.write_text(text, encoding="utf-8-sig")

        self._prune_cards(desktop, safe)
        return f"已写入 {path.name}"

    @staticmethod
    def _prune_cards(desktop: Path, program: str, keep: int = 3) -> None:
        """每个程序只保留最近 keep 张原因卡，其余删掉。

        文件名格式：EgressGuard_已掐断_<程序>_<pid>_<时间>.txt
        所以按前缀 `EgressGuard_已掐断_<程序>_` 就能圈出同一个程序的所有卡片。
        """
        try:
            prefix = f"EgressGuard_已掐断_{program}_"
            cards = sorted(
                (p for p in desktop.glob("EgressGuard_已掐断_*.txt")
                 if p.name.startswith(prefix)),
                key=lambda p: p.stat().st_mtime, reverse=True)
            for old in cards[keep:]:
                try:
                    old.unlink()
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _console_inject(pid: int, title: str, body: str) -> str:
        """把红字写进目标程序的控制台。

        ⚠ **必须放到子进程里做**，不能在本进程里直接 AttachConsole/FreeConsole。

        实测踩到的大坑：AttachConsole 要求本进程当前没有控制台。
        如果本进程已经有控制台（守护从命令行启动、或调用方继承了控制台），
        就得先 FreeConsole 让出来 —— 而 FreeConsole 摘掉的是**本进程自己的**
        控制台，摘完之后本进程 stdout 句柄失效，下一次 print() 直接抛
        `OSError: [WinError 6] 句柄无效`，整个进程崩掉。
        验收脚本就是因为这个在"通知靶子"那一步 exit 1、报告都没写出来。

        所以这里 spawn 一个短命子进程去干脏活，父进程的控制台毫发无损。
        """
        import json as _json
        import subprocess as _sp
        import sys as _sys

        job = _json.dumps({"pid": pid, "title": title, "body": body},
                          ensure_ascii=False)
        frozen = bool(getattr(_sys, "frozen", False))
        if frozen:
            # 打包后：自己的 exe 带一个隐藏入口
            cmd = [_sys.executable, "--inject-console"]
        else:
            cmd = [_sys.executable,
                   str(Path(__file__).resolve().parent / "console_inject.py")]
        try:
            p = _sp.run(cmd, input=job.encode("utf-8"),
                        capture_output=True, timeout=20,
                        creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
            out = (p.stdout or b"").decode("utf-8", "replace").strip()
            if out:
                return out
            err = (p.stderr or b"").decode("utf-8", "replace").strip()
            return f"注入子进程无输出（rc={p.returncode}）{err[:120]}"
        except Exception as e:
            return f"注入子进程启动失败：{e}"

    def _messagebox(self, pid: int, title: str, body: str) -> str:
        with self._lock:
            if self._dialogs_open >= self._max_dialogs:
                return "弹窗已达并发上限，跳过"
            self._dialogs_open += 1

        hwnd = find_main_window(pid)
        owner = hwnd or 0
        text = body if len(body) < 1800 else body[:1800] + "\n…（完整内容见桌面原因卡）"
        typ = MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND

        def run():
            try:
                # MessageBoxTimeoutW 会自己超时关闭，不会把线程永久挂住
                rc = _user32.MessageBoxTimeoutW(owner, text, title, typ, 0, 25000)
                if rc == 0:
                    _user32.MessageBoxW(owner, text, title, typ)
            except Exception:
                pass
            finally:
                with self._lock:
                    self._dialogs_open -= 1

        threading.Thread(target=run, daemon=True, name="eg-msgbox").start()
        return (f"已在目标窗口（hwnd={hwnd}）上弹出原因说明，25 秒后自动关闭"
                if hwnd else "目标没有可见窗口，已弹独立置顶窗，25 秒后自动关闭")

    @staticmethod
    def _eventlog(title: str, body: str) -> str:
        """写 Windows 事件日志。

        三条路依次试，因为权限要求不同：
          1. pywin32 ReportEvent —— 事件源注册过就能用，**普通权限也行**，
             且能写长文本。装好之后（install.ps1 注册了源）这条最稳。
          2. eventcreate.exe —— 不需要注册源，但**需要管理员**，且正文限 255 字符。
          3. .NET EventLog 类 —— 兜底。
        """
        msg = (title + " | " + body.replace("\r", " ").replace("\n", " ")).strip()

        # 路 1：pywin32
        try:
            import win32evtlog  # noqa
            import win32evtlogutil
            win32evtlogutil.ReportEvent(
                "EgressGuard", 900,
                eventType=win32evtlog.EVENTLOG_ERROR_TYPE,
                strings=[msg[:3000]])
            return "已写入 Windows 事件日志（源 EgressGuard，ID 900）"
        except ImportError:
            pass
        except Exception as e1:
            first_err = str(e1)
        else:
            first_err = ""

        # 路 2：eventcreate
        try:
            p = subprocess.run(
                ["eventcreate", "/T", "ERROR", "/ID", "900", "/L", "APPLICATION",
                 "/SO", "EgressGuard", "/D", msg[:250]],
                capture_output=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if p.returncode == 0:
                return "已写入 Windows 事件日志（eventcreate）"
        except Exception:
            pass

        # 路 3：.NET
        script = (
            "try { $l = New-Object System.Diagnostics.EventLog('Application'); "
            "$l.Source = 'EgressGuard'; "
            f"$l.WriteEntry('{msg[:900].replace(chr(39), chr(39)*2)}', 'Error', 900); "
            "Write-Output 'OK' } catch { Write-Output ('ERR ' + $_.Exception.Message) }"
        )
        try:
            p = subprocess.run(_PSEXE + ["-Command", script],
                               capture_output=True, timeout=25,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            out = (p.stdout or b"").decode("utf-8", "replace").strip()
            if "OK" in out:
                return "已写入 Windows 事件日志（.NET）"
            return (f"三条路径都失败（{first_err[:60]} / {out[:80]}）。"
                    "安装脚本注册事件源后即可正常写入。")
        except Exception as e:
            return f"失败：{e}"

    @staticmethod
    def _toast(title: str, detail: str) -> str:
        safe_t = title.replace("'", "''")[:120]
        safe_d = detail.replace("'", "''")[:200]
        script = (
            "try {"
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            "ContentType=WindowsRuntime] | Out-Null;"
            "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
            "$x=$t.GetElementsByTagName('text');"
            f"$x.Item(0).AppendChild($t.CreateTextNode('{safe_t}')) | Out-Null;"
            f"$x.Item(1).AppendChild($t.CreateTextNode('{safe_d}')) | Out-Null;"
            "$n=[Windows.UI.Notifications.ToastNotification]::new($t);"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
            "'EgressGuard').Show($n); Write-Output 'OK'"
            "} catch { Write-Output ('ERR ' + $_.Exception.Message) }"
        )
        try:
            p = subprocess.run(_PSEXE + ["-Command", script],
                               capture_output=True, timeout=25,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            out = (p.stdout or b"").decode("utf-8", "replace").strip()
            return "已发送系统通知" if "OK" in out else f"失败：{out[:120]}"
        except Exception as e:
            return f"失败：{e}"

    # ---- 查询 ---------------------------------------------------------

    def last_violation(self) -> dict:
        with self._lock:
            return dict(self._last_violation)

    def violation_for_pid(self, pid: int) -> dict | None:
        p = DATA_DIR / "notices" / f"pid_{pid}.json"
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return None
        lv = self.last_violation()
        return lv if lv.get("pid") == pid else None
