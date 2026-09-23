"""启动守护进程的入口。计划任务用这个，避免 -m 的各种路径坑。

同时兼任三件事：

1. **打包后的隐藏入口**：`EgressGuardCore.exe --inject-console`
   通知模块会 spawn 这个入口去往目标程序的控制台写红字，
   见 eg/console_inject.py 里关于"为什么必须在子进程里做"的说明。

2. **窗口化 exe 的控制台附着**：
   打包用了 --windowed（这样被计划任务拉起时不弹黑框），
   但代价是 sys.stdout 变成 None，命令行模式下 `--status` 之类什么都打印不出来。
   解决：发现 stdout 不可用时，AttachConsole(ATTACH_PARENT_PROCESS)
   挂到父进程（终端）的控制台上，再重新绑定 stdout/stderr。
   于是同一份 exe：终端里跑有输出，计划任务里跑无窗口。

3. **把可写数据固定在 exe 旁边**：由 eg.paths 负责，这里不用管。
"""
import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _rebind_console() -> bool:
    """窗口化 exe 没有控制台时，挂到父进程的控制台上。

    返回是否成功挂上。注意两点：

    1. 如果父进程的输出被重定向到管道/文件，这个办法拿不到那个管道
       （AttachConsole 只能拿控制台），所以调用方仍要接受"输出丢失"。
    2. **必须按控制台实际代码页写**，不能一律 UTF-8。
       实测：中文 Windows 控制台是 cp936，往 CONOUT$ 写 UTF-8 字节，
       控制台按 GBK 解释，中文全是乱码。
       正确做法是问 GetConsoleOutputCP() 拿当前代码页，用它来编码。
    """
    if sys.stdout is not None:
        try:
            sys.stdout.write("")
            return True
        except Exception:
            pass
    try:
        k = ctypes.WinDLL("kernel32.dll")
        # ATTACH_PARENT_PROCESS = -1
        if not k.AttachConsole(ctypes.c_uint(-1).value):
            return False
        cp = int(k.GetConsoleOutputCP() or 0)
        enc = f"cp{cp}" if cp else "utf-8"
        out = open("CONOUT$", "w", encoding=enc, errors="replace", buffering=1)
        err = open("CONOUT$", "w", encoding=enc, errors="replace", buffering=1)
        sys.stdout = out
        sys.stderr = err
        return True
    except Exception:
        return False


# 必须放在 import eg.core 之前：这个入口不启动守护，只做一次注入然后退出
if "--inject-console" in sys.argv:
    from eg.console_inject import run_from_stdin

    sys.exit(run_from_stdin())

# 只有命令行模式才需要控制台；正常起守护（无参数）不需要，也不该弹窗
_CLI_FLAGS = ("--status", "--once", "--leak-test", "--probe", "--calibrate",
              "--enable", "--disable", "-h", "--help")
if any(f in sys.argv for f in _CLI_FLAGS):
    _rebind_console()

from eg.core import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
