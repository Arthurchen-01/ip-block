"""路径解析：同时支持「源码运行」和「PyInstaller 打包后运行」。

为什么必须单独一个模块
----------------------
PyInstaller 打包后：
  - `__file__` 指向临时解包目录（sys._MEIPASS，通常在 %TEMP%\\_MEIxxxxx），
    进程退出就删。把 data/ 建在那里等于每次重启都丢配置和日志。
  - 只读资源（ui.html）在 _MEIPASS 里；
    可写数据（config.json / events.jsonl / notices）必须在 exe 旁边。

所以两类路径要分开：
    资源路径 resource(name)  -> 冻结时在 _MEIPASS，源码时在 eg/ 目录
    数据路径 DATA_DIR        -> 冻结时在 exe 所在目录\\data，源码时在工程根\\data
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    """是否运行在 PyInstaller 打包出来的 exe 里。"""
    return bool(getattr(sys, "frozen", False))


def app_root() -> Path:
    """应用根目录。

    冻结时 = exe 所在目录（用户看得见、可写、可备份的地方）
    源码时 = 工程根目录
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_root() -> Path:
    """只读资源根目录。冻结时是解包目录，源码时是工程根。"""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", app_root()))
    return Path(__file__).resolve().parent.parent


def resource(rel: str) -> Path:
    """取一个随程序分发的只读资源（如 ui.html）。"""
    return resource_root() / rel


def data_dir() -> Path:
    """可写数据目录。**源码形态和 exe 形态共用同一个位置。**

    ⚠ 为什么不再用"exe 旁边的 data\\"

    最初的做法是"数据跟着 exe 走"（源码形态 → 工程根\\data，exe 形态 → exe 所在目录\\data）。
    看起来干净，实际踩了两个坑（都是真实反馈带来的）：

    1. **两种形态有两份互不相干的配置。** dist\\EgressGuardCore.exe 跑出来的
       token 和源码形态不一样，命令行工具去查状态就对不上。
    2. **通知里写的路径和集成方读的路径不是同一个。**
       反馈原话："我们读 data\\events.jsonl，最后一条是 15:17；
       而桌面通知是 15:25 生成的 —— 一度误判成闸门有 bug，翻了半天
       才发现是读了另一个目录。"

    现在统一到 `%LOCALAPPDATA%\\EgressGuard\\`（和其他 Windows 程序一致），
    源码、exe、命令行工具、集成方读到的永远是同一份。

    保留两个逃生口：
      - 环境变量 `EGRESSGUARD_DATA` 可以覆盖（便携部署用）
      - 首次运行时如果发现旧的 `<根目录>\\data\\config.json`，自动迁移过来
    """
    override = os.environ.get("EGRESSGUARD_DATA", "").strip()
    if override:
        d = Path(override)
    else:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        d = (Path(base) / "EgressGuard") if base else (app_root() / "data")

    d.mkdir(parents=True, exist_ok=True)
    for sub in ("notices", "reports", "logs"):
        (d / sub).mkdir(parents=True, exist_ok=True)

    _migrate_legacy(d)
    return d


def _migrate_legacy(new_dir: Path) -> None:
    """把旧的"exe 旁边的 data\\"迁到新位置。只做一次，且只在目标是空的时候做。"""
    try:
        if (new_dir / "config.json").exists():
            return
        legacy = app_root() / "data"
        if not legacy.exists() or legacy.resolve() == new_dir.resolve():
            return
        src = legacy / "config.json"
        if not src.exists():
            return
        import shutil
        for item in legacy.iterdir():
            if item.is_file():
                shutil.copy2(item, new_dir / item.name)
        for sub in ("notices",):
            s = legacy / sub
            if s.is_dir():
                (new_dir / sub).mkdir(parents=True, exist_ok=True)
                for item in s.iterdir():
                    if item.is_file():
                        shutil.copy2(item, new_dir / sub / item.name)
    except Exception:
        # 迁移失败不影响使用，下次启动会再试
        pass


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)
