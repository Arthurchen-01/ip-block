"""把 EgressGuard 打包成 Windows exe（PyInstaller）。

产出
----
    dist/EgressGuardCore.exe   守护进程（无黑框，计划任务跑这个）
    dist/EgressGuard.exe       仪表盘（无黑框，桌面快捷方式跑这个）

为什么是两个 exe 而不是一个
---------------------------
守护必须常驻且以最高权限运行（关掉仪表盘也要继续拦），
仪表盘只是看和点，不该常驻提权。两个职责混在一个 exe 里，
要么仪表盘被迫提权常驻，要么守护拿不到提权 —— 两种都不对。

关键细节
--------
1. `eg/ui.html` 必须用 --add-data 打进包里（`eg/ui.html;eg`），
   运行时通过 eg.paths.resource("eg/ui.html") 取，
   冻结后落在 sys._MEIPASS/eg/ui.html。
2. 数据目录（config.json / events.jsonl / notices）**不能**放 _MEIPASS，
   那是个进程退出就删的临时目录。eg.paths.data_dir() 在冻结时
   返回 exe 同级的 data\，这是刻意的。
3. `--windowed` 消灭黑框。守护用 pythonw 等价物，仪表盘同理。
4. pywebview 在 Windows 上走 EdgeChromium，依赖 pythonnet(clr) 与
   WebView2 运行时，需要 collect-all 才能打全。

用法：
    python tools/build_exe.py            # 打包两个 exe
    python tools/build_exe.py --clean    # 先清 dist/build
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"


def run(cmd: list[str]) -> int:
    print("  $ " + " ".join(f'"{c}"' if " " in c else c for c in cmd), flush=True)
    return subprocess.call(cmd)


def write_version_resource() -> Path:
    """生成 PyInstaller 的 --version-file，把版本写进 exe 元数据。

    为什么必须做：不然右键 exe -> 属性 -> 详细信息里什么都没有，
    用户/运维根本看不出这个 exe 是哪一版。会出现"README 说 1.1、
    exe 属性里是空的"这种撒谎情况。
    """
    ver = (ROOT / "VERSION").read_text(encoding="utf-8").strip() or "0.0.0"
    parts = (ver.split(".") + ["0", "0", "0"])[:4]
    nums = ",".join(str(int(p) if p.isdigit() else 0) for p in parts)
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({nums}), prodvers=({nums}),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([StringTable('080404B0', [
      StringStruct('CompanyName', 'EgressGuard'),
      StringStruct('FileDescription', 'EgressGuard 零泄漏闸门'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'EgressGuard'),
      StringStruct('LegalCopyright', 'Local build'),
      StringStruct('OriginalFilename', '{ver}'),
      StringStruct('ProductName', 'EgressGuard'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
"""
    p = BUILD / "version_info.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def build_one(name: str, entry: str, windowed: bool = True,
              extra: list[str] | None = None) -> bool:
    print(f"\n=== 打包 {name} （入口 {entry}）===", flush=True)
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile",
        "--name", name,
        "--distpath", str(DIST),
        "--workpath", str(BUILD / name),
        "--specpath", str(BUILD),
        # 仪表盘页面：运行时用 paths.resource("eg/ui.html") 取
        "--add-data", f"{ROOT / 'eg' / 'ui.html'};eg",
        # VERSION 也打进包：eg/__init__.py 优先从它读版本号，
        # 保证 exe 报的版本和仓库里的 VERSION 永远一致
        "--add-data", f"{ROOT / 'VERSION'};.",
        "--version-file", str(write_version_resource()),
        # 隐藏 import：pywebview 的平台后端是动态加载的，静态分析抓不到
        "--hidden-import", "webview",
        "--hidden-import", "webview.platforms.edgechromium",
        "--hidden-import", "webview.platforms.winforms",
        "--hidden-import", "clr",
        "--collect-all", "webview",
        "--log-level", "WARN",
    ]
    if windowed:
        cmd.append("--windowed")
    cmd += extra or []
    cmd.append(str(ROOT / entry))
    rc = run(cmd)
    ok = rc == 0 and (DIST / f"{name}.exe").exists()
    print(f"  {'[OK]' if ok else '[失败]'} {name}.exe "
          f"{(DIST / (name + '.exe')).stat().st_size / 1048576:.1f} MB"
          if (DIST / f"{name}.exe").exists() else f"  [失败] {name}.exe 未生成",
          flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--only", default=None, help="只打某一个：core / dashboard")
    args = ap.parse_args()

    try:
        import PyInstaller  # noqa
        print(f"PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("缺 PyInstaller：python -m pip install pyinstaller", file=sys.stderr)
        return 2

    if args.clean:
        for d in (DIST, BUILD):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
                print(f"已清理 {d}")

    DIST.mkdir(parents=True, exist_ok=True)
    ok_all = True

    if args.only in (None, "core"):
        ok_all &= build_one("EgressGuardCore", "run_core.py", windowed=True)
    if args.only in (None, "dashboard"):
        ok_all &= build_one("EgressGuard", "run_dashboard.py", windowed=True)

    print("\n" + "=" * 62)
    if ok_all:
        print("打包完成：")
        for f in sorted(DIST.glob("*.exe")):
            print(f"  {f}   {f.stat().st_size / 1048576:.1f} MB")
    else:
        print("有打包失败项，见上面的输出")
    print("=" * 62)
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
