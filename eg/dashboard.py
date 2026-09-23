"""仪表盘：pywebview 原生窗口（WebView2）+ 兜底浏览器模式。

两种跑法
--------
A. 守护已在运行（推荐：由计划任务以 SYSTEM 身份常驻）
   -> 仪表盘只是连上去看，关掉窗口不影响防护。

B. 守护没在跑
   -> 仪表盘就地起一个"普通权限的观察用核心"，
      能看能测能通知，但不能改防火墙/掐连接。
      界面顶部会明确标出"普通权限"。

为什么要分这两种：提权守护必须常驻（关窗口也要拦），
而 GUI 不该常驻提权。分开是唯一正确的结构。
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

from . import __version__
from .config import Config


def probe_api(port: int, token: str, timeout: float = 1.2) -> dict | None:
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/health",
            headers={"X-EG-Token": token})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8"))
            if d.get("ok"):
                return d
    except Exception:
        return None
    return None


def find_live_api(cfg: Config) -> tuple[int, dict] | None:
    """守护可能因为端口占用而挪到了别的端口，逐个试。"""
    token = cfg.api_token
    base = int(cfg.get("api", {}).get("port", 47821))
    for p in range(base, base + 12):
        d = probe_api(p, token)
        if d:
            return p, d
    return None


def run_window(url: str, title: str, width: int, height: int, gui: str | None) -> None:
    import webview  # pywebview

    webview.create_window(title, url, width=width, height=height,
                          min_size=(980, 640), text_select=True)
    kw = {}
    if gui:
        kw["gui"] = gui
    webview.start(**kw)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser("egdashboard", description="EgressGuard 仪表盘")
    ap.add_argument("--web", action="store_true", help="用系统浏览器打开而不是原生窗口")
    ap.add_argument("--gui", default=None,
                    help="pywebview 后端：edgechromium / mshtml / cef / qt")
    ap.add_argument("--port", type=int, default=0, help="强制使用某个 API 端口")
    ap.add_argument("--width", type=int, default=1180)
    ap.add_argument("--height", type=int, default=800)
    ap.add_argument("--no-spawn", action="store_true",
                    help="守护没在跑时不要就地起核心，只报错")
    args = ap.parse_args(argv)

    cfg = Config()
    token = cfg.api_token

    live = None
    if args.port:
        d = probe_api(args.port, token)
        live = (args.port, d) if d else None
    else:
        live = find_live_api(cfg)

    own_core = None
    if live:
        port, _info = live
        print(f"[仪表盘] 已连上常驻守护，API 端口 {port}")
    else:
        if args.no_spawn:
            print("[仪表盘] 守护未运行。请先启动 EgressGuard 守护（计划任务或 egcore.exe）。",
                  file=sys.stderr)
            return 2
        print("[仪表盘] 未发现常驻守护，就地启动一个普通权限的观察核心…")
        from .core import GuardCore
        own_core = GuardCore(cfg)
        port = own_core.start_api()
        own_core._refresh_adapters()
        threading.Thread(target=own_core._hot_loop, daemon=True).start()
        threading.Thread(target=own_core._slow_loop, daemon=True).start()
        print(f"[仪表盘] 观察核心已就绪，API 端口 {port}"
              f"（普通权限：只能检测与通知，不能阻断）")

    url = f"http://127.0.0.1:{port}/?token={token}"

    if args.web:
        webbrowser.open(url)
        print(f"[仪表盘] 已在浏览器打开：{url}")
        if own_core:
            print("[仪表盘] 观察核心随本进程退出。按 Ctrl+C 结束。")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                own_core.shutdown()
        return 0

    try:
        run_window(url, f"EgressGuard · 零泄漏闸门 v{__version__}",
                   args.width, args.height, args.gui)
    except Exception as e:
        print(f"[仪表盘] 原生窗口启动失败（{e}），回退到浏览器模式", file=sys.stderr)
        webbrowser.open(url)
        if own_core:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    if own_core:
        own_core.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
