"""EgressGuard —— 昆明 IP / 本机指纹零泄露闸门。

包结构
------
    winapi.py       ctypes 底层：连接枚举（权威本地地址）、连接强杀
    netinfo.py      网卡/隧道识别、出口 IP 探测、地理归属
    config.py       配置读写
    logbus.py       事件总线 + 落盘
    policy.py       五类泄漏的判定引擎
    enforce.py      防火墙规则 / 连接掐断 / 进程隔离
    fingerprint.py  指纹信道封杀 + 内容指纹扫描
    notify.py       多通道"把原因告诉那个程序"
    guardproxy.py   本地清洗代理
    core.py         守护主循环 + 本地 API
    dashboard.py    pywebview 仪表盘
"""

# 版本号的唯一权威来源是仓库根目录的 VERSION 文件。
# 打包成 exe 后 VERSION 也被打进包（build_exe.py 用 --add-data 带进去），
# 所以 exe 里报的版本和仓库里的 VERSION 永远一致。
# 最后的字符串是兜底：两边都读不到时才用它。
def _read_version() -> str:
    try:
        import sys
        from pathlib import Path
        cands = [Path(__file__).resolve().parent.parent / "VERSION"]
        mei = getattr(sys, "_MEIPASS", "")
        if mei:
            cands.append(Path(mei) / "VERSION")
        for cand in cands:
            if cand.exists():
                v = cand.read_text(encoding="utf-8").strip()
                if v:
                    return v
    except Exception:
        pass
    return "1.1.0"


__version__ = _read_version()
__all__ = ["__version__"]
