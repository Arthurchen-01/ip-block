"""探测 ETW 能不能给出「每进程字节数」。

Microsoft-Windows-Kernel-Network 提供者会发 KERNEL_NETWORK_TASK_TCPIP /
UDPIP 事件，每个事件带 PID + 上下行字节数。用 logman 采一小段再 tracerpt
转 CSV，看能不能按 PID 汇总出字节数。

如果能，界面上的"谁在吃带宽"就是**真实字节**；不能就用连接活动度做代理。
"""

import csv
import io
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SESSION = "egnetprobe"


def run(args, timeout=90):
    p = subprocess.run(args, capture_output=True, text=True,
                       creationflags=NO_WIN, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def main():
    print("=" * 72)
    print("  ETW 能不能给出「每进程字节数」？")
    print("=" * 72)

    tmp = Path(tempfile.gettempdir())
    etl = tmp / "egnetprobe.etl"
    csvp = tmp / "egnetprobe.csv"
    for p in (etl, csvp):
        p.unlink(missing_ok=True)

    print("\n--- 1. 启动 ETW 会话（Microsoft-Windows-Kernel-Network）---")
    rc, o, e = run(["logman", "start", SESSION,
                    "-p", "Microsoft-Windows-Kernel-Network", "0xFFFF", "5",
                    "-ets", "-o", str(etl)])
    print(f"  rc={rc}")
    if rc != 0:
        print(f"  stdout: {o[:300]}")
        print(f"  stderr: {e[:300]}")
        print("  => ETW 这条路不通，改用连接活动度做代理")
        return

    print("  采集 8 秒…")
    time.sleep(8)
    rc2, o2, e2 = run(["logman", "stop", SESSION, "-ets"])
    print(f"  停止 rc={rc2}  {'ok' if rc2 == 0 else e2[:200]}")
    if not etl.exists():
        print("  !! 没生成 .etl")
        return
    print(f"  etl 大小 = {etl.stat().st_size} 字节")

    print("\n--- 2. tracerpt 转 CSV ---")
    rc3, o3, e3 = run(["tracerpt", str(etl), "-o", str(csvp),
                       "-of", "CSV", "-y"])
    print(f"  rc={rc3}")
    if not csvp.exists():
        print(f"  !! 没生成 CSV。stderr: {e3[:300]}")
        return
    print(f"  csv 大小 = {csvp.stat().st_size} 字节")

    print("\n--- 3. 解析 CSV，看有没有 PID + 字节数 ---")
    with open(csvp, encoding="utf-8-sig", errors="replace", newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"  共 {len(rows)} 行")
    if not rows:
        print("  !! 没有事件行")
        return
    cols = list(rows[0].keys())
    print(f"  列名（{len(cols)} 个）:")
    for c in cols:
        print(f"    {c!r} = {str(rows[0].get(c))[:60]!r}")

    # 找 PID 列和字节列
    pid_col = next((c for c in cols if c.strip().lower() in
                    ("pid", "processid", "process id", "process id (pid)")), None)
    size_cols = [c for c in cols if any(k in c.lower() for k in
                                        ("size", "bytes", "length", "count"))]
    print(f"\n  PID 列 = {pid_col!r}")
    print(f"  可能的字节列 = {size_cols}")

    if pid_col:
        agg = defaultdict(int)
        for r in rows:
            try:
                pid = int(r.get(pid_col) or 0)
            except Exception:
                continue
            for sc in size_cols:
                try:
                    agg[pid] += int(r.get(sc) or 0)
                except Exception:
                    pass
        top = sorted(agg.items(), key=lambda x: -x[1])[:8]
        print("\n  按 PID 汇总（前 8）:")
        for pid, n in top:
            print(f"    pid={pid:<8} {n:>12,}")
        if any(n > 0 for _, n in top):
            print("\n  => ✅ ETW 可用，能给出每进程字节数（真实流量）")
        else:
            print("\n  => ⚠ 有事件但字节列没解析出来，需要按具体列名再调")

    print("\n--- 4. 清理 ---")
    run(["logman", "delete", SESSION, "-ets"])
    for p in (etl, csvp):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    print("  done")
    print("=" * 72)


if __name__ == "__main__":
    main()
