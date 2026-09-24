"""细化 ETW 探测：哪些事件是网络收发、能不能按 PID 汇总出上下行字节。"""
import csv
import io
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SESSION = "egnetprobe2"


def run(args, timeout=120):
    p = subprocess.run(args, capture_output=True, text=True,
                       creationflags=NO_WIN, timeout=timeout,
                       encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or ""), (p.stderr or "")


def main():
    tmp = Path(tempfile.gettempdir())
    etl, csvp = tmp / "egp2.etl", tmp / "egp2.csv"
    for p in (etl, csvp):
        p.unlink(missing_ok=True)

    rc, o, e = run(["logman", "start", SESSION,
                    "-p", "Microsoft-Windows-Kernel-Network", "0xFFFF", "5",
                    "-ets", "-o", str(etl)])
    if rc != 0:
        print("启动失败:", e[:200])
        return
    print("采集 10 秒（期间制造点流量）…")
    # 制造流量：下点东西
    try:
        import urllib.request
        for _ in range(3):
            try:
                urllib.request.urlopen("http://ip-api.com/line/?fields=query",
                                       timeout=5).read()
            except Exception:
                pass
    except Exception:
        pass
    time.sleep(10)
    run(["logman", "stop", SESSION, "-ets"])
    rc3, o3, e3 = run(["tracerpt", str(etl), "-o", str(csvp), "-of", "CSV", "-y"])
    if not csvp.exists():
        print("tracerpt 失败:", e3[:200])
        return
    print(f"CSV {csvp.stat().st_size:,} 字节")

    with open(csvp, encoding="utf-8-sig", errors="replace", newline="") as f:
        rows = list(csv.DictReader(f))
    rows = [r for r in rows if r.get("  Event Name")]

    names = Counter((r.get("  Event Name") or "").strip() for r in rows)
    print(f"\n事件类型分布（共 {len(rows)} 行）:")
    for n, c in names.most_common(15):
        print(f"  {c:>6}  {n}")

    # 找网络任务事件
    net_rows = [r for r in rows
                if "TCPIP" in (r.get("  Event Name") or "")
                or "UDPIP" in (r.get("  Event Name") or "")]
    print(f"\n网络事件 {len(net_rows)} 条")

    if net_rows:
        sample = net_rows[0]
        print("\n取样一条网络事件的完整字段:")
        for k, v in sample.items():
            if k is None:
                continue
            print(f"  {k!r} = {str(v)[:70]!r}")
        # None 键那一列（csv 里列数不齐时会落到 None）
        extra = sample.get(None)
        if extra:
            print(f"  额外列（None 键）= {extra}")

        # 按 PID 汇总所有数值列
        agg_out, agg_in = defaultdict(int), defaultdict(int)
        for r in net_rows:
            try:
                pid = int(str(r.get("        PID") or "0").strip(), 16)
            except Exception:
                continue
            # 把所有能转成整数的列都加起来（先看哪个列是 size）
            for k, v in r.items():
                if k is None:
                    continue
                try:
                    n = int(str(v).strip())
                except Exception:
                    continue
                agg_out[pid] += n
        top = sorted(agg_out.items(), key=lambda x: -x[1])[:10]
        print("\n按 PID 汇总（粗略，含所有数值列）:")
        for pid, n in top:
            print(f"  pid={pid:<8} {n:>14,}")

    run(["logman", "delete", SESSION, "-ets"])
    for p in (etl, csvp):
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass


if __name__ == "__main__":
    main()
