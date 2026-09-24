"""测流量 API + 指纹面板。"""
import io
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")

from eg.config import Config  # noqa: E402
from eg.core import GuardCore  # noqa: E402

c = GuardCore(Config())
c._refresh_adapters()
print("采样中（6 秒）…")
for _ in range(6):
    c.traffic.sample(c._adapters)
    time.sleep(1.1)

s = c.traffic.snapshot(top=8)
print()
print("=" * 72)
print("  流量快照")
print("=" * 72)
print(f"  总速率: ↓{s['total']['in_h']}  ↑{s['total']['out_h']}")
print(f"  网卡: {[(a['alias'], a['in_h'], a['out_h']) for a in s['adapters']]}")
print(f"  连接数: {s['connection_count']}   裸奔: {s['leaked_connections']}")
print(f"  进程数: {s['process_count']}")
print()
for p in s["processes"][:8]:
    flag = " ⚠裸奔" if p["leaked"] else ""
    print(f"  {p['name'][:26]:28} 活跃={p['live']:<3} 新建={p['new']:<3} "
          f"目的={p['dest_count']:<3} 裸奔={p['leaked']}{flag}")
    for d in p["destinations"][:2]:
        g = f"{d['country']} {d['city']}".strip() or "[待解析]"
        print(f"      -> {d['ip']:18} {g}")

t = c.traffic.timeline(seconds=60, buckets=20)
print()
print(f"  时间线: {len(t['series'])} 条泳道 / {len(t['buckets'])} 个桶")
for se in t["series"][:5]:
    cells = "".join("█" if x > 8 else ("▓" if x > 3 else ("░" if x > 0 else "·"))
                    for x in se["cells"])
    print(f"    {se['name'][:22]:24} {cells}")

f = c.fingerprint_report()
print()
print("=" * 72)
print("  指纹面板")
print("=" * 72)
print(f"  {f['verdict']}   {f['counts']}")
for i in f["items"]:
    print(f"  [{i['status']:9}] {i['kind']:10} {str(i['value'])[:44]}")
    print(f"              {i['how'][:76]}")
print()
print(f"  note: {f['note']}")
