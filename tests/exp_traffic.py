"""测流量模块：网卡字节计数 + 采样。"""
import io
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")

import ctypes  # noqa: E402

from eg import traffic as T  # noqa: E402

print("=" * 72)
print("  1. MIB_IF_ROW2 结构体布局自检")
print("=" * 72)
n = ctypes.sizeof(T._MIB_IF_ROW2)
print(f"  ctypes 算出的大小 = {n}")
print(f"  期望（MSDN x64）  = {T._EXPECTED_ROW2}")
print(f"  判定可用 = {T._row2_usable()}")

print()
print("=" * 72)
print("  2. GetIfEntry2 读网卡字节计数")
print("=" * 72)
c1 = T.if_counters()
if not c1:
    print("  !! 读不到（结构体布局不对，或 API 不可用）")
else:
    for idx, v in sorted(c1.items()):
        print(f"  if{idx:<4} {v['alias'][:24]:26} "
              f"in={v['in']:>16,}  out={v['out']:>16,}  oper={v['oper']}")

print()
print("=" * 72)
print("  3. 采样两次算速率")
print("=" * 72)
time.sleep(3)
c2 = T.if_counters()
dt = 3.0
for idx in sorted(set(c1) & set(c2)):
    din = c2[idx]["in"] - c1[idx]["in"]
    dout = c2[idx]["out"] - c1[idx]["out"]
    print(f"  if{idx:<4} {c2[idx]['alias'][:24]:26} "
          f"↓{T._fmt_rate(din / dt):>12}  ↑{T._fmt_rate(dout / dt):>12}")

print()
print("=" * 72)
print("  4. TrafficMonitor 采样")
print("=" * 72)
from eg.config import Config  # noqa: E402
from eg.geo import GeoCache  # noqa: E402
from eg.logbus import LogBus  # noqa: E402
from eg.policy import PolicyEngine, ProcessTable  # noqa: E402
from eg import netinfo as NI  # noqa: E402
from eg.paths import data_dir  # noqa: E402

cfg = Config()
bus = LogBus()
procs = ProcessTable(cfg)
eng = PolicyEngine(cfg, procs, bus)
geo = GeoCache(data_dir())
mon = T.TrafficMonitor(cfg, eng, geo)
net = NI.NetInfo(cfg.snapshot())
ads = net.adapters(force=True)

for i in range(3):
    mon.sample(ads)
    time.sleep(1.2)

snap = mon.snapshot(top=12)
print(f"  总速率: ↓{snap['total']['in_h']}  ↑{snap['total']['out_h']}")
print(f"  连接总数: {snap['connection_count']}   裸奔连接: {snap['leaked_connections']}")
print(f"  进程数: {snap['process_count']}")
print(f"  网卡速率: {[(a['alias'], a['in_h'], a['out_h']) for a in snap['adapters']]}")
print()
print("  活动度前 12 的进程:")
for p in snap["processes"][:12]:
    flag = " ⚠裸奔" if p["leaked"] else ""
    print(f"    {p['name'][:26]:28} pid={p['pid']:<7} "
          f"活跃={p['live']:<3} 新建={p['new']:<3} 总={p['conns']:<4} "
          f"目的={p['dest_count']:<3} 活动度={p['activity']}{flag}")
    for d in p["destinations"][:3]:
        print(f"        -> {d['ip']:18} {d['country']} {d['city']} "
              f"{'[待解析]' if d['pending'] else ''}")

tl = mon.timeline(seconds=60, buckets=30)
print()
print(f"  时间线: {len(tl['series'])} 条泳道, {len(tl['buckets'])} 个桶")
for s in tl["series"][:6]:
    cells = "".join("█" if c > 8 else ("▓" if c > 3 else ("░" if c > 0 else "·"))
                    for c in s["cells"])
    print(f"    {s['name'][:24]:26} {cells}")
print(f"  速率曲线（非零桶数）: {sum(1 for r in tl['rate'] if r > 0)}")

print()
print("  地理缓存:", geo.stats())
