"""测地理缓存：能不能真的查到、限流对不对。"""
import io
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\工具\EgressGuard")

from eg.geo import GeoCache, local_label  # noqa: E402
from eg.paths import data_dir  # noqa: E402

print("=== 内网/保留地址判定 ===")
for ip in ("198.18.0.17", "192.168.1.232", "127.0.0.1", "169.254.1.1",
           "8.8.8.8", "45.141.170.103"):
    print(f"  {ip:18} -> {local_label(ip) or '（公网，需要查）'}")

print("\n=== 公网查询（走缓存）===")
g = GeoCache(data_dir(), per_round=4, round_seconds=0.1)
for ip in ("45.141.170.103", "156.225.31.92", "91.108.56.142", "1.12.12.12"):
    r = g.lookup(ip)
    print(f"  {ip:18} 首次 -> pending={r.get('pending')}")

print("\n  解析中…")
for i in range(6):
    n = g.resolve_pending()
    print(f"    第{i+1}轮: 解析了 {n} 个")
    time.sleep(1.2)
    st = g.stats()
    if st["pending"] == 0:
        break

print("\n=== 结果 ===")
for ip in ("45.141.170.103", "156.225.31.92", "91.108.56.142", "1.12.12.12"):
    r = g.lookup(ip)
    if r.get("ok"):
        print(f"  {ip:18} {r.get('country')} {r.get('city')} "
              f"{r.get('isp')} ({r.get('lat')},{r.get('lon')})")
    else:
        print(f"  {ip:18} 未解析: {r.get('error') or r.get('pending')}")

print(f"\n  缓存统计: {g.stats()}")
print(f"  缓存文件: {g.path}  存在={g.path.exists()}")
if g.path.exists():
    print(f"  大小 {g.path.stat().st_size} 字节")
