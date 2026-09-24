"""把 Natural Earth 的陆地 GeoJSON 压成能内嵌进 ui.html 的紧凑格式。

为什么要压：原始 GeoJSON 135 KB，直接内嵌会让 ui.html 变得很笨重。
压法：
  1. 坐标取整到 0.1°（约 11 km）—— 一张 1000px 宽的世界地图上，
     0.1° 只有 0.28 像素，肉眼看不出差别
  2. 丢掉面积过小的多边形（小岛在图上就是一个点，没必要）
  3. 输出成扁平整数数组，坐标 ×10 存成整数，再用差分编码 —— JS 解压很快

产物：assets/world_land.js  —— 内容是 `window.EG_WORLD=[[...],[...]]`
"""

import io
import json
import sys
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "world_land.json"
OUT = ROOT / "assets" / "world_land.js"

MIN_POINTS = 5          # 少于这么多点的多边形丢掉
MIN_SPAN = 0.8          # 经纬跨度小于 0.8° 的丢掉（小岛）


def ring_area(pts) -> float:
    """鞋带公式算面积（度²），用来筛掉小岛。"""
    a = 0.0
    n = len(pts)
    for i in range(n):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 1) % n]
        a += x1 * y2 - x2 * y1
    return abs(a) / 2.0


def simplify_ring(pts, step: float = 0.1):
    """按网格去重 + 取整。相邻重复点合并。"""
    out = []
    for x, y in pts:
        qx = round(x / step) * step
        qy = round(y / step) * step
        if out and abs(out[-1][0] - qx) < 1e-9 and abs(out[-1][1] - qy) < 1e-9:
            continue
        out.append((qx, qy))
    # 首尾重合时去掉尾点（SVG 路径会自动闭合）
    if len(out) > 2 and abs(out[0][0] - out[-1][0]) < 1e-9 \
            and abs(out[0][1] - out[-1][1]) < 1e-9:
        out.pop()
    return out


def main() -> int:
    if not SRC.exists():
        print(f"缺少 {SRC} —— 先下载 Natural Earth 的 ne_110m_land.geojson")
        return 1
    gj = json.loads(SRC.read_text(encoding="utf-8"))
    polys = []
    dropped_small = dropped_pts = 0

    for feat in gj.get("features", []):
        geom = feat.get("geometry") or {}
        gtype = geom.get("type")
        coords = geom.get("coordinates") or []
        rings = []
        if gtype == "Polygon":
            rings = [coords[0]] if coords else []
        elif gtype == "MultiPolygon":
            rings = [p[0] for p in coords if p]
        for ring in rings:
            if len(ring) < MIN_POINTS:
                dropped_pts += 1
                continue
            xs = [p[0] for p in ring]
            ys = [p[1] for p in ring]
            if (max(xs) - min(xs)) < MIN_SPAN and (max(ys) - min(ys)) < MIN_SPAN:
                dropped_small += 1
                continue
            if ring_area(ring) < 0.05:
                dropped_small += 1
                continue
            simp = simplify_ring(ring)
            if len(simp) < 3:
                dropped_pts += 1
                continue
            # 差分编码：第一个点存绝对值（×10 取整），后面存增量
            flat = []
            px = py = 0
            for i, (x, y) in enumerate(simp):
                ix, iy = int(round(x * 10)), int(round(y * 10))
                if i == 0:
                    flat += [ix, iy]
                else:
                    flat += [ix - px, iy - py]
                px, py = ix, iy
            polys.append(flat)

    js = "window.EG_WORLD=" + json.dumps(polys, separators=(",", ":")) + ";"
    OUT.write_text(js, encoding="utf-8")
    print(f"[OK] 生成 {OUT}")
    print(f"     多边形 {len(polys)} 个（丢掉小岛 {dropped_small} 个、"
          f"点数不足 {dropped_pts} 个）")
    print(f"     大小 {OUT.stat().st_size / 1024:.1f} KB"
          f"（原始 {SRC.stat().st_size / 1024:.1f} KB）")
    total_pts = sum(len(p) // 2 for p in polys)
    print(f"     总点数 {total_pts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
