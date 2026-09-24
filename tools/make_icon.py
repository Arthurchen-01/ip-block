"""生成 EgressGuard 的应用图标（多尺寸 .ico）。

为什么要自己画：原来两个 exe 用的都是 PyInstaller 的默认图标 ——
任务栏、资源管理器、属性页里全是那个通用图标，一眼就能看出是脚本打的包。
"做成软件"这件事上，图标是最便宜也最直观的一步。

图形语义：
  盾牌   = 闸门 / 防护
  中间一条断开的横线 = 被掐断的出站连接
  右下角小锁 = 指纹不外发

只用 Pillow 画，不引入设计资源，保证仓库自洽（没有二进制美术文件）。
"""

import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("需要 Pillow：pip install Pillow", file=sys.stderr)
    raise

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "egressguard.ico"

# 配色：深蓝底（安全/网络）+ 青色断线（数据流）+ 琥珀色锁（指纹）
BG = (14, 30, 54, 255)
SHIELD = (28, 78, 138, 255)
SHIELD_EDGE = (86, 178, 255, 255)
CUT = (255, 92, 92, 255)
LOCK = (255, 196, 64, 255)
OK = (74, 222, 128, 255)


def draw_icon(size: int, state: str = "ok") -> Image.Image:
    """画一张 size x size 的图标。state: ok / warn / leak"""
    s = 4  # 超采样倍数，先画大再缩，边缘才干净
    W = size * s
    img = Image.new("RGBA", (W, W), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 圆角方底
    pad = int(W * 0.04)
    r = int(W * 0.22)
    d.rounded_rectangle([pad, pad, W - pad, W - pad], radius=r, fill=BG)

    # 盾牌
    cx = W // 2
    top = int(W * 0.16)
    bot = int(W * 0.84)
    half = int(W * 0.30)
    shield = [
        (cx, top),
        (cx + half, top + int(W * 0.10)),
        (cx + half, int(W * 0.52)),
        (cx, bot),
        (cx - half, int(W * 0.52)),
        (cx - half, top + int(W * 0.10)),
    ]
    d.polygon(shield, fill=SHIELD)
    d.line(shield + [shield[0]], fill=SHIELD_EDGE, width=max(1, int(W * 0.022)))

    # 中间那条"被掐断的连接"：左半段 + 缺口 + 右半段
    y = int(W * 0.42)
    th = max(1, int(W * 0.055))
    gap = int(W * 0.10)
    d.rounded_rectangle([cx - int(W * 0.20), y - th // 2,
                         cx - gap // 2, y + th // 2],
                        radius=th // 2, fill=OK if state == "ok" else CUT)
    d.rounded_rectangle([cx + gap // 2, y - th // 2,
                         cx + int(W * 0.20), y + th // 2],
                        radius=th // 2, fill=OK if state == "ok" else CUT)

    # 缺口处画一个叉（表示被切断）
    if state != "ok":
        x0, x1 = cx - gap // 2, cx + gap // 2
        yy0, yy1 = y - int(W * 0.06), y + int(W * 0.06)
        d.line([(x0, yy0), (x1, yy1)], fill=CUT, width=max(1, int(W * 0.03)))
        d.line([(x0, yy1), (x1, yy0)], fill=CUT, width=max(1, int(W * 0.03)))

    # 右下角小锁（指纹不外发）
    lx, ly = int(W * 0.60), int(W * 0.58)
    lw, lh = int(W * 0.26), int(W * 0.24)
    d.rounded_rectangle([lx, ly + lh // 3, lx + lw, ly + lh],
                        radius=int(W * 0.03), fill=LOCK)
    d.arc([lx + int(lw * 0.18), ly, lx + int(lw * 0.82), ly + int(lh * 0.75)],
          start=180, end=360, fill=LOCK, width=max(1, int(W * 0.035)))

    return img.resize((size, size), Image.LANCZOS)


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
    base = draw_icon(256, "ok")
    # ico 里塞多尺寸，Windows 按场景自己挑（任务栏 32、资源管理器 48、大图标 256）
    base.save(OUT, format="ICO",
              sizes=[(n, n) for n in sizes])
    print(f"[OK] 生成 {OUT}（{len(sizes)} 种尺寸：{sizes}）")

    # 顺便给托盘和文档各存一份 PNG
    for st in ("ok", "leak"):
        p = ROOT / "assets" / f"icon_{st}.png"
        draw_icon(256, st).save(p)
        print(f"[OK] 生成 {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
