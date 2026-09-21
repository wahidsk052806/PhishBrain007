from PIL import Image, ImageDraw
import os

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "icons")
os.makedirs(OUT_DIR, exist_ok=True)

SIZES = [16, 32, 48, 128]

SHIELD = (30, 41, 59, 255)
ACCENT = (56, 189, 248, 255)
CHECK = (239, 68, 68, 255)


def draw_shield(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = max(1, size // 16)
    w = size - pad * 2
    h = size - pad * 2
    x0, y0 = pad, pad

    points = [
        (x0 + w * 0.5, y0),
        (x0 + w, y0 + h * 0.22),
        (x0 + w, y0 + h * 0.55),
        (x0 + w * 0.5, y0 + h),
        (x0, y0 + h * 0.55),
        (x0, y0 + h * 0.22),
    ]
    draw.polygon(points, fill=SHIELD, outline=ACCENT)

    cx, cy = x0 + w * 0.5, y0 + h * 0.48
    r = max(1, size // 10)
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=ACCENT)

    br = max(1, size // 14)
    bx, by = x0 + w * 0.5, y0 + h * 0.75
    draw.ellipse((bx - br, by - br, bx + br, by + br), fill=CHECK)

    return img


for s in SIZES:
    icon = draw_shield(s)
    icon.save(os.path.join(OUT_DIR, f"icon{s}.png"))

print("Icons generated:", os.listdir(OUT_DIR))
