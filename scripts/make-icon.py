#!/usr/bin/env python3
"""Generate the LineGuard icon (SVG + PNG + ICO + raw RGBA) from one geometry definition.

Concept: a shield (the guard) cut by a single horizontal line (the one narrow path) that
ends in a small node. Colours are the GUI palette (crates/ui/src/app.rs).
Run: python3 scripts/make-icon.py   (needs Pillow)
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets"
S = 1024  # design grid

BG_TOP, BG_BOTTOM = (34, 43, 57), (16, 20, 28)
ACCENT_TOP, ACCENT_BOTTOM = (176, 207, 235), (110, 150, 190)
SLOT = (16, 20, 28)
AMBER = (226, 185, 123)

TILE_INSET, TILE_RADIUS = 48, 208


def cubic(p0, p1, p2, p3, n=48):
    pts = []
    for i in range(n + 1):
        t = i / n
        a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t * t, t ** 3
        pts.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0],
                    a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return pts


# Shield: flat top with rounded shoulders, sides curving to a point. Symmetric about x=512.
SHIELD = [
    ("M", (512, 196)),
    ("C", (600, 246), (690, 262), (772, 262)),
    ("C", (772, 520), (720, 716), (512, 840)),
    ("C", (304, 716), (252, 520), (252, 262)),
    ("C", (334, 262), (424, 246), (512, 196)),
]
SLOT_Y, SLOT_H = 512, 76          # the horizontal line through the shield
NODE = (812, 512, 58)             # the single node the path reaches (cx, cy, r)
LINE_X0 = 150                     # where the path enters from the left


def shield_points():
    pts, cur = [], None
    for seg in SHIELD:
        if seg[0] == "M":
            cur = seg[1]
            pts.append(cur)
        else:
            pts.extend(cubic(cur, seg[1], seg[2], seg[3])[1:])
            cur = seg[3]
    return pts


def shield_path_d():
    d = []
    for seg in SHIELD:
        coords = " ".join(f"{x},{y}" for x, y in seg[1:])
        d.append(f"{seg[0]}{coords}")
    return " ".join(d) + " Z"


def svg():
    cx, cy, r = NODE
    y0, y1 = SLOT_Y - SLOT_H // 2, SLOT_Y + SLOT_H // 2
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {S} {S}" width="{S}" height="{S}">
  <title>LineGuard</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="rgb{BG_TOP}"/><stop offset="1" stop-color="rgb{BG_BOTTOM}"/>
    </linearGradient>
    <linearGradient id="shield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="rgb{ACCENT_TOP}"/><stop offset="1" stop-color="rgb{ACCENT_BOTTOM}"/>
    </linearGradient>
    <clipPath id="shieldclip"><path d="{shield_path_d()}"/></clipPath>
    <clipPath id="tile"><rect x="{TILE_INSET}" y="{TILE_INSET}" width="{S - 2 * TILE_INSET}" height="{S - 2 * TILE_INSET}" rx="{TILE_RADIUS}"/></clipPath>
  </defs>
  <rect x="{TILE_INSET}" y="{TILE_INSET}" width="{S - 2 * TILE_INSET}" height="{S - 2 * TILE_INSET}" rx="{TILE_RADIUS}" fill="url(#bg)"/>
  <g clip-path="url(#tile)">
    <path d="{shield_path_d()}" fill="url(#shield)"/>
    <rect x="0" y="{y0}" width="{S}" height="{y1 - y0}" fill="rgb{SLOT}" clip-path="url(#shieldclip)"/>
    <rect x="{LINE_X0}" y="{SLOT_Y - 10}" width="{cx - LINE_X0}" height="20" rx="10" fill="rgb{AMBER}"/>
    <circle cx="{cx}" cy="{cy}" r="{r}" fill="rgb{AMBER}"/>
  </g>
</svg>
"""


def gradient(size, top, bottom):
    img = Image.new("RGBA", (1, size[1]))
    for y in range(size[1]):
        t = y / max(1, size[1] - 1)
        img.putpixel((0, y), tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3)) + (255,))
    return img.resize(size)


def render(scale=4, line=10, slot=SLOT_H, node=NODE[2]):
    n = S * scale
    k = lambda v: v * scale
    out = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    tile = Image.new("L", (n, n), 0)
    ImageDraw.Draw(tile).rounded_rectangle(
        [k(TILE_INSET), k(TILE_INSET), n - k(TILE_INSET), n - k(TILE_INSET)], radius=k(TILE_RADIUS), fill=255)
    out.paste(gradient((n, n), BG_TOP, BG_BOTTOM), (0, 0), tile)
    mask = Image.new("L", (n, n), 0)
    ImageDraw.Draw(mask).polygon([(k(x), k(y)) for x, y in shield_points()], fill=255)
    out.paste(gradient((n, n), ACCENT_TOP, ACCENT_BOTTOM), (0, 0), mask)
    # The dark slot is cut only inside the shield; the amber path runs across the whole tile.
    band = Image.new("L", (n, n), 0)
    ImageDraw.Draw(band).rectangle([0, k(SLOT_Y - slot // 2), n, k(SLOT_Y + slot // 2)], fill=255)
    out.paste(Image.new("RGBA", (n, n), SLOT + (255,)), (0, 0), Image.composite(band, Image.new("L", (n, n), 0), mask))
    d = ImageDraw.Draw(out)
    cx, cy, _ = NODE
    r = node
    d.rounded_rectangle([k(LINE_X0), k(SLOT_Y - line), k(cx), k(SLOT_Y + line)], radius=k(line), fill=AMBER + (255,))
    d.ellipse([k(cx - r), k(cy - r), k(cx + r), k(cy + r)], fill=AMBER + (255,))
    # keep everything inside the rounded tile
    alpha = Image.composite(out.getchannel("A"), Image.new("L", (n, n), 0), tile)
    out.putalpha(alpha)
    return out.resize((S, S), Image.LANCZOS)


BOLD = None


def small(master, size):
    # Small sizes use a bolder variant so the path and node survive downsampling.
    global BOLD
    if size <= 32:
        if BOLD is None:
            BOLD = render(line=34, slot=150, node=96)
        img = BOLD.resize((size, size), Image.LANCZOS)
        return img.filter(ImageFilter.UnsharpMask(radius=1, percent=60, threshold=0))
    return master.resize((size, size), Image.LANCZOS)


def main():
    OUT.mkdir(exist_ok=True)
    (OUT / "lineguard.svg").write_text(svg(), encoding="utf-8")
    master = render()
    master.resize((512, 512), Image.LANCZOS).save(OUT / "lineguard-512.png", optimize=True)
    master.resize((256, 256), Image.LANCZOS).save(OUT / "lineguard-256.png", optimize=True)
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    frames = [small(master, s) for s in sizes]
    frames[-1].save(OUT / "lineguard.ico", format="ICO", sizes=[(s, s) for s in sizes],
                    append_images=frames[:-1])
    # Raw 64x64 RGBA for the egui window icon (no image decoder needed at runtime).
    (OUT / "lineguard-64.rgba").write_bytes(small(master, 64).tobytes())
    preview = Image.new("RGBA", (sum(sizes) + 10 * len(sizes) + 10, 276), (240, 242, 245, 255))
    x = 10
    for f, s in zip(frames, sizes):
        preview.paste(f, (x, 266 - s), f)
        x += s + 10
    preview.save(OUT / "icon-preview.png")
    print("wrote", ", ".join(p.name for p in sorted(OUT.iterdir())))


if __name__ == "__main__":
    main()
