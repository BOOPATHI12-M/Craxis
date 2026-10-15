"""Generate the Craxis logo: icons/craxis-logo.svg and icons/icon{16,32,48,128}.png.

Mark: a shield (protection) holding a "C" whose opening is crossed by an "X"
(Craxis = C + X). Run: python tools/make_logo.py  (needs Pillow).
"""
import math
from pathlib import Path
from PIL import Image, ImageDraw

ICONS = Path(__file__).resolve().parent.parent / "icons"
VIOLET, MINT, INK = (124, 92, 255), (46, 230, 166), (11, 11, 26)

SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="128" height="128" role="img" aria-label="Craxis">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#7c5cff"/><stop offset="1" stop-color="#2ee6a6"/>
    </linearGradient>
  </defs>
  <path d="M32 3 57 12v20c0 15-11 25-25 29C18 57 7 47 7 32V12z" fill="url(#g)"/>
  <path d="M32 8 52 15v17c0 12-8 20-20 24C20 52 12 44 12 32V15z" fill="#0b0b1a"/>
  <path d="M40 23a12.5 12.5 0 1 0 0 18" fill="none" stroke="#f5f3ff" stroke-width="5.5" stroke-linecap="round"/>
  <path d="M41 26.5l10 11M51 26.5l-10 11" fill="none" stroke="#2ee6a6" stroke-width="5" stroke-linecap="round"/>
</svg>
"""


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def bezier(p0, p1, p2, p3, n=24):
    out = []
    for i in range(n + 1):
        t = i / n
        u = 1 - t
        out.append((u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
                    u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]))
    return out


def shield(inset):
    # outline in the 64-unit space, shrunk toward the centre by `inset`
    top, bot = 3 + inset, 61 - inset * 1.2
    l, r = 7 + inset, 57 - inset
    pts = [(32, top), (r, top + 9 - inset * 0.3), (r, 32)]
    pts += bezier((r, 32), (r, 47 - inset), (46 - inset * 0.5, bot - 4), (32, bot))
    pts += bezier((32, bot), (18 + inset * 0.5, bot - 4), (l, 47 - inset), (l, 32))
    pts += [(l, top + 9 - inset * 0.3)]
    return pts


def stroke_line(d, a, b, w, fill, k):
    d.line([(a[0] * k, a[1] * k), (b[0] * k, b[1] * k)], fill=fill, width=int(w * k))
    for p in (a, b):
        r = w * k / 2
        d.ellipse([p[0] * k - r, p[1] * k - r, p[0] * k + r, p[1] * k + r], fill=fill)


def render(size):
    k = 16
    big = size * k
    s = big / 64
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    # gradient shield
    grad = Image.new("RGBA", (big, big))
    gp = grad.load()
    for y in range(big):
        for x in range(big):
            gp[x, y] = lerp(VIOLET, MINT, (x + y) / (2 * big)) + (255,)
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).polygon([(x * s, y * s) for x, y in shield(0)], fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    d.polygon([(x * s, y * s) for x, y in shield(5)], fill=INK + (255,))
    # C: arc of radius 12.5 centred (32.5,32), open to the right
    cx, cy, rad, w = 32.5, 32, 12.5, 5.5
    pts = []
    for i in range(0, 181):
        ang = math.radians(42 + i * (276 / 180))
        pts.append((cx + rad * math.cos(ang), cy + rad * math.sin(ang)))
    for a, b in zip(pts, pts[1:]):
        stroke_line(d, a, b, w, (245, 243, 255, 255), s)
    # X
    stroke_line(d, (41, 26.5), (51, 37.5), 5, MINT + (255,), s)
    stroke_line(d, (51, 26.5), (41, 37.5), 5, MINT + (255,), s)
    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    ICONS.mkdir(exist_ok=True)
    (ICONS / "craxis-logo.svg").write_text(SVG, encoding="utf-8")
    for n in (16, 32, 48, 128):
        render(n).save(ICONS / f"icon{n}.png")
    print("written")
