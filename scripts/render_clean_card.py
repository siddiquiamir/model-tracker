"""Render clean minimal 1400x540 @StatsWire model alert cards for OpenAI, Google, Anthropic, xAI, DeepSeek, Z.ai, etc."""

from __future__ import annotations

import argparse
import math
import pathlib
import re
from typing import List, Tuple
from PIL import Image, ImageChops, ImageDraw, ImageFont

W, H = 1400, 540
BG = (0, 0, 0)
CARD_BG = (0, 0, 0)
CARD_BORDER = (38, 42, 48)
WHITE = (255, 255, 255)
TEXT_LIST = (212, 218, 226)
TEXT_MUTED = (156, 163, 175)
ACCENT_BLUE = (185, 213, 245)

PROVIDER_THEMES = {
    "openai": ("New OpenAI Models", (34, 197, 94)),
    "google": ("New Google Models", (56, 189, 248)),
    "anthropic": ("New Anthropic Models", (217, 119, 87)),
    "xai": ("New xAI Models", (244, 63, 94)),
    "deepseek": ("New DeepSeek Models", (6, 182, 212)),
    "zai": ("New Z.ai Models", (99, 102, 241)),
    "qwen": ("New Qwen Models", (168, 85, 247)),
    "mistral": ("New Mistral Models", (245, 158, 11)),
}

OPENAI_SVG_PATH = (
    "M22.282 9.821a5.985 5.985 0 0 0-.516-4.91 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.18"
    "a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.097 5.98 5.98 0 0 0 .51 4.911 6.051 6.051 0 0 0 6.515 2.9"
    "A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.99 5.99 0 0 0 3.997-2.9 6.056 6.056 0 0 0-.747-7.073z"
    "M13.26 22.43a4.476 4.476 0 0 1-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 0 0 .392-.681v-6.737l2.02 1.168"
    "a.071.071 0 0 1 .038.052v5.583a4.504 4.504 0 0 1-4.494 4.494z"
    "M3.6 18.304a4.47 4.47 0 0 1-.535-3.014l.142.085 4.783 2.759a.771.771 0 0 0 .78 0l5.843-3.369v2.332"
    "a.08.08 0 0 1-.033.062L9.74 19.95a4.5 4.5 0 0 1-6.14-1.646z"
    "M2.34 7.896a4.485 4.485 0 0 1 2.366-1.973V11.6a.766.766 0 0 0 .388.676l5.815 3.355-2.02 1.168"
    "a.076.076 0 0 1-.071 0l-4.83-2.786A4.504 4.504 0 0 1 2.34 7.872z"
    "m16.597 3.855l-5.833-3.387L15.119 7.2a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105"
    "v-5.678a.79.79 0 0 0-.407-.667z"
    "m2.01-3.023l-.141-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061"
    "l4.83-2.787a4.5 4.5 0 0 1 6.68 4.66z"
    "m-12.64 4.135l-2.02-1.164a.08.08 0 0 1-.038-.057V6.075a4.5 4.5 0 0 1 7.375-3.453l-.142.08L8.704 5.46"
    "a.795.795 0 0 0-.393.681z"
    "m1.097-2.365l2.602-1.5 2.607 1.5v2.999l-2.597 1.5-2.607-1.5z"
)


def load_font(names: List[str], size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except Exception:
            pass
    return ImageFont.load_default()


def _arc_points(x1, y1, rx, ry, phi, fa, fs, x2, y2, steps=28):
    if rx == 0 or ry == 0 or (x1 == x2 and y1 == y2):
        return [(x2, y2)]
    rx, ry = abs(rx), abs(ry)
    phi_r = math.radians(phi)
    dx2, dy2 = (x1 - x2) / 2.0, (y1 - y2) / 2.0
    x1p = math.cos(phi_r) * dx2 + math.sin(phi_r) * dy2
    y1p = -math.sin(phi_r) * dx2 + math.cos(phi_r) * dy2
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1:
        s = math.sqrt(lam)
        rx *= s
        ry *= s
    num = max(0.0, rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p)
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    rad = math.sqrt(num / den) if den else 0.0
    if bool(fa) == bool(fs):
        rad = -rad
    cxp = rad * rx * y1p / ry
    cyp = -rad * ry * x1p / rx
    cx = math.cos(phi_r) * cxp - math.sin(phi_r) * cyp + (x1 + x2) / 2.0
    cy = math.sin(phi_r) * cxp + math.cos(phi_r) * cyp + (y1 + y2) / 2.0

    def _ang(ux, uy, vx, vy):
        n = math.hypot(ux, uy) * math.hypot(vx, vy)
        c = max(-1.0, min(1.0, (ux * vx + uy * vy) / n)) if n else 1.0
        a = math.acos(c)
        return -a if (ux * vy - uy * vx) < 0 else a

    t1 = _ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dt = _ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not fs and dt > 0:
        dt -= 2 * math.pi
    elif fs and dt < 0:
        dt += 2 * math.pi
    return [
        (
            cx + rx * math.cos(phi_r) * math.cos(t1 + dt * k / steps) - ry * math.sin(phi_r) * math.sin(t1 + dt * k / steps),
            cy + rx * math.sin(phi_r) * math.cos(t1 + dt * k / steps) + ry * math.cos(phi_r) * math.sin(t1 + dt * k / steps),
        )
        for k in range(1, steps + 1)
    ]


def parse_svg_subpaths(d_str: str, scale: float):
    tokens = re.findall(r"[MmLlVvHhAaZz]|[-+]?(?:\d*\.\d+|\d+)", d_str)
    i = 0
    cmd = ""
    cx = cy = sx = sy = 0.0
    subpaths = []
    curr = []

    def next_f():
        nonlocal i
        v = float(tokens[i])
        i += 1
        return v

    while i < len(tokens):
        if tokens[i].isalpha():
            cmd = tokens[i]
            i += 1
        if cmd in ("M", "m"):
            if curr:
                subpaths.append(curr)
            x, y = next_f(), next_f()
            cx = (cx + x) if cmd == "m" else x
            cy = (cy + y) if cmd == "m" else y
            sx, sy = cx, cy
            curr = [(cx * scale, cy * scale)]
            cmd = "l" if cmd == "m" else "L"
        elif cmd in ("L", "l"):
            x, y = next_f(), next_f()
            cx = (cx + x) if cmd == "l" else x
            cy = (cy + y) if cmd == "l" else y
            curr.append((cx * scale, cy * scale))
        elif cmd in ("V", "v"):
            y = next_f()
            cy = (cy + y) if cmd == "v" else y
            curr.append((cx * scale, cy * scale))
        elif cmd in ("H", "h"):
            x = next_f()
            cx = (cx + x) if cmd == "h" else x
            curr.append((cx * scale, cy * scale))
        elif cmd in ("A", "a"):
            rx, ry, phi = next_f(), next_f(), next_f()
            fa, fs = int(next_f()), int(next_f())
            x, y = next_f(), next_f()
            nx = (cx + x) if cmd == "a" else x
            ny = (cy + y) if cmd == "a" else y
            for px, py in _arc_points(cx, cy, rx, ry, phi, fa, fs, nx, ny):
                curr.append((px * scale, py * scale))
            cx, cy = nx, ny
        elif cmd in ("Z", "z"):
            cx, cy = sx, sy
            if curr:
                subpaths.append(curr)
                curr = []
    if curr:
        subpaths.append(curr)
    return subpaths


def make_provider_emblem(provider: str, size: int, accent: Tuple[int, int, int]) -> Image.Image:
    ss = size * 4
    if provider == "openai":
        subpaths = parse_svg_subpaths(OPENAI_SVG_PATH, ss / 24.0)
        mask = Image.new("L", (ss, ss), 0)
        for sp in subpaths:
            if len(sp) >= 3:
                poly = Image.new("L", (ss, ss), 0)
                ImageDraw.Draw(poly).polygon(sp, fill=255)
                mask = ImageChops.difference(mask, poly)
        img = Image.new("RGBA", (ss, ss), (255, 255, 255, 0))
        img.putalpha(mask)
        return img.resize((size, size), Image.Resampling.LANCZOS)

    if provider == "google":
        # Clean 4-point Gemini sparkle star
        img = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        c = ss / 2.0
        r_out = ss * 0.46
        pts = []
        for deg in range(0, 360, 2):
            rad = math.radians(deg)
            cs, sn = math.cos(rad), math.sin(rad)
            # Superellipse / astroid curve |x|^0.55 + |y|^0.55 = 1
            denom = (abs(cs) ** 0.55 + abs(sn) ** 0.55) ** (1 / 0.55)
            r = r_out / denom if denom else 0
            pts.append((c + r * cs, c + r * sn))
        d.polygon(pts, fill=(*accent, 255))
        return img.resize((size, size), Image.Resampling.LANCZOS)

    # Fallback clean monogram badge for Anthropic, xAI, DeepSeek, Z.ai, etc.
    img = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([ss * 0.06, ss * 0.06, ss * 0.94, ss * 0.94], radius=int(ss * 0.22), outline=(*accent, 255), width=int(ss * 0.045))
    f = load_font([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"], int(ss * 0.44))
    monogram = {"anthropic": "A\\", "xai": "X", "deepseek": "DS", "zai": "Z", "qwen": "Q", "mistral": "M"}.get(provider, provider[:2].upper())
    bbox = f.getbbox(monogram)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((ss - tw) / 2 - bbox[0], (ss - th) / 2 - bbox[1]), monogram, font=f, fill=(255, 255, 255, 255))
    return img.resize((size, size), Image.Resampling.LANCZOS)


def make_sw_circle(size: int) -> Image.Image:
    logo_file = pathlib.Path(__file__).resolve().parent.parent / "docs" / "statswire-logo.png"
    ss = size * 4
    if logo_file.exists():
        raw = Image.open(logo_file).convert("RGBA").resize((ss, ss), Image.Resampling.LANCZOS)
        mask = Image.new("L", (ss, ss), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, ss - 1, ss - 1], radius=int(ss * 0.24), fill=255)
        out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
        out.paste(raw, (0, 0), mask)
        ImageDraw.Draw(out).rounded_rectangle(
            [2, 2, ss - 3, ss - 3],
            radius=int(ss * 0.24),
            outline=(72, 78, 88, 255),
            width=max(4, int(ss * 0.035)),
        )
        return out.resize((size, size), Image.Resampling.LANCZOS)
    img = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse([0, 0, ss - 1, ss - 1], fill=(255, 255, 255, 255))
    f = load_font([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"], int(ss * 0.42))
    txt = "SW"
    bbox = f.getbbox(txt)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((ss - tw) / 2 - bbox[0], (ss - th) / 2 - bbox[1]), txt, font=f, fill=(18, 20, 24, 255))
    return img.resize((size, size), Image.Resampling.LANCZOS)


def render_card(provider: str, models: List[str], out_path: str, custom_title: str = "") -> str:
    p_key = provider.lower().strip()
    default_title, accent = PROVIDER_THEMES.get(p_key, (f"New {provider.title()} Models", (34, 197, 94)))
    title = custom_title or default_title

    extra_rows = max(0, len(models) - 2)
    h = H + extra_rows * 64

    f_title = load_font([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"], 54)
    f_item = load_font([r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\arial.ttf"], 42)
    f_bullet = load_font([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"], 42)
    f_foot = load_font([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"], 30)
    f_wm = load_font([r"C:\Windows\Fonts\segoeuib.ttf", r"C:\Windows\Fonts\arialbd.ttf"], 26)

    base = Image.new("RGB", (W, h), BG)
    draw = ImageDraw.Draw(base)

    cx0, cy0, cx1, cy1 = 44, 36, W - 44, h - 36
    draw.rounded_rectangle([cx0, cy0, cx1, cy1], radius=30, fill=CARD_BG, outline=CARD_BORDER, width=2)

    bar_mask = Image.new("L", (W, h), 0)
    ImageDraw.Draw(bar_mask).rounded_rectangle([cx0, cy0, cx1, cy1], radius=30, fill=255)
    bar_layer = Image.new("RGB", (W, h), accent)
    left_clip = Image.new("L", (W, h), 0)
    ImageDraw.Draw(left_clip).rectangle([cx0, cy0, cx0 + 12, cy1], fill=255)
    final_bar_mask = Image.composite(bar_mask, Image.new("L", (W, h), 0), left_clip)
    base.paste(bar_layer, (0, 0), final_bar_mask)

    draw = ImageDraw.Draw(base)
    lx = cx0 + 64
    y = cy0 + 54

    draw.text((lx, y), title, font=f_title, fill=WHITE)

    emblem = make_provider_emblem(p_key, 224, accent)
    base.paste(emblem, (cx1 - 80 - 224, cy0 + 70), emblem)

    y += 104
    for m in models:
        draw.text((lx + 4, y), "•", font=f_bullet, fill=TEXT_LIST)
        draw.text((lx + 46, y), m, font=f_item, fill=TEXT_LIST)
        y += 68

    fy = cy1 - 88
    sw_icon = make_sw_circle(54)
    base.paste(sw_icon, (lx, fy), sw_icon)

    fx = lx + 68
    draw.text((fx, fy + 6), "Tracked by ", font=f_foot, fill=TEXT_MUTED)
    fx += int(draw.textlength("Tracked by ", font=f_foot))
    draw.text((fx, fy + 6), "@StatsWire", font=f_foot, fill=ACCENT_BLUE)
    fx += int(draw.textlength("@StatsWire", font=f_foot))
    draw.text((fx, fy + 6), " · x.com/StatsWire", font=f_foot, fill=TEXT_MUTED)

    wm_layer = Image.new("RGBA", (W, h), (0, 0, 0, 0))
    for wy in range(-40, h + 100, 165):
        for wx in range(-60, W + 140, 290):
            stamp = Image.new("RGBA", (240, 80), (0, 0, 0, 0))
            ImageDraw.Draw(stamp).text((14, 20), "@StatsWire", font=f_wm, fill=(255, 255, 255, 13))
            rot = stamp.rotate(22, resample=Image.Resampling.BICUBIC, expand=True)
            wm_layer.alpha_composite(rot, (wx, wy))

    final = Image.alpha_composite(base.convert("RGBA"), wm_layer).convert("RGB")
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    final.save(str(out), "PNG", optimize=True)
    return str(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Render a clean @StatsWire model card PNG")
    ap.add_argument("--provider", required=True, help="Provider slug (openai, google, anthropic, xai, deepseek, zai, qwen, mistral)")
    ap.add_argument("--models", nargs="+", required=True, help="One or more model IDs to list as bullets")
    ap.add_argument("--out", required=True, help="Output PNG path")
    ap.add_argument("--title", default="", help="Optional custom card title")
    args = ap.parse_args()
    saved = render_card(args.provider, args.models, args.out, args.title)
    print(f"Saved card: {saved}")
