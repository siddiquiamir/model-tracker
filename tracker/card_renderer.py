"""Cross-platform minimalist 16:9 @StatsWire PNG card renderer for ModelPulse Discord & X alerts."""

from __future__ import annotations

from datetime import datetime, timezone
import io
import math
import pathlib
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:  # pragma: no cover - graceful fallback when Pillow is absent
    Image = None  # type: ignore[assignment]
    ImageDraw = None  # type: ignore[assignment]
    ImageFont = None  # type: ignore[assignment]

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
STATSWIRE_LOGO_PATH = REPO_ROOT / "docs" / "statswire-logo.png"

_SANS_BOLD_FONTS = [
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\arialbd.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-B.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]
_SANS_REG_FONTS = [
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
]
_MONO_BOLD_FONTS = [
    r"C:\Windows\Fonts\consolab.ttf",
    r"C:\Windows\Fonts\consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    "/usr/share/fonts/truetype/ubuntu/UbuntuMono-B.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]

PROVIDER_PALETTE: Dict[str, Tuple[Tuple[int, int, int], str]] = {
    "google": ((138, 180, 248), "G"),
    "openai": ((52, 211, 153), "O"),
    "anthropic": ((251, 146, 60), "A\\"),
    "xai": ((226, 232, 240), "X"),
    "meta": ((96, 165, 250), "M"),
    "deepseek": ((34, 211, 238), "DS"),
    "mistral": ((251, 191, 36), "M"),
    "qwen": ((192, 132, 252), "Q"),
    "kimi": ((129, 140, 248), "K"),
    "nvidia": ((163, 230, 53), "NV"),
    "microsoft": ((56, 189, 248), "MS"),
    "azure": ((56, 189, 248), "AZ"),
    "amazon": ((251, 191, 36), "AWS"),
    "zai": ((45, 212, 191), "Z"),
    "minimax": ((244, 114, 182), "MM"),
    "cohere": ((74, 222, 128), "CO"),
    "perplexity": ((56, 189, 248), "PX"),
    "cursor": ((148, 163, 184), "CR"),
    "opencode": ((192, 132, 252), "OC"),
    "mcp": ((45, 212, 191), "MCP"),
    "opensource": ((74, 222, 128), "OS"),
    "multi": ((129, 140, 248), "AI"),
}

STAGE_PILL_STYLE: Dict[str, Tuple[str, Tuple[int, int, int], Tuple[int, int, int], Tuple[int, int, int]]] = {
    "leak": ("LEAK", (245, 200, 96), (34, 27, 13), (112, 88, 36)),
    "release": ("NEW MODEL", (74, 222, 128), (13, 34, 22), (40, 108, 66)),
    "open_weights": ("OPEN WEIGHTS", (45, 212, 191), (12, 32, 32), (38, 104, 100)),
    "registry": ("REGISTRY", (125, 211, 252), (14, 28, 44), (48, 96, 144)),
    "unverified": ("EARLY SIGNAL", (186, 196, 212), (20, 24, 34), (66, 76, 94)),
}


def _load_font(candidates: List[str], size: int):
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _parse_hex_rgb(hex_str: str, fallback: Tuple[int, int, int] = (138, 180, 248)) -> Tuple[int, int, int]:
    clean = (hex_str or "").lstrip("#").strip()
    if len(clean) == 6:
        try:
            return (int(clean[0:2], 16), int(clean[2:4], 16), int(clean[4:6], 16))
        except ValueError:
            pass
    return fallback


def _fmt_utc_compact(iso: str) -> str:
    try:
        dt = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%d %b %Y · %H:%M UTC")
    except Exception:
        return datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")


def _truncate(text: str, font, max_w: int, draw: ImageDraw.ImageDraw) -> str:
    s = (text or "").strip()
    if draw.textlength(s, font=font) <= max_w:
        return s
    while len(s) > 4 and draw.textlength(s + "…", font=font) > max_w:
        s = s[:-1]
    return s.rstrip(" .,-_/") + "…"


def _draw_vcenter_text(
    draw: ImageDraw.ImageDraw,
    x: int,
    cy: int,
    text: str,
    font,
    fill: Tuple[int, int, int],
) -> int:
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    ty = cy - th // 2 - bbox[1]
    draw.text((x - bbox[0], ty), text, font=font, fill=fill)
    return int(tw)


def _draw_pill(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    text: str,
    font,
    text_fill: Tuple[int, int, int],
    bg_fill: Tuple[int, int, int],
    border_fill: Tuple[int, int, int],
    pad_x: int = 18,
    radius: int = 12,
    fixed_h: int = 44,
    max_w: Optional[int] = None,
) -> Tuple[int, int]:
    if max_w is not None:
        text = _truncate(text, font, max(40, max_w - pad_x * 2), draw)
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    w = int(tw + pad_x * 2)
    draw.rounded_rectangle([x, y, x + w, y + fixed_h], radius=radius, fill=bg_fill, outline=border_fill, width=2)
    _draw_vcenter_text(draw, x + pad_x, y + fixed_h // 2, text, font, text_fill)
    return w, fixed_h


def _make_gemini_spark(size: int, badge_bg: bool = True) -> Image.Image:
    ss = size * 4
    out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    if badge_bg:
        ImageDraw.Draw(out).rounded_rectangle(
            [0, 0, ss - 1, ss - 1],
            radius=int(ss * 0.24),
            fill=(26, 30, 38, 255),
            outline=(56, 64, 78, 255),
            width=3,
        )
    mask = Image.new("L", (ss, ss), 0)
    c = ss / 2.0
    r_out = ss * (0.33 if badge_bg else 0.46)
    pts = []
    for deg in range(0, 360, 3):
        rad = math.radians(deg)
        cs, sn = math.cos(rad), math.sin(rad)
        denom = (abs(cs) ** 0.55 + abs(sn) ** 0.55) ** (1.0 / 0.55)
        r = r_out / denom if denom else 0.0
        pts.append((c + r * cs, c + r * sn))
    ImageDraw.Draw(mask).polygon(pts, fill=255)

    gs = 80
    grad = Image.new("RGBA", (gs, gs), (0, 0, 0, 0))
    px = grad.load()
    anchors = [
        (0.50, 0.14, (234, 67, 53), 1.15),
        (0.14, 0.50, (251, 188, 5), 1.05),
        (0.50, 0.86, (52, 168, 83), 1.10),
        (0.84, 0.50, (66, 133, 244), 1.55),
        (0.58, 0.48, (66, 133, 244), 1.25),
    ]
    for py in range(gs):
        ny = py / (gs - 1)
        for pxx in range(gs):
            nx = pxx / (gs - 1)
            w_sum = rr = gg = bb = 0.0
            for ax, ay, col, boost in anchors:
                dist2 = (nx - ax) ** 2 + (ny - ay) ** 2 + 0.032
                w = boost / (dist2 ** 1.65)
                w_sum += w
                rr += col[0] * w
                gg += col[1] * w
                bb += col[2] * w
            px[pxx, py] = (int(rr / w_sum), int(gg / w_sum), int(bb / w_sum), 255)

    star = grad.resize((ss, ss), Image.Resampling.BICUBIC)
    star.putalpha(mask)
    out.alpha_composite(star)
    return out.resize((size, size), Image.Resampling.LANCZOS)


def _make_google_g_badge(size: int) -> Image.Image:
    ss = size * 4
    out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(out)
    d.rounded_rectangle(
        [0, 0, ss - 1, ss - 1],
        radius=int(ss * 0.24),
        fill=(24, 28, 36, 255),
        outline=(54, 62, 76, 255),
        width=4,
    )
    cx = cy = ss // 2
    r_out = int(ss * 0.34)
    r_in = int(ss * 0.19)
    ring_w = r_out - r_in
    bbox = [cx - r_out, cy - r_out, cx + r_out, cy + r_out]

    d.arc(bbox, start=210, end=325, fill=(234, 67, 53, 255), width=ring_w)
    d.arc(bbox, start=140, end=215, fill=(251, 188, 5, 255), width=ring_w)
    d.arc(bbox, start=42, end=144, fill=(52, 168, 83, 255), width=ring_w)
    d.arc(bbox, start=-6, end=46, fill=(66, 133, 244, 255), width=ring_w)

    bar_h = int(ring_w * 0.88)
    d.rectangle([cx - int(ss * 0.01), cy - bar_h // 2, cx + r_out, cy + bar_h // 2], fill=(66, 133, 244, 255))
    d.ellipse([cx - r_in, cy - r_in, cx + r_in, cy + r_in], fill=(24, 28, 36, 255))
    d.rectangle([cx + int(ss * 0.01), cy - bar_h // 2, cx + r_out - 2, cy + bar_h // 2], fill=(66, 133, 244, 255))
    return out.resize((size, size), Image.Resampling.LANCZOS)


def _make_provider_badge(provider_slug: str, accent_rgb: Tuple[int, int, int], size: int = 136) -> Image.Image:
    slug = (provider_slug or "").lower().strip()
    if slug == "google":
        return _make_google_g_badge(size)

    ss = size * 4
    out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(out)
    r, g, b = accent_rgb
    bg_tint = (max(16, r // 11), max(18, g // 11), max(24, b // 11), 255)
    bd_tint = (min(255, r // 2 + 28), min(255, g // 2 + 28), min(255, b // 2 + 28), 255)
    d.rounded_rectangle(
        [0, 0, ss - 1, ss - 1],
        radius=int(ss * 0.24),
        fill=bg_tint,
        outline=bd_tint,
        width=5,
    )

    if slug == "openai":
        cx = cy = ss // 2
        rad = int(ss * 0.14)
        orbit = int(ss * 0.14)
        stroke = max(12, ss // 24)
        for i in range(6):
            ang = math.radians(i * 60 - 30)
            px = int(cx + math.cos(ang) * orbit)
            py = int(cy + math.sin(ang) * orbit)
            d.ellipse([px - rad, py - rad, px + rad, py + rad], outline=(235, 255, 245, 255), width=stroke)
        return out.resize((size, size), Image.Resampling.LANCZOS)

    if slug == "xai":
        pad = int(ss * 0.26)
        w1 = max(18, ss // 14)
        d.line([(pad, pad), (ss - pad, ss - pad)], fill=(242, 246, 252, 255), width=w1)
        d.line([(ss - pad, pad), (pad, ss - pad)], fill=(148, 163, 184, 255), width=max(10, w1 // 2))
        return out.resize((size, size), Image.Resampling.LANCZOS)

    _, mono = PROVIDER_PALETTE.get(slug, (accent_rgb, (slug[:2].upper() or "AI")))
    ring_pad = int(ss * 0.14)
    d.ellipse([ring_pad, ring_pad, ss - ring_pad, ss - ring_pad], outline=(r, g, b, 90), width=6)
    font_sz = int(ss * (0.42 if len(mono) == 1 else (0.34 if len(mono) == 2 else 0.26)))
    f_mono = _load_font(_SANS_BOLD_FONTS, font_sz)
    bbox = d.textbbox((0, 0), mono, font=f_mono)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text(((ss - tw) // 2 - bbox[0], (ss - th) // 2 - bbox[1]), mono, font=f_mono, fill=(r, g, b, 255))
    return out.resize((size, size), Image.Resampling.LANCZOS)


def _make_sw_square(size: int) -> Image.Image:
    ss = size * 4
    if STATSWIRE_LOGO_PATH.exists():
        raw = Image.open(STATSWIRE_LOGO_PATH).convert("RGBA").resize((ss, ss), Image.Resampling.LANCZOS)
        mask = Image.new("L", (ss, ss), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, ss - 1, ss - 1], radius=int(ss * 0.22), fill=255)
        out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
        out.paste(raw, (0, 0), mask)
        ImageDraw.Draw(out).rounded_rectangle(
            [1, 1, ss - 2, ss - 2],
            radius=int(ss * 0.22),
            outline=(60, 68, 82, 255),
            width=4,
        )
        return out.resize((size, size), Image.Resampling.LANCZOS)
    out = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    d = ImageDraw.Draw(out)
    d.rounded_rectangle([0, 0, ss - 1, ss - 1], radius=int(ss * 0.22), fill=(18, 22, 30, 255), outline=(66, 76, 92, 255), width=4)
    f = _load_font(_SANS_BOLD_FONTS, int(ss * 0.42))
    bbox = d.textbbox((0, 0), "SW", font=f)
    d.text(((ss - (bbox[2] - bbox[0])) // 2 - bbox[0], (ss - (bbox[3] - bbox[1])) // 2 - bbox[1]), "SW", font=f, fill=(138, 180, 248, 255))
    return out.resize((size, size), Image.Resampling.LANCZOS)


def render_alert_card_png(item: Dict[str, Any]) -> Optional[bytes]:
    """Render a clean, minimalist 16:9 (1200x675) @StatsWire PNG card for Discord & X."""
    if Image is None or ImageDraw is None or ImageFont is None:
        return None

    W, H = 1200, 675
    lx, rx = 68, W - 68
    content_w = rx - lx

    slug = str(item.get("provider_slug") or "opensource").lower().strip()
    prov_name = str(item.get("provider_name") or slug.upper() or "AI MODEL").strip()
    accent_rgb = PROVIDER_PALETTE.get(slug, (_parse_hex_rgb(str(item.get("accent_color") or "")), ""))[0]

    kind = str(item.get("kind") or "").lower().strip()
    if not kind:
        if item.get("intelligence"):
            kind = "registry" if item.get("event_label") == "Registry update" else "unverified"
        else:
            kind = "leak"
    stage_key = "open_weights" if (kind == "release" and item.get("open_weights")) else (kind if kind in STAGE_PILL_STYLE else "leak")
    stage_label, st_fg, st_bg, st_bd = STAGE_PILL_STYLE[stage_key]

    title = str(item.get("title") or item.get("family") or "New Model Detected").strip()
    first_source = str(item.get("first_source") or item.get("build_label") or item.get("scanner") or "Live Tracker").strip()
    src_count = int(item.get("source_count") or len(item.get("sources") or []) or 1)
    pricing = str(item.get("pricing") or "").strip()
    ts_str = _fmt_utc_compact(str(item.get("updated_at") or item.get("detected_at") or item.get("observed_at") or ""))

    if src_count > 1:
        subtitle = f"Spotted in {first_source} · {src_count} confirmed sources"
    else:
        subtitle = f"Spotted in {first_source}"
    if pricing:
        subtitle += f" · {pricing.split(',')[0].strip()}"

    seen_m = set()
    model_ids: List[str] = []
    for m in (item.get("models") or []):
        mid = str(m.get("id") or m.get("name") or "").strip()
        if mid and mid.lower() not in seen_m:
            seen_m.add(mid.lower())
            model_ids.append(mid)
    if not model_ids:
        model_ids = [title.lower().replace(" ", "-")]

    f_eyebrow = _load_font(_SANS_BOLD_FONTS, 24)
    f_badge = _load_font(_SANS_BOLD_FONTS, 19)
    f_sub = _load_font(_SANS_REG_FONTS, 27)
    f_pill = _load_font(_MONO_BOLD_FONTS, 26)
    f_foot_b = _load_font(_SANS_BOLD_FONTS, 24)
    f_date = _load_font(_SANS_REG_FONTS, 21)
    f_wm = _load_font(_SANS_BOLD_FONTS, 24)

    base = Image.new("RGB", (W, H), (0, 0, 0))
    draw = ImageDraw.Draw(base)

    cx0, cy0, cx1, cy1 = 8, 8, W - 9, H - 9
    draw.rounded_rectangle([cx0, cy0, cx1, cy1], radius=32, fill=(7, 9, 14), outline=(44, 50, 62), width=2)

    # Subtle top accent bar
    card_mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(card_mask).rounded_rectangle([cx0 + 1, cy0 + 1, cx1 - 1, cy1 - 1], radius=31, fill=255)
    top_bar = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(top_bar).rectangle([cx0, cy0, cx1, cy0 + 5], fill=(*accent_rgb, 210))
    top_bar.putalpha(Image.composite(top_bar.split()[3], Image.new("L", (W, H), 0), card_mask))
    base = Image.alpha_composite(base.convert("RGBA"), top_bar).convert("RGB")
    draw = ImageDraw.Draw(base)

    # Top-right provider badge
    badge = _make_provider_badge(slug, accent_rgb, size=144)
    base.paste(badge, (rx - 144, 54), badge)

    max_left_w = content_w - 178

    # Eyebrow row
    y = 62
    ex = lx
    if slug == "google":
        spark = _make_gemini_spark(38, badge_bg=True)
        base.paste(spark, (lx, y), spark)
        ex = lx + 52
    else:
        draw.ellipse([lx, y + 11, lx + 16, y + 27], fill=accent_rgb)
        ex = lx + 30

    ex += _draw_vcenter_text(draw, ex, y + 19, _truncate(prov_name.upper(), f_eyebrow, max_left_w - 190, draw), f_eyebrow, accent_rgb) + 16
    _draw_pill(draw, ex, y + 2, stage_label, f_badge, text_fill=st_fg, bg_fill=st_bg, border_fill=st_bd, pad_x=16, radius=10, fixed_h=34)

    # Big crisp title (auto-scaled)
    y += 62
    f_title = _load_font(_SANS_BOLD_FONTS, 64)
    for sz in (64, 54, 46, 38):
        cand = _load_font(_SANS_BOLD_FONTS, sz)
        if draw.textlength(title, font=cand) <= max_left_w:
            f_title = cand
            break
    else:
        f_title = _load_font(_SANS_BOLD_FONTS, 38)
        title = _truncate(title, f_title, max_left_w, draw)
    draw.text((lx, y), title, font=f_title, fill=(255, 255, 255))

    # One crisp subtitle line
    y += 84
    draw.text((lx, y), _truncate(subtitle, f_sub, max_left_w, draw), font=f_sub, fill=(178, 188, 204))

    # Divider
    y = 278
    draw.line([(lx, y), (rx, y)], fill=(32, 37, 46), width=2)

    # Up to 3 clean model ID pills (large, spacious, 1-second scan)
    y += 40
    shown = model_ids[:3]
    extra = len(model_ids) - len(shown)
    pill_h = 56
    for idx, mid in enumerate(shown):
        cy_row = y + pill_h // 2
        dot_col = accent_rgb if idx == 0 else (142, 152, 168)
        draw.ellipse([lx, cy_row - 6, lx + 12, cy_row + 6], fill=dot_col)
        is_first = idx == 0
        w_p, _ = _draw_pill(
            draw,
            lx + 30,
            y,
            mid,
            f_pill,
            text_fill=(255, 255, 255) if is_first else (226, 234, 244),
            bg_fill=(16, 26, 44) if is_first else (13, 17, 25),
            border_fill=(*accent_rgb,) if is_first else (52, 60, 74),
            pad_x=22,
            radius=13,
            fixed_h=pill_h,
            max_w=content_w - 180 if (idx == len(shown) - 1 and extra > 0) else content_w - 30,
        )
        if idx == len(shown) - 1 and extra > 0:
            _draw_pill(
                draw,
                lx + 30 + w_p + 14,
                y + 8,
                f"+{extra} more",
                f_badge,
                text_fill=(170, 180, 196),
                bg_fill=(16, 20, 28),
                border_fill=(52, 60, 74),
                pad_x=14,
                radius=10,
                fixed_h=40,
            )
        y += 72

    # Clean footer
    draw.line([(lx, H - 110), (rx, H - 110)], fill=(32, 37, 46), width=2)
    fy = H - 82
    sw = _make_sw_square(44)
    base.paste(sw, (lx, fy), sw)
    fx = lx + 58
    fx += _draw_vcenter_text(draw, fx, fy + 22, "Developed by ", f_foot_b, (255, 255, 255))
    fx += _draw_vcenter_text(draw, fx, fy + 22, "@StatsWire", f_foot_b, (138, 180, 248))
    _draw_vcenter_text(draw, fx, fy + 22, " on X", f_foot_b, (255, 255, 255))

    dw = int(draw.textlength(ts_str, font=f_date))
    _draw_vcenter_text(draw, rx - dw, fy + 22, ts_str, f_date, (140, 150, 166))

    # Subtle diagonal watermark
    wm_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    for wy in range(-20, H + 80, 220):
        for wx in range(-40, W + 120, 360):
            stamp = Image.new("RGBA", (240, 80), (0, 0, 0, 0))
            ImageDraw.Draw(stamp).text((14, 20), "@StatsWire", font=f_wm, fill=(255, 255, 255, 9))
            rot = stamp.rotate(20, resample=Image.Resampling.BICUBIC, expand=True)
            wm_layer.alpha_composite(rot, (wx, wy))
    wm_layer.putalpha(Image.composite(wm_layer.split()[3], Image.new("L", (W, H), 0), card_mask))

    final = Image.alpha_composite(base.convert("RGBA"), wm_layer).convert("RGB")
    buf = io.BytesIO()
    final.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def card_filename(item: Dict[str, Any]) -> str:
    """Return a clean Discord-safe attachment filename for a story or card."""
    raw = str(item.get("group") or item.get("title") or item.get("family") or item.get("id") or "model-card")
    slug = re.sub(r"[^a-z0-9-]+", "-", raw.lower()).strip("-")[:48] or "model"
    return f"statswire-{slug}.png"


def render_release_card_png(
    *,
    display_name: str,
    version: str,
    provider_slug: str,
    org_label: str,
    badge_text: str,
    item_count: int,
    subtitle: str,
    highlights: List[str],
    gem_chips: Optional[List[str]] = None,
    timestamp_iso: str = "",
) -> Optional[bytes]:
    """Render a 16:9 dark @StatsWire Release Card PNG (1200x675).

    Returns PNG bytes, or ``None`` if Pillow is unavailable.
    """
    if Image is None or ImageDraw is None or ImageFont is None:
        return None

    W, H = 1200, 675
    lx, rx = 56, W - 56
    content_w = rx - lx

    slug = (provider_slug or "google").lower()
    accent_rgb = PROVIDER_PALETTE.get(slug, ((138, 180, 248), "AI"))[0]
    ts_str = _fmt_utc_compact(timestamp_iso)

    is_alpha = "ALPHA" in (badge_text or "").upper()
    is_spec = "SPEC" in (badge_text or "").upper()
    if is_alpha:
        st_fg, st_bg, st_bd = (245, 200, 96), (34, 27, 13), (112, 88, 36)
    elif is_spec:
        st_fg, st_bg, st_bd = (45, 212, 191), (12, 32, 32), (38, 104, 100)
    else:
        st_fg, st_bg, st_bd = (74, 222, 128), (13, 34, 22), (40, 108, 66)

    f_eyebrow = _load_font(_SANS_BOLD_FONTS, 22)
    f_badge = _load_font(_SANS_BOLD_FONTS, 18)
    f_sub = _load_font(_SANS_REG_FONTS, 24)
    f_bullet = _load_font(_SANS_REG_FONTS, 23)
    f_chip = _load_font(_MONO_BOLD_FONTS, 17)
    f_foot_b = _load_font(_SANS_BOLD_FONTS, 23)
    f_date = _load_font(_SANS_REG_FONTS, 20)
    f_wm = _load_font(_SANS_BOLD_FONTS, 24)

    base = Image.new("RGB", (W, H), (0, 0, 0))
    draw = ImageDraw.Draw(base)

    cx0, cy0, cx1, cy1 = 8, 8, W - 9, H - 9
    draw.rounded_rectangle([cx0, cy0, cx1, cy1], radius=32, fill=(7, 9, 14), outline=(44, 50, 62), width=2)

    card_mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(card_mask).rounded_rectangle([cx0 + 1, cy0 + 1, cx1 - 1, cy1 - 1], radius=31, fill=255)
    top_bar = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(top_bar).rectangle([cx0, cy0, cx1, cy0 + 5], fill=(*accent_rgb, 220))
    top_bar.putalpha(Image.composite(top_bar.split()[3], Image.new("L", (W, H), 0), card_mask))
    base = Image.alpha_composite(base.convert("RGBA"), top_bar).convert("RGB")
    draw = ImageDraw.Draw(base)

    # Top-right provider badge
    badge = _make_provider_badge(slug, accent_rgb, size=128)
    base.paste(badge, (rx - 128, 46), badge)
    max_left_w = content_w - 156

    # Eyebrow row
    y = 48
    ex = lx
    if slug == "google":
        spark = _make_gemini_spark(34, badge_bg=True)
        base.paste(spark, (lx, y), spark)
        ex = lx + 46
    else:
        draw.ellipse([lx, y + 9, lx + 16, y + 25], fill=accent_rgb)
        ex = lx + 28

    ex += _draw_vcenter_text(draw, ex, y + 17, _truncate(org_label.upper(), f_eyebrow, 260, draw), f_eyebrow, accent_rgb) + 14
    w_b, _ = _draw_pill(draw, ex, y + 1, badge_text.upper(), f_badge, text_fill=st_fg, bg_fill=st_bg, border_fill=st_bd, pad_x=14, radius=10, fixed_h=32)
    ex += w_b + 10
    if item_count > 0:
        count_label = f"{item_count} {'ITEM' if item_count == 1 else 'ITEMS'}"
        _draw_pill(
            draw,
            ex,
            y + 1,
            count_label,
            f_badge,
            text_fill=(210, 220, 236),
            bg_fill=(18, 22, 32),
            border_fill=(56, 66, 84),
            pad_x=14,
            radius=10,
            fixed_h=32,
        )

    # Title (auto-scaled)
    y += 52
    full_title = f"{display_name} {version}".strip()
    f_title = _load_font(_SANS_BOLD_FONTS, 50)
    for sz in (50, 44, 38, 34):
        cand = _load_font(_SANS_BOLD_FONTS, sz)
        if draw.textlength(full_title, font=cand) <= max_left_w:
            f_title = cand
            break
    else:
        f_title = _load_font(_SANS_BOLD_FONTS, 34)
        full_title = _truncate(full_title, f_title, max_left_w, draw)
    draw.text((lx, y), full_title, font=f_title, fill=(255, 255, 255))

    # Subtitle
    y += 66
    draw.text((lx, y), _truncate(subtitle, f_sub, max_left_w, draw), font=f_sub, fill=(178, 188, 204))

    # Divider
    y = 224
    draw.line([(lx, y), (rx, y)], fill=(32, 37, 46), width=2)

    # Highlights list (up to 4 clean rows)
    y += 24
    shown_highlights = [h.strip() for h in highlights if h and h.strip()][:4]
    row_h = 56
    for idx, line_txt in enumerate(shown_highlights):
        cy_row = y + 18
        dot_col = accent_rgb if idx == 0 else (142, 152, 168)
        draw.ellipse([lx, cy_row - 5, lx + 10, cy_row + 5], fill=dot_col)
        clean_line = _truncate(line_txt, f_bullet, content_w - 28, draw)
        _draw_vcenter_text(
            draw,
            lx + 24,
            cy_row,
            clean_line,
            f_bullet,
            (244, 247, 252) if idx == 0 else (212, 220, 232),
        )
        y += row_h

    # Buried gem / signal chips row (above footer)
    chips = [c.strip() for c in (gem_chips or []) if c and c.strip()][:5]
    if chips:
        chip_y = H - 156
        cx = lx
        for chip in chips:
            max_rem = rx - cx
            if max_rem < 110:
                break
            w_c, _ = _draw_pill(
                draw,
                cx,
                chip_y,
                chip,
                f_chip,
                text_fill=(186, 214, 255),
                bg_fill=(14, 22, 36),
                border_fill=(44, 62, 92),
                pad_x=13,
                radius=9,
                fixed_h=34,
                max_w=min(290, max_rem),
            )
            cx += w_c + 10

    # Clean footer
    draw.line([(lx, H - 102), (rx, H - 102)], fill=(32, 37, 46), width=2)
    fy = H - 78
    sw = _make_sw_square(42)
    base.paste(sw, (lx, fy), sw)
    fx = lx + 56
    fx += _draw_vcenter_text(draw, fx, fy + 21, "Developed by ", f_foot_b, (255, 255, 255))
    fx += _draw_vcenter_text(draw, fx, fy + 21, "@StatsWire", f_foot_b, (138, 180, 248))
    _draw_vcenter_text(draw, fx, fy + 21, " · Full .md attached", f_foot_b, (172, 182, 198))

    dw = int(draw.textlength(ts_str, font=f_date))
    _draw_vcenter_text(draw, rx - dw, fy + 21, ts_str, f_date, (140, 150, 166))

    # Subtle diagonal watermark
    wm_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    for wy in range(-20, H + 80, 220):
        for wx in range(-40, W + 120, 360):
            stamp = Image.new("RGBA", (240, 80), (0, 0, 0, 0))
            ImageDraw.Draw(stamp).text((14, 20), "@StatsWire", font=f_wm, fill=(255, 255, 255, 9))
            rot = stamp.rotate(20, resample=Image.Resampling.BICUBIC, expand=True)
            wm_layer.alpha_composite(rot, (wx, wy))
    wm_layer.putalpha(Image.composite(wm_layer.split()[3], Image.new("L", (W, H), 0), card_mask))

    final = Image.alpha_composite(base.convert("RGBA"), wm_layer).convert("RGB")
    buf = io.BytesIO()
    final.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
