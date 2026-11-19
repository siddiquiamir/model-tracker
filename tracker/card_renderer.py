"""Cross-platform studio-grade @StatsWire PNG card renderer for ModelPulse Discord & X alerts."""

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

# Cross-platform font search lists (Windows + Ubuntu GitHub Actions + macOS)
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
    "opensource": ((74, 222, 128), "OS"),
    "multi": ((129, 140, 248), "AI"),
}

STAGE_PILL_STYLE: Dict[str, Tuple[str, Tuple[int, int, int], Tuple[int, int, int], Tuple[int, int, int]]] = {
    "leak": ("LEAK", (245, 200, 96), (34, 27, 13), (112, 88, 36)),
    "release": ("NEW MODEL", (74, 222, 128), (13, 34, 22), (40, 108, 66)),
    "open_weights": ("OPEN WEIGHTS", (45, 212, 191), (12, 32, 32), (38, 104, 100)),
    "registry": ("REGISTRY UPDATE", (125, 211, 252), (14, 28, 44), (48, 96, 144)),
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


def _fmt_utc_short(iso: str) -> Tuple[str, str]:
    """Return ('19 Nov', '04:02 UTC') from ISO timestamp."""
    try:
        dt = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%d %b"), dt.strftime("%H:%M UTC")
    except Exception:
        now = datetime.now(timezone.utc)
        return now.strftime("%d %b"), now.strftime("%H:%M UTC")


def _fmt_utc_full(iso: str) -> str:
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
    pad_x: int = 16,
    radius: int = 10,
    fixed_h: int = 36,
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


def _wrap_spans(
    draw: ImageDraw.ImageDraw,
    spans: List[Tuple[str, Any, Tuple[int, int, int]]],
    max_w: int,
) -> List[List[Tuple[str, Any, Tuple[int, int, int], int]]]:
    """Pre-compute wrapped lines so we can measure exact dynamic height before drawing."""
    lines: List[List[Tuple[str, Any, Tuple[int, int, int], int]]] = [[]]
    cur_w = 0
    for text, font, col in spans:
        words = text.split(" ")
        for idx, word in enumerate(words):
            tok = word + (" " if idx < len(words) - 1 else "")
            if not tok:
                continue
            w = int(draw.textlength(tok, font=font))
            if cur_w > 0 and cur_w + w > max_w:
                lines.append([])
                cur_w = 0
            lines[-1].append((tok, font, col, w))
            cur_w += w
    return [ln for ln in lines if ln] or [[]]


def _draw_wrapped_lines(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    lines: List[List[Tuple[str, Any, Tuple[int, int, int], int]]],
    line_h: int,
) -> int:
    cur_y = y
    for line in lines:
        cur_x = x
        for tok, font, col, w in line:
            draw.text((cur_x, cur_y), tok, font=font, fill=col)
            cur_x += w
        cur_y += line_h
    return cur_y


def _make_gemini_spark(size: int, badge_bg: bool = True) -> Image.Image:
    """4x supersampled anti-aliased 4-color Gemini spark icon."""
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
    """4x supersampled crisp 4-color Google G badge on dark rounded tile."""
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

    # Google brand colors: Red top, Yellow left, Green bottom, Blue right + bar
    d.arc(bbox, start=210, end=325, fill=(234, 67, 53, 255), width=ring_w)
    d.arc(bbox, start=140, end=215, fill=(251, 188, 5, 255), width=ring_w)
    d.arc(bbox, start=42, end=144, fill=(52, 168, 83, 255), width=ring_w)
    d.arc(bbox, start=-6, end=46, fill=(66, 133, 244, 255), width=ring_w)

    # Clean horizontal blue crossbar of the G
    bar_h = int(ring_w * 0.88)
    d.rectangle([cx - int(ss * 0.01), cy - bar_h // 2, cx + r_out, cy + bar_h // 2], fill=(66, 133, 244, 255))
    # Inner dark punch to keep the ring crisp
    d.ellipse([cx - r_in, cy - r_in, cx + r_in, cy + r_in], fill=(24, 28, 36, 255))
    # Re-draw inner end of crossbar cleanly
    d.rectangle([cx + int(ss * 0.01), cy - bar_h // 2, cx + r_out - 2, cy + bar_h // 2], fill=(66, 133, 244, 255))
    # Mask outer corners cleanly to exact r_out circle for the crossbar tip
    return out.resize((size, size), Image.Resampling.LANCZOS)


def _make_provider_badge(provider_slug: str, accent_rgb: Tuple[int, int, int], size: int = 124) -> Image.Image:
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
        # Geometric 6-petal interlocking emerald rosette
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

    # Crisp bold monogram inside subtle ring
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


def _normalize_item_to_view(item: Dict[str, Any]) -> Dict[str, Any]:
    """Unify either a ModelPulse story or a single diff/intelligence card into a clean card layout model."""
    is_story = "sources" in item and isinstance(item.get("sources"), list)
    slug = str(item.get("provider_slug") or "opensource").lower().strip()
    prov_name = str(item.get("provider_name") or slug.upper() or "AI MODEL").strip()
    accent_rgb = PROVIDER_PALETTE.get(slug, (_parse_hex_rgb(str(item.get("accent_color") or "")), ""))[0]

    kind = str(item.get("kind") or "").lower().strip()
    if not kind:
        if item.get("intelligence"):
            kind = "registry" if item.get("event_label") == "Registry update" else "unverified"
        else:
            kind = "leak"
    if kind == "release" and item.get("open_weights"):
        stage_key = "open_weights"
    else:
        stage_key = kind if kind in STAGE_PILL_STYLE else "leak"

    title = str(item.get("title") or item.get("family") or "New Model Detected").strip()
    detected_at = str(item.get("detected_at") or item.get("observed_at") or datetime.now(timezone.utc).isoformat())
    updated_at = str(item.get("updated_at") or detected_at)
    first_source = str(item.get("first_source") or item.get("build_label") or item.get("scanner") or "Live Tracker").strip()
    pricing = str(item.get("pricing") or "").strip()
    codenames = [str(c) for c in (item.get("codenames") or []) if c]
    lead = str(item.get("lead") or "").strip()
    models = [str(m.get("id") or m.get("name") or "").strip() for m in (item.get("models") or []) if (m.get("id") or m.get("name"))]
    # Deduplicate preserving order
    seen_m = set()
    uniq_models: List[str] = []
    for mid in models:
        if mid.lower() not in seen_m:
            seen_m.add(mid.lower())
            uniq_models.append(mid)

    signals: List[Dict[str, Any]] = []
    if is_story:
        srcs = item.get("sources") or []
        src_count = int(item.get("source_count") or len(srcs) or 1)
        if kind == "leak":
            subtitle = (
                f"Detected across {src_count} independent sources ahead of official launch"
                if src_count > 1
                else f"Spotted in {first_source} ahead of public launch"
            )
        elif kind == "release":
            subtitle = (
                f"Confirmed live across {src_count} sources · first detected in {first_source}"
                if src_count > 1
                else f"Live model listing detected in {first_source}"
            )
        elif kind == "registry":
            subtitle = f"Catalog entry observed in {first_source}"
        else:
            subtitle = f"Early identifier signal spotted in {first_source}"

        # Show up to 4 most informative sources (newest first, keeping earliest if >4)
        ordered_srcs = list(reversed(srcs))
        picked_srcs = ordered_srcs[:4]
        for idx, s in enumerate(picked_srcs):
            d_day, d_tm = _fmt_utc_short(str(s.get("detected_at") or detected_at))
            lbl = str(s.get("label") or s.get("scanner") or "Source").strip()
            s_title = str(s.get("title") or f"Detected in {lbl}").strip()
            tone = "green" if idx == 0 and kind == "release" else ("amber" if idx == 0 and kind == "leak" else ("blue" if idx == 0 else "slate"))
            signals.append({
                "pill": lbl,
                "lead": f"{d_day} · {d_tm}: ",
                "body": s_title,
                "tone": tone,
            })
        if not signals and item.get("registry_evidence"):
            ev = item["registry_evidence"][0]
            signals.append({
                "pill": str(ev.get("file_path") or "Registry Evidence"),
                "lead": f"Build {ev.get('build', 'latest')}: ",
                "body": str(ev.get("excerpt") or "").replace("\n", " ")[:140],
                "tone": "blue",
            })
    else:
        src_count = 1
        subtitle = str(item.get("subtitle") or f"Verified diff detected in {first_source}").strip()
        d_day, d_tm = _fmt_utc_short(detected_at)
        transition = str(item.get("build_transition") or item.get("build") or "Latest build").strip()
        signals.append({
            "pill": first_source,
            "lead": f"{d_day} · {d_tm}: ",
            "body": f"{transition} — {item.get('evidence') or item.get('source_text') or 'Verified diff'}",
            "tone": "amber" if kind == "leak" else "blue",
        })
        if item.get("registry_evidence"):
            ev = item["registry_evidence"][0]
            signals.append({
                "pill": str(ev.get("file_path") or "Evidence Excerpt"),
                "lead": "Excerpt: ",
                "body": str(ev.get("excerpt") or "").replace("\n", " ")[:150],
                "tone": "slate",
            })
        elif item.get("sku_samples"):
            signals.append({
                "pill": "Billing SKU Samples",
                "lead": "Observed Rates: ",
                "body": " · ".join(str(x) for x in item["sku_samples"][:2])[:170],
                "tone": "green",
            })

    d_day, d_tm = _fmt_utc_short(detected_at)
    # Build 3-column metrics
    col1 = ("FIRST SPOTTED", f"{d_day} · {d_tm.replace(' UTC', '')}", f"{first_source} (UTC)")
    if pricing:
        col2 = ("PRICING", pricing.split(",")[0].strip()[:18], (f"Codename: {codenames[0]}" if codenames else f"{src_count} confirmed source{'s' if src_count != 1 else ''}"))
    elif codenames:
        col2 = ("CODENAME", codenames[0][:16], f"{src_count} confirmed surface{'s' if src_count != 1 else ''}")
    else:
        col2 = ("SURFACES", f"{src_count} Verified", lead[:28] if lead else ("Backend pre-launch signal" if kind == "leak" else "Live catalog confirmation"))

    n_ids = len(uniq_models)
    col3 = (
        "IDENTIFIERS",
        f"{n_ids} Model ID{'s' if n_ids != 1 else ''}" if n_ids else "1 Signal",
        uniq_models[0] if uniq_models else title,
    )

    if kind == "release":
        disclaimer = "Verified across public model catalogs & official endpoints; availability may vary by region."
    elif kind == "registry":
        disclaimer = "Catalog/registry diff only; verify official provider announcements for rollout status."
    else:
        disclaimer = "Backend/build sighting only; public API availability & official launch remain unconfirmed."

    return {
        "slug": slug,
        "provider_name": prov_name,
        "accent_rgb": accent_rgb,
        "stage_key": stage_key,
        "title": title,
        "subtitle": subtitle,
        "metrics": [col1, col2, col3],
        "models": uniq_models,
        "signals": signals[:4],
        "disclaimer": disclaimer,
        "footer_date": _fmt_utc_full(updated_at),
        "src_count": src_count,
    }


def render_alert_card_png(item: Dict[str, Any]) -> Optional[bytes]:
    """Render a crisp 1080px-wide @StatsWire Insights PNG card for any ModelPulse story or diff card."""
    if Image is None or ImageDraw is None or ImageFont is None:
        return None

    view = _normalize_item_to_view(item)
    W = 1080
    lx = 62
    rx = W - 62
    content_w = rx - lx

    f_eyebrow = _load_font(_SANS_BOLD_FONTS, 21)
    f_badge = _load_font(_SANS_BOLD_FONTS, 18)
    f_sub = _load_font(_SANS_REG_FONTS, 23)
    f_sec = _load_font(_SANS_BOLD_FONTS, 16)
    f_stat = _load_font(_SANS_BOLD_FONTS, 30)
    f_stat_sub = _load_font(_SANS_REG_FONTS, 18)
    f_b = _load_font(_SANS_BOLD_FONTS, 22)
    f_r = _load_font(_SANS_REG_FONTS, 22)
    f_mono = _load_font(_MONO_BOLD_FONTS, 20)
    f_chip = _load_font(_MONO_BOLD_FONTS, 19)
    f_note = _load_font(_SANS_REG_FONTS, 19)
    f_foot_b = _load_font(_SANS_BOLD_FONTS, 24)
    f_wm = _load_font(_SANS_BOLD_FONTS, 24)

    # Scratch draw for exact layout height measurement
    tmp = Image.new("RGB", (W, 100), (0, 0, 0))
    tdraw = ImageDraw.Draw(tmp)

    # Auto-size headline to fit cleanly left of the 124px right badge
    max_title_w = content_w - 154
    title_txt = view["title"]
    f_title = _load_font(_SANS_BOLD_FONTS, 52)
    for sz in (52, 44, 38, 33):
        cand_f = _load_font(_SANS_BOLD_FONTS, sz)
        if tdraw.textlength(title_txt, font=cand_f) <= max_title_w:
            f_title = cand_f
            break
    else:
        f_title = _load_font(_SANS_BOLD_FONTS, 33)
        title_txt = _truncate(title_txt, f_title, max_title_w, tdraw)

    sub_lines = _wrap_spans(tdraw, [(view["subtitle"], f_sub, (182, 190, 204))], max_title_w)[:2]

    # Measure model ID chips layout
    chips_to_show = view["models"][:6]
    extra_chips = max(0, len(view["models"]) - len(chips_to_show))
    chip_rows: List[List[Tuple[str, int]]] = []
    if chips_to_show:
        cur_row: List[Tuple[str, int]] = []
        cur_x = 0
        all_chip_labels = list(chips_to_show) + ([f"+{extra_chips} more"] if extra_chips else [])
        for raw_c in all_chip_labels:
            lbl = _truncate(raw_c, f_chip, 360, tdraw)
            cw = int(tdraw.textlength(lbl, font=f_chip)) + 28
            if cur_x > 0 and cur_x + cw > content_w:
                chip_rows.append(cur_row)
                cur_row = []
                cur_x = 0
            cur_row.append((lbl, cw))
            cur_x += cw + 10
        if cur_row:
            chip_rows.append(cur_row)

    # Pre-wrap signal bullets
    wrapped_signals = []
    for sig in view["signals"]:
        wlines = _wrap_spans(
            tdraw,
            [(sig["lead"], f_b, (255, 255, 255)), (sig["body"], f_r, (212, 220, 232))],
            content_w - 28,
        )[:3]
        wrapped_signals.append((sig, wlines))

    # Compute exact dynamic height
    y_calc = 54 + 54 + 66 + len(sub_lines) * 30 + 22  # header + divider
    y_calc += 26 + 98 + 20  # 3-col metrics + divider
    if chip_rows:
        y_calc += 24 + 28 + len(chip_rows) * 44 + 14  # chips section
    y_calc += 24 + 30  # signals section header
    for _, wlines in wrapped_signals:
        y_calc += 44 + len(wlines) * 29 + 18
    H = max(780, y_calc + 166)

    # Render final canvas
    base = Image.new("RGB", (W, H), (0, 0, 0))
    draw = ImageDraw.Draw(base)

    cx0, cy0, cx1, cy1 = 6, 6, W - 7, H - 7
    draw.rounded_rectangle(
        [cx0, cy0, cx1, cy1],
        radius=34,
        fill=(7, 9, 14),
        outline=(44, 50, 62),
        width=2,
    )

    # Subtle top accent bar clipped to rounded card
    accent_rgb = view["accent_rgb"]
    top_bar = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(top_bar).rectangle([cx0, cy0, cx1, cy0 + 5], fill=(*accent_rgb, 200))
    card_mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(card_mask).rounded_rectangle([cx0 + 1, cy0 + 1, cx1 - 1, cy1 - 1], radius=33, fill=255)
    top_bar.putalpha(Image.composite(top_bar.split()[3], Image.new("L", (W, H), 0), card_mask))
    base = Image.alpha_composite(base.convert("RGBA"), top_bar).convert("RGB")
    draw = ImageDraw.Draw(base)

    # Top-right provider emblem
    big_badge = _make_provider_badge(view["slug"], accent_rgb, size=124)
    base.paste(big_badge, (rx - 124, 46), big_badge)

    # Top-left eyebrow
    y = 54
    ex = lx
    if view["slug"] == "google":
        spark = _make_gemini_spark(36, badge_bg=True)
        base.paste(spark, (lx, y), spark)
        ex = lx + 48
    else:
        draw.ellipse([lx, y + 11, lx + 14, y + 25], fill=accent_rgb)
        ex = lx + 26

    stage_label, st_fg, st_bg, st_bd = STAGE_PILL_STYLE[view["stage_key"]]
    eyebrow_txt = _truncate(f"{view['provider_name'].upper()} · MODELPULSE", f_eyebrow, max_title_w - 190, draw)
    ex += _draw_vcenter_text(draw, ex, y + 18, eyebrow_txt, f_eyebrow, accent_rgb) + 14
    _draw_pill(draw, ex, y + 2, stage_label, f_badge, text_fill=st_fg, bg_fill=st_bg, border_fill=st_bd, pad_x=14, radius=10, fixed_h=32)

    y += 52
    draw.text((lx, y), title_txt, font=f_title, fill=(255, 255, 255))
    y += 66
    y = _draw_wrapped_lines(draw, lx, y, sub_lines, 30)

    y += 22
    draw.line([(lx, y), (rx, y)], fill=(32, 37, 46), width=2)

    # 3-Column Metrics Strip
    y += 24
    col_w = content_w // 3
    for i, (m_lbl, m_val, m_sub) in enumerate(view["metrics"]):
        cx = lx + i * col_w
        max_col_w = col_w - 18
        draw.text((cx, y), m_lbl, font=f_sec, fill=(138, 146, 162))
        val_col = accent_rgb if i == 0 else (st_fg if i == 1 else (255, 255, 255))
        draw.text((cx, y + 24), _truncate(m_val, f_stat, max_col_w, draw), font=f_stat, fill=val_col)
        draw.text((cx, y + 64), _truncate(m_sub, f_stat_sub, max_col_w, draw), font=f_stat_sub, fill=(154, 162, 178))

    y += 98
    draw.line([(lx, y), (rx, y)], fill=(32, 37, 46), width=2)

    # Model Identifier Chips
    if chip_rows:
        y += 22
        draw.text((lx, y), "DETECTED IDENTIFIERS", font=f_sec, fill=(138, 146, 162))
        y += 28
        for row in chip_rows:
            cx = lx
            for lbl, _ in row:
                is_more = lbl.startswith("+") and lbl.endswith("more")
                w_pill, _ = _draw_pill(
                    draw,
                    cx,
                    y,
                    lbl,
                    f_chip,
                    text_fill=(170, 180, 196) if is_more else (238, 244, 252),
                    bg_fill=(16, 20, 28) if is_more else (15, 22, 34),
                    border_fill=(52, 60, 74) if is_more else (58, 86, 132),
                    pad_x=14,
                    radius=9,
                    fixed_h=34,
                )
                cx += w_pill + 10
            y += 44
        y += 8
        draw.line([(lx, y), (rx, y)], fill=(26, 30, 38), width=2)

    # Verified Sightings Timeline
    y += 22
    draw.text((lx, y), "VERIFIED SIGHTINGS & EVIDENCE", font=f_sec, fill=(138, 146, 162))
    y += 30

    tone_styles = {
        "green": ((74, 222, 128), (13, 34, 22), (46, 122, 74)),
        "amber": ((245, 200, 96), (32, 26, 13), (112, 88, 38)),
        "blue": ((138, 180, 248), (16, 26, 46), (76, 122, 208)),
        "slate": ((156, 166, 184), (15, 19, 27), (52, 60, 74)),
    }
    for sig, wlines in wrapped_signals:
        dot_col, p_bg, p_bd = tone_styles.get(sig["tone"], tone_styles["slate"])
        draw.ellipse([lx, y + 12, lx + 12, y + 24], fill=dot_col)
        _draw_pill(
            draw,
            lx + 28,
            y,
            sig["pill"],
            f_mono,
            text_fill=(242, 246, 252),
            bg_fill=p_bg,
            border_fill=p_bd,
            pad_x=16,
            radius=9,
            fixed_h=36,
            max_w=content_w - 28,
        )
        y += 44
        y = _draw_wrapped_lines(draw, lx + 28, y, wlines, 29)
        y += 18

    # Footer separator + disclaimer + branding
    draw.line([(lx, H - 144), (rx, H - 144)], fill=(32, 37, 46), width=2)
    draw.text(
        (lx, H - 124),
        _truncate(view["disclaimer"], f_note, content_w, draw),
        font=f_note,
        fill=(138, 146, 162),
    )

    fy = H - 80
    sw = _make_sw_square(44)
    base.paste(sw, (lx, fy), sw)
    fx = lx + 58
    fx += _draw_vcenter_text(draw, fx, fy + 22, "Developed by ", f_foot_b, (255, 255, 255))
    fx += _draw_vcenter_text(draw, fx, fy + 22, "@StatsWire", f_foot_b, (138, 180, 248))
    _draw_vcenter_text(draw, fx, fy + 22, " on X", f_foot_b, (255, 255, 255))

    dw = int(draw.textlength(view["footer_date"], font=f_note))
    _draw_vcenter_text(draw, rx - dw, fy + 22, view["footer_date"], f_note, (138, 146, 162))

    # Subtle 20-degree diagonal @StatsWire watermark masked inside rounded card
    wm_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    for wy in range(-20, H + 80, 220):
        for wx in range(-40, W + 120, 360):
            stamp = Image.new("RGBA", (240, 80), (0, 0, 0, 0))
            ImageDraw.Draw(stamp).text((14, 20), "@StatsWire", font=f_wm, fill=(255, 255, 255, 10))
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
