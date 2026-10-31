"""Live pricing tracker and enrichment for ModelPulse cards and stories."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import pathlib
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
import urllib.request

from tracker.extractor import humanize_model_id, infer_provider, is_legacy_model_id
from tracker.novelty import normalize, strip_variants

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
PRICING_CACHE_FILE = ROOT_DIR / ".cache" / "pricing_catalog.json"
PRICING_TTL = timedelta(minutes=10)

OPENAI_PRICING_MD_URL = "https://developers.openai.com/api/docs/pricing.md"
ANTHROPIC_PRICING_MD_URL = "https://platform.claude.com/docs/en/about-claude/pricing.md"
XAI_PRICING_MD_URL = "https://docs.x.ai/developers/models.md"
LITELLM_PRICING_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
MODELS_DEV_URL = "https://models.dev/api.json"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
    ),
}


def _http_get_text(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers=BROWSER_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _http_get_json(url: str, timeout: int = 15) -> Any:
    return json.loads(_http_get_text(url, timeout=timeout))


def fmt_usd_per_m(val: float) -> str:
    """Format a USD per 1M token number cleanly ($15, $1.50, $0.075)."""
    if val <= 0:
        return ""
    if abs(val - round(val)) < 1e-6 and val >= 1:
        return f"${int(round(val))}"
    if abs(val * 100 - round(val * 100)) < 1e-4:
        return f"${val:.2f}"
    return f"${val:.4g}"


def format_token_pricing(
    inp_per_m: Optional[float],
    out_per_m: Optional[float],
    cached_per_m: Optional[float] = None,
) -> str:
    if not inp_per_m or not out_per_m or inp_per_m <= 0 or out_per_m <= 0:
        return ""
    inp_s = fmt_usd_per_m(inp_per_m)
    out_s = fmt_usd_per_m(out_per_m)
    if not inp_s or not out_s:
        return ""
    base = f"{inp_s} / {out_s} per 1M tokens"
    if cached_per_m and cached_per_m > 0:
        c_s = fmt_usd_per_m(cached_per_m)
        if c_s:
            base += f" ({c_s} cached)"
    return base


def _clean_price_token(cell: str) -> Optional[float]:
    m = re.search(r"\$\s*([0-9]+(?:\.[0-9]+)?)", re.sub(r"<[^>]+>", "", cell or ""))
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def parse_openai_pricing_md(txt: str) -> Dict[str, str]:
    """Parse developers.openai.com/api/docs/pricing.md standard pricing tables."""
    out: Dict[str, str] = {}
    section = ""
    headers: List[str] = []
    excluded_rows = {"containers", "web search", "file search", "agent kit", "whisper", "tts-1", "tts-1-hd", "davinci-002", "babbage-002"}
    for raw_line in txt.splitlines():
        line = raw_line.strip()
        if line.startswith("#"):
            section = line.lstrip("#").strip().lower()
            headers = []
            continue
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        first_lower = cells[0].lower()
        if first_lower in ("model", "model configuration", "category"):
            headers = [c.lower() for c in cells]
            continue
        if any(skip in section for skip in ("batch", "flex", "fast", "ultrafast", "training")):
            continue

        if headers and headers[0] == "category" and len(cells) >= 4:
            m_cell = cells[1]
            rest = cells[2:]
            h_rest = headers[2:]
        else:
            m_cell = cells[0]
            rest = cells[1:]
            h_rest = headers[1:] if headers else []

        m_id = re.sub(r"\s*\([^)]*\)", "", m_cell).strip(" `").lower()
        if not m_id or " " in m_id or m_id in excluded_rows or is_legacy_model_id(m_id):
            continue

        # Modality table (e.g. Model | Modality | Input | Output | Cached input)
        if h_rest and h_rest[0] == "modality" and len(rest) >= 3:
            modality = rest[0].lower()
            inp_v = _clean_price_token(rest[1])
            out_v = _clean_price_token(rest[2])
            cac_v = _clean_price_token(rest[3]) if len(rest) >= 4 else None
            if modality in ("text", "image") and inp_v and out_v:
                summary = format_token_pricing(inp_v, out_v, cac_v)
                if summary and m_id not in out:
                    out[m_id] = summary
            continue

        # Standard token table (Input | Output | Cached input)
        if len(rest) >= 2 and "$" in rest[0] and "$" in rest[1]:
            inp_v = _clean_price_token(rest[0])
            out_v = _clean_price_token(rest[1])
            cac_v = _clean_price_token(rest[2]) if len(rest) >= 3 else None
            summary = format_token_pricing(inp_v, out_v, cac_v)
            if summary and m_id not in out:
                out[m_id] = summary
        else:
            # Per-minute / flat pricing (e.g. gpt-live-1, gpt-realtime-translate)
            dollar_cells = [c for c in rest if "$" in c]
            if len(dollar_cells) == 1 and m_id not in out:
                val_s = dollar_cells[0].strip()
                if "/" not in val_s and h_rest and "minute" in " ".join(h_rest):
                    val_s = f"{val_s} / min"
                out[m_id] = val_s
    return out


def parse_anthropic_pricing_md(txt: str) -> Dict[str, str]:
    """Parse platform.claude.com/docs/en/about-claude/pricing.md main model pricing table."""
    out: Dict[str, str] = {}
    in_main = False
    for raw_line in txt.splitlines():
        line = raw_line.strip()
        if line.startswith("## Model pricing"):
            in_main = True
            continue
        if in_main and line.startswith("## "):
            break
        if not in_main or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 6 or cells[0].lower().startswith("model") or set(cells[0]) <= {"-", ":", " "}:
            continue
        if "retired" in cells[0].lower():
            continue
        m_name = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cells[0])
        m_name = re.sub(r"\s*\([^)]*\)", "", m_name).strip()
        slug = re.sub(r"[^a-z0-9.]+", "-", m_name.lower()).strip("-")
        if not slug.startswith("claude-") or is_legacy_model_id(slug):
            continue
        inp_v = _clean_price_token(cells[1])
        cac_v = _clean_price_token(cells[4])
        out_v = _clean_price_token(cells[5])
        summary = format_token_pricing(inp_v, out_v, cac_v)
        if summary and slug not in out:
            out[slug] = summary
            # Also register hyphenated version (e.g. claude-fable-5-1 alongside claude-fable-5.1)
            out[slug.replace(".", "-")] = summary
    return out


def parse_xai_pricing_md(txt: str) -> Dict[str, str]:
    """Parse docs.x.ai/developers/models.md pricing tables."""
    out: Dict[str, str] = {}
    for raw_line in txt.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2 or cells[0].lower() in ("model", "mode") or set(cells[0]) <= {"-", ":", " "}:
            continue
        if "≥" in cells[0] or "deprecated" in cells[0].lower():
            continue
        m_id = re.sub(r"\s*\([^)]*\)", "", cells[0]).strip(" `").lower()
        if not m_id.startswith("grok-") or is_legacy_model_id(m_id):
            continue
        if len(cells) >= 5 and "$" in cells[2] and "$" in cells[4]:
            inp_v = _clean_price_token(cells[2])
            cac_v = _clean_price_token(cells[3])
            out_v = _clean_price_token(cells[4])
            summary = format_token_pricing(inp_v, out_v, cac_v)
            if summary and m_id not in out:
                out[m_id] = summary
        elif len(cells) == 2 and "$" in cells[1] and m_id not in out:
            out[m_id] = re.sub(r"<br\s*/?>", " · ", cells[1]).strip()
    return out


class PricingCatalog:
    """Lookup table mapping normalized/raw model IDs to formatted pricing strings."""

    def __init__(self, by_key: Dict[str, str]) -> None:
        self.by_key = by_key

    def lookup(self, raw_id: str) -> str:
        if not raw_id:
            return ""
        raw_clean = raw_id.strip().lower()
        if raw_clean in self.by_key:
            return self.by_key[raw_clean]
        tail = raw_clean.split("/")[-1].split(":")[0].split("@")[0]
        if tail in self.by_key:
            return self.by_key[tail]
        norm = normalize(raw_id)
        if norm in self.by_key:
            return self.by_key[norm]
        base = strip_variants(norm)
        if base in self.by_key:
            return self.by_key[base]
        return ""


_MEM_CATALOG: Optional[PricingCatalog] = None
_MEM_AT: Optional[datetime] = None


def get_pricing_catalog(force_refresh: bool = False) -> PricingCatalog:
    """Build or load cached unified pricing catalog across Official Docs, LiteLLM, models.dev & OpenRouter."""
    global _MEM_CATALOG, _MEM_AT
    now = datetime.now(timezone.utc)
    if not force_refresh and _MEM_CATALOG is not None and _MEM_AT and now - _MEM_AT < PRICING_TTL:
        return _MEM_CATALOG

    if not force_refresh and PRICING_CACHE_FILE.exists():
        try:
            cached = json.loads(PRICING_CACHE_FILE.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(cached["fetched_at"])
            if now - fetched_at < PRICING_TTL and isinstance(cached.get("by_key"), dict):
                _MEM_CATALOG = PricingCatalog(cached["by_key"])
                _MEM_AT = fetched_at
                return _MEM_CATALOG
        except Exception:
            pass

    by_key: Dict[str, str] = {}

    def _register(mid: str, price_str: str, overwrite: bool = False) -> None:
        if not mid or not price_str:
            return
        k_raw = mid.strip().lower()
        k_tail = k_raw.split("/")[-1].split(":")[0].split("@")[0]
        k_norm = normalize(mid)
        for k in (k_raw, k_tail, k_norm):
            if k and (overwrite or k not in by_key):
                by_key[k] = price_str

    # 1. OpenRouter (/api/v1/models)
    try:
        or_data = _http_get_json(OPENROUTER_MODELS_URL, timeout=12)
        for m in (or_data.get("data") or []) if isinstance(or_data, dict) else []:
            if not isinstance(m, dict) or not m.get("id"):
                continue
            pr = m.get("pricing") or {}
            try:
                inp_m = float(pr.get("prompt") or 0) * 1_000_000
                out_m = float(pr.get("completion") or 0) * 1_000_000
                cac_m = float(pr.get("input_cache_read") or 0) * 1_000_000
            except (TypeError, ValueError):
                continue
            summary = format_token_pricing(inp_m, out_m, cac_m)
            if summary:
                _register(str(m["id"]), summary, overwrite=False)
    except Exception:
        pass

    # 2. models.dev (/api.json)
    try:
        mdev = _http_get_json(MODELS_DEV_URL, timeout=15)
        if isinstance(mdev, dict):
            for prov_id, prov in mdev.items():
                if not isinstance(prov, dict):
                    continue
                for mid, minfo in (prov.get("models") or {}).items():
                    if not isinstance(minfo, dict):
                        continue
                    cost = minfo.get("cost") or {}
                    try:
                        inp_m = float(cost.get("input") or 0)
                        out_m = float(cost.get("output") or 0)
                        cac_m = float(cost.get("cache_read") or 0)
                    except (TypeError, ValueError):
                        continue
                    summary = format_token_pricing(inp_m, out_m, cac_m)
                    if summary:
                        _register(f"{prov_id}/{mid}", summary, overwrite=True)
                        _register(mid, summary, overwrite=False)
                        if minfo.get("canonical_model_id"):
                            _register(str(minfo["canonical_model_id"]), summary, overwrite=False)
    except Exception:
        pass

    # 3. LiteLLM (model_prices_and_context_window.json)
    try:
        ll = _http_get_json(LITELLM_PRICING_URL, timeout=15)
        if isinstance(ll, dict):
            for k, spec in ll.items():
                if k == "sample_spec" or not isinstance(spec, dict):
                    continue
                try:
                    inp_m = float(spec.get("input_cost_per_token") or 0) * 1_000_000
                    out_m = float(spec.get("output_cost_per_token") or 0) * 1_000_000
                    cac_m = float(spec.get("cache_read_input_token_cost") or 0) * 1_000_000
                except (TypeError, ValueError):
                    continue
                summary = format_token_pricing(inp_m, out_m, cac_m)
                if summary:
                    is_primary = "/" not in k or k.split("/")[0] in ("openai", "anthropic", "gemini", "vertex_ai", "xai", "deepseek")
                    _register(k, summary, overwrite=is_primary)
    except Exception:
        pass

    # 4. Official First-Party Pricing Pages (Highest priority — overwrites router estimates)
    for url, parser in (
        (OPENAI_PRICING_MD_URL, parse_openai_pricing_md),
        (ANTHROPIC_PRICING_MD_URL, parse_anthropic_pricing_md),
        (XAI_PRICING_MD_URL, parse_xai_pricing_md),
    ):
        try:
            md_txt = _http_get_text(url, timeout=12)
            for mid, summary in parser(md_txt).items():
                _register(mid, summary, overwrite=True)
        except Exception:
            pass

    try:
        PRICING_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        PRICING_CACHE_FILE.write_text(
            json.dumps({"fetched_at": now.isoformat(), "by_key": by_key}),
            encoding="utf-8",
        )
    except Exception:
        pass

    _MEM_CATALOG = PricingCatalog(by_key)
    _MEM_AT = now
    return _MEM_CATALOG


def scan_official_pricing_pages(baselines: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Diff official OpenAI, Anthropic, and xAI pricing pages against baselines['official_pricing_v1'].
    Emits a card the instant a new model or pricing row is published on an official pricing page.
    """
    state: Dict[str, Dict[str, str]] = baselines.get("official_pricing_v1", {})
    changed = False
    cards: List[Dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    targets = [
        {
            "key": "openai_pricing_md",
            "url": OPENAI_PRICING_MD_URL,
            "link_url": "https://developers.openai.com/api/docs/pricing",
            "parser": parse_openai_pricing_md,
            "header": "OPENAI OFFICIAL PRICING RADAR · OPENAI",
            "title_prefix": "New Model Pricing Published on OpenAI",
            "evidence": "developers.openai.com/api/docs/pricing.md",
            "source_text": "official OpenAI API pricing page (developers.openai.com/api/docs/pricing.md).",
            "provider_name": "OPENAI",
            "provider_slug": "openai",
            "accent_color": "#10b981",
            "seed_highlight": ["gpt-6-rosalind", "gpt-6-astra-law", "gpt-rosalind-research", "gpt-rosalind-discovery"],
            "seed_detected_at": "2026-10-30T18:35:00+00:00",
        },
        {
            "key": "anthropic_pricing_md",
            "url": ANTHROPIC_PRICING_MD_URL,
            "link_url": "https://platform.claude.com/docs/en/about-claude/pricing",
            "parser": parse_anthropic_pricing_md,
            "header": "ANTHROPIC OFFICIAL PRICING RADAR · ANTHROPIC",
            "title_prefix": "New Claude Pricing Published on Anthropic",
            "evidence": "platform.claude.com/docs/en/about-claude/pricing.md",
            "source_text": "official Anthropic Platform pricing documentation.",
            "provider_name": "ANTHROPIC",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
            "seed_highlight": [],
            "seed_detected_at": now_iso,
        },
        {
            "key": "xai_pricing_md",
            "url": XAI_PRICING_MD_URL,
            "link_url": "https://docs.x.ai/developers/models",
            "parser": parse_xai_pricing_md,
            "header": "XAI GROK OFFICIAL PRICING RADAR · XAI",
            "title_prefix": "New Grok Pricing Published on xAI",
            "evidence": "docs.x.ai/developers/models.md",
            "source_text": "official xAI developer models & pricing documentation.",
            "provider_name": "XAI",
            "provider_slug": "xai",
            "accent_color": "#e2e8f0",
            "seed_highlight": [],
            "seed_detected_at": now_iso,
        },
    ]

    for tgt in targets:
        try:
            txt = _http_get_text(tgt["url"], timeout=14)
            parsed = tgt["parser"](txt)
            if not parsed:
                continue
            bkey = tgt["key"]
            prev_map: Dict[str, str] = state.get(bkey, {})
            if prev_map:
                added_ids = [m for m in parsed if m not in prev_map and not is_legacy_model_id(m)]
            else:
                # First run: emit card for newly launched models specified in seed_highlight
                added_ids = [m for m in tgt["seed_highlight"] if m in parsed]

            if parsed != prev_map:
                state[bkey] = parsed
                changed = True

            if added_ids:
                sig = hashlib.sha256(",".join(added_ids[:8]).encode("utf-8")).hexdigest()[:8]
                det_ts = now_iso if prev_map else tgt["seed_detected_at"]
                models_payload = [
                    {
                        "id": m,
                        "name": f"{humanize_model_id(m)} — {parsed[m]}",
                        "pricing": parsed[m],
                    }
                    for m in added_ids[:10]
                ]
                first_m = added_ids[0]
                cards.append(
                    {
                        "id": f"pricing-radar-{bkey}-{sig}",
                        "category": "cli-sdk-diff",
                        "scanner": "pricing-radar",
                        "header": tgt["header"],
                        "title": f"{tgt['title_prefix']}: {first_m} ({parsed[first_m]})",
                        "subtitle": f"Verified official token pricing in {tgt['evidence']}",
                        "build_label": "Official Pricing",
                        "build_transition": f"{first_m}: {parsed[first_m]}",
                        "pricing": parsed[first_m],
                        "models": models_payload,
                        "evidence": tgt["evidence"],
                        "source_text": tgt["source_text"],
                        "disclaimer_1": "Extracted directly from official first-party API pricing tables.",
                        "disclaimer_2": "",
                        "provider_name": tgt["provider_name"],
                        "provider_slug": tgt["provider_slug"],
                        "accent_color": tgt["accent_color"],
                        "links": [
                            {"label": "Official Pricing Page", "url": tgt["link_url"]},
                            {"label": "Raw Pricing Markdown", "url": tgt["url"]},
                        ],
                        "detected_at": det_ts,
                    }
                )
        except Exception as exc:
            print(f"[PricingScanner] Warning ({tgt['key']}): {exc}")

    if changed:
        baselines["official_pricing_v1"] = state

    return cards, changed


def enrich_cards_with_pricing(cards: Iterable[Dict[str, Any]], catalog: Optional[PricingCatalog] = None) -> None:
    """Attach pricing to every model entry and top-level card in place when available."""
    catalog = catalog or get_pricing_catalog()
    for card in cards:
        card_prices: List[str] = []
        for m in card.get("models") or []:
            mid = str(m.get("id") or "")
            price = m.get("pricing") or catalog.lookup(mid)
            if price:
                m["pricing"] = price
                if price not in card_prices:
                    card_prices.append(price)
        if card_prices and not card.get("pricing"):
            card["pricing"] = card_prices[0]
