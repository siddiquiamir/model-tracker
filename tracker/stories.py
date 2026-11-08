"""Collapse per-source cards into one "story" per model (one launch = one entry, many confirmations)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from tracker.extractor import infer_provider
from tracker.novelty import RELEASE_GRACE, ReleasedCatalog, extract_embedded_date, normalize, strip_variants
from tracker.pricing import PricingCatalog, get_pricing_catalog

# Scanners whose sighting means the model is publicly usable (a release, not a leak)
RELEASE_SCANNERS: Set[str] = {"openrouter", "huggingface", "gateway-radar", "provider-openapi"}
UNVERIFIED_SCANNERS: Set[str] = {"github-code-leak"}
OPEN_WEIGHT_SCANNERS: Set[str] = {"huggingface", "engine-pr-leak"}
EXCLUDED_SCANNERS: Set[str] = {"cert-transparency", "cert-transparency-snapshot"}
GENERIC_PROVIDERS: Set[str] = {"modelsdev", "openrouter", "opensource", ""}
STORY_WINDOW = timedelta(days=21)

PROVIDER_NAMES: Dict[str, str] = {
    "google": "Google", "anthropic": "Anthropic", "openai": "OpenAI", "xai": "xAI", "meta": "Meta",
    "mistral": "Mistral", "deepseek": "DeepSeek", "qwen": "Qwen", "kimi": "Moonshot", "zai": "Z.ai",
    "minimax": "MiniMax", "nvidia": "NVIDIA", "microsoft": "Microsoft", "azure": "Azure", "amazon": "Amazon",
    "cohere": "Cohere", "perplexity": "Perplexity", "cursor": "Cursor", "thinkingmachines": "Thinking Machines",
}
LITELLM_PREFIX_PROVIDERS: Dict[str, Tuple[str, str]] = {
    "azure": ("azure", "Azure"),
    "azure_ai": ("azure", "Azure AI"),
    "openai": ("openai", "OpenAI"),
    "chatgpt": ("openai", "OpenAI"),
    "anthropic": ("anthropic", "Anthropic"),
    "gemini": ("google", "Google"),
    "vertex_ai": ("google", "Vertex AI"),
    "bedrock": ("amazon", "AWS Bedrock"),
    "bedrock_converse": ("amazon", "AWS Bedrock"),
    "bedrock_mantle": ("amazon", "AWS Bedrock"),
    "dashscope": ("qwen", "DashScope"),
    "xai": ("xai", "xAI"),
    "deepseek": ("deepseek", "DeepSeek"),
    "moonshot": ("kimi", "Moonshot"),
    "zai": ("zai", "Z.ai"),
    "minimax": ("minimax", "MiniMax"),
    "mistral": ("mistral", "Mistral"),
    "github_copilot": ("microsoft", "GitHub Copilot"),
    "vercel_ai_gateway": ("openrouter", "Vercel AI Gateway"),
    "openrouter": ("openrouter", "OpenRouter"),
}
ORG_NAMES: Dict[str, str] = {
    "liquidai": "Liquid AI", "inclusionai": "Ant Group", "ibm-granite": "IBM", "ai21labs": "AI21 Labs",
    "allenai": "Ai2", "internlm": "InternLM", "baidu": "Baidu", "tencent": "Tencent", "apple": "Apple",
    "bytedance-seed": "ByteDance Seed", "meituan-longcat": "Meituan LongCat", "wan-ai": "Alibaba Wan",
    "rednote-hilab": "RedNote", "xiaomimimo": "Xiaomi MiMo", "stepfun-ai": "StepFun", "openbmb": "OpenBMB",
    "black-forest-labs": "Black Forest Labs", "stabilityai": "Stability AI", "microsoft-ai": "Microsoft AI",
}
ARENA_ORGS: Dict[str, str] = {
    "google": "google", "openai": "openai", "anthropic": "anthropic", "xai": "xai", "meta": "meta",
    "microsoft-ai": "microsoft", "microsoft": "microsoft", "deepseek": "deepseek", "alibaba": "qwen",
    "moonshot": "kimi", "zhipu": "zai", "zai": "zai", "mistral": "mistral", "amazon": "amazon",
    "minimax": "minimax", "nvidia": "nvidia", "cohere": "cohere",
}

SCANNER_LABELS: Dict[str, str] = {
    "openrouter": "OpenRouter",
    "huggingface": "Hugging Face",
    "litellm": "LiteLLM registry",
    "models-dev": "models.dev",
    "npm": "npm SDK release",
    "antigravity": "Antigravity desktop build",
    "antigravity-acp": "Antigravity ACP config",
    "lmarena": "LMArena",
    "git-forensics": "SDK git history",
    "kimi-code": "Kimi Code",
    "vllm-registry": "vLLM registry",
    "openai-spec": "OpenAI API spec",
    "pricing-radar": "Official pricing page",
    "github-code-leak": "GitHub benchmark & config",
    "provider-openapi": "Official OpenAPI spec",
    "vertex-ai-quotas": "Vertex AI Quotas registry",
}
_WORD_FIX = {
    "Openai": "OpenAI", "Ai": "AI", "Sdk": "SDK", "Github": "GitHub", "Vllm": "vLLM", "Sglang": "SGLang",
    "Pr": "PR", "Api": "API", "Ct": "CT", "Npm": "npm", "Xai": "xAI", "Llm": "LLM", "Gcp": "GCP",
    "Aws": "AWS", "Deepseek": "DeepSeek", "Minimax": "MiniMax", "Z.ai": "Z.ai", "Day-0": "Day-0",
    "Ibm": "IBM", "Ai21": "AI21", "Internlm": "InternLM", "Minicpm": "MiniCPM", "Longcat": "LongCat",
    "Rednote": "RedNote", "Llama.cpp": "llama.cpp", "Cli": "CLI", "Ide": "IDE", "Eap": "EAP",
}
_SIZE = re.compile(r"^\d+(?:\.\d+)?[mbkt]$")
_PRECISION = {"fp", "bf", "int", "nvfp", "mxfp", "w"}
_DISPLAY_NOISE = re.compile(r"[-_\s](?:NVFP4|MXFP4|FP8|FP4|BF16|FP16|GGUF|AWQ|GPTQ|MLX|INT4|INT8|Diffusers)\b", re.I)
_DISPLAY_SIZE = re.compile(r"[-_\s](?:[AE]?\d+(?:\.\d+)?[MBK])\b", re.I)


def story_key(raw: str) -> str:
    """'openai/gpt-6.1-terra-pro:batch' -> 'gpt-6-1-terra'; 'tencent/Hy-SimulMT-30B-A3B-FP8' -> 'hy-simulmt'."""
    toks = normalize(raw).split("-")
    if toks and toks[0] == "introducing":
        toks = toks[1:]
    out: List[str] = []
    i = 0
    while i < len(toks):
        t, nxt = toks[i], toks[i + 1] if i + 1 < len(toks) else ""
        if _SIZE.match(t):
            i += 1
            continue
        if t in ("a", "e") and _SIZE.match(nxt):  # MoE active-params / effective size: a3b, e4b
            i += 2
            continue
        if t in _PRECISION and nxt.isdigit():
            i += 2
            continue
        out.append(t)
        i += 1
    key = strip_variants("-".join(t for t in out if t))
    toks = key.split("-")
    while len(toks) > 1 and toks[-1] in ("pro", "batch", "interleave"):
        toks.pop()
        key = strip_variants("-".join(toks))
        toks = key.split("-")
    return key


def source_label(card: Dict[str, Any]) -> str:
    scanner = card.get("scanner", "")
    if scanner in SCANNER_LABELS:
        return SCANNER_LABELS[scanner]
    if scanner == "engine-pr-leak":
        engine = str(card.get("header", "")).split()[0].capitalize()
        return f"{_WORD_FIX.get(engine, engine)} pull request"
    head = str(card.get("header", "")).split(" · ")[0]
    head = re.sub(r"\s+(?:DIFF|SCOUT|RADAR)$", "", head.strip(), flags=re.I)
    words = [_WORD_FIX.get(w.capitalize(), w.capitalize()) for w in head.split()]
    return " ".join(words) or scanner


def _model_label(m: Dict[str, Any]) -> str:
    mid = str(m.get("id", ""))
    return str(m.get("name", "")) if (not mid or mid.startswith("org:") or " · " in mid) else mid


def _clean_name(name: str) -> str:
    name = re.sub(r"^[^:]{1,40}:\s+", "", name.strip())  # "OpenAI: GPT-6.1 Terra"
    name = re.sub(r"\s*\([^)]*\)", "", name).strip()
    return name


def _parse(iso: str) -> datetime:
    try:
        dt = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _humanize(key: str) -> str:
    out: List[str] = []
    for t in key.split("-"):
        if t.isdigit() and out and out[-1][-1:].isdigit():
            out[-1] += "." + t
        elif t.isdigit() or len(t) <= 3 and not t.isalpha():
            out.append(t.upper())
        else:
            out.append("DeepSeek" if t == "deepseek" else (t.upper() if t in ("gpt", "glm", "vl", "oss") else t.capitalize()))
    return " ".join(out)


def _fmt_delta(seconds: float) -> str:
    mins = int(seconds // 60)
    if mins < 60:
        return f"{max(mins, 1)} min"
    hours = mins // 60
    if hours < 48:
        return f"{hours} h"
    return f"{hours // 24} days"


def _card_keys(card: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    models = card.get("models") or []
    if card.get("scanner") == "engine-pr-leak":
        # Bare architecture IDs ("LiquidAI/lfm3") add nothing next to "LiquidAI/LFM3-1.7B"
        ids = [str(m.get("id", "")).lower() for m in models]
        models = [m for m in models if not any(o.startswith(str(m.get("id", "")).lower() + "-") for o in ids)]
    for m in models:
        k = story_key(_model_label(m))
        if k:
            out.append((k, m))
    if not out:
        k = story_key(str(card.get("title", ""))) or f"card-{card.get('id')}"
        out.append((k, {"id": card.get("title", ""), "name": card.get("title", "")}))
    return out


def build_stories(
    cards: Iterable[Dict[str, Any]],
    catalog: Optional[ReleasedCatalog] = None,
    now: Optional[datetime] = None,
    pricing_catalog: Optional[PricingCatalog] = None,
) -> List[Dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    pricing_catalog = pricing_catalog or get_pricing_catalog()
    usable = [
        c for c in cards
        if c.get("scanner") not in EXCLUDED_SCANNERS
        and c.get("category") != "subdomain-ct"
        and not str(c.get("id", "")).startswith("web-bundle-aistudio-routes-")
    ]
    non_litellm_keyed = [(c, _card_keys(c)) for c in usable if c.get("scanner") != "litellm"]
    non_litellm_all_keys = {k for _, kms in non_litellm_keyed for k, _ in kms}
    litellm_shared_primaries = {
        kms[0][0]
        for c in usable
        if c.get("scanner") == "litellm"
        for kms in (_card_keys(c),)
        if kms and kms[0][0] in non_litellm_all_keys and not kms[0][1].get("registry_update")
    }
    primaries = {kms[0][0] for _, kms in non_litellm_keyed if kms} | litellm_shared_primaries

    def resolve(k: str) -> Optional[str]:
        if k in primaries:
            return k
        best = None
        for p in primaries:
            if k.startswith(p + "-") and "-" in p and (best is None or len(p) > len(best)):
                best = p
        return best

    groups: Dict[str, Dict[str, Any]] = {}
    for card, kms in non_litellm_keyed:
        primary = kms[0][0]
        per_story: Dict[str, List[Dict[str, Any]]] = {}
        for k, m in kms:
            target = resolve(k) or primary
            per_story.setdefault(target, []).append(m)
        for target, models in per_story.items():
            g = groups.setdefault(target, {"cards": [], "models": []})
            g["cards"].append(card)
            g["models"].extend(models)

    # Process LiteLLM cards: merge entries that confirm an existing story from another source,
    # and group standalone LiteLLM additions by (card, provider_prefix) as "REGISTRY UPDATE" alerts.
    for card in (c for c in usable if c.get("scanner") == "litellm"):
        kms = _card_keys(card)
        per_story: Dict[str, List[Dict[str, Any]]] = {}
        for k, m in kms:
            matched = resolve(k) if not m.get("registry_update") else None
            if matched:
                per_story.setdefault(matched, []).append(m)
            else:
                raw_id = _model_label(m)
                prefix = raw_id.split("/")[0].lower() if "/" in raw_id else "openai"
                short_cid = str(card.get("id", "litellm")).rsplit("-", 1)[-1]
                reg_key = f"litellm-registry-{prefix}-{short_cid}"
                per_story.setdefault(reg_key, []).append(m)
        for target, models in per_story.items():
            g = groups.setdefault(target, {"cards": [], "models": []})
            g["cards"].append(card)
            g["models"].extend(models)

    stories: List[Dict[str, Any]] = []
    for key, g in groups.items():
        story = _make_story(key, g["cards"], g["models"], catalog, pricing_catalog=pricing_catalog)
        if _parse(story["updated_at"]) >= now - STORY_WINDOW:
            stories.append(story)
    stories.sort(key=lambda s: s["detected_at"], reverse=True)
    return stories


def _make_story(
    key: str,
    cards: List[Dict[str, Any]],
    models: List[Dict[str, Any]],
    catalog: Optional[ReleasedCatalog],
    pricing_catalog: Optional[PricingCatalog] = None,
) -> Dict[str, Any]:
    cards = sorted(cards, key=lambda c: c.get("detected_at") or "")
    first = cards[0]
    scanners = {c.get("scanner", "") for c in cards}
    is_litellm_registry_group = key.startswith("litellm-registry-")

    # Provider: most specific lab seen across sources
    lab = next((c for c in cards if c.get("provider_slug") not in GENERIC_PROVIDERS), first)
    provider_name = PROVIDER_NAMES.get(lab.get("provider_slug", ""), "")
    provider_slug = lab.get("provider_slug", "")
    # Arena's model config names the lab: {"id": "org:microsoft-ai · microsoftFalcon"} or {"org": "google"}
    arena_org = next(
        (
            (str(m.get("org") or "") or (str(m["id"])[4:].split(" · ")[0] if str(m.get("id", "")).startswith("org:") else "")).lower()
            for c in cards
            for m in c.get("models") or []
            if m.get("org") or str(m.get("id", "")).startswith("org:")
        ),
        "",
    )
    if not provider_name and arena_org and arena_org not in ("unknown", "none", "null"):
        slug = ARENA_ORGS.get(arena_org, "")
        provider_slug = slug or provider_slug
        provider_name = (ORG_NAMES.get(arena_org) or PROVIDER_NAMES.get(slug)
                         or " ".join(_WORD_FIX.get(w.capitalize(), w.capitalize()) for w in arena_org.split("-")))
    if not provider_name and " · " in str(lab.get("header", "")):
        org = str(lab["header"]).split(" · ")[-1]
        if org.upper() not in ("LIVE MODELS", "MULTI-PROVIDER", "NEXT.JS RSC STREAM", "LIVE DIFF") and not org.startswith("v"):
            provider_name = " ".join(_WORD_FIX.get(w.capitalize(), w.capitalize()) for w in org.split())
    if not provider_name:
        org_ids = [str(m.get("id", "")).split("/")[0].lower() for m in models if "/" in str(m.get("id", ""))]
        org = org_ids[0] if org_ids else ""
        if org in LITELLM_PREFIX_PROVIDERS:
            provider_slug, provider_name = LITELLM_PREFIX_PROVIDERS[org]
        else:
            slug = {"mistralai": "mistral", "moonshotai": "kimi", "deepseek-ai": "deepseek", "meta-llama": "meta",
                    "zai-org": "zai", "minimaxai": "minimax", "qwen": "qwen", "google": "google", "openai": "openai",
                    "nvidia": "nvidia", "microsoft": "microsoft", "xai-org": "xai", "coherelabs": "cohere",
                    "perplexity-ai": "perplexity"}.get(org, "")
            if slug:
                provider_slug, provider_name = slug, PROVIDER_NAMES.get(slug, org)
            elif org:
                provider_name = ORG_NAMES.get(org, org)
        if not provider_name and models:
            m0 = str(models[0].get("id") or "").lower()
            m_dot = re.match(r"^(?:us-gov|us|eu|global|apac|jp|au)\.([a-z0-9-]+)\.", m0)
            if m_dot:
                v_slug = {"xai": "xai", "anthropic": "anthropic", "meta": "meta", "mistral": "mistral", "deepseek": "deepseek", "qwen": "qwen", "amazon": "amazon", "cohere": "cohere"}.get(m_dot.group(1), "amazon")
                provider_slug, provider_name = v_slug, PROVIDER_NAMES.get(v_slug, "AWS Bedrock")

    # Display name: the most-used clean catalog name that maps back to this story
    names: Counter = Counter()
    for c in cards:
        bonus = 2 if c.get("scanner") in ("openrouter", "models-dev", "gateway-radar", "huggingface") else 1
        for m in c.get("models") or []:
            label = _model_label(m)
            if c.get("scanner") in OPEN_WEIGHT_SCANNERS and "/" in label:
                n = label.rsplit("/", 1)[-1].replace("-", " ").replace("_", " ")
            else:
                n = _clean_name(str(m.get("name") or ""))
            if n and key in (story_key(n), story_key(label)):
                names[n] += bonus
    pretty = [n for n in names if " " in n or any(ch.isupper() for ch in n)]
    if pretty:
        title = sorted(pretty, key=lambda n: (-names[n], len(n)))[0]
    else:
        title = _humanize(key)
    model_ids_lower = {str(m.get("id", "")).lower() for m in models}
    if key == "cactus" and any(mid.startswith("kraken-") for mid in model_ids_lower):
        title = "Cactus & Kraken"
    elif key == "claude-donut-eap" and any(mid.startswith("silicon-") for mid in model_ids_lower):
        title = "Claude Donut EAP & Silicon"
    elif key == "hyperion":
        title = "Hyperion"

    variants: List[Dict[str, str]] = []
    by_norm: Dict[str, Dict[str, str]] = {}
    story_prices: List[str] = []
    model_release_dates: List[str] = []
    for m in models:
        label = _model_label(m)
        vid = re.sub(r"^(?:[\w.-]+/)+", "", label)
        vid = re.sub(r"^(?:global|us|eu|apac|jp|au)\.(?:[a-z]+\.)?", "", vid)
        vid = re.sub(r"\s*\((?:in|out):[^)]*\)$", "", vid).strip()
        vk = vid.lower() if is_litellm_registry_group else re.sub(r"^introducing-", "", normalize(vid))
        if not vid:
            continue
        price = str(m.get("pricing") or (pricing_catalog.lookup(label) if pricing_catalog else "") or (pricing_catalog.lookup(vid) if pricing_catalog else "")).strip()
        if price and price not in story_prices:
            story_prices.append(price)
        rel_hit = catalog.released_on(label) if catalog is not None else None
        emb_dt = extract_embedded_date(label) or extract_embedded_date(vid)
        m_rel = str(m.get("released_on") or (rel_hit[0] if rel_hit else "") or emb_dt or "").strip()
        if m_rel and m_rel not in model_release_dates:
            model_release_dates.append(m_rel)
        if vk not in by_norm:
            raw_name = str(m.get("name") or "")
            if raw_name.startswith("Referenced in "):
                raw_name = vid
            clean_n = _clean_name(raw_name or vid) or vid
            # Strip trailing pricing suffix from clean_n if pricing_radar put it in name
            clean_n = re.sub(r"\s+—\s+\$[0-9].*$", "", clean_n).strip()
            entry: Dict[str, str] = {"id": vid, "name": clean_n}
            if m_rel:
                entry["released_on"] = m_rel
            for extra_k in ("host_slot", "uuid", "minted_at", "prev_uuid", "prev_minted_at", "org", "arena_provider"):
                if m.get(extra_k):
                    entry[extra_k] = str(m[extra_k])
            by_norm[vk] = entry
            variants.append(by_norm[vk])
        else:
            if len(vid) < len(by_norm[vk]["id"]):
                by_norm[vk]["id"] = vid
            if m_rel and not by_norm[vk].get("released_on"):
                by_norm[vk]["released_on"] = m_rel
    if not is_litellm_registry_group:
        variants.sort(key=lambda v: (len(v["id"]), v["id"]))
    if is_litellm_registry_group:
        prov_title = provider_name or "Model"
        n_entries = len(variants)
        title = f"LiteLLM {prov_title} Registry Update — {n_entries} {'Entry' if n_entries == 1 else 'Entries'} Detected"
    else:
        if len(variants) > 1:
            title = _DISPLAY_SIZE.sub("", title)
        title = re.sub(r"\s+—\s+\$[0-9].*$", "", title)
        title = _DISPLAY_NOISE.sub("", title).strip(" -_") or title
    story_pricing = ""

    sources: List[Dict[str, Any]] = []
    seen_src: Set[str] = set()
    for c in cards:
        label = source_label(c)
        if label in seen_src:
            continue
        seen_src.add(label)
        link = next((lnk.get("url") for lnk in c.get("links") or [] if lnk.get("url")), "")
        sources.append({
            "label": label,
            "scanner": c.get("scanner", ""),
            "detected_at": c.get("detected_at", ""),
            "title": c.get("title", ""),
            "url": link,
            "backfill": bool(c.get("backfill")),
        })

    first_dt = _parse(first.get("detected_at", ""))
    released = catalog.released_on(key) if (catalog is not None and not is_litellm_registry_group) else None
    earliest_model_rel = min(model_release_dates) if model_release_dates else (released[0] if released else "")
    latest_model_rel = max(model_release_dates) if model_release_dates else earliest_model_rel
    released_on_str = (
        f"{earliest_model_rel} to {latest_model_rel}"
        if (is_litellm_registry_group and earliest_model_rel and latest_model_rel and earliest_model_rel != latest_model_rel)
        else earliest_model_rel
    )

    release_srcs = [c for c in cards if c.get("scanner") in RELEASE_SCANNERS]
    cutoff_str = (first_dt - RELEASE_GRACE).strftime("%Y-%m-%d")
    is_previously_released = bool(earliest_model_rel and earliest_model_rel < cutoff_str)

    # 4-Stage Taxonomy:
    # 1. REGISTRY UPDATE ("registry"): Existing models newly added to LiteLLM (or registry-only additions of older models)
    # 2. UNVERIFIED ("unverified"): Unknown model identifiers from single-source external configs or anonymous/unmapped routers
    # 3. NEW MODEL ("release"): Evidence of a genuinely new release
    # 4. LEAK ("leak"): Reserved for credible evidence of an unreleased model
    is_anonymous = key.startswith("anonymous-") or any(v["id"].lower().startswith("anonymous-") for v in variants)
    is_stealth_gateway = (
        scanners <= {"gateway-radar", "models-dev"}
        and (
            any("stealth codename" in str(c.get("subtitle", "")).lower() for c in cards)
            or (provider_slug in GENERIC_PROVIDERS and not released)
        )
    )
    if is_litellm_registry_group or (scanners <= {"litellm", "models-dev"} and is_previously_released):
        kind = "registry"
    elif scanners <= UNVERIFIED_SCANNERS or is_anonymous or is_stealth_gateway:
        kind = "unverified"
    elif (released and not is_previously_released) or release_srcs or (scanners == {"models-dev"} and not is_previously_released):
        kind = "release"
    else:
        kind = "leak"

    lead = ""
    if kind in ("leak", "release") and first.get("scanner") not in RELEASE_SCANNERS:
        if release_srcs:
            delta = (_parse(release_srcs[0].get("detected_at", "")) - first_dt).total_seconds()
            if delta >= 60:
                lead = f"{_fmt_delta(delta)} before it went live on {source_label(release_srcs[0])}"
        if not lead and released and released[0] > first_dt.strftime("%Y-%m-%d"):
            days = (datetime.fromisoformat(released[0]).replace(tzinfo=timezone.utc) - first_dt).days + 1
            lead = f"{days} day{'s' if days != 1 else ''} before public release"

    # Only codenames that occur in this story's own identifiers (multi-model cards carry others)
    var_toks = {t for v in variants for t in normalize(v["id"]).split("-")}
    codenames = [] if kind == "registry" else sorted({cn for c in cards for cn in (c.get("codenames") or []) if cn in var_toks})
    open_weights = bool(scanners & OPEN_WEIGHT_SCANNERS) and kind != "registry"
    stage_map = {
        "leak": "LEAK",
        "release": "OPEN WEIGHTS" if open_weights else "NEW MODEL",
        "registry": "REGISTRY UPDATE",
        "unverified": "UNVERIFIED",
    }
    stage_word = stage_map.get(kind, "LEAK")

    model_providers = {infer_provider(v["id"])["name"] for v in variants if v.get("id")}
    if len(model_providers) > 1 and not is_litellm_registry_group:
        provider_name = "AI Model Identifiers"
        provider_slug = "multi"
        story_accent = "#6366f1"
    else:
        story_accent = lab.get("accent_color", "#38bdf8")

    return {
        "id": f"story-{key}",
        "group": key,
        "kind": kind,
        "open_weights": open_weights,
        "title": title,
        "provider_slug": provider_slug,
        "provider_name": provider_name,
        "accent_color": story_accent,
        "detected_at": first.get("detected_at", ""),
        "updated_at": cards[-1].get("detected_at", ""),
        "first_source": sources[0]["label"] if sources else "",
        "lead": lead,
        "released_on": released_on_str,
        "pricing": story_pricing,
        "codenames": codenames,
        "models": variants[:40],
        "sources": sources,
        "source_count": len(sources),
        "backfill": all(s["backfill"] for s in sources),
        "header": f"{stage_word} · {provider_name.upper()}".strip(" ·"),
        "card_ids": [c["id"] for c in cards],
    }


def story_x_text(story: Dict[str, Any]) -> str:
    """Post copy that fits X's 280-character limit (optional lines are dropped until it fits)."""
    when = _parse(story["detected_at"]).strftime("%d %b %H:%M UTC")
    tag = {
        "leak": "🟠 LEAK",
        "release": "🟢 NEW MODEL",
        "registry": "🔵 REGISTRY UPDATE",
        "unverified": "⚪ UNVERIFIED",
    }.get(story["kind"], "🟠 LEAK")
    by_suffix = (
        f" by {story['provider_name']}"
        if story.get("provider_name") and story["kind"] != "registry"
        else ""
    )
    head = f"{tag}: {story['title']}{by_suffix}"
    others = [s["label"] for s in story["sources"][1:]]
    optional: List[Tuple[int, str]] = []  # (drop priority, line); highest priority dropped first
    if story.get("released_on"):
        optional.append((1, f"📅 First released: {story['released_on']}"))
    if story.get("lead"):
        optional.append((3, f"⏱ {story['lead']}"))
    if others:
        extra = f" +{len(others) - 3}" if len(others) > 3 else ""
        optional.append((4, f"Confirmed by {', '.join(others[:3])}{extra}"))
    if story.get("codenames"):
        optional.append((5, f"Codename: {', '.join(story['codenames'][:3])}"))
    ckpt_models = [v for v in story["models"] if v.get("uuid")]
    if ckpt_models:
        if len(ckpt_models) == 1:
            optional.append((2, f"🆔 UUID: {ckpt_models[0]['uuid']}"))
        else:
            optional.append((2, "🆔 UUIDs: " + ", ".join(v["uuid"][:8] for v in ckpt_models[:3])))
        if ckpt_models[0].get("prev_uuid"):
            optional.append((7, f"📜 Prev: {ckpt_models[0]['prev_uuid'][:8]}"))
    else:
        ids = [v["id"] for v in story["models"][:3]]
        if len(story["models"]) > 1:
            optional.append((6, f"IDs: {', '.join(ids)}" + (f" +{len(story['models']) - 3}" if len(story["models"]) > 3 else "")))
    while True:
        lines = [head, "", f"First detected {when} in {story['first_source']}"]
        lines += [line for _, line in sorted(optional)]
        lines += ["", "via @StatsWire"]
        text = "\n".join(lines)
        if len(text) <= 280 or not optional:
            return text
        optional.remove(max(optional))
