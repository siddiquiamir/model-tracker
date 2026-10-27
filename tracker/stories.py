"""Collapse per-source cards into one "story" per model (one launch = one entry, many confirmations)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from tracker.novelty import ReleasedCatalog, normalize, strip_variants

# Scanners whose sighting means the model is publicly usable (a release, not a leak)
RELEASE_SCANNERS: Set[str] = {"openrouter", "huggingface", "gateway-radar"}
OPEN_WEIGHT_SCANNERS: Set[str] = {"huggingface", "engine-pr-leak"}
EXCLUDED_SCANNERS: Set[str] = {"cert-transparency-snapshot"}
GENERIC_PROVIDERS: Set[str] = {"modelsdev", "openrouter", "opensource", ""}
STORY_WINDOW = timedelta(days=21)

PROVIDER_NAMES: Dict[str, str] = {
    "google": "Google", "anthropic": "Anthropic", "openai": "OpenAI", "xai": "xAI", "meta": "Meta",
    "mistral": "Mistral", "deepseek": "DeepSeek", "qwen": "Qwen", "kimi": "Moonshot", "zai": "Z.ai",
    "minimax": "MiniMax", "nvidia": "NVIDIA", "microsoft": "Microsoft", "amazon": "Amazon",
    "cohere": "Cohere", "perplexity": "Perplexity", "cursor": "Cursor", "thinkingmachines": "Thinking Machines",
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
    "cert-transparency": "TLS certificate log",
    "kimi-code": "Kimi Code",
    "vllm-registry": "vLLM registry",
}
_WORD_FIX = {
    "Openai": "OpenAI", "Ai": "AI", "Sdk": "SDK", "Github": "GitHub", "Vllm": "vLLM", "Sglang": "SGLang",
    "Pr": "PR", "Api": "API", "Ct": "CT", "Npm": "npm", "Xai": "xAI", "Llm": "LLM", "Gcp": "GCP",
    "Aws": "AWS", "Deepseek": "DeepSeek", "Minimax": "MiniMax", "Z.ai": "Z.ai", "Day-0": "Day-0",
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
            out.append(t.upper() if t in ("gpt", "glm", "vl", "oss") else t.capitalize())
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
    if card.get("scanner") == "cert-transparency":
        return [(f"ct-{card['id']}", m) for m in card.get("models") or [{}]]
    out: List[Tuple[str, Dict[str, Any]]] = []
    for m in card.get("models") or []:
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
) -> List[Dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    usable = [c for c in cards if c.get("scanner") not in EXCLUDED_SCANNERS]
    keyed = [(c, _card_keys(c)) for c in usable]
    primaries = {kms[0][0] for _, kms in keyed}

    def resolve(k: str) -> Optional[str]:
        if k in primaries:
            return k
        best = None
        for p in primaries:
            if k.startswith(p + "-") and "-" in p and (best is None or len(p) > len(best)):
                best = p
        return best

    groups: Dict[str, Dict[str, Any]] = {}
    for card, kms in keyed:
        primary = kms[0][0]
        per_story: Dict[str, List[Dict[str, Any]]] = {}
        for k, m in kms:
            target = resolve(k) or primary
            per_story.setdefault(target, []).append(m)
        for target, models in per_story.items():
            g = groups.setdefault(target, {"cards": [], "models": []})
            g["cards"].append(card)
            g["models"].extend(models)

    stories: List[Dict[str, Any]] = []
    for key, g in groups.items():
        story = _make_story(key, g["cards"], g["models"], catalog)
        if _parse(story["updated_at"]) >= now - STORY_WINDOW:
            stories.append(story)
    stories.sort(key=lambda s: s["detected_at"], reverse=True)
    return stories


def _make_story(
    key: str, cards: List[Dict[str, Any]], models: List[Dict[str, Any]], catalog: Optional[ReleasedCatalog]
) -> Dict[str, Any]:
    cards = sorted(cards, key=lambda c: c.get("detected_at") or "")
    first = cards[0]
    scanners = {c.get("scanner", "") for c in cards}

    # Provider: most specific lab seen across sources
    lab = next((c for c in cards if c.get("provider_slug") not in GENERIC_PROVIDERS), first)
    provider_name = PROVIDER_NAMES.get(lab.get("provider_slug", ""), "")
    if not provider_name and " · " in str(lab.get("header", "")):
        org = str(lab["header"]).split(" · ")[-1]
        if org.upper() not in ("LIVE MODELS", "MULTI-PROVIDER") and not org.startswith("v"):
            provider_name = " ".join(_WORD_FIX.get(w.capitalize(), w.capitalize()) for w in org.split())
    provider_slug = lab.get("provider_slug", "")
    if not provider_name:
        org_ids = [str(m.get("id", "")).split("/")[0].lower() for m in models if "/" in str(m.get("id", ""))]
        org = org_ids[0] if org_ids else ""
        slug = {"mistralai": "mistral", "moonshotai": "kimi", "deepseek-ai": "deepseek", "meta-llama": "meta",
                "zai-org": "zai", "minimaxai": "minimax", "qwen": "qwen", "google": "google", "openai": "openai",
                "nvidia": "nvidia", "microsoft": "microsoft", "xai-org": "xai"}.get(org, "")
        if slug:
            provider_slug, provider_name = slug, PROVIDER_NAMES.get(slug, org)
        elif org and not key.startswith("ct-"):
            provider_name = org

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
    if key.startswith("ct-"):
        title = first.get("title", key)
    elif pretty:
        title = sorted(pretty, key=lambda n: (-names[n], len(n)))[0]
    else:
        title = _humanize(key)

    variants: List[Dict[str, str]] = []
    by_norm: Dict[str, Dict[str, str]] = {}
    for m in models:
        label = _model_label(m)
        if key.startswith("ct-"):
            vid, vk = label, label
        else:
            vid = re.sub(r"^(?:[\w.-]+/)+", "", label)
            vid = re.sub(r"^(?:global|us|eu|apac|jp|au)\.(?:[a-z]+\.)?", "", vid)
            vk = re.sub(r"^introducing-", "", normalize(vid))
        if not vid:
            continue
        if vk not in by_norm:
            by_norm[vk] = {"id": vid, "name": _clean_name(str(m.get("name") or vid)) or vid}
            variants.append(by_norm[vk])
        elif len(vid) < len(by_norm[vk]["id"]):
            by_norm[vk]["id"] = vid
    variants.sort(key=lambda v: (len(v["id"]), v["id"]))
    if len(variants) > 1:
        title = _DISPLAY_SIZE.sub("", title)
    title = _DISPLAY_NOISE.sub("", title).strip(" -_") or title

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

    released = catalog.released_on(key) if catalog is not None and not key.startswith("ct-") else None
    release_srcs = [c for c in cards if c.get("scanner") in RELEASE_SCANNERS]
    kind = "release" if (released or release_srcs) else "leak"

    lead = ""
    first_dt = _parse(first.get("detected_at", ""))
    if first.get("scanner") not in RELEASE_SCANNERS:
        if release_srcs:
            delta = (_parse(release_srcs[0].get("detected_at", "")) - first_dt).total_seconds()
            if delta >= 60:
                lead = f"{_fmt_delta(delta)} before it went live on {source_label(release_srcs[0])}"
        if not lead and released and released[0] > first_dt.strftime("%Y-%m-%d"):
            days = (datetime.fromisoformat(released[0]).replace(tzinfo=timezone.utc) - first_dt).days + 1
            lead = f"{days} day{'s' if days != 1 else ''} before public release"

    # Only codenames that occur in this story's own identifiers (multi-model cards carry others)
    var_toks = {t for v in variants for t in normalize(v["id"]).split("-")}
    codenames = sorted({cn for c in cards for cn in (c.get("codenames") or []) if cn in var_toks})
    open_weights = bool(scanners & OPEN_WEIGHT_SCANNERS)
    stage_word = "LEAK" if kind == "leak" else ("OPEN WEIGHTS" if open_weights else "RELEASE")

    return {
        "id": f"story-{key}",
        "group": key,
        "kind": kind,
        "open_weights": open_weights,
        "title": title,
        "provider_slug": provider_slug,
        "provider_name": provider_name,
        "accent_color": lab.get("accent_color", "#38bdf8"),
        "detected_at": first.get("detected_at", ""),
        "updated_at": cards[-1].get("detected_at", ""),
        "first_source": sources[0]["label"] if sources else "",
        "lead": lead,
        "released_on": released[0] if released else "",
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
    tag = {"leak": "🟠 LEAK", "release": "🟢 NEW"}[story["kind"]]
    head = f"{tag}: {story['title']}" + (f" by {story['provider_name']}" if story.get("provider_name") else "")
    others = [s["label"] for s in story["sources"][1:]]
    optional: List[Tuple[int, str]] = []  # (drop priority, line); highest priority dropped first
    if story.get("lead"):
        optional.append((1, f"⏱ {story['lead']}"))
    if others:
        extra = f" +{len(others) - 3}" if len(others) > 3 else ""
        optional.append((2, f"Confirmed by {', '.join(others[:3])}{extra}"))
    if story.get("codenames"):
        optional.append((3, f"Codename: {', '.join(story['codenames'][:3])}"))
    ids = [v["id"] for v in story["models"][:3]]
    if len(story["models"]) > 1:
        optional.append((4, f"IDs: {', '.join(ids)}" + (f" +{len(story['models']) - 3}" if len(story["models"]) > 3 else "")))
    while True:
        lines = [head, "", f"First spotted {when} in {story['first_source']}"]
        lines += [line for _, line in sorted(optional)]
        lines += ["", "via @StatsWire"]
        text = "\n".join(lines)
        if len(text) <= 280 or not optional:
            return text
        optional.remove(max(optional))
