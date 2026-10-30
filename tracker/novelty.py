"""Novelty filter: drops already-released models from cards and flags unknown codename hints.

The reference of "already public" is the models.dev catalog (~9k models from 200+ providers,
every entry with a release_date). A model on a card is considered OLD when it was publicly
released more than RELEASE_GRACE before the card was detected, matched by:
  1. exact normalized name (after stripping effort/quant/date variant suffixes),
  2. family prefix (e.g. "ernie-5-0" when "ernie-5-0-thinking-preview" shipped long ago),
  3. version floor (e.g. "gpt-5-chat" when the "gpt" family already shipped major version 6),
  4. the static legacy rules in extractor.is_legacy_model_id.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from tracker.extractor import is_legacy_model_id

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
CATALOG_CACHE = ROOT_DIR / ".cache" / "released_catalog.json"
HINTS_FILE = ROOT_DIR / "data" / "hints.json"
MODELS_DEV_URL = "https://models.dev/api.json"
CATALOG_TTL = timedelta(hours=6)
CATALOG_FORMAT = 2  # bump whenever normalize() changes so cached keys are rebuilt
RELEASE_GRACE = timedelta(days=7)
HF_PUBLIC_GRACE = timedelta(days=30)
# Cards that reference Hugging Face repos by "org/repo" (checked against the repo's public createdAt)
HF_REPO_SCANNERS: Set[str] = {"engine-pr-leak"}

# Scanners whose card "models" are not model identifiers
NON_MODEL_SCANNERS: Set[str] = set()
# Public repo releases: every new product name is "unknown", so codename tagging would only add noise
NO_CODENAME_SCANNERS: Set[str] = {"huggingface"}

# Trailing tokens that describe a deployment variant of the same model, not a different model
VARIANT_TOKENS: Set[str] = {
    "high", "low", "medium", "xhigh", "minimal", "none", "max", "thinking", "reasoning", "nonreasoning",
    "non", "instant", "fast", "chat", "latest", "preview", "exp", "experimental", "beta", "alpha",
    "tf", "teamfood", "fp8", "fp4", "nvfp4", "bf16", "fp16", "int4", "int8", "awq", "gptq", "gguf",
    "mlx", "it", "instruct", "free", "online", "tiered", "router", "default", "base", "hf", "local",
}
# Tokens that are generic model-naming vocabulary and never a codename on their own
GENERIC_TOKENS: Set[str] = VARIANT_TOKENS | {
    "pro", "flash", "lite", "mini", "nano", "micro", "small", "large", "medium", "ultra", "plus", "turbo",
    "image", "images", "imagine", "vision", "audio", "voice", "video", "realtime", "live", "tts", "stt",
    "asr", "omni", "embedding", "embed", "rerank", "search", "deep", "research", "code", "coder", "codex",
    "agent", "computer", "use", "tools", "tool", "vl", "next", "edit", "mode", "native", "model", "models",
    "open", "oss", "next", "release", "staging", "internal", "test", "eval", "evals", "dev", "prod",
    "global", "us", "eu", "au", "apac", "jp", "regional", "version", "new", "final", "response",
    "concise", "visibles", "permissive", "disabled", "enabled", "cyber", "safety", "teamfood",
    "introducing", "with", "and", "for", "the", "bon", "le", "dense", "moe", "sparse", "distill",
    "robotics", "er", "gemma", "llama", "qwen", "mistral", "claude", "gemini", "gpt", "grok", "kimi",
    "glm", "deepseek", "minimax", "ernie", "hunyuan", "doubao", "seed", "nemotron", "nvidia", "phi",
    "command", "sonnet", "opus", "haiku", "sora", "veo", "imagen", "lyria", "chirp", "flux", "banana",
}

_DATE_TOKEN = re.compile(r"^(?:\d{4,8}|20\d{2}-\d{2}(?:-\d{2})?)$")
_PREFIX_PATH = re.compile(r"^(?:[a-z0-9_-]+/)+")
_DOTTED_VENDOR = re.compile(r"^(?:[a-z]+\.)+(?=[a-z])")


def normalize(raw: str) -> str:
    """'us.anthropic.claude-sonnet-4-5-20250929-v1:0' -> 'claude-sonnet-4-5-v-1'; 'GPT-5.4 mini (High)' -> 'gpt-5-4-mini'."""
    s = (raw or "").strip().lower()
    s = re.sub(r"\([^)]*\)|\[[^\]]*\]", " ", s)
    s = _PREFIX_PATH.sub("", s)
    s = re.split(r"[:@]", s, maxsplit=1)[0]
    s = _DOTTED_VENDOR.sub("", s)
    s = re.sub(r"(?<=[a-z])(?=\d)", "-", s)
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    toks = [t for t in s.split("-") if t and not _DATE_TOKEN.match(t)]
    out: List[str] = []
    for i, t in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        if t == "v" and nxt.isdigit():  # ideogram-v2 == ideogram 2
            continue
        if t == "0" and out and out[-1].isdigit():  # 2.0 == 2
            continue
        out.append(t)
    return "-".join(out)


def strip_variants(key: str) -> str:
    toks = key.split("-")
    while len(toks) > 1 and (
        toks[-1] in VARIANT_TOKENS or (toks[-1].isdigit() and len(toks) > 2 and toks[-2] in VARIANT_TOKENS)
    ):
        toks.pop()
    return "-".join(toks)


def family_version(key: str) -> Tuple[str, Optional[int]]:
    """'claude-sonnet-4-5' -> ('claude-sonnet', 4); 'gpt-oss-120b' -> ('gpt-oss', None)."""
    toks = key.split("-")
    fam: List[str] = []
    for i, t in enumerate(toks):
        if t.isdigit():
            if fam and len(t) <= 2:
                return "-".join(fam), int(t)
            return "-".join(fam), None
        if not t.isalpha():
            return "-".join(fam), None
        fam.append(t)
    return "-".join(fam), None


class ReleasedCatalog:
    def __init__(self, release: Dict[str, str], extra_public_names: Iterable[str] = ()) -> None:
        self.release = release  # normalized key -> earliest release date (YYYY-MM-DD)
        self.vocab: Set[str] = set()
        self.family_majors: Dict[str, List[Tuple[int, str]]] = {}
        self.prefix_min: Dict[str, str] = {}
        for name in extra_public_names:
            self.vocab.update(t for t in normalize(str(name)).split("-") if t.isalpha())
        for key, date in release.items():
            self.vocab.update(t for t in key.split("-") if t.isalpha())
            fam, major = family_version(key)
            if fam and major is not None and len(fam) >= 2:
                self.family_majors.setdefault(fam, []).append((major, date))
            toks = key.split("-")
            for n in range(2, len(toks)):
                p = "-".join(toks[:n])
                if p not in self.prefix_min or date < self.prefix_min[p]:
                    self.prefix_min[p] = date

    @classmethod
    def from_models_dev(cls, data: Dict[str, Any], extra_public_names: Iterable[str] = ()) -> "ReleasedCatalog":
        release: Dict[str, str] = {}
        for prov in data.values():
            if not isinstance(prov, dict):
                continue
            for mid, m in (prov.get("models") or {}).items():
                if not isinstance(m, dict):
                    continue
                date = str(m.get("release_date") or "")[:10]
                if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
                    continue
                for raw in (mid, m.get("id") or "", m.get("canonical_model_id") or "", m.get("name") or ""):
                    key = strip_variants(normalize(str(raw)))
                    if key and "-" in key:
                        if key not in release or date < release[key]:
                            release[key] = date
        return cls(release, extra_public_names)

    def released_on(self, raw: str) -> Optional[Tuple[str, str]]:
        """Return (date, reason) when the model is already public, else None."""
        key = normalize(raw)
        if not key:
            return None
        base = strip_variants(key)
        for k in (key, base):
            if k in self.release:
                return self.release[k], f"released as {k}"
        if any(c.isdigit() for c in base) and base.count("-") >= 1 and base in self.prefix_min:
            return self.prefix_min[base], f"family {base} shipped"
        fam, major = family_version(base)
        if fam and major is not None and fam in self.family_majors:
            # Two full generations behind the shipped frontier is never a leak (gpt-4 vs gpt-6);
            # one generation behind can still be a pending lower tier (gemini-3.8-flash after gemini-4).
            newer = [d for (mj, d) in self.family_majors[fam] if mj >= major + 2]
            if newer:
                return min(newer), f"{fam} {major} superseded"
        return None

    def unknown_tokens(self, raw: str) -> List[str]:
        toks = normalize(raw).split("-")
        out: List[str] = []
        for i, t in enumerate(toks):
            if not t.isalpha() or len(t) < 4 or t in self.vocab or t in GENERIC_TOKENS:
                continue
            if i == 0 and len(toks) > 1 and toks[1].isdigit():
                continue  # 'ming-3-0-asr': leading word + version is a (new) family name, not a codename
            out.append(t)
        return out


_RELEASE: Optional[Dict[str, str]] = None
_RELEASE_AT: Optional[datetime] = None


def _release_map() -> Optional[Dict[str, str]]:
    """models.dev release map, cached in memory and on disk; stale cache is used when the fetch fails."""
    global _RELEASE, _RELEASE_AT
    now = datetime.now(timezone.utc)
    if _RELEASE is not None and _RELEASE_AT and now - _RELEASE_AT < CATALOG_TTL:
        return _RELEASE
    cached: Optional[Dict[str, Any]] = None
    try:
        cached = json.loads(CATALOG_CACHE.read_text(encoding="utf-8"))
    except Exception:
        cached = None
    if cached and cached.get("format") == CATALOG_FORMAT and now - datetime.fromisoformat(cached["fetched_at"]) < CATALOG_TTL:
        _RELEASE, _RELEASE_AT = cached["release"], datetime.fromisoformat(cached["fetched_at"])
        return _RELEASE
    try:
        req = urllib.request.Request(MODELS_DEV_URL, headers={"User-Agent": "ModelPulse/2.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = ReleasedCatalog.from_models_dev(json.loads(resp.read().decode("utf-8"))).release
        CATALOG_CACHE.parent.mkdir(parents=True, exist_ok=True)
        CATALOG_CACHE.write_text(
            json.dumps({"format": CATALOG_FORMAT, "fetched_at": now.isoformat(), "release": release}), encoding="utf-8"
        )
        _RELEASE, _RELEASE_AT = release, now
    except Exception as exc:
        print(f"[novelty] models.dev catalog fetch failed: {exc}")
        if cached and cached.get("format") == CATALOG_FORMAT:
            _RELEASE, _RELEASE_AT = cached["release"], now
    return _RELEASE


def get_catalog(extra_public_names: Iterable[str] = ()) -> Optional[ReleasedCatalog]:
    """Catalog of released models; extra_public_names only widen the codename vocabulary."""
    release = _release_map()
    if release is None:
        return None
    return ReleasedCatalog(release, extra_public_names)


_HF_CACHE = ROOT_DIR / ".cache" / "hf_created.json"


def hf_created_at(repo_id: str) -> str:
    """createdAt of a public HF repo ('' when private/missing/unreachable). Cached on disk."""
    try:
        cache: Dict[str, str] = json.loads(_HF_CACHE.read_text(encoding="utf-8"))
    except Exception:
        cache = {}
    if repo_id in cache:
        return cache[repo_id]
    created = ""
    try:
        url = f"https://huggingface.co/api/models/{urllib.parse.quote(repo_id, safe='/')}"
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ModelPulse/2.0"}), timeout=8) as resp:
            created = str(json.loads(resp.read().decode("utf-8")).get("createdAt") or "")
    except urllib.error.HTTPError as exc:
        if exc.code not in (401, 404):
            return ""
    except Exception:
        return ""
    cache[repo_id] = created
    _HF_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _HF_CACHE.write_text(json.dumps(cache), encoding="utf-8")
    return created


def load_watchlist() -> Set[str]:
    try:
        return {str(w).strip().lower() for w in json.loads(HINTS_FILE.read_text(encoding="utf-8")).get("codenames", [])}
    except Exception:
        return set()


def _model_label(m: Dict[str, Any]) -> str:
    mid = str(m.get("id", ""))
    if not mid or mid.startswith("org:") or " · " in mid:
        return str(m.get("name", ""))
    return mid


def _parse_dt(iso: str) -> datetime:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def is_old_model(raw: str, detected_at: datetime, catalog: Optional[ReleasedCatalog]) -> Optional[str]:
    if is_legacy_model_id(raw.lower()) or is_legacy_model_id(normalize(raw)):
        return "legacy generation"
    if catalog is None:
        return None
    hit = catalog.released_on(raw)
    if hit and hit[0] < (detected_at - RELEASE_GRACE).strftime("%Y-%m-%d"):
        return f"{hit[1]} ({hit[0]})"
    return None


def apply(cards: Iterable[Dict[str, Any]], catalog: Optional[ReleasedCatalog] = None) -> List[Dict[str, Any]]:
    """Strip already-released models from every card, drop emptied cards, tag codename hints."""
    catalog = catalog if catalog is not None else get_catalog()
    watch = load_watchlist()
    out: List[Dict[str, Any]] = []
    for card in cards:
        if card.get("scanner") in NON_MODEL_SCANNERS or not card.get("models"):
            out.append(card)
            continue
        det = _parse_dt(card.get("detected_at") or "")
        kept: List[Dict[str, Any]] = []
        removed: List[str] = []
        for m in card["models"]:
            label = _model_label(m)
            if label and is_old_model(label, det, catalog):
                removed.append(label)
            elif card.get("scanner") in HF_REPO_SCANNERS and re.fullmatch(r"[\w.-]+/[\w.-]+", label):
                created = hf_created_at(label)
                if created and _parse_dt(created) < det - HF_PUBLIC_GRACE:
                    removed.append(label)
                else:
                    kept.append(m)
            else:
                kept.append(m)
        if not kept:
            continue
        if removed:
            card["models"] = kept
            card["filtered_released"] = len(removed)
            first = _model_label(kept[0])
            for r in removed:
                if r and r in card.get("title", ""):
                    card["title"] = card["title"].replace(r, first)
        # Codename flags are sticky: once a card was flagged, a later public release does not unflag it
        hints: Set[str] = set(card.get("codenames") or [])
        for m in kept if card.get("scanner") not in NO_CODENAME_SCANNERS else []:
            label = _model_label(m)
            if catalog is not None and catalog.released_on(label):
                continue  # already-public identifier (released within the grace window): no codename flag
            key_toks = set(normalize(label).split("-"))
            hints.update(t for t in key_toks if t in watch and (catalog is None or t not in catalog.vocab))
            if catalog is not None:
                hints.update(catalog.unknown_tokens(label))
        if hints:
            card["codenames"] = sorted(hints)
        out.append(card)
    return out
