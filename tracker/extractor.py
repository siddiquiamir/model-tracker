"""Binary & bundle string extraction, ELF64 .rodata Range slicing, and model grammar cleaning."""

from __future__ import annotations

import hashlib
import pathlib
import re
import struct
import urllib.request
from typing import Dict, List, Optional, Set

CACHE_DIR = pathlib.Path(__file__).resolve().parent.parent / ".cache"

# Valid hyphen-separated tokens that can appear in compiled-in model identifiers.
# Used to strip trailing neighbor strings from Go's length-sorted .rodata string table.
VALID_MODEL_TOKENS: Set[str] = {
    # Tiers & sizes
    "pro", "flash", "ultra", "lite", "mini", "nano", "max", "high", "xhigh", "medium", "low",
    "extra", "plus", "base", "small", "large", "huge", "tiny", "micro", "super",
    # Lifecycle & channels
    "preview", "exp", "experimental", "latest", "beta", "alpha", "rc", "nightly",
    "stable", "instant", "spark", "001", "002", "003", "v1", "v2", "v3", "v4", "r1", "r2",
    # Capabilities & modalities
    "thinking", "reasoning", "non", "fast", "turbo", "instruct", "chat", "vision",
    "audio", "realtime", "tts", "stt", "image", "video", "voice", "imagine", "coder", "code",
    "robotics", "omni", "search", "live", "native", "embed", "embedding", "multi", "agent", "build", "composer",
    "edit", "inpaint", "transcribe", "guard", "reward", "vl", "moe", "deep", "research",
    # Family code-names, noble gases, periodic table elements & series (Argon, Carbon, Fable, etc.)
    "argon", "helium", "neon", "krypton", "xenon", "radon",
    "carbon", "lithium", "beryllium", "boron", "nitrogen", "oxygen", "silicon", "cobalt", "titanium",
    "fable", "opus", "sonnet", "haiku", "mythos", "fennec", "capybara", "orion", "strawberry", "behemoth",
    "astra", "sol", "luna", "terra", "sunburst", "flare", "daybreak", "rosalind", "heisenberg", "glacier", "arcanine",
    "blue", "red", "translate",
    "aurora", "vega", "stella", "eclipse", "sirius", "hyperion", "titan", "atlas",
    "solaris", "nebula", "cosmos", "nova", "apex", "zenith", "horizon", "pegasus",
    "maas", "tiered", "customtools", "windsurf", "debug", "clip", "er", "oss",
    "banana", "jarvis", "sc", "1p", "thoughts", "nemotron", "pixtral", "codestral",
    "ministral", "magistral", "devstral", "voxtral", "command", "aya", "solar",
    "jamba", "hermes", "mercury", "kimi", "k3", "glm", "minimax", "mimo", "step",
    "mai", "muse", "wonder", "lightning", "swe", "obsidian", "theia", "slate",
    # Internal Google ACP / Teamfood / Discovery Doc tokens
    "teamfood", "tf", "barium", "discovery", "math", "cyber", "permissive",
    "router", "latency", "benchmark", "disabled", "bon", "le", "concise",
    "visibles", "final", "response", "di", "v7", "mode", "a", "b", "c", "g",
}

EXCLUDED_EXACT: Set[str] = {
    "gemini-api",
    "gemini-cli",
    "gemini-plugin",
    "gemini-extension",
    "gemini-edit-images",
    "gemini-enterprise-agent",
    "gemini-enterprise-agent-platform",
    "gemini-robotics",
    "gemini-2",
    "gemini-3",
    "gemini-4",
    "claude-plugin",
    "claude-code",
    "claude-sdk",
    "claude-sonnet",
    "claude-opus",
    "claude-haiku",
    "claude-fable",
    "claude-mythos",
    "claude-tag",
    "gpt-oss",
    "gpt-image",
    "gpt-live",
    "gpt-realtime",
    "gpt-4",
    "gpt-5",
    "grok-3",
    "grok-4",
}


def is_legacy_model_id(model_id: str) -> bool:
    """Return True if a model ID belongs to a 2024/2025 legacy generation and should not trigger 2026 leak cards."""
    m = model_id.lower()
    if re.search(r"(?:2023|2024|2025)", m):
        return True
    if m.startswith((
        "gemini-1.", "gemini-1-", "gemini-2.0", "gemini-2-0", "gemini-2.5", "gemini-2-5",
        "claude-2", "claude-3", "claude-sonnet-4", "claude-opus-4", "claude-haiku-4",
        "gpt-3", "gpt-4", "o1", "o3", "o4-mini",
        "grok-1", "grok-2", "grok-3", "llama-2", "llama-3", "llama3",
    )):
        return True
    return False


def fetch_range(url: str, start: int, end: int, timeout: int = 20) -> bytes:
    """Fetch an inclusive byte range [start, end] from an HTTP server supporting Range requests."""
    req = urllib.request.Request(
        url,
        headers={
            "Range": f"bytes={start}-{end}",
            "User-Agent": "ModelPulse-Tracker/2.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_elf_rodata_slice(url: str, cache_key: Optional[str] = None, max_bytes: int = 4_500_000) -> bytes:
    """
    Extract the string table slice of the .rodata section from a remote ELF64 binary
    using HTTP Range requests (~2.5-4 MB instead of downloading ~190 MB).
    Caches slices locally in .cache/ for instant repeat diffs.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = cache_key or hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    cache_file = CACHE_DIR / f"rodata_{key}.bin"
    if cache_file.exists() and cache_file.stat().st_size > 100_000:
        return cache_file.read_bytes()

    ehdr = fetch_range(url, 0, 63)
    if len(ehdr) < 64 or ehdr[:4] != b"\x7fELF":
        raise ValueError(f"Not a valid ELF64 binary at {url}")

    (e_shoff,) = struct.unpack_from("<Q", ehdr, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", ehdr, 58)

    shdrs_len = e_shentsize * e_shnum
    shdrs = fetch_range(url, e_shoff, e_shoff + shdrs_len - 1)

    str_sh_off = e_shstrndx * e_shentsize
    shstr_offset, shstr_size = struct.unpack_from("<QQ", shdrs, str_sh_off + 24)
    shstrtab = fetch_range(url, shstr_offset, shstr_offset + shstr_size - 1)

    rodata_offset = 0
    rodata_size = 0
    for i in range(e_shnum):
        off = i * e_shentsize
        (sh_name,) = struct.unpack_from("<I", shdrs, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", shdrs, off + 24)
        end_idx = shstrtab.find(b"\x00", sh_name)
        sec_name = shstrtab[sh_name:end_idx].decode("ascii", "ignore")
        if sec_name == ".rodata":
            rodata_offset = sh_offset
            rodata_size = sh_size
            break

    if not rodata_offset:
        raise ValueError(f"No .rodata section found in {url}")

    slice_len = min(rodata_size, max_bytes)
    data = fetch_range(url, rodata_offset, rodata_offset + slice_len - 1, timeout=30)
    cache_file.write_bytes(data)
    return data


def clean_go_model_id(raw: str) -> str:
    """
    Clean a raw model identifier extracted from Go's un-delimited .rodata string table
    or minified JS bundles, stripping adjacent neighbor tokens and legacy 2024/2025 IDs.
    """
    raw = raw.strip(".-_ \t\r\n\"'`")
    parts = raw.split("-")
    if len(parts) < 2:
        return ""

    prefix = parts[0].lower()
    second = parts[1].lower()

    if prefix in {"gemini", "grok", "qwen", "llama", "lyria", "veo", "imagen", "gemma", "kimi", "glm", "minimax"}:
        if not (re.fullmatch(r"[0-9a-z]+(?:\.[0-9a-z]+)?", second) or second in VALID_MODEL_TOKENS):
            return ""
    elif prefix == "claude":
        has_version_after = len(parts) >= 3 and bool(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", parts[2]))
        if (
            second not in VALID_MODEL_TOKENS
            and not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", second)
            and not (has_version_after and re.fullmatch(r"[a-z]{3,12}", second))
        ):
            return ""
    elif prefix == "gpt":
        if not (
            (re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[a-z]?", second) and not re.fullmatch(r"[56789][0-9]", second))
            or second in {"oss", "image", "audio", "realtime", "live", "daybreak", "rosalind", "aurora", "astra", "sol", "luna", "terra"}
        ):
            return ""
    elif prefix == "mai":
        if second not in {"code", "voice", "vision", "omni", "1", "2", "3", "4"}:
            return ""
    elif prefix == "composer":
        if not re.fullmatch(r"[2345](?:\.[0-9]+)?", second):
            return ""
    elif prefix == "fable":
        if not re.fullmatch(r"[567](?:\.[0-9]+)?", second):
            return ""

    out = [prefix, second]
    for tok in parts[2:]:
        tok_l = tok.lower()
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?(?:[bkm]|_[0-9]+[bkm])?", tok_l):
            out.append(tok_l)
        elif tok_l in VALID_MODEL_TOKENS:
            out.append(tok_l)
        else:
            num_m = re.match(r"^([0-9]+(?:\.[0-9]+)?)[a-z_]", tok_l)
            if num_m:
                out.append(num_m.group(1))
                break
            matched_prefix = None
            for vt in sorted(VALID_MODEL_TOKENS, key=len, reverse=True):
                if tok_l.startswith(vt) and len(tok_l) > len(vt):
                    matched_prefix = vt
                    break
            if matched_prefix:
                out.append(matched_prefix)
            break

    candidate = "-".join(out).rstrip(".-_")
    if candidate in EXCLUDED_EXACT or len(candidate) < 5:
        return ""
    if len(out) == 2 and re.fullmatch(r"[0-9]", out[1]):
        if not ((prefix == "grok" and int(out[1]) >= 5) or (prefix == "gpt" and int(out[1]) >= 6)):
            return ""
    if is_legacy_model_id(candidate):
        return ""
    return candidate


def extract_models_from_bytes(data: bytes) -> Set[str]:
    """
    Extract all compiled-in or documented frontier model identifiers from binary/text bytes.
    """
    text = data.decode("ascii", "ignore")

    split_lookahead = (
        r"(?=(?:"
        r"gemini-[0-9a-z]|"
        r"claude-(?:opus|sonnet|haiku|fable|mythos|[a-z]{3,10}-[0-9])|"
        r"gpt-(?:[56789]|oss|image|audio|realtime|live|daybreak|rosalind|aurora)|"
        r"o[56789]-(?:mini|preview|pro|high|low|medium)|"
        r"grok-(?:[3456789]|imagine|voice|build)|"
        r"deepseek-(?:r[2345]|v[4567]|chat|coder|reasoner)|"
        r"qwen[345]?-(?:[0-9]|max|plus|turbo|vl|coder|omni)|"
        r"kimi-(?:k[234]|for-coding)|"
        r"glm-[567]|"
        r"minimax-m[345]|"
        r"llama-[456]|"
        r"lyria-[2345]|"
        r"veo-[2345]|"
        r"imagen-[345]|"
        r"mai-(?:code|[234])|"
        r"astra-cyber|"
        r"fable-[567]|"
        r"composer-[2345]|"
        r"muse-(?:spark|wonder)|"
        r"swe-[23]"
        r"))"
    )
    segmented = re.sub(split_lookahead, "\n", text)

    raw_pattern = re.compile(
        r"((?:"
        r"gemini-[0-9a-z][a-z0-9._-]{1,42}|"
        r"claude-(?:opus|sonnet|haiku|fable|mythos|[a-z]{3,10})-[0-9a-z][a-z0-9._-]{0,38}|"
        r"gpt-(?:[56789]|oss|image|audio|realtime|live|daybreak|rosalind|aurora)[a-z0-9._-]{0,35}|"
        r"o[56789]-(?:mini|preview|pro)[a-z0-9._-]{0,25}|"
        r"grok-(?:[3456789]|imagine|voice|build)[a-z0-9._-]{0,30}|"
        r"deepseek-(?:r[2345]|v[4567]|chat|coder|reasoner)[a-z0-9._-]{0,30}|"
        r"kimi-(?:k[234]|for-coding)[a-z0-9._-]{0,30}|"
        r"glm-[567][a-z0-9._-]{0,30}|"
        r"minimax-m[345][a-z0-9._-]{0,30}|"
        r"lyria-[2345][a-z0-9._-]{1,30}|"
        r"veo-[2345][a-z0-9._-]{1,30}|"
        r"imagen-[345][a-z0-9._-]{1,30}|"
        r"mai-(?:code|[234])[a-z0-9._-]{0,25}|"
        r"astra-cyber[a-z0-9._-]{0,25}|"
        r"fable-[567][a-z0-9._-]{0,20}|"
        r"composer-[2345][a-z0-9._-]{0,20}|"
        r"muse-(?:spark|wonder)[a-z0-9._-]{0,20}|"
        r"swe-[23][a-z0-9._-]{1,25}"
        r"))"
    )

    models: Set[str] = set()
    for m in raw_pattern.finditer(segmented):
        cleaned = clean_go_model_id(m.group(1))
        if cleaned:
            models.add(cleaned)

    return models


def humanize_model_id(model_id: str) -> str:
    """
    Convert a model identifier like 'gemini-4-argon-high' or 'claude-fable-5-5'
    into a clean human-readable display name like 'Gemini 4 Argon (High)' or 'Claude Fable 5.5'.
    """
    parts = model_id.split("-")
    if not parts:
        return model_id

    tier_parentheticals = {"high", "medium", "low", "max"}
    extra_tier = None
    if len(parts) >= 3 and parts[-2] == "extra" and parts[-1] == "low":
        extra_tier = "Extra Low"
        parts = parts[:-2]
    elif len(parts) >= 3 and parts[-1] in tier_parentheticals:
        extra_tier = parts[-1].capitalize()
        parts = parts[:-1]

    if parts[0] == "claude" and len(parts) >= 4 and parts[2].isdigit() and parts[3].isdigit():
        parts = [parts[0], parts[1], f"{parts[2]}.{parts[3]}"] + parts[4:]
    elif parts[0] in {"grok", "gpt"} and len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
        parts = [parts[0], f"{parts[1]}.{parts[2]}"] + parts[3:]

    special_caps = {
        "gpt": "GPT",
        "oss": "OSS",
        "xhigh": "XHigh",
        "maas": "MaaS",
        "tts": "TTS",
        "stt": "STT",
        "vl": "VL",
        "1p": "1P",
        "er": "ER",
        "v1": "v1",
        "v2": "v2",
        "v3": "v3",
        "v4": "V4",
        "r1": "R1",
        "r2": "R2",
        "o5": "o5",
        "k3": "K3",
        "k3.1": "K3.1",
        "glm": "GLM",
        "tf": "TF",
        "bon": "BoN",
        "le": "LE",
        "di": "DI",
        "v7": "v7",
        "acp": "ACP",
        "mai": "MAI",
        "swe": "SWE",
    }

    words = []
    for p in parts:
        if p in special_caps:
            words.append(special_caps[p])
        elif re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[bmk]?", p):
            words.append(p.upper() if p[-1].isalpha() else p)
        else:
            words.append(p.capitalize())

    base_name = " ".join(words)
    if extra_tier:
        return f"{base_name} ({extra_tier})"
    return base_name


def infer_family_title(model_ids: List[str]) -> str:
    """Infer the headline family name from a list of model IDs."""
    if not model_ids:
        return "New Model Update"

    sorted_ids = sorted(model_ids, key=len)
    shortest = sorted_ids[0]
    stem = re.sub(r"-(?:extra-low|high|medium|low|max|preview|latest|tiered)$", "", shortest)
    return humanize_model_id(stem)


def infer_provider(model_id: str) -> Dict[str, str]:
    """Return provider metadata (name, slug, accent color) for a model ID."""
    mid = model_id.lower()
    if mid.startswith(("gemini", "lyria", "veo", "imagen", "gemma", "google/", "carbon-", "barium-", "argon-")):
        return {"name": "GOOGLE", "slug": "google", "color": "#38bdf8"}
    if mid.startswith(("claude", "anthropic/", "sonnet-", "opus-", "haiku-", "fable-")):
        return {"name": "ANTHROPIC", "slug": "anthropic", "color": "#f97316"}
    if mid.startswith(("gpt", "o1", "o3", "o4", "o5", "codex", "openai/", "astra-cyber")):
        return {"name": "OPENAI", "slug": "openai", "color": "#10b981"}
    if mid.startswith(("mai-", "microsoft/")):
        return {"name": "MICROSOFT AI", "slug": "openai", "color": "#38bdf8"}
    if mid.startswith(("composer-",)):
        return {"name": "CURSOR", "slug": "cursor", "color": "#94a3b8"}
    if mid.startswith(("qwen", "alibaba/")):
        return {"name": "QWEN · ALIBABA", "slug": "qwen", "color": "#a855f7"}
    if mid.startswith(("deepseek",)):
        return {"name": "DEEPSEEK", "slug": "deepseek", "color": "#06b6d4"}
    if mid.startswith(("kimi", "k3", "moonshot")):
        return {"name": "MOONSHOT · KIMI", "slug": "kimi", "color": "#6366f1"}
    if mid.startswith(("minimax",)):
        return {"name": "MINIMAX", "slug": "minimax", "color": "#ec4899"}
    if mid.startswith(("glm", "zai", "zhipu", "thudm")):
        return {"name": "Z.AI · ZHIPU GLM", "slug": "zai", "color": "#14b8a6"}
    if mid.startswith(("nvidia/", "nemotron", "cosmos")):
        return {"name": "NVIDIA", "slug": "nvidia", "color": "#84cc16"}
    if mid.startswith(("llama", "meta-llama", "meta/", "muse-")):
        return {"name": "META", "slug": "meta", "color": "#3b82f6"}
    if mid.startswith(("mistral", "ministral", "codestral", "pixtral", "magistral", "voxtral", "timestral")):
        return {"name": "MISTRAL AI", "slug": "mistral", "color": "#f59e0b"}
    if mid.startswith(("grok", "x-ai/", "xai/")):
        return {"name": "XAI", "slug": "xai", "color": "#e2e8f0"}
    return {"name": "OPENROUTER", "slug": "openrouter", "color": "#10b981"}
