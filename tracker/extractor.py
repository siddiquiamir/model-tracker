"""Binary & bundle string extraction, ELF64 .rodata Range slicing, and model grammar cleaning."""

from __future__ import annotations

import hashlib
import pathlib
import re
import struct
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

CACHE_DIR = pathlib.Path(__file__).resolve().parent.parent / ".cache"

# Valid hyphen-separated tokens that can appear in compiled-in model identifiers.
# Used to strip trailing neighbor strings from Go's length-sorted .rodata string table.
VALID_MODEL_TOKENS: Set[str] = {
    # Tiers & sizes
    "pro", "flash", "ultra", "lite", "mini", "nano", "max", "high", "medium", "low",
    "extra", "plus", "base", "small", "large", "huge", "tiny", "micro", "super",
    # Lifecycle & channels
    "preview", "exp", "experimental", "latest", "beta", "alpha", "rc", "nightly",
    "stable", "001", "002", "003", "v1", "v2", "v3", "v4", "r1", "r2",
    # Capabilities & modalities
    "thinking", "reasoning", "fast", "turbo", "instruct", "chat", "vision",
    "audio", "realtime", "tts", "stt", "image", "video", "coder", "code",
    "robotics", "omni", "search", "live", "native", "embed", "embedding",
    "edit", "inpaint", "transcribe", "guard", "reward", "vl", "moe",
    # Family code-names & series
    "argon", "sonnet", "opus", "haiku", "maas", "tiered", "customtools",
    "windsurf", "debug", "clip", "er", "oss", "banana", "jarvis", "sc",
    "1p", "thoughts", "nemotron", "pixtral", "codestral", "ministral",
    "magistral", "devstral", "command", "aya", "solar", "jamba", "hermes",
}

# Known non-model suffixes/phrases that should be excluded even if prefixed by a provider name
EXCLUDED_EXACT: Set[str] = {
    "gemini-api",
    "gemini-cli",
    "gemini-plugin",
    "gemini-extension",
    "gemini-edit-images",
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
    "gpt-oss",
}


def fetch_range(url: str, start: int, end: int, timeout: int = 20) -> bytes:
    """Fetch an inclusive byte range [start, end] from an HTTP server supporting Range requests."""
    req = urllib.request.Request(
        url,
        headers={
            "Range": f"bytes={start}-{end}",
            "User-Agent": "ModelPulse-Tracker/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_elf_rodata_slice(url: str, cache_key: Optional[str] = None, max_bytes: int = 4_500_000) -> bytes:
    """
    Extract the string table slice of the .rodata section from a remote ELF64 binary
    using HTTP Range requests (~3-4 MB instead of downloading ~190 MB).
    Caches slices locally in .cache/ for instant repeat diffs.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = cache_key or hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    cache_file = CACHE_DIR / f"rodata_{key}.bin"
    if cache_file.exists() and cache_file.stat().st_size > 100_000:
        return cache_file.read_bytes()

    # 1. Read 64-byte ELF64 header
    ehdr = fetch_range(url, 0, 63)
    if len(ehdr) < 64 or ehdr[:4] != b"\x7fELF":
        raise ValueError(f"Not a valid ELF64 binary at {url}")

    (e_shoff,) = struct.unpack_from("<Q", ehdr, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", ehdr, 58)

    # 2. Read ELF64 section header table
    shdrs_len = e_shentsize * e_shnum
    shdrs = fetch_range(url, e_shoff, e_shoff + shdrs_len - 1)

    # 3. Read section header string table (.shstrtab)
    str_sh_off = e_shstrndx * e_shentsize
    shstr_offset, shstr_size = struct.unpack_from("<QQ", shdrs, str_sh_off + 24)
    shstrtab = fetch_range(url, shstr_offset, shstr_offset + shstr_size - 1)

    # 4. Find .rodata section and fetch its first `max_bytes` (where Go packs length-sorted strings)
    for i in range(e_shnum):
        off = i * e_shentsize
        sh_name, _sh_type, _sh_flags, _sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", shdrs, off
        )
        end_null = shstrtab.find(b"\x00", sh_name)
        sec_name = shstrtab[sh_name:end_null].decode("ascii", "ignore")
        if sec_name == ".rodata":
            slice_len = min(sh_size, max_bytes)
            rodata = fetch_range(url, sh_offset, sh_offset + slice_len - 1, timeout=30)
            cache_file.write_bytes(rodata)
            return rodata

    raise RuntimeError(f"Could not find .rodata section in ELF binary: {url}")


def clean_go_model_id(raw: str) -> str:
    """
    Clean a raw model identifier candidate extracted from a Go binary or JS bundle.
    Strips concatenated neighbor strings from Go's non-null-terminated .rodata table.
    """
    raw = raw.strip(".-_ \t\r\n\"'`")
    parts = raw.split("-")
    if len(parts) < 2:
        return ""

    prefix = parts[0].lower()
    second = parts[1].lower()

    # Validate second token based on prefix
    if prefix in {"gemini", "grok", "qwen", "llama", "lyria", "veo", "imagen", "gemma"}:
        # Second token must be a version number (e.g. 2.5, 3, 3.1, 3.8, 4) or known family token
        if not (re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[a-z]?", second) or second in VALID_MODEL_TOKENS):
            return ""
    elif prefix == "claude":
        if second not in {"opus", "sonnet", "haiku"} and not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", second):
            return ""
    elif prefix == "gpt":
        if not (re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[a-z]?", second) or second in {"oss", "image", "audio", "realtime"}):
            return ""

    out = [prefix, second]
    for tok in parts[2:]:
        tok_l = tok.lower()
        # Pure version/date/parameter token: e.g., 5, 4.5, 120b, 20b, 20261021, 0514, 1m, 840k
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?(?:[bkm]|_[0-9]+[bkm])?", tok_l):
            out.append(tok_l)
        elif tok_l in VALID_MODEL_TOKENS:
            out.append(tok_l)
        else:
            # Check if tok_l starts with a valid token followed by concatenated Go string garbage
            matched_prefix = None
            for vt in sorted(VALID_MODEL_TOKENS, key=len, reverse=True):
                if tok_l.startswith(vt) and len(tok_l) > len(vt):
                    matched_prefix = vt
                    break
            if matched_prefix:
                out.append(matched_prefix)
            break

    candidate = "-".join(out).rstrip(".-_")
    if candidate in EXCLUDED_EXACT or len(candidate) < 7:
        return ""
    # Reject bare prefix + single digit without family/subversion (e.g., gemini-2, claude-opus-4)
    if len(out) == 2 and re.fullmatch(r"[0-9]", out[1]):
        return ""
    return candidate


def extract_models_from_bytes(data: bytes) -> Set[str]:
    """
    Extract all compiled-in model identifiers from binary bytes (Go ELF/PE or JS bundle).
    """
    text = data.decode("ascii", "ignore")

    # Split adjacent concatenated model identifiers in Go's .rodata string table
    split_Lookahead = (
        r"(?=(?:"
        r"gemini-[0-9a-z]|"
        r"claude-(?:opus|sonnet|haiku)-[0-9]|"
        r"gpt-(?:[0-9]|oss|image|audio|realtime)|"
        r"o[134]-(?:mini|preview|pro|high|low|medium)|"
        r"grok-[0-9]|"
        r"deepseek-(?:r[0-9]|v[0-9]|chat|coder|reasoner)|"
        r"qwen[0-9]?-(?:[0-9]|max|plus|turbo|vl|coder)|"
        r"llama-[0-9]|"
        r"lyria-[0-9]|"
        r"veo-[0-9]|"
        r"imagen-[0-9]"
        r"))"
    )
    segmented = re.sub(split_Lookahead, "\n", text)

    raw_pattern = re.compile(
        r"((?:"
        r"gemini-[0-9a-z][a-z0-9._-]{1,42}|"
        r"claude-(?:opus|sonnet|haiku)-[0-9][a-z0-9._-]{0,38}|"
        r"gpt-(?:[0-9]|oss|image)[a-z0-9._-]{1,35}|"
        r"o[134]-(?:mini|preview|pro)[a-z0-9._-]{0,25}|"
        r"grok-[0-9][a-z0-9._-]{1,30}|"
        r"deepseek-(?:r[0-9]|v[0-9]|chat|coder|reasoner)[a-z0-9._-]{0,30}|"
        r"lyria-[0-9][a-z0-9._-]{1,30}|"
        r"veo-[0-9][a-z0-9._-]{1,30}|"
        r"imagen-[0-9][a-z0-9._-]{1,30}"
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
    Convert a model identifier like 'gemini-4-argon-high' or 'claude-opus-5-5-max'
    into a clean human-readable display name like 'Gemini 4 Argon (High)' or 'Claude Opus 5.5 (Max)'.
    """
    parts = model_id.split("-")
    if not parts:
        return model_id

    tier_Parentheticals = {"high", "medium", "low", "max"}
    extra_tier = None
    if len(parts) >= 3 and parts[-2] == "extra" and parts[-1] == "low":
        extra_tier = "Extra Low"
        parts = parts[:-2]
    elif len(parts) >= 3 and parts[-1] in tier_Parentheticals:
        extra_tier = parts[-1].capitalize()
        parts = parts[:-1]

    # Reconstruct version pairs for Claude (e.g., claude-opus-5-5 -> Claude Opus 5.5)
    if parts[0] == "claude" and len(parts) >= 4 and parts[2].isdigit() and parts[3].isdigit():
        parts = [parts[0], parts[1], f"{parts[2]}.{parts[3]}"] + parts[4:]

    special_caps = {
        "gpt": "GPT",
        "oss": "OSS",
        "maas": "MaaS",
        "tts": "TTS",
        "stt": "STT",
        "vl": "VL",
        "1p": "1P",
        "er": "ER",
        "v1": "v1",
        "v2": "v2",
        "v3": "v3",
        "r1": "R1",
        "o1": "o1",
        "o3": "o3",
        "o4": "o4",
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
    """
    Given a list of newly added model IDs (e.g. ['gemini-4-argon', 'gemini-4-argon-high', ...]),
    infer the headline family name (e.g. 'Gemini 4 Argon').
    """
    if not model_ids:
        return "New Model Update"

    sorted_ids = sorted(model_ids, key=len)
    shortest = sorted_ids[0]
    # Strip trailing tier suffixes if all models share a common stem
    stem = re.sub(r"-(?:extra-low|high|medium|low|max|preview|latest|tiered)$", "", shortest)
    return humanize_model_id(stem)


def infer_provider(model_id: str) -> Dict[str, str]:
    """Return provider metadata (name, slug, accent color, icon type) for a model ID."""
    mid = model_id.lower()
    if mid.startswith(("gemini", "lyria", "veo", "imagen", "gemma", "google/")):
        return {"name": "GOOGLE", "slug": "google", "color": "#38bdf8"}
    if mid.startswith(("claude", "anthropic/")):
        return {"name": "ANTHROPIC", "slug": "anthropic", "color": "#f97316"}
    if mid.startswith(("gpt", "o1", "o3", "o4", "codex", "openai/")):
        return {"name": "OPENAI", "slug": "openai", "color": "#10b981"}
    if mid.startswith(("qwen", "alibaba/")):
        return {"name": "QWEN · ALIBABA", "slug": "qwen", "color": "#a855f7"}
    if mid.startswith(("deepseek",)):
        return {"name": "DEEPSEEK", "slug": "deepseek", "color": "#06b6d4"}
    if mid.startswith(("llama", "meta-llama", "meta/")):
        return {"name": "META LLAMA", "slug": "meta", "color": "#3b82f6"}
    if mid.startswith(("mistral", "ministral", "codestral", "pixtral", "magistral")):
        return {"name": "MISTRAL AI", "slug": "mistral", "color": "#f59e0b"}
    if mid.startswith(("grok", "x-ai/", "xai/")):
        return {"name": "XAI", "slug": "xai", "color": "#e2e8f0"}
    return {"name": "OPEN SOURCE / FRONTIER", "slug": "opensource", "color": "#8b5cf6"}
