"""Static model-registry discovery. Downloaded code is never executed."""

from __future__ import annotations

import hashlib
import gzip
import io
import json
import base64
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
import os
import pathlib
import re
import struct
import tarfile
import urllib.parse
import urllib.request
import zipfile
import uuid
from typing import Any, Dict, Iterable

from tracker.extractor import is_legacy_model_id
from tracker.novelty import RELEASE_GRACE, extract_embedded_date, normalize

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

MAX_DOWNLOAD = 256 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_EXPANDED = 768 * 1024 * 1024
MAX_MEMBERS = 30000
VARIANT = re.compile(r"(?:-(?:minimal|low|medium|high|xhigh|max|none|fast|slow|thinking|reasoning))+$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[-_./:][a-z0-9]+)*$", re.I)
TOKEN = re.compile(rb"(?<![a-zA-Z0-9_-])([a-z][a-z0-9]*(?:-[a-z0-9]+)+)(?![a-zA-Z0-9_-])")
EFFORT_BYTES = re.compile(rb"-(?:minimal|low|medium|high|xhigh|max|none|fast|slow|thinking|reasoning)")
MODEL_FIELD = re.compile(r'''(?<![a-zA-Z0-9_])["']?(model_id|modelId|model_name|modelName|model)["']?\s*[:=]\s*["']([a-zA-Z][a-zA-Z0-9_./:-]{1,119})["']''')
PROVIDERS = {
    "google": "Google", "anthropic": "Anthropic", "openai": "OpenAI",
    "cognition": "Cognition", "xai": "xAI", "deepseek": "DeepSeek",
    "mistral": "Mistral", "meta": "Meta",
}
AGGREGATOR_SOURCES = {"litellm-intelligence", "models-dev-api", "models-dev-git"}
COMMUNITY_TUNE_RE = re.compile(r"(?:uncensored|abliterat|heretic|roleplay|nsfw|venice-edition)", re.I)


def _is_old_registry_entry(identifier: str, record: Dict[str, Any], ref_dt: datetime) -> bool:
    if is_legacy_model_id(identifier) or is_legacy_model_id(normalize(identifier)):
        return True
    metadata = record.get("metadata") or {}
    canonical = str(record.get("canonical_id") or metadata.get("canonical_model_id") or metadata.get("base_model") or "")
    if canonical and (is_legacy_model_id(canonical) or is_legacy_model_id(normalize(canonical))):
        return True
    cutoff = (ref_dt - RELEASE_GRACE).strftime("%Y-%m-%d")
    rel_date = str(metadata.get("release_date") or "")[:10]
    if re.match(r"^\d{4}-\d{2}-\d{2}$", rel_date) and rel_date < cutoff:
        return True
    emb = extract_embedded_date(identifier) or (extract_embedded_date(canonical) if canonical else None)
    if emb and emb < cutoff:
        return True
    return False


def family(identifier: str) -> str:
    return VARIANT.sub("", identifier.split("/")[-1].lower())


def _valid(identifier: Any) -> bool:
    return isinstance(identifier, str) and 2 <= len(identifier) <= 120 and bool(IDENTIFIER.fullmatch(identifier))


def _elf_registry_strings(payload: bytes) -> Dict[str, tuple[int, int]]:
    if payload[:6] != b"\x7fELF\x02\x01" or len(payload) < 64:
        return {}
    section_offset = struct.unpack_from("<Q", payload, 40)[0]
    entry_size, count = struct.unpack_from("<HH", payload, 58)
    if entry_size != 64 or count > 8192 or section_offset + count * entry_size > len(payload):
        raise ValueError("Invalid ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", payload, section_offset + index * entry_size) for index in range(count)]
    allocated = [section for section in sections if section[2] & 2 and section[1] == 1 and section[4] + section[5] <= len(payload)]
    strings: Dict[str, tuple[int, int]] = {}

    def file_offset(address: int, length: int) -> int | None:
        for section in allocated:
            if section[3] <= address and address + length <= section[3] + section[5]:
                return section[4] + address - section[3]
        return None

    def recover(address: int, length: int) -> None:
        if not 2 <= length <= 120:
            return
        offset = file_offset(address, length)
        if offset is None:
            return
        candidate = payload[offset:offset + length]
        if not candidate.isascii():
            return
        identifier = candidate.decode("ascii")
        if _valid(identifier):
            strings.setdefault(identifier, (offset, offset + length))

    for section in allocated:
        if not section[2] & 1:
            continue
        for offset in range(section[4], section[4] + section[5] - 15, 8):
            address, length = struct.unpack_from("<QQ", payload, offset)
            recover(address, length)
    for section in sections:
        if section[1] != 4 or section[9] != 24:
            continue
        if section[4] + section[5] > len(payload) or section[5] % 24:
            raise ValueError("Invalid ELF relocations")
        for offset in range(section[4], section[4] + section[5], 24):
            address, relocation, addend = struct.unpack_from("<QQq", payload, offset)
            if relocation & 0xFFFFFFFF != 8:
                continue
            pointer = file_offset(address, 16)
            if pointer is not None:
                recover(addend, struct.unpack_from("<Q", payload, pointer + 8)[0])
    groups: Dict[str, list[str]] = {}
    for identifier in strings:
        if VARIANT.search(identifier):
            groups.setdefault(family(identifier), []).append(identifier)
    seeds = [identifier for siblings in groups.values() if len(siblings) >= 2 for identifier in siblings]
    seed_offsets = sorted(strings[identifier][0] for identifier in seeds)
    if not seed_offsets:
        return {}
    import bisect

    selected = {}
    bases = {family(identifier) for identifier in seeds}
    for identifier, span in strings.items():
        index = bisect.bisect_left(seed_offsets, span[0])
        neighbors = seed_offsets[max(0, index - 1):index + 1]
        if identifier in seeds or identifier in bases or ("-" in identifier and any(abs(span[0] - offset) <= 2048 for offset in neighbors)):
            selected[identifier] = span
    return selected


def extract_registry(payload: bytes, file_path: str) -> Dict[str, Dict[str, Any]]:
    """Accept registry fields or repeated effort variants, not a vocabulary of labs."""
    records: Dict[str, Dict[str, Any]] = {}

    def add(identifier: str, excerpt: str, metadata: Dict[str, Any], method: str) -> None:
        provider = str(metadata.get("provider", "")).lower()
        entry = {
            "id": identifier, "family": family(identifier), "file_path": file_path,
            "excerpt": excerpt[:1200], "method": method,
            "provider": provider if provider in PROVIDERS else "unknown",
            "provider_evidence": "registry metadata" if provider in PROVIDERS else "unattributed",
            "metadata": metadata,
        }
        if identifier not in records or method == "structured registry":
            records[identifier] = entry

    def walk(value: Any, model_context: bool = False) -> None:
        if isinstance(value, dict):
            identifiers = [value.get(field) for field in ("model_id", "modelId", "model_name", "modelName", "model")]
            if model_context:
                identifiers.append(value.get("id"))
            metadata = {key: value[key] for key in ("provider", "capabilities", "aliases", "routing", "litellm_provider", "canonical_model_id", "base_model", "status", "deprecated") if key in value}
            excerpt = json.dumps(value, ensure_ascii=True)
            for identifier in identifiers:
                if _valid(identifier):
                    add(identifier, excerpt, metadata, "structured registry")
            for key, child in value.items():
                context = model_context or bool(re.search(r"model|registry", key, re.I))
                if model_context and _valid(key) and isinstance(child, dict) and any(field in child for field in ("provider", "capabilities", "canonical_model_id", "base_model")):
                    child_meta = {field: child[field] for field in ("provider", "capabilities", "aliases", "canonical_model_id", "base_model", "status", "deprecated") if field in child}
                    add(key, json.dumps({key: child}), child_meta, "structured registry")
                if context and _valid(child) and key in ("id", "model", "model_id", "modelId"):
                    add(child, excerpt, metadata, "structured registry")
                walk(child, context)
        elif isinstance(value, list):
            for child in value:
                if model_context and _valid(child):
                    add(child, json.dumps(child), {}, "structured registry")
                else:
                    walk(child, model_context)

    text = payload.decode("utf-8", "replace")
    if file_path.endswith((".json", ".toml", ".yaml", ".yml")):
        try:
            if file_path.endswith(".toml"):
                if tomllib is None:
                    raise RuntimeError("TOML inspection requires tomli on Python 3.10")
                walk(tomllib.loads(text))
            elif file_path.endswith((".yaml", ".yml")):
                import yaml

                walk(yaml.safe_load(text))
            else:
                walk(json.loads(payload))
        except (ValueError, RecursionError):
            pass
    for match in MODEL_FIELD.finditer(text):
        add(match[2], match[0], {}, "model field")
    if file_path.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx")):
        for match in re.finditer(r"\{([^{}]{1,3000})\}", text):
            body = match[1]
            provider_match = re.search(r'''["']?provider["']?\s*:\s*["']([a-zA-Z]+)["']''', body)
            metadata = {"provider": provider_match[1]} if provider_match else {}
            for model_match in MODEL_FIELD.finditer(body):
                add(model_match[2], match[0], metadata, "structured registry")
            context = text[max(0, match.start() - 100):match.start()]
            if re.search(r"models|modelRegistry|model_registry", context):
                identifier_match = re.search(r'''["']?id["']?\s*:\s*["']([a-zA-Z][a-zA-Z0-9_./:-]{1,119})["']''', body)
                if identifier_match:
                    add(identifier_match[1], match[0], metadata, "structured registry")
    tokens: Dict[str, tuple[int, int]] = {}
    for match in TOKEN.finditer(payload):
        identifier = match[1].decode("ascii")
        if len(identifier) <= 120:
            tokens.setdefault(identifier, match.span(1))
    groups: Dict[str, list[str]] = {}
    for identifier in tokens:
        if VARIANT.search(identifier):
            groups.setdefault(family(identifier), []).append(identifier)
    for base, variants in groups.items():
        if len(variants) < 2:
            continue
        bare = re.search(rb"(?<![a-zA-Z0-9_-])" + re.escape(base.encode()) + rb"(?![a-zA-Z0-9_-])", payload)
        if bare:
            tokens[base] = bare.span()
        for identifier in variants + ([base] if base in tokens else []):
            start, end = tokens[identifier]
            excerpt = payload[max(0, start - 100):end + 100].decode("utf-8", "replace")
            add(identifier, excerpt, {"byte_offset": start}, "variant siblings")
    for identifier, (start, end) in _elf_registry_strings(payload).items():
        excerpt = payload[max(0, start - 80):end + 80].decode("utf-8", "replace")
        add(identifier, excerpt, {"byte_offset": start, "byte_length": end - start}, "ELF string descriptor in variant registry region")
    previous_effort = None
    stems = set()
    for effort in EFFORT_BYTES.finditer(payload):
        if previous_effort and 2 <= effort.start() - previous_effort.end() <= 100:
            stem = payload[previous_effort.end():effort.start()]
            if stem.isascii() and _valid(stem.decode("ascii")) and payload[previous_effort.start() - len(stem):previous_effort.start()] == stem:
                stems.add(stem)
        previous_effort = effort
    for stem in stems:
        pattern = re.compile(re.escape(stem) + rb"-(?:minimal|low|medium|high|xhigh|max|none|fast|slow|thinking|reasoning)")
        for match in pattern.finditer(payload):
            start, end = match.span()
            identifier = match[0].decode("ascii")
            excerpt = payload[max(0, start - 80):end + 80].decode("utf-8", "replace")
            add(identifier, excerpt, {"byte_offset": start, "byte_length": end - start}, "repeated stem in concatenated variant registry")
        bare = re.search(re.escape(stem + stem) + rb"-(?:minimal|low|medium|high|xhigh|max|none)", payload)
        if bare:
            start = bare.start()
            add(stem.decode("ascii"), payload[start:start + len(stem) + 80].decode("utf-8", "replace"), {"byte_offset": start, "byte_length": len(stem)}, "bare stem preceding concatenated variants")
    return records


def provenance_group(source: str) -> str:
    if source in {"devin-cli", "devin-desktop"}:
        return "devin"
    if source in {"models-dev-api", "models-dev-git"}:
        return "models-dev"
    return source


def evidence_confidence(records: Iterable[Dict[str, Any]], label: str) -> Dict[str, Any]:
    records = list(records)
    providers = {record.get("provider", "unknown") for record in records}
    examples = all(bool(re.search(r"(?:^|/)(?:examples?|tests?|fixtures|__tests__)(?:/|$)|\.(?:test|spec)\.", record.get("file_path", ""), re.I)) or record.get("metadata", {}).get("status") == "deprecated" or record.get("metadata", {}).get("deprecated") is True for record in records)
    return {
        "existence": {"level": "medium" if examples else "high", "basis": "Identifier present in retained static evidence; not proof of a serving model"},
        "attribution": {"level": "medium" if len(providers) == 1 and "unknown" not in providers else "unknown", "basis": "Explicit source metadata only; not independently verified lab ownership"},
        "availability": {"level": "unknown", "basis": "No authenticated inference or official launch verification performed"},
        "novelty": {"level": "candidate" if examples else label.lower(), "basis": "Never-forget source baseline; registry changes are not launches"},
    }


class IdentityLedger:
    def __init__(self, state_dir: pathlib.Path | None = None):
        self.state_dir = pathlib.Path(state_dir) if state_dir is not None else STATE_DIR
        self.state: Dict[str, Any] | None = None

    def ingest(self, source: str, registry: Dict[str, Any], build: Dict[str, Any], evidence_path: str, observed_at: str, persist: bool = True) -> None:
        path = self.state_dir / "identities.json"
        state = self.state if self.state is not None else _read(path)
        self.state = state
        nodes = state.setdefault("nodes", {})
        edges = {edge["id"]: edge for edge in state.get("edges", [])}
        for identifier, record in registry.items():
            node_id = source + ":" + identifier
            node = nodes.setdefault(node_id, {"identifier": identifier, "source": source, "first_seen": build["published_at"], "first_evidence": evidence_path})
            if build["published_at"] < node["first_seen"]:
                node.update(first_seen=build["published_at"], first_evidence=evidence_path)
            if build["published_at"] >= node.get("last_present", ""):
                node.update(family=family(identifier), last_observed=max(observed_at, node.get("last_observed", "")), last_present=build["published_at"], evidence_path=evidence_path, build=build["version"], provider=record.get("provider", "unknown"), provider_evidence=record.get("provider_evidence", ""), provenance=provenance_group(source), file_sha256=record.get("file_sha256", ""))
            metadata = record.get("metadata", {})
            canonical = record.get("canonical_id") or metadata.get("canonical_model_id") or metadata.get("base_model")
            aliases = metadata.get("aliases", [])
            if isinstance(aliases, str):
                aliases = [aliases]
            elif not isinstance(aliases, list):
                aliases = []
            for target in [canonical, *aliases]:
                if not _valid(target):
                    continue
                edge_id = hashlib.sha256(f"{node_id}:{target}".encode()).hexdigest()[:20]
                old = edges.get(edge_id, {})
                edges[edge_id] = {"id": edge_id, "from": node_id, "to": target, "relation": "declared_alias", "evidence_path": evidence_path if observed_at >= old.get("last_observed", "") else old["evidence_path"], "first_seen": min(old.get("first_seen", build["published_at"]), build["published_at"]), "last_observed": max(observed_at, old.get("last_observed", "")), "basis": "Explicit canonical/base-model/alias metadata, not name similarity"}
        state["edges"] = list(edges.values())
        state["updated_at"] = observed_at
        if persist:
            self.flush()

    def flush(self) -> None:
        if self.state is not None:
            _write(self.state_dir / "identities.json", self.state)

    def summarize(self) -> Dict[str, Any]:
        state = _read(self.state_dir / "identities.json")
        queue = _read(self.state_dir / "candidate_queue.json")
        return {"identifiers": len(state.get("nodes", {})), "declared_aliases": len(state.get("edges", [])), "pending_candidates": sum(item.get("review") == "pending" for item in queue.get("items", {}).values())}

    def enqueue(self, cards: list[Dict[str, Any]]) -> None:
        path = self.state_dir / "candidate_queue.json"
        queue = _read(path)
        items = queue.setdefault("items", {})
        for card in cards:
            if not card.get("candidate_only") and card.get("scanner") not in {"community-lead", "reddit-lead", "x-lead", "github-code-leak"}:
                continue
            card["candidate_only"] = True
            card["confidence"] = {"existence": {"level": "unverified"}, "attribution": {"level": "unknown"}, "availability": {"level": "unknown"}, "novelty": {"level": "candidate"}}
            old = items.get(card["id"], {})
            items[card["id"]] = {**old, "id": card["id"], "source": card.get("scanner"), "models": card.get("models", []), "source_url": card.get("source_text", ""), "evidence_path": card.get("evidence_path", ""), "first_seen": old.get("first_seen", card.get("detected_at")), "last_observed": card.get("observed_at", card.get("detected_at")), "review": old.get("review", "pending")}
        if items:
            _write(path, queue)


def registry_diff(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Group additions and metadata changes; reappearance is not a new launch."""
    old_families = {family(identifier) for identifier in previous}
    groups: Dict[str, Dict[str, Any]] = {}
    for identifier in sorted(current.keys() - previous.keys()):
        base = family(identifier)
        group = groups.setdefault(base, {
            "event_label": "New variant" if base in old_families else "New identifier",
            "identifiers": [],
        })
        group["identifiers"].append(identifier)
    for identifier in sorted(current.keys() & previous.keys()):
        if current[identifier].get("metadata", {}) == previous[identifier].get("metadata", {}):
            continue
        group = groups.setdefault(family(identifier), {"event_label": "Registry update", "identifiers": []})
        group["identifiers"].append(identifier)
        group.setdefault("metadata_changed", []).append(identifier)
    return groups


def _safe_path(name: str) -> None:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or ".." in pathlib.PurePosixPath(normalized).parts or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError("Unsafe archive path")


def archive_members(payload: bytes, archive_name: str, download_limit: int = MAX_DOWNLOAD, expanded_limit: int | None = None) -> Iterable[tuple[str, bytes]]:
    """Read regular members in memory with cumulative limits; never extract to disk."""
    if len(payload) > download_limit:
        raise ValueError("Download size limit exceeded")
    total = 0
    count = 0
    expansion_budget = MAX_EXPANDED if expanded_limit is None else expanded_limit

    def budget(name: str, size: int) -> None:
        nonlocal total, count
        _safe_path(name)
        total += size
        count += 1
        if count > MAX_MEMBERS or total > expansion_budget or size > MAX_MEMBER:
            raise ValueError("Archive expansion limit exceeded")

    def useful(name: str) -> bool:
        return name.endswith((".json", ".js", ".cjs", ".mjs", ".ts", ".tsx", ".go", ".toml", ".yaml", ".yml", "/devin", "/language_server_linux_x64")) or name == "devin"

    if archive_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for member in archive.infolist():
                budget(member.filename, member.file_size)
                if member.is_dir() or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                if useful(member.filename):
                    yield member.filename, archive.read(member)
    else:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r|*") as archive:
            for member in archive:
                budget(member.name, member.size)
                if not member.isfile() or not useful(member.name):
                    continue
                stream = archive.extractfile(member)
                if stream:
                    content = stream.read(MAX_MEMBER + 1)
                    if len(content) != member.size:
                        raise ValueError("Truncated archive member")
                    yield member.name, content


def verify_digest(payload: bytes, expected: str, algorithm: str = "sha256") -> str:
    actual = hashlib.new(algorithm, payload).hexdigest()
    if actual.lower() != expected.lower():
        raise ValueError("Upstream artifact checksum mismatch")
    return hashlib.sha256(payload).hexdigest()


ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / "data" / "intelligence"
CLI_MANIFEST = "https://static.devin.ai/cli/current/manifest.json"
DESKTOP_RELEASES = "https://docs.devin.ai/desktop/releases"
LITELLM_REPO = "https://api.github.com/repos/BerriAI/litellm"
LITELLM_PATH = "model_prices_and_context_window.json"
ALLOWED_HOSTS = {"static.devin.ai", "docs.devin.ai", "registry.npmjs.org", "api.github.com", "raw.githubusercontent.com", "codeload.github.com", "models.dev", "windsurf-stable.codeiumdata.com", "windsurf.codeiumdata.com"}


def _trusted_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("Artifact URL is outside the official HTTPS allowlist")


class _TrustedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _trusted_url(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and urllib.parse.urlsplit(newurl).hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


def fetch(url: str, limit: int = 8 * 1024 * 1024) -> bytes:
    _trusted_url(url)
    headers = {"User-Agent": "ModelPulse-Tracker/3.0", "Accept": "*/*"}
    if urllib.parse.urlsplit(url).hostname == "api.github.com" and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.build_opener(_TrustedRedirect()).open(request, timeout=60) as response:
        size = int(response.headers.get("Content-Length", 0))
        if size > limit:
            raise ValueError("Download size limit exceeded")
        content = bytearray()
        while True:
            chunk = response.read(min(1024 * 1024, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > limit:
                raise ValueError("Download size limit exceeded")
        return bytes(content)


def _read(path: pathlib.Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            data = json.load(stream)
    else:
        data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid intelligence state; refusing to reset baseline")
    return data


def _write(path: pathlib.Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        if path.suffix == ".gz":
            with gzip.open(temporary, "wt", encoding="utf-8", newline="\n") as stream:
                json.dump(data, stream, ensure_ascii=True, separators=(",", ":"))
        else:
            temporary.write_text(json.dumps(data, indent=2, ensure_ascii=True), encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class _ReleaseText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("h1", "h2", "h3", "h4"):
            self.parts.append("\n## ")
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href:
                self.parts.append(f" [{href}]({href}) ")

    def handle_endtag(self, tag):
        if tag in ("h1", "h2", "h3", "h4", "p", "li"):
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def desktop_builds(text: str) -> list[Dict[str, str]]:
    if "<html" in text.lower() or "<a " in text.lower():
        parser = _ReleaseText()
        parser.feed(text)
        compiled = ""
        for part in parser.parts:
            if not part.lstrip().startswith("{"):
                continue
            try:
                page = json.loads(part).get("page", {})
                mdx = page.get("mdx", "")
                candidate = mdx if isinstance(mdx, str) else json.dumps(mdx)
                if "linuxX64" in candidate and "label:" in candidate:
                    compiled = candidate
                    break
            except (ValueError, AttributeError):
                continue
        text = compiled or "".join(parser.parts)
    builds = {}
    for section in re.split(r"\n(?=## |\*\*v)|(?=label:\s*`v\d+\.\d+\.\d+`)", text):
        version = re.search(r"\b(\d+\.\d+\.\d+)\b", section)
        date = re.search(r"\b(202\d-\d{2}-\d{2})\b", section)
        published = date[1] + "T00:00:00+00:00" if date else ""
        if not published:
            date = re.search(r"\b([A-Z][a-z]+ \d{1,2}, 202\d)\b", section)
            if date:
                try:
                    published = datetime.strptime(date[1], "%B %d, %Y").replace(tzinfo=timezone.utc).isoformat()
                except ValueError:
                    pass
        if not version or not published:
            continue
        literal_linux = re.search(r"linuxX64:\s*`(https://[^`]+)`", section)
        urls = [literal_linux[1]] if literal_linux else [match[0] for match in re.finditer(r"https://[^\s\"<>\)]+", section)]
        for url in urls:
            url = url.replace("&amp;", "&")
            if not re.search(r"linux.*(?:x64|x86_64)|(?:x64|x86_64).*linux", url, re.I) or not urllib.parse.urlsplit(url).path.endswith((".tar.gz", ".tgz", ".zip")):
                continue
            _trusted_url(url)
            checksum = re.search(r"\b[0-9a-fA-F]{64}\b", section)
            builds[version[1]] = {"version": version[1], "url": url, "published_at": published, "manifest_url": DESKTOP_RELEASES, "sha256": checksum[0] if checksum else ""}
    return sorted(builds.values(), key=lambda build: build["published_at"])


class ModelRegistryScanner:
    source = ""
    label = ""
    download_limit = MAX_DOWNLOAD
    expanded_limit = MAX_EXPANDED
    registry_only = False
    poll_interval = 300

    def __init__(self, state_dir: pathlib.Path = STATE_DIR):
        self.state_dir = pathlib.Path(state_dir)
        self.status: Dict[str, Any] = {}

    def list_builds(self, history: bool = False) -> list[Dict[str, Any]]:
        raise NotImplementedError

    def get_registry(self, build: Dict[str, Any]) -> tuple[Dict[str, Any], str, str]:
        cache_id = hashlib.sha256((build["url"] + build.get("sha256", "") + build.get("integrity", "")).encode()).hexdigest()
        cache_file = ROOT / ".cache" / "intelligence" / f"{cache_id}.archive"
        if cache_file.exists() and cache_file.stat().st_size <= self.download_limit:
            payload = cache_file.read_bytes()
        else:
            payload = fetch(build["url"], self.download_limit)
        sha256 = hashlib.sha256(payload).hexdigest()
        verification = "HTTPS source; upstream checksum unavailable"
        if build.get("sha256"):
            verify_digest(payload, build["sha256"])
            verification = "Upstream SHA-256 verified"
        elif build.get("integrity"):
            integrity = next((item for item in build["integrity"].split() if item.startswith("sha512-")), "")
            if not integrity:
                raise ValueError("No supported strong npm integrity hash")
            expected = base64.b64decode(integrity.split("-", 1)[1], validate=True).hex()
            verify_digest(payload, expected, "sha512")
            verification = "npm SHA-512 integrity verified"
        if build.get("sha256") or build.get("integrity"):
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            if not cache_file.exists():
                temporary = cache_file.with_suffix(".tmp")
                temporary.write_bytes(payload)
                os.replace(temporary, cache_file)
        records: Dict[str, Any] = {}
        for path, content in archive_members(payload, urllib.parse.urlsplit(build["url"]).path, self.download_limit, self.expanded_limit):
            file_sha256 = hashlib.sha256(content).hexdigest()
            for identifier, record in extract_registry(content, path).items():
                record["file_sha256"] = file_sha256
                old = records.get(identifier)
                if old and old.get("provider_evidence") == "Conflicting registry metadata":
                    continue
                if not old or old["provider"] == "unknown":
                    records[identifier] = record
                elif record["provider"] not in ("unknown", old["provider"]):
                    records[identifier]["provider"] = "unknown"
                    records[identifier]["provider_evidence"] = "Conflicting registry metadata"
        if not records:
            raise ValueError("No model registry candidates extracted; baseline unchanged")
        return records, sha256, verification

    def _other_sightings(self, identifiers: list[str], current: Dict[str, Any]) -> list[Dict[str, str]]:
        if getattr(self, "sighting_index", None) is None:
            self.sighting_index: Dict[str, list[tuple[str, str, Dict[str, Any]]]] = {}
            for source in ("devin-cli", "devin-desktop", "litellm-intelligence", "models-dev-api", "models-dev-git"):
                if provenance_group(source) == provenance_group(self.source):
                    continue
                state = _read(self.state_dir / f"{source}.json")
                for identifier, record in state.get("known", {}).items():
                    self.sighting_index.setdefault(identifier.split("/")[-1], []).append((source, identifier, record))
        hashes = {current[mid].get("file_sha256") for mid in identifiers}
        sightings = []
        seen_sources = set()
        for mid in identifiers:
            for source, identifier, record in self.sighting_index.get(mid.split("/")[-1], []):
                if source not in seen_sources and record.get("file_sha256") not in hashes:
                    sightings.append({"source": source, "identifier": identifier, "first_seen": record["first_seen"], "evidence_path": record["evidence_path"]})
                    seen_sources.add(source)
        return sightings

    def ingest(self, build: Dict[str, Any], registry: Dict[str, Any], sha256: str, verification: str, history: bool = False) -> list[Dict[str, Any]]:
        self.sighting_index = None
        state_path = self.state_dir / f"{self.source}.json"
        state = _read(state_path)
        known = state.get("known", {})
        evidence_path = f"evidence/{self.source}/{sha256}.json.gz"
        observed_at = datetime.now(timezone.utc).isoformat()
        published_at = datetime.fromisoformat(build["published_at"].replace("Z", "+00:00")).isoformat()
        historical = history or not state or datetime.fromisoformat(published_at) < datetime.now(timezone.utc) - timedelta(hours=48)
        snapshot = {"source": self.source, "build": build, "artifact_sha256": sha256, "verification": verification, "observed_at": observed_at, "registry": registry}
        _write(self.state_dir / evidence_path, snapshot)
        is_aggregator = self.registry_only or self.source in AGGREGATOR_SOURCES
        pub_dt = datetime.fromisoformat(published_at)
        events = []
        for base, change in registry_diff(known, registry).items():
            identifiers = change["identifiers"]
            if is_aggregator and not historical:
                identifiers = [mid for mid in identifiers if not _is_old_registry_entry(mid, registry[mid], pub_dt)]
                if not identifiers:
                    continue
            sightings = self._other_sightings(identifiers, registry)
            event_label = "Registry update" if is_aggregator else change["event_label"]
            if sightings and change["event_label"] != "Registry update":
                has_primary_sighting = any(s["source"] not in AGGREGATOR_SOURCES for s in sightings)
                if not is_aggregator or (change["event_label"] == "New identifier" and has_primary_sighting):
                    event_label = "Multiple sightings"
            providers = {registry[mid]["provider"] for mid in identifiers}
            provider = next(iter(providers)) if len(providers) == 1 else "unknown"
            event_id = hashlib.sha256(f"{self.source}:{sha256}:{base}".encode()).hexdigest()[:20]
            excerpts = [{**registry[mid], "build": build["version"], "source_url": build["url"], "first_seen": published_at} for mid in identifiers]
            confidence = evidence_confidence(excerpts, event_label)
            retained_excerpts = [
                {k: v for k, v in item.items() if k != "metadata"}
                for item in excerpts[:25]
            ]
            events.append({
                "id": f"intel-{event_id}", "scanner": self.source, "intelligence": True,
                "header": f"{event_label.upper()} · MULTI-PROVIDER", "title": base,
                "event_label": event_label, "registry_update": event_label == "Registry update",
                "subtitle": f"{len(identifiers)} identifier(s) observed in {self.label}; not a model release claim.",
                "confidence": confidence, "candidate_only": confidence["novelty"]["level"] == "candidate",
                "timestamp_source": build.get("timestamp_source", "Upstream release/commit timestamp; first inspected presence is an upper bound"),
                "family": base, "provider_slug": provider, "provider_name": PROVIDERS.get(provider, "Unattributed"),
                "provider_evidence": "Registry metadata" if provider != "unknown" else "No lab attribution established",
                "models": [
                    {
                        "id": mid,
                        "name": mid,
                        "registry_update": event_label == "Registry update",
                        **(
                            {"released_on": str(registry[mid].get("metadata", {}).get("release_date"))[:10]}
                            if re.match(r"^\d{4}-\d{2}-\d{2}$", str(registry[mid].get("metadata", {}).get("release_date") or "")[:10])
                            else {}
                        ),
                    }
                    for mid in identifiers
                ],
                "detected_at": published_at if historical else observed_at,
                "first_seen": published_at, "observed_at": observed_at,
                "backfill": historical, "build_label": self.label,
                "build_transition": f"{state.get('latest', {}).get('version', 'seed')} -> {build['version']}",
                "build": build["version"], "source_text": build["url"],
                "artifact_sha256": sha256, "verification": verification,
                "evidence": f"data/intelligence/{evidence_path}", "evidence_path": f"data/intelligence/{evidence_path}",
                "evidence_retained": True, "registry_evidence": retained_excerpts, "sightings": sightings,
                "accent_color": "#0891b2", "links": [{"label": self.label, "url": build["url"]}, {"label": "Release metadata", "url": build["manifest_url"]}],
            })
        for identifier, record in registry.items():
            previous = known.get(identifier, {})
            first_seen = min(published_at, previous.get("first_seen", published_at))
            first_evidence = previous.get("first_seen_evidence_path", previous.get("evidence_path", "")) if previous.get("first_seen", "") <= published_at else ""
            compact_record = {k: v for k, v in record.items() if k != "excerpt"}
            known[identifier] = {**compact_record, "first_seen": first_seen, "first_seen_evidence_path": first_evidence or f"data/intelligence/{evidence_path}", "evidence_path": f"data/intelligence/{evidence_path}"}
        latest = state.get("latest", {})
        if not latest or published_at >= latest.get("published_at", ""):
            state["latest"] = {**build, "published_at": published_at, "artifact_sha256": sha256, "registry_ids": sorted(registry)}
        state["known"] = known
        state.setdefault("builds", {})[build["version"]] = {"published_at": published_at, "artifact_sha256": sha256, "evidence_path": evidence_path, "url": build["url"], "integrity": build.get("integrity", "")}
        existing_events = {event["id"]: event for event in state.get("events", []) if not event.get("backfill")}
        existing_events.update({event["id"]: event for event in events if not event.get("backfill")})
        cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
        state["events"] = [event for event in existing_events.values() if event.get("detected_at", "") >= cutoff]
        _write(state_path, state)
        IdentityLedger(self.state_dir).ingest(self.source, registry, {**build, "published_at": published_at}, f"data/intelligence/{evidence_path}", observed_at)
        return events

    def scan(self, history: bool = False, since: str = "2026-10-01", until: str = "") -> list[Dict[str, Any]]:
        state_path = self.state_dir / f"{self.source}.json"
        state = _read(state_path)
        builds = sorted(self.list_builds(history), key=lambda build: build["published_at"])
        for build in builds:
            build["published_at"] = datetime.fromisoformat(build["published_at"].replace("Z", "+00:00")).isoformat()
        if history:
            builds = [build for build in builds if build["published_at"][:10] >= since and (not until or build["published_at"][:10] < until)]
        elif not state:
            builds = builds[-2:]
        if not builds:
            raise ValueError("No verified dated upstream builds found")
        bootstrap = not state
        for build in builds:
            old = state.get("builds", {}).get(build["version"], {})
            if old.get("url") == build["url"] and old.get("integrity", "") == build.get("integrity", "") and (not build.get("sha256") or old.get("artifact_sha256") == build["sha256"]):
                continue
            if not history and state.get("latest") and build["published_at"] < state["latest"]["published_at"]:
                continue
            registry, sha256, verification = self.get_registry(build)
            self.ingest(build, registry, sha256, verification, history or bootstrap)
            state = _read(state_path)
        self.status = {"status": "ok", "latest_build": state.get("latest", {}).get("version"), "builds_retained": len(state.get("builds", {})), "identifiers": len(state.get("known", {}))}
        return [event for event in state.get("events", []) if not event.get("backfill")]


def classify_known(cards: list[Dict[str, Any]], public_names: Iterable[str]) -> list[Dict[str, Any]]:
    public_exact: set[str] = set()
    for name in public_names:
        raw = str(name)
        tail = raw.split("/")[-1].lower()
        if tail:
            public_exact.add(tail)
        norm = normalize(raw)
        if norm:
            public_exact.add(norm)
    public_families = {family(identifier) for identifier in public_exact}
    for card in cards:
        models = card.get("models") or []
        if not models:
            continue
        all_public = all(
            model["id"].split("/")[-1].lower() in public_exact
            or (bool(normalize(model["id"])) and normalize(model["id"]) in public_exact)
            for model in models
        )
        prev_label = card.get("event_label", "")
        if all_public:
            card["event_label"] = "Registry update"
            card["registry_update"] = True
            for model in models:
                model["registry_update"] = True
        elif prev_label == "New identifier" and (
            card.get("family") in public_families or normalize(str(card.get("family") or "")) in public_families
        ):
            card["event_label"] = "New variant"
        if card.get("event_label") != prev_label or prev_label == "New identifier":
            card["header"] = f"{card['event_label'].upper()} · MULTI-PROVIDER"
            if card.get("confidence") and not card.get("candidate_only"):
                card["confidence"]["novelty"]["level"] = card["event_label"].lower()
    return cards


class DevinCliScanner(ModelRegistryScanner):
    source = "devin-cli"
    label = "Devin CLI"

    def list_builds(self, history: bool = False) -> list[Dict[str, Any]]:
        manifest_builds = []
        if not history:
            try:
                manifest = json.loads(fetch(CLI_MANIFEST))
                platform = manifest["platforms"]["x86_64-unknown-linux"]
                manifest_builds.append({"version": manifest["version"], "url": platform["url"], "sha256": platform["sha256"], "manifest_url": CLI_MANIFEST})
            except (OSError, ValueError, KeyError):
                pass
        metadata = json.loads(fetch("https://registry.npmjs.org/devin"))
        builds = []
        for version, entry in metadata["versions"].items():
            if not version.endswith("-linux-x64"):
                continue
            if "CognitionAI/devin-cli" not in str(entry.get("repository", "")):
                raise ValueError("npm package is not linked to the official CLI repository")
            builds.append({"version": version.removesuffix("-linux-x64"), "url": entry["dist"]["tarball"], "integrity": entry["dist"]["integrity"], "published_at": metadata["time"][version], "manifest_url": "https://registry.npmjs.org/devin"})
        for manifest_build in manifest_builds:
            matching = next((build for build in builds if build["version"] == manifest_build["version"]), None)
            if matching:
                builds.remove(matching)
                manifest_build["published_at"] = matching["published_at"]
                builds.append(manifest_build)
            else:
                _trusted_url(manifest_build["url"])
                request = urllib.request.Request(manifest_build["url"], method="HEAD", headers={"User-Agent": "ModelPulse-Tracker/3.0"})
                with urllib.request.build_opener(_TrustedRedirect()).open(request, timeout=30) as response:
                    modified = response.headers.get("Last-Modified")
                    if not modified:
                        raise ValueError("Undated CLI manifest build; refusing a discovery-today timestamp")
                    manifest_build["published_at"] = parsedate_to_datetime(modified).astimezone(timezone.utc).isoformat()
                    manifest_build["timestamp_source"] = "Official artifact Last-Modified"
                builds.append(manifest_build)
        return builds


class DevinDesktopScanner(ModelRegistryScanner):
    source = "devin-desktop"
    label = "Devin Desktop / Windsurf"
    download_limit = 512 * 1024 * 1024
    expanded_limit = 1536 * 1024 * 1024
    poll_interval = 900

    def list_builds(self, history: bool = False) -> list[Dict[str, Any]]:
        return desktop_builds(fetch(DESKTOP_RELEASES).decode("utf-8"))


class LiteLlmRegistryScanner(ModelRegistryScanner):
    source = "litellm-intelligence"
    label = "LiteLLM model registry"
    registry_only = True
    poll_interval = 180

    def list_builds(self, history: bool = False) -> list[Dict[str, Any]]:
        query = urllib.parse.urlencode({"path": LITELLM_PATH, "per_page": 100 if history else 2})
        commits = json.loads(fetch(f"{LITELLM_REPO}/commits?{query}"))
        if not isinstance(commits, list):
            raise ValueError("Invalid LiteLLM commit response")
        return [{"version": commit["sha"], "url": f"https://raw.githubusercontent.com/BerriAI/litellm/{commit['sha']}/{LITELLM_PATH}", "published_at": commit["commit"]["committer"]["date"], "manifest_url": commit["html_url"]} for commit in commits]

    def get_registry(self, build: Dict[str, Any]) -> tuple[Dict[str, Any], str, str]:
        payload = fetch(build["url"])
        data = json.loads(payload)
        if not isinstance(data, dict) or not data:
            raise ValueError("Empty or invalid LiteLLM registry")
        records = {}
        file_sha256 = hashlib.sha256(payload).hexdigest()
        for identifier, metadata in data.items():
            if identifier == "sample_spec" or not _valid(identifier) or not isinstance(metadata, dict):
                continue
            provider = str(metadata.get("provider", "")).lower()
            records[identifier] = {"id": identifier, "family": family(identifier), "file_path": LITELLM_PATH, "excerpt": json.dumps({identifier: metadata})[:1200], "metadata": metadata, "provider": provider if provider in PROVIDERS else "unknown", "provider_evidence": "Explicit provider field" if provider in PROVIDERS else "Integration route is not lab ownership", "file_sha256": file_sha256, "method": "structured registry"}
        if not records:
            raise ValueError("No LiteLLM identifiers extracted")
        return records, hashlib.sha256(payload).hexdigest(), "Commit-pinned upstream registry; local SHA-256 retained"


def catalog_record(identifier: str, metadata: Dict[str, Any], path: str, file_sha256: str, canonical: str = "") -> Dict[str, Any]:
    canonical = canonical or str(metadata.get("canonical_model_id") or metadata.get("base_model") or "")
    origin = canonical.split("/", 1)[0].lower() if "/" in canonical else ""
    provider = origin if origin in PROVIDERS else "unknown"
    return {
        "id": identifier, "family": family(identifier), "file_path": path,
        "file_sha256": file_sha256, "excerpt": json.dumps({identifier: metadata}, ensure_ascii=True)[:1200],
        "metadata": metadata, "canonical_id": canonical, "provider": provider,
        "provider_evidence": "Explicit canonical catalog mapping" if provider != "unknown" else "Hosting route does not establish creator",
        "method": "structured catalog definition",
    }


class ModelsDevApiScanner(ModelRegistryScanner):
    source = "models-dev-api"
    label = "models.dev full catalog"
    registry_only = True
    catalog_url = "https://models.dev/api.json?type=all"
    poll_interval = 120

    def list_builds(self, history: bool = False) -> list[Dict[str, Any]]:
        self.payload = fetch(self.catalog_url, 32 * 1024 * 1024)
        version = hashlib.sha256(self.payload).hexdigest()
        return [{"version": version, "url": self.catalog_url, "manifest_url": self.catalog_url, "published_at": datetime.now(timezone.utc).isoformat(), "timestamp_source": "Tracker observation; catalog publication time unavailable"}]

    def get_registry(self, build: Dict[str, Any]) -> tuple[Dict[str, Any], str, str]:
        payload = self.payload
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("Invalid models.dev catalog")
        digest = hashlib.sha256(payload).hexdigest()
        records = {}
        for route, provider in data.items():
            if not isinstance(provider, dict):
                continue
            for identifier, metadata in provider.get("models", {}).items():
                full_id = f"{route}/{identifier}"
                if not _valid(full_id) or not isinstance(metadata, dict):
                    continue
                if COMMUNITY_TUNE_RE.search(full_id) or COMMUNITY_TUNE_RE.search(str(metadata.get("name") or "")):
                    continue
                records[full_id] = catalog_record(full_id, metadata, "api.json?type=all", digest)
        if not records:
            raise ValueError("Empty models.dev full catalog; baseline unchanged")
        return records, digest, "Published full catalog; local SHA-256 retained"


class ModelsDevGitScanner(ModelRegistryScanner):
    source = "models-dev-git"
    label = "models.dev source definitions"
    registry_only = True
    poll_interval = 600

    def list_builds(self, history: bool = False) -> list[Dict[str, Any]]:
        query = urllib.parse.urlencode({"per_page": 100 if history else 2})
        commits = json.loads(fetch("https://api.github.com/repos/anomalyco/models.dev/commits?" + query))
        if not isinstance(commits, list):
            raise ValueError("Invalid models.dev commit response")
        return [{"version": commit["sha"], "url": f"https://codeload.github.com/anomalyco/models.dev/zip/{commit['sha']}", "published_at": commit["commit"]["committer"]["date"], "manifest_url": commit["html_url"]} for commit in commits]

    def get_registry(self, build: Dict[str, Any]) -> tuple[Dict[str, Any], str, str]:
        payload = fetch(build["url"], 64 * 1024 * 1024)
        digest = hashlib.sha256(payload).hexdigest()
        records = {}
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            total = 0
            if len(archive.infolist()) > MAX_MEMBERS:
                raise ValueError("Source archive member limit exceeded")
            for member in archive.infolist():
                _safe_path(member.filename)
                total += member.file_size
                if total > MAX_EXPANDED or member.file_size > MAX_MEMBER:
                    raise ValueError("Source archive expansion limit exceeded")
                path = member.filename.split("/", 1)[-1]
                if member.is_dir() or not path.endswith(".toml") or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                parts = pathlib.PurePosixPath(path).parts
                if parts[0] == "models" and len(parts) >= 3:
                    identifier = "/".join(parts[1:]).removesuffix(".toml")
                    canonical = identifier
                elif parts[0] == "providers" and len(parts) >= 4 and parts[2] == "models":
                    identifier = parts[1] + "/" + "/".join(parts[3:]).removesuffix(".toml")
                    canonical = ""
                else:
                    continue
                content = archive.read(member)
                if tomllib is None:
                    raise RuntimeError("models.dev source inspection requires tomli on Python 3.10")
                metadata = tomllib.loads(content.decode("utf-8"))
                if _valid(identifier):
                    if COMMUNITY_TUNE_RE.search(identifier) or COMMUNITY_TUNE_RE.search(str(metadata.get("name") or "")):
                        continue
                    if not canonical and identifier in records:
                        canonical = records[identifier].get("canonical_id", "")
                    record = catalog_record(identifier, metadata, path, hashlib.sha256(content).hexdigest(), canonical)
                    record["definition_url"] = f"https://github.com/anomalyco/models.dev/blob/{build['version']}/{path}"
                    records[identifier] = record
        for identifier, record in records.items():
            meta = record.get("metadata") or {}
            if meta.get("release_date"):
                continue
            cand_ids = [record.get("canonical_id", ""), identifier.split("/", 1)[-1] if "/" in identifier else ""]
            for cid in cand_ids:
                if cid and cid in records and (records[cid].get("metadata") or {}).get("release_date"):
                    meta["release_date"] = records[cid]["metadata"]["release_date"]
                    break
        if not records:
            raise ValueError("No models.dev definitions found; baseline unchanged")
        return records, digest, "Commit-pinned source definitions; local SHA-256 retained"


def reconcile_identities(state_dir: pathlib.Path = STATE_DIR) -> Dict[str, Any]:
    ledger = IdentityLedger(state_dir)
    checked = 0
    failures = []
    for path in sorted((state_dir / "evidence").glob("*/*.json.gz")):
        snapshot = _read(path)
        if not snapshot.get("registry") or snapshot.get("artifact_sha256") != path.name.removesuffix(".json.gz"):
            failures.append(path.relative_to(state_dir).as_posix())
            continue
        ledger.ingest(snapshot["source"], snapshot["registry"], snapshot["build"], "data/intelligence/" + path.relative_to(state_dir).as_posix(), snapshot["observed_at"], persist=False)
        checked += 1
    if not failures:
        ledger.flush()
    result = {"completed_at": datetime.now(timezone.utc).isoformat(), "snapshots_checked": checked, "invalid_evidence": failures, "identities": ledger.summarize(), "mode": "Offline retained evidence replay; no historical alerts or binary execution"}
    _write(state_dir / "reconciliation.json", result)
    if failures:
        raise ValueError("Retained evidence reconciliation failed")
    return result


def intelligence_metrics(cards: list[Dict[str, Any]], health: Dict[str, Any], state_dir: pathlib.Path = STATE_DIR) -> Dict[str, Any]:
    events = {card["id"]: card for card in cards if card.get("intelligence") and not card.get("backfill")}
    complete = 0
    lags = []
    for card in events.values():
        path = state_dir.parent.parent / card.get("evidence_path", "")
        evidence = _read(path) if path.is_file() else {}
        if card.get("artifact_sha256") and evidence.get("artifact_sha256") == card["artifact_sha256"] and card.get("registry_evidence"):
            complete += 1
        if card.get("timestamp_source", "").startswith("Tracker observation"):
            continue
        try:
            lag = (datetime.fromisoformat(card["observed_at"].replace("Z", "+00:00")) - datetime.fromisoformat(card["first_seen"].replace("Z", "+00:00"))).total_seconds()
            if lag >= 0:
                lags.append(lag)
        except (ValueError, KeyError):
            pass
    reviews = _read(state_dir / "candidate_queue.json").get("items", {})
    reviewed = [item for item in reviews.values() if item.get("review") in {"confirmed", "false_positive"}]
    regressions = _read(state_dir / "regression_results.json")
    return {
        "window": "Retained non-backfill cards; not an all-time performance claim",
        "detection_lag": {"samples": len(lags), "seconds_mean": sum(lags) / len(lags) if lags else None, "basis": "Observation minus first inspected build timestamp; upper-bound publication lag, not exact introduction time"},
        "missed_discoveries": {"missed": regressions.get("missed"), "cases_checked": regressions.get("cases_checked", 0), "basis": "Explicit regression report only; unknown without a replay report"},
        "false_positives": {"reviewed": len(reviewed), "count": sum(item.get("review") == "false_positive" for item in reviewed), "rate": sum(item.get("review") == "false_positive" for item in reviewed) / len(reviewed) if reviewed else None},
        "evidence_completeness": {"complete": complete, "events": len(events), "rate": complete / len(events) if events else None},
        "source_health": {"sources": len(health), "failed": sum(item.get("status") == "failed" for item in health.values()), "stale": sum(bool(item.get("stale")) for item in health.values())},
    }


def historical_backfill(state_dir: pathlib.Path = STATE_DIR, since: str = "2026-10-01", until: str = "2026-12-01", report_only: bool = False) -> Dict[str, Any]:
    report: Dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "since": since, "until_exclusive": until, "sources": {}, "notice": "First present in inspected builds is an upper bound, not an exact introduction date. Missing releases remain unverified."}
    for scanner_type in (DevinCliScanner, DevinDesktopScanner, LiteLlmRegistryScanner):
        scanner = scanner_type(state_dir)
        try:
            if not report_only:
                scanner.scan(history=True, since=since, until=until)
            state = _read(pathlib.Path(state_dir) / f"{scanner.source}.json")
            if not state.get("builds"):
                raise ValueError("No retained upstream builds")
            if report_only:
                scanner.status = {"status": "ok", "latest_build": state.get("latest", {}).get("version"), "builds_retained": len(state["builds"]), "identifiers": len(state.get("known", {}))}
            timeline = {}
            inspected = set()
            for version, build in sorted(state.get("builds", {}).items(), key=lambda item: item[1]["published_at"]):
                if not since <= build["published_at"][:10] < until:
                    continue
                snapshot = _read(pathlib.Path(state_dir) / build["evidence_path"])
                for identifier in snapshot.get("registry", {}):
                    if identifier in inspected:
                        continue
                    inspected.add(identifier)
                    base = family(identifier)
                    entry = timeline.setdefault(base, {"first_present": build["published_at"], "identifiers": []})
                    entry["identifiers"].append({"id": identifier, "first_present": build["published_at"], "build": version, "evidence_path": "data/intelligence/" + build["evidence_path"]})
            report["sources"][scanner.source] = {**scanner.status, "builds": state.get("builds", {}), "families": timeline}
        except Exception as exc:
            report["sources"][scanner.source] = {"status": "failed", "error_type": type(exc).__name__}
    _write(pathlib.Path(state_dir) / "backfill_report.json", report)
    return report


def compact_evidence(state_dir: pathlib.Path = STATE_DIR) -> int:
    root = pathlib.Path(state_dir)
    replacements = {}
    originals = list((root / "evidence").glob("*/*.json"))
    for path in originals:
        compressed = path.with_suffix(".json.gz")
        data = _read(path)
        _write(compressed, data)
        if _read(compressed) != data:
            raise ValueError("Evidence compression verification failed")
        old = path.relative_to(root).as_posix()
        replacements[old] = compressed.relative_to(root).as_posix()
        replacements["data/intelligence/" + old] = "data/intelligence/" + replacements[old]

    def rewrite(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: rewrite(child) for key, child in value.items()}
        if isinstance(value, list):
            return [rewrite(child) for child in value]
        return replacements.get(value, value) if isinstance(value, str) else value

    for path in root.glob("*.json"):
        _write(path, rewrite(_read(path)))
    for path in originals:
        path.unlink()
    return len(originals)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Binary & Model Registry Intelligence (static analysis only)")
    parser.add_argument("--backfill", action="store_true")
    parser.add_argument("--report-only", action="store_true", help="Rebuild history from retained evidence without network calls")
    parser.add_argument("--compact-evidence", action="store_true", help="Losslessly compress earlier retained snapshots and update references")
    parser.add_argument("--reconcile", action="store_true", help="Replay retained snapshots into identity state without downloads or alerts")
    parser.add_argument("--since", default="2026-10-01")
    parser.add_argument("--until", default="2026-12-01", help="Exclusive historical cutoff")
    parser.add_argument("--state-dir", type=pathlib.Path, default=STATE_DIR)
    args = parser.parse_args()
    if args.reconcile:
        result = reconcile_identities(args.state_dir)
        print(f"Reconciled {result['snapshots_checked']} retained snapshots")
        if not args.backfill and not args.report_only and not args.compact_evidence:
            return
    if args.compact_evidence:
        print(f"Compressed {compact_evidence(args.state_dir)} retained registry snapshots")
        if not args.backfill and not args.report_only:
            return
    if not args.backfill and not args.report_only:
        parser.error("Use --backfill for history; normal scans run through server.py --scan")
    report = historical_backfill(args.state_dir, args.since, args.until, args.report_only)
    for source, result in report["sources"].items():
        print(f"{source}: {result['status']}, {len(result.get('builds', {}))} builds retained")
    if any(result["status"] != "ok" for result in report["sources"].values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()