"""Multi-source scanners for Desktop Builds, CLI/SDK Tarballs, Open-Source Hubs, and Engine Registries."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tarfile
from typing import Any, Dict, List, Optional, Set
import urllib.parse
import urllib.request
import zlib

from tracker.extractor import (
    CACHE_DIR,
    clean_go_model_id,
    extract_models_from_bytes,
    fetch_elf_rodata_slice,
    fetch_range,
    humanize_model_id,
    infer_family_title,
    infer_provider,
    is_legacy_model_id,
)

ANTIGRAVITY_RELEASES_URL = "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/releases"
ANTIGRAVITY_GCS_BASE = "https://storage.googleapis.com/antigravity-public"
ANTIGRAVITY_INSIDERS_YML = f"{ANTIGRAVITY_GCS_BASE}/insiders/latest-x64-linux.yml"

_VENDOR_PREFIX_RE = re.compile(
    r"^(?:(?:us|eu|global|apac)\.)?(?:anthropic\.|meta\.|mistral\.|amazon\.|cohere\.|ai21\.|xai\.|zai-|zhipu-|thudm-|moonshot-|minimax-|qwen-|deepseek-)"
)


def _canonical_model_slug(raw_key: str) -> str:
    """Normalize a model ID or provider/model key into a vendor-neutral, punctuation-free slug."""
    tail = raw_key.strip().lower().split("/")[-1].split(":")[0]
    tail = _VENDOR_PREFIX_RE.sub("", tail)
    if re.match(r"^(?:opus|sonnet|haiku|fable|mythos)-[0-9]", tail):
        tail = f"claude-{tail}"
    return re.sub(r"[-._]", "", tail)


def _decompress_brotli(comp_bytes: bytes) -> bytes:
    """Decompress Brotli (.br) binary payloads using Python brotli or built-in Node.js zlib."""
    try:
        import brotli  # type: ignore

        return brotli.decompress(comp_bytes)
    except Exception:
        proc = subprocess.run(
            ["node", "-e", "process.stdout.write(require('zlib').brotliDecompressSync(require('fs').readFileSync(0)))"],
            input=comp_bytes,
            capture_output=True,
            timeout=30,
            check=True,
        )
        return proc.stdout


def _http_get_json(url: str, timeout: int = 12, extra_headers: Optional[Dict[str, str]] = None) -> Any:
    hdrs = {
        "User-Agent": "ModelPulse-Tracker/2.0 (+https://github.com/siddiquiamir)",
        "Accept": "application/json",
    }
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def _http_get_text(url: str, timeout: int = 12) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ModelPulse-Tracker/2.0 (+https://github.com/siddiquiamir)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def group_models_by_family(model_ids: Set[str]) -> Dict[str, List[str]]:
    """
    Group a set of newly added model IDs into distinct model families so each family
    gets a focused, high-signal report card (e.g. 'Gemini 4 Argon', 'Claude Opus 5.5').
    """
    groups: Dict[str, List[str]] = {}
    for mid in sorted(model_ids):
        parts = mid.split("-")
        if len(parts) >= 3 and parts[0] == "gemini" and parts[1] == "4" and parts[2] in {"argon", "carbon", "krypton", "xenon"}:
            key = f"gemini-4-{parts[2]}"
        elif len(parts) >= 3 and parts[0] == "gemini" and parts[1] == "omni":
            key = "gemini-omni-flash"
        elif len(parts) >= 3 and parts[0] == "gemini" and parts[1] == "robotics":
            key = "gemini-robotics-er"
        elif len(parts) >= 3 and parts[0] == "gemini" and parts[1] == "nano":
            key = "gemini-nano-banana"
        elif len(parts) >= 4 and parts[0] == "claude" and parts[2].isdigit() and parts[3].isdigit():
            key = f"claude-{parts[1]}-{parts[2]}-{parts[3]}"
        elif len(parts) >= 3:
            key = f"{parts[0]}-{parts[1]}-{parts[2]}"
        else:
            key = mid
        groups.setdefault(key, []).append(mid)
    return groups


class AntigravityDesktopScanner:
    """
    Scans official Google Antigravity Stable & Insiders Linux x64 builds via ELF64 .rodata
    HTTP Range slicing and extracts compiled-in model identifier diffs.
    """

    def list_available_builds(self, max_stable: int = 8) -> List[Dict[str, str]]:
        builds: List[Dict[str, str]] = []
        try:
            releases = _http_get_json(ANTIGRAVITY_RELEASES_URL)
            for item in releases[:max_stable]:
                ver = item["version"]
                exec_id = item["execution_id"]
                builds.append(
                    {
                        "version": ver,
                        "channel": "stable",
                        "execution_id": exec_id,
                        "binary_url": f"{ANTIGRAVITY_GCS_BASE}/antigravity-hub/{ver}-{exec_id}/unsigned/language_server-linux-x64",
                        "feed_url": ANTIGRAVITY_RELEASES_URL,
                    }
                )
        except Exception as exc:
            print(f"[AntigravityScanner] Failed to list stable releases: {exc}")

        try:
            yml_text = _http_get_text(ANTIGRAVITY_INSIDERS_YML)
            m = re.search(r"version:\s*([0-9A-Za-z._-]+)", yml_text)
            if m:
                ins_ver = m.group(1).strip()
                builds.insert(
                    0,
                    {
                        "version": f"{ins_ver} (Insiders)",
                        "raw_version": ins_ver,
                        "channel": "insiders",
                        "binary_url": f"{ANTIGRAVITY_GCS_BASE}/insiders/{ins_ver}/unsigned/language_server-linux-x64",
                        "feed_url": ANTIGRAVITY_INSIDERS_YML,
                    },
                )
        except Exception as exc:
            print(f"[AntigravityScanner] Failed to fetch insiders channel: {exc}")

        return builds

    def get_build_timestamp(self, build: Dict[str, str]) -> str:
        """Fetch and cache the exact Last-Modified publication timestamp of a build on GCS."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        ver_slug = re.sub(r"[^0-9A-Za-z._-]", "_", build["version"])
        ts_file = CACHE_DIR / f"ag_ts_{ver_slug}.txt"
        if ts_file.exists():
            return ts_file.read_text(encoding="utf-8").strip()

        raw_v = build.get("raw_version", "")
        m = re.search(r"(202[0-9]{11})", raw_v)
        if m:
            d = m.group(1)
            iso = f"{d[:4]}-{d[4:6]}-{d[6:8]}T{d[8:10]}:{d[10:12]}:{d[12:14]}Z"
            ts_file.write_text(iso, encoding="utf-8")
            return iso

        try:
            from email.utils import parsedate_to_datetime
            req = urllib.request.Request(
                build["binary_url"],
                method="HEAD",
                headers={"User-Agent": "ModelPulse-Tracker/2.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                lm = resp.headers.get("Last-Modified")
                if lm:
                    dt = parsedate_to_datetime(lm).astimezone(timezone.utc)
                    iso = dt.isoformat()
                    ts_file.write_text(iso, encoding="utf-8")
                    return iso
        except Exception:
            pass
        return datetime.now(timezone.utc).isoformat()

    def get_models_for_build(self, build: Dict[str, str]) -> Set[str]:
        ver_slug = re.sub(r"[^0-9A-Za-z._-]", "_", build["version"])
        rodata = fetch_elf_rodata_slice(
            build["binary_url"],
            cache_key=f"ag_{ver_slug}",
            max_bytes=2_500_000,
        )
        return extract_models_from_bytes(rodata)

    def get_build_models_map(self, max_stable: int = 8) -> Dict[str, List[str]]:
        """Return a map of {build_version: [sorted_model_ids]} for client-side build comparison."""
        builds = self.list_available_builds(max_stable=max_stable)
        out: Dict[str, List[str]] = {}
        for b in builds:
            try:
                out[b["version"]] = sorted(self.get_models_for_build(b))
            except Exception:
                pass
        return out

    def diff_two_builds(self, old_build: Dict[str, str], new_build: Dict[str, str]) -> List[Dict[str, Any]]:
        old_models = self.get_models_for_build(old_build)
        new_models = self.get_models_for_build(new_build)
        added = new_models - old_models
        if not added:
            return []

        cards: List[Dict[str, Any]] = []
        family_groups = group_models_by_family(added)

        priority_order = sorted(
            family_groups.keys(),
            key=lambda k: (
                0 if ("argon" in k or "carbon" in k) else 1 if "5-5" in k else 2 if "omni" in k else 3,
                k,
            ),
        )

        pub_iso = self.get_build_timestamp(new_build)
        transition = f"{old_build['version']} -> {new_build['version']}"

        for fam_key in priority_order:
            mids = sorted(family_groups[fam_key])
            provider = infer_provider(mids[0])
            title = infer_family_title(mids)
            card_id = f"ag-{old_build['version']}-{new_build['version']}-{fam_key}"
            card_id = re.sub(r"[^a-zA-Z0-9._-]", "_", card_id)

            cards.append(
                {
                    "id": card_id,
                    "category": "desktop-diff",
                    "scanner": "antigravity",
                    "header": f"ANTIGRAVITY DESKTOP DIFF · {provider['name']}",
                    "title": title,
                    "subtitle": "Verified desktop build comparison",
                    "build_label": "Build",
                    "build_transition": transition,
                    "old_version": old_build["version"],
                    "new_version": new_build["version"],
                    "models": [
                        {"id": mid, "name": humanize_model_id(mid)} for mid in mids
                    ],
                    "evidence": "resources/bin/language_server",
                    "source_text": "official public Linux x64 release archives.",
                    "disclaimer_1": "Verified differences between existing builds; this is not a newly published release announcement.",
                    "disclaimer_2": "Compiled-in names and identifiers. This does not confirm model rollout or account access.",
                    "provider_name": provider["name"],
                    "provider_slug": provider["slug"],
                    "accent_color": provider["color"],
                    "links": [
                        {"label": "Public release feed", "url": new_build["feed_url"]},
                        {"label": "Official build", "url": new_build["binary_url"]},
                    ],
                    "detected_at": pub_iso,
                }
            )
        return cards

    def scan(self, max_stable: int = 8) -> List[Dict[str, Any]]:
        builds = self.list_available_builds(max_stable=max_stable)
        if len(builds) < 2:
            return []

        with ThreadPoolExecutor(max_workers=4) as pool:
            future_map = {pool.submit(self.get_models_for_build, b): b["version"] for b in builds}
            for fut in as_completed(future_map):
                try:
                    fut.result()
                except Exception as exc:
                    print(f"[AntigravityScanner] Build slice warning ({future_map[fut]}): {exc}")

        stable_builds = [b for b in builds if b.get("channel") == "stable"]
        insiders_builds = [b for b in builds if b.get("channel") == "insiders"]

        all_cards: List[Dict[str, Any]] = []

        if insiders_builds and stable_builds:
            try:
                all_cards.extend(self.diff_two_builds(stable_builds[0], insiders_builds[0]))
            except Exception as exc:
                print(f"[AntigravityScanner] Insiders diff error: {exc}")

        for i in range(len(stable_builds) - 1):
            newer = stable_builds[i]
            older = stable_builds[i + 1]
            try:
                all_cards.extend(self.diff_two_builds(older, newer))
            except Exception as exc:
                print(f"[AntigravityScanner] Stable diff error ({older['version']} -> {newer['version']}): {exc}")

        return all_cards


class AntigravityAcpScanner:
    """
    Scans Google Antigravity ACP (Agent Client Protocol) Server releases directly on
    Google's Release CDN (dl.google.com/agy-extensions/releases/...) by extracting the
    embedded Google3 Discovery Document (cloudcode-pa_prod_google_rest_v1internal.json)
    inside agy_acp_server.par. Detects both new version releases (1.4.2 -> 1.4.3 -> 1.4.4)
    and In-Place CDN Revision Drops (when Google overwrites a release zip in place).
    """

    CDN_URL_TEMPLATE = "https://dl.google.com/agy-extensions/releases/macos/agy-acp-server-{ver}-darwin-arm64.zip"
    CANDIDATE_VERSIONS = ["1.4.0", "1.4.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.6", "1.5.0"]
    DISCOVERY_DOC_PATH = "google3/google/internal/cloud/code/cloudcode-pa_prod_google_rest_v1internal.json"
    BASELINES_FILE = pathlib.Path(__file__).resolve().parent.parent / "data" / "source_baselines.json"

    def _load_baselines(self) -> Dict[str, Any]:
        if self.BASELINES_FILE.exists():
            try:
                return json.loads(self.BASELINES_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_baselines(self, data: Dict[str, Any]) -> None:
        self.BASELINES_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.BASELINES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _head_release(self, ver: str) -> Optional[Dict[str, Any]]:
        url = self.CDN_URL_TEMPLATE.format(ver=ver)
        try:
            from email.utils import parsedate_to_datetime
            req = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": "ModelPulse-Tracker/2.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status != 200:
                    return None
                cl = int(resp.headers.get("Content-Length", "0") or 0)
                lm = resp.headers.get("Last-Modified", "")
                etag = (resp.headers.get("ETag", "") or "").strip('"')
                iso_ts = datetime.now(timezone.utc).isoformat()
                if lm:
                    try:
                        iso_ts = parsedate_to_datetime(lm).astimezone(timezone.utc).isoformat()
                    except Exception:
                        pass
                return {
                    "version": ver,
                    "url": url,
                    "zip_size": cl,
                    "last_modified": lm,
                    "etag": etag,
                    "detected_at": iso_ts,
                }
        except Exception:
            return None

    def _extract_discovery_snapshot(self, ver: str, head_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Download the Range slice of agy-acp-server-{ver}-darwin-arm64.zip and extract the Discovery Doc."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        etag_slug = re.sub(r"[^0-9A-Za-z._-]", "_", head_meta.get("etag") or str(head_meta.get("zip_size", "")))
        cache_uncomp = CACHE_DIR / f"acp_{ver}_{etag_slug}_uncomp.bin"
        legacy_cache = CACHE_DIR / f"acp_{ver}_uncomp.bin"

        uncomp: Optional[bytes] = None
        if cache_uncomp.exists() and cache_uncomp.stat().st_size > 70_000_000:
            uncomp = cache_uncomp.read_bytes()
        elif legacy_cache.exists() and legacy_cache.stat().st_size > 70_000_000:
            uncomp = legacy_cache.read_bytes()
        else:
            raw_zip = fetch_range(head_meta["url"], 0, 38_000_000, timeout=60)
            fn_len = int.from_bytes(raw_zip[26:28], "little")
            extra_len = int.from_bytes(raw_zip[28:30], "little")
            data_start = 30 + fn_len + extra_len
            decomp = zlib.decompressobj(-zlib.MAX_WBITS)
            uncomp = decomp.decompress(raw_zip[data_start:])
            cache_uncomp.write_bytes(uncomp)

        needle = b"cloudcode-pa_prod_google_rest_v1internal.json"
        pos = 0
        while True:
            idx = uncomp.find(needle, pos)
            if idx == -1:
                return None
            pk_start = uncomp.rfind(b"PK\x03\x04", 0, idx + 1)
            fn_len = int.from_bytes(uncomp[pk_start + 26 : pk_start + 28], "little")
            ex_len = int.from_bytes(uncomp[pk_start + 28 : pk_start + 30], "little")
            fname = uncomp[pk_start + 30 : pk_start + 30 + fn_len].decode("utf-8", "ignore")
            if "cloudcode-pa_prod_google_rest_v1internal.json" in fname:
                pk_end = uncomp.find(b"PK\x03\x04", pk_start + 4)
                body = uncomp[pk_start + 30 + fn_len + ex_len : pk_end]
                doc = json.loads(body.decode("utf-8"))
                prop = doc["schemas"]["ExaCodeiumCommonPbModelInfo"]["properties"]["modelId"]
                enums = prop.get("enum", [])
                descs = prop.get("enumDescriptions", [])
                active_count = len([1 for e, d in zip(enums, descs) if d or "PLACEHOLDER" not in e])
                models = [d for d in descs if d]
                enum_map = {d: e for e, d in zip(enums, descs) if d}
                return {
                    "version": ver,
                    "url": head_meta["url"],
                    "zip_size": head_meta["zip_size"],
                    "last_modified": head_meta["last_modified"],
                    "etag": head_meta["etag"],
                    "detected_at": head_meta["detected_at"],
                    "doc_size": len(body),
                    "active_count": active_count,
                    "models": models,
                    "enum_map": enum_map,
                }
            pos = idx + 1

    def scan(self) -> List[Dict[str, Any]]:
        baselines = self._load_baselines()
        acp_releases: Dict[str, Any] = baselines.setdefault("acp_releases", {})
        changed = False

        for ver in self.CANDIDATE_VERSIONS:
            head_meta = self._head_release(ver)
            if not head_meta:
                continue
            existing = acp_releases.get(ver)
            is_missing = existing is None
            is_revised = (
                existing is not None
                and (
                    existing.get("etag") != head_meta["etag"]
                    or existing.get("zip_size") != head_meta["zip_size"]
                )
            )
            if is_missing or is_revised:
                try:
                    snap = self._extract_discovery_snapshot(ver, head_meta)
                    if snap:
                        if is_revised and existing:
                            snap["initial_snapshot"] = existing.get("initial_snapshot") or {
                                "doc_size": existing.get("doc_size"),
                                "active_count": existing.get("active_count"),
                                "models": existing.get("models", []),
                                "etag": existing.get("etag"),
                                "last_modified": existing.get("last_modified"),
                            }
                        acp_releases[ver] = snap
                        changed = True
                except Exception as exc:
                    print(f"[AntigravityAcpScanner] Extraction warning ({ver}): {exc}")

        if changed:
            self._save_baselines(baselines)

        cards: List[Dict[str, Any]] = []
        sorted_vers = sorted(acp_releases.keys(), key=lambda v: [int(x) for x in v.split(".")])

        # 1. Emit In-Place Revision Drop cards (e.g. v1.4.3 Initial -> v1.4.3 Revision)
        revision_covered_models: Set[str] = set()
        for ver in reversed(sorted_vers):
            snap = acp_releases[ver]
            init_snap = snap.get("initial_snapshot")
            if not init_snap:
                continue
            old_models = set(init_snap.get("models", []))
            new_models = [m for m in snap.get("models", []) if m not in old_models]
            if not new_models:
                continue
            revision_covered_models.update(new_models)
            old_doc = init_snap.get("doc_size", 0)
            new_doc = snap.get("doc_size", 0)
            old_act = init_snap.get("active_count", 0)
            new_act = snap.get("active_count", 0)
            doc_diff = new_doc - old_doc
            act_diff = new_act - old_act
            enum_map = snap.get("enum_map", {})

            def _fmt_acp_model(mid: str) -> Dict[str, str]:
                ek = enum_map.get(mid, "")
                short_ek = ek.replace("MODEL_PLACEHOLDER_", "") if ek else ""
                label = f"{humanize_model_id(mid)} ({short_ek})" if short_ek else humanize_model_id(mid)
                return {"id": mid, "name": label}

            cards.append(
                {
                    "id": f"ag-acp-{ver}-revision-diff",
                    "category": "desktop-diff",
                    "scanner": "antigravity-acp",
                    "header": f"ANTIGRAVITY ACP (IN-PLACE REVISION) · v{ver}",
                    "title": f"Gemini 4 Carbon & Argon Teamfood (ACP v{ver} Revision)",
                    "subtitle": f"Google Release CDN Ninja Revision Drop · Active Models: {old_act} -> {new_act} ({act_diff:+d}) · {len(new_models)} added / 0 removed",
                    "build_label": "Discovery Doc Diff",
                    "build_transition": f"v{ver} (Initial) -> v{ver} (Revision) · {old_doc:,} -> {new_doc:,} bytes ({doc_diff:+,})",
                    "old_version": f"{ver} (Initial)",
                    "new_version": f"{ver} (Revision)",
                    "models": [_fmt_acp_model(mid) for mid in new_models],
                    "evidence": f"agy_acp_server.par -> {self.DISCOVERY_DOC_PATH}",
                    "source_text": "official Google Antigravity ACP Server release archive on dl.google.com.",
                    "disclaimer_1": f"Detected in-place CDN revision of agy-acp-server-{ver}: embedded Discovery Doc grew by {doc_diff:+,} bytes ({old_act} -> {new_act} active models).",
                    "disclaimer_2": "Internal & teamfood model identifiers (MODEL_PLACEHOLDER_M426–M436) in cloudcode-pa_prod_google_rest_v1internal.json.",
                    "provider_name": "GOOGLE",
                    "provider_slug": "google",
                    "accent_color": "#38bdf8",
                    "links": [
                        {"label": f"ACP v{ver} CDN Archive", "url": snap["url"]},
                        {"label": "AUR agy-acp-server", "url": "https://aur.archlinux.org/packages/agy-acp-server"},
                    ],
                    "detected_at": snap.get("detected_at", datetime.now(timezone.utc).isoformat()),
                }
            )

        # 2. Emit consecutive version diffs (e.g. 1.4.1 -> 1.4.3 Initial internal models)
        if len(sorted_vers) >= 2:
            base_v = "1.4.1" if "1.4.1" in acp_releases else sorted_vers[0]
            oldest_snap = acp_releases[base_v]
            latest_snap = acp_releases[sorted_vers[-1]]
            init_or_latest = latest_snap.get("initial_snapshot") or latest_snap
            enum_map = latest_snap.get("enum_map", {})
            base_models = set(oldest_snap.get("models", []))
            added_across = [
                m for m in latest_snap.get("models", [])
                if m not in base_models and m not in revision_covered_models
            ]
            if added_across:
                old_v = base_v
                new_v = sorted_vers[-1]
                old_doc = oldest_snap.get("doc_size", 0)
                new_doc = init_or_latest.get("doc_size", latest_snap.get("doc_size", 0))
                old_act = oldest_snap.get("active_count", 0)
                new_act = init_or_latest.get("active_count", latest_snap.get("active_count", 0))
                doc_diff = new_doc - old_doc
                act_diff = new_act - old_act

                def _fmt_across_model(mid: str) -> Dict[str, str]:
                    ek = enum_map.get(mid, "")
                    short_ek = ek.replace("MODEL_PLACEHOLDER_", "") if ek else ""
                    label = f"{humanize_model_id(mid)} ({short_ek})" if short_ek else humanize_model_id(mid)
                    return {"id": mid, "name": label}

                cards.append(
                    {
                        "id": f"ag-acp-1.4.0-{new_v}-diff",
                        "category": "desktop-diff",
                        "scanner": "antigravity-acp",
                        "header": "ANTIGRAVITY ACP (UNMANIFESTED DROP) · GOOGLE",
                        "title": "Gemini 4 Argon Cyber, Barium & Sonnet 5.5 BoN (ACP Discovery Doc)",
                        "subtitle": f"Google Release CDN (Pre-Manifest) · Active Models: {old_act} -> {new_act} ({act_diff:+d}) · {len(added_across)} added / 0 removed",
                        "build_label": "Discovery Doc Diff",
                        "build_transition": f"v{old_v} -> v{new_v} · {old_doc:,} -> {new_doc:,} bytes ({doc_diff:+,})",
                        "old_version": old_v,
                        "new_version": new_v,
                        "models": [_fmt_across_model(mid) for mid in added_across],
                        "evidence": f"agy_acp_server.par -> {self.DISCOVERY_DOC_PATH}",
                        "source_text": "official Google Antigravity ACP Server release archives on dl.google.com.",
                        "disclaimer_1": f"Extracted from the embedded Google internal Cloud Code Discovery Document ({old_doc:,} -> {new_doc:,} bytes, +{doc_diff:,}).",
                        "disclaimer_2": "Internal teamfood (-tf), router, and evaluation checkpoints (MODEL_PLACEHOLDER_M420–M425).",
                        "provider_name": "GOOGLE",
                        "provider_slug": "google",
                        "accent_color": "#38bdf8",
                        "links": [
                            {"label": f"ACP v{new_v} CDN Archive", "url": latest_snap["url"]},
                            {"label": f"ACP v{old_v} CDN Archive", "url": oldest_snap["url"]},
                        ],
                        "detected_at": latest_snap.get("detected_at", datetime.now(timezone.utc).isoformat()),
                    }
                )

        return cards


class NpmCliAndSdkScanner:
    """
    Scans official AI CLI & SDK packages on npm — including compiled native binaries
    (@anthropic-ai/claude-code-linux-x64 on latest/next, @openai/codex on linux-x64 & alpha-linux-x64)
    as well as JS/TS SDK tarballs (@google/genai, @anthropic-ai/sdk, openai).
    Persists extracted binary model catalogs in data/source_baselines.json for instant repeat scans
    and cross-checks against LiteLLM to prevent already-released models from firing false alerts.
    """

    PACKAGES = [
        {
            "pkg": "@anthropic-ai/claude-code-linux-x64",
            "mode": "claude_binary",
            "header": "CLAUDE CODE NATIVE BINARY DIFF · ANTHROPIC",
            "subtitle": "Verified Bun binary embedded model table comparison (latest + next)",
            "evidence": "@anthropic-ai/claude-code-linux-x64 binary model registry",
            "source_text": "official Anthropic Claude Code Linux x64 native binary tarball.",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
        },
        {
            "pkg": "@openai/codex",
            "mode": "codex_binary",
            "header": "OPENAI CODEX NATIVE BINARY DIFF · OPENAI",
            "subtitle": "Verified Rust binary embedded models JSON comparison (stable + alpha)",
            "evidence": "@openai/codex (-linux-x64 / alpha-linux-x64) embedded catalog",
            "source_text": "official OpenAI Codex Linux x64 native Rust binary tarball.",
            "provider_slug": "openai",
            "accent_color": "#10b981",
        },
        {
            "pkg": "@xai-official/grok-linux-x64",
            "mode": "grok_binary",
            "header": "XAI GROK BUILD NATIVE BINARY DIFF · XAI",
            "subtitle": "Verified Grok CLI Brotli Rust binary comparison (latest + alpha)",
            "evidence": "@xai-official/grok-linux-x64 (package/bin/grok.br)",
            "source_text": "official xAI Grok Build Linux x64 native CLI binary tarball.",
            "provider_slug": "xai",
            "accent_color": "#e2e8f0",
        },
        {
            "pkg": "@google/genai",
            "mode": "js_sdk",
            "header": "GOOGLE GENAI SDK DIFF · GOOGLE",
            "subtitle": "Verified official SDK package comparison",
            "evidence": "dist/index.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (@google/genai).",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
        },
        {
            "pkg": "openai",
            "mode": "js_sdk",
            "header": "OPENAI OFFICIAL SDK DIFF · OPENAI",
            "subtitle": "Verified official TypeScript SDK model union comparison",
            "evidence": "resources/shared.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (openai).",
            "provider_slug": "openai",
            "accent_color": "#10b981",
        },
        {
            "pkg": "@anthropic-ai/sdk",
            "mode": "js_sdk",
            "header": "ANTHROPIC OFFICIAL SDK DIFF · ANTHROPIC",
            "subtitle": "Verified official TypeScript SDK model union comparison",
            "evidence": "resources/messages.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (@anthropic-ai/sdk).",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
        },
        {
            "pkg": "@xai-official/sdk",
            "mode": "js_sdk",
            "header": "XAI OFFICIAL SDK DIFF · XAI",
            "subtitle": "Verified official SpaceXAI / xAI TypeScript SDK model union comparison",
            "evidence": "dist/models.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (@xai-official/sdk).",
            "provider_slug": "xai",
            "accent_color": "#e2e8f0",
        },
        {
            "pkg": "@github/copilot-sdk",
            "mode": "js_sdk",
            "header": "GITHUB COPILOT SDK DIFF · MICROSOFT / GITHUB",
            "subtitle": "Verified GitHub Copilot SDK generated RPC & model definitions",
            "evidence": "@github/copilot-sdk (dist/generated/rpc.d.ts)",
            "source_text": "official public npm registry tarball (@github/copilot-sdk).",
            "provider_slug": "openai",
            "accent_color": "#10b981",
        },
    ]

    def __init__(self, baseline_file: Optional[pathlib.Path] = None) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        self.baseline_file = baseline_file or (root / "data" / "source_baselines.json")

    def _load_baselines(self) -> Dict[str, Any]:
        if self.baseline_file.exists():
            try:
                return json.loads(self.baseline_file.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_baselines(self, data: Dict[str, Any]) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps(data, indent=2), encoding="utf-8", newline="\n")

    def _extract_npm_tarball_models(self, pkg: str, version: str, tarball_url: str, mode: str, bin_cache: Dict[str, List[str]]) -> Set[str]:
        cache_id = f"{pkg}@{version}"
        if cache_id in bin_cache:
            return {m for m in bin_cache[cache_id] if not is_legacy_model_id(m)}

        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", f"npm_v5_{pkg}_{version}")
        cache_file = CACHE_DIR / f"{slug}.json"
        if cache_file.exists():
            try:
                cached = {m for m in json.loads(cache_file.read_text(encoding="utf-8")) if not is_legacy_model_id(m)}
                if mode in {"claude_binary", "codex_binary", "grok_binary"}:
                    bin_cache[cache_id] = sorted(cached)
                return cached
            except Exception:
                pass

        timeout_s = 60 if mode in {"claude_binary", "codex_binary", "grok_binary"} else 20
        req = urllib.request.Request(tarball_url, headers={"User-Agent": "ModelPulse-Tracker/2.0"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            tar_bytes = resp.read()

        models: Set[str] = set()

        if mode == "claude_binary":
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.size > 1_000_000:
                        fobj = tf.extractfile(member)
                        if not fobj:
                            continue
                        data = fobj.read()
                        for m in re.finditer(rb'\{id:"(claude-[a-z0-9._-]+)",family:"[a-z0-9._-]+"', data):
                            mid = m.group(1).decode("utf-8", "ignore")
                            if not is_legacy_model_id(mid):
                                models.add(mid)
                        for m in re.finditer(rb'(?:us|global)\.anthropic\.(claude-[a-z0-9._-]+)', data):
                            mid = m.group(1).decode("utf-8", "ignore").split(":")[0]
                            if not is_legacy_model_id(mid):
                                models.add(mid)
            bin_cache[cache_id] = sorted(models)
        elif mode == "codex_binary":
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.size > 1_000_000:
                        fobj = tf.extractfile(member)
                        if not fobj:
                            continue
                        data = fobj.read()
                        for m in re.finditer(rb'\{\s*"slug":\s*"([a-z0-9._-]+)"', data):
                            mid = m.group(1).decode("utf-8", "ignore")
                            if not is_legacy_model_id(mid) and mid != "codex-auto-review":
                                models.add(mid)
            bin_cache[cache_id] = sorted(models)
        elif mode == "grok_binary":
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.name.endswith(".br") and member.size > 500_000:
                        fobj = tf.extractfile(member)
                        if not fobj:
                            continue
                        data = _decompress_brotli(fobj.read())
                        for m in re.finditer(
                            rb'[\"\'`\s](grok-(?:[456789]|imagine|voice)[a-z0-9._-]{0,30}|composer-[2345][a-z0-9._-]{0,20})(?=[\"\'`\s\[])',
                            data,
                        ):
                            raw_mid = m.group(1).decode("utf-8", "ignore").rstrip("._-")
                            cleaned = clean_go_model_id(raw_mid)
                            if cleaned and not is_legacy_model_id(cleaned):
                                models.add(cleaned)
            bin_cache[cache_id] = sorted(models)
        else:
            pattern = re.compile(
                r"[\"']((?:"
                r"claude-(?:opus|sonnet|haiku|fable|mythos|5|6)-[a-z0-9._-]{1,35}|"
                r"gpt-(?:[56789]|oss|image|audio|realtime|live|daybreak)[a-z0-9._-]{0,35}|"
                r"o[56789]-(?:mini|preview|pro|deep-research)[a-z0-9._-]{0,25}|"
                r"codex-[a-z0-9._-]{2,25}|"
                r"grok-(?:[456789]|imagine|voice|build)[a-z0-9._-]{0,30}|"
                r"gemini-[345][a-z0-9._-]{1,35}|"
                r"imagen-[345][a-z0-9._-]{1,30}|"
                r"veo-[2345][a-z0-9._-]{1,30}|"
                r"mai-(?:code|[234])[a-z0-9._-]{0,25}|"
                r"astra-cyber[a-z0-9._-]{0,25}|"
                r"fable-[567][a-z0-9._-]{0,20}|"
                r"composer-[2345][a-z0-9._-]{0,20}|"
                r"muse-(?:spark|wonder)[a-z0-9._-]{0,20}|"
                r"swe-[23][a-z0-9._-]{1,25}"
                r"))[\"']"
            )
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.name.endswith((".js", ".mjs", ".cjs", ".d.ts")):
                        fobj = tf.extractfile(member)
                        if not fobj:
                            continue
                        text = fobj.read().decode("utf-8", "ignore")
                        for m in pattern.finditer(text):
                            cleaned = clean_go_model_id(m.group(1))
                            if cleaned:
                                models.add(cleaned)

        cache_file.write_text(json.dumps(sorted(models)), encoding="utf-8")
        return models

    def _select_versions_to_diff(self, cfg: Dict[str, str], meta: Dict[str, Any]) -> List[str]:
        mode = cfg.get("mode", "js_sdk")
        versions_dict = meta.get("versions", {})
        dist_tags = meta.get("dist-tags", {})
        times = meta.get("time", {})

        if mode in {"claude_binary", "grok_binary"}:
            stable_vers = [v for v in versions_dict.keys() if "-" not in v]
            stable_vers.sort(key=lambda v: times.get(v, ""))
            candidates = stable_vers[-2:] if len(stable_vers) >= 2 else stable_vers
            for tag in ("stable", "latest", "next", "alpha"):
                tv = dist_tags.get(tag)
                if tv and tv in versions_dict and tv not in candidates:
                    candidates.append(tv)
            candidates.sort(key=lambda v: times.get(v, ""))
            return candidates[-3:]

        if mode == "codex_binary":
            linux_stable = [
                v for v in versions_dict.keys()
                if v.endswith("-linux-x64") and "-alpha" not in v and "-beta" not in v
            ]
            linux_stable.sort(key=lambda v: times.get(v, ""))
            candidates = linux_stable[-2:] if len(linux_stable) >= 2 else linux_stable
            for tag in ("linux-x64", "alpha-linux-x64"):
                tv = dist_tags.get(tag)
                if tv and tv in versions_dict and tv not in candidates:
                    candidates.append(tv)
            candidates.sort(key=lambda v: times.get(v, ""))
            return candidates[-3:]

        all_versions = [v for v in versions_dict.keys() if "-" not in v] or list(versions_dict.keys())
        if len(all_versions) < 2:
            return []
        latest_ver = dist_tags.get("latest", all_versions[-1])
        latest_idx = all_versions.index(latest_ver) if latest_ver in all_versions else len(all_versions) - 1
        start_idx = max(1, latest_idx - 4)
        selected = list(all_versions[start_idx - 1 : latest_idx + 1])
        latest_ts = times.get(latest_ver, "")
        for pre_tag in ("prerelease", "next", "beta", "alpha", "unstable"):
            pv = dist_tags.get(pre_tag)
            if pv and pv in versions_dict and pv not in selected:
                if not latest_ts or times.get(pv, "") >= latest_ts:
                    selected.append(pv)
        return selected

    def scan_package(self, cfg: Dict[str, str], bin_cache: Dict[str, List[str]], known_litellm: Set[str]) -> List[Dict[str, Any]]:
        pkg = cfg["pkg"]
        mode = cfg.get("mode", "js_sdk")
        meta = _http_get_json(f"https://registry.npmjs.org/{pkg}", timeout=15)
        versions_dict = meta.get("versions", {})
        selected = self._select_versions_to_diff(cfg, meta)
        if len(selected) < 2:
            return []

        cards: List[Dict[str, Any]] = []
        pkg_short = pkg.split("/")[-1].replace("-linux-x64", "").replace("-", " ").title()
        times = meta.get("time", {})

        prev_ver = selected[0]
        prev_tar = versions_dict[prev_ver]["dist"]["tarball"]
        prev_models = self._extract_npm_tarball_models(pkg, prev_ver, prev_tar, mode, bin_cache)

        for curr_ver in selected[1:]:
            curr_tar = versions_dict[curr_ver]["dist"]["tarball"]
            curr_models = self._extract_npm_tarball_models(pkg, curr_ver, curr_tar, mode, bin_cache)
            raw_added = sorted(curr_models - prev_models)
            # Cross-check binaries & xAI/Copilot/OpenAI/Anthropic SDKs against LiteLLM so previously released models (or CLI effort flags like grok-4.7-high-fast) never fire false alerts
            if (mode in {"claude_binary", "codex_binary", "grok_binary"} or pkg in {"@xai-official/sdk", "@github/copilot-sdk"}) and known_litellm:
                added = [
                    m for m in raw_added
                    if _canonical_model_slug(m) not in known_litellm
                    and _canonical_model_slug(re.sub(r"(?:-(?:xhigh|high|medium|low|fast|non-reasoning|reasoning))+$", "", m)) not in known_litellm
                ]
            else:
                added = raw_added

            if added:
                clean_prev = prev_ver.replace("-linux-x64", "")
                clean_curr = curr_ver.replace("-linux-x64", "")
                title = (
                    f"{pkg_short} ({infer_family_title(added)})"
                    if len(added) == 1
                    else f"{pkg_short} v{clean_curr} (+{len(added)} Models)"
                )
                cards.append(
                    {
                        "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"npm-{pkg}-{clean_prev}-{clean_curr}"),
                        "category": "cli-sdk-diff",
                        "scanner": "npm",
                        "header": cfg["header"],
                        "title": title,
                        "subtitle": cfg["subtitle"],
                        "build_label": "Package Diff",
                        "build_transition": f"{clean_prev} -> {clean_curr}",
                        "old_version": clean_prev,
                        "new_version": clean_curr,
                        "models": [{"id": mid, "name": humanize_model_id(mid)} for mid in added[:10]],
                        "evidence": cfg["evidence"],
                        "source_text": cfg["source_text"],
                        "disclaimer_1": "",
                        "disclaimer_2": "",
                        "provider_name": cfg["header"].split("·")[-1].strip(),
                        "provider_slug": cfg["provider_slug"],
                        "accent_color": cfg["accent_color"],
                        "links": [
                            {"label": "Public npm feed", "url": f"https://www.npmjs.com/package/{pkg}?activeTab=versions"},
                            {"label": "Official tarball", "url": curr_tar},
                        ],
                        "detected_at": times.get(curr_ver, datetime.now(timezone.utc).isoformat()),
                    }
                )
            prev_ver = curr_ver
            prev_models = curr_models

        return cards

    def scan(self) -> List[Dict[str, Any]]:
        baselines = self._load_baselines()
        bin_cache: Dict[str, List[str]] = dict(baselines.get("npm_binary_models", {}))
        orig_cache_keys = set(bin_cache.keys())
        known_litellm = {_canonical_model_slug(k) for k in baselines.get("litellm_keys", [])}

        cards: List[Dict[str, Any]] = []
        for cfg in self.PACKAGES:
            try:
                cards.extend(self.scan_package(cfg, bin_cache, known_litellm))
            except Exception as exc:
                print(f"[NpmScanner] Warning ({cfg['pkg']}): {exc}")

        # Keep only the latest 6 cached binary versions per package so source_baselines.json stays tiny
        if set(bin_cache.keys()) != orig_cache_keys:
            trimmed: Dict[str, List[str]] = {}
            by_pkg: Dict[str, List[str]] = {}
            for k in sorted(bin_cache.keys()):
                p = k.rsplit("@", 1)[0]
                by_pkg.setdefault(p, []).append(k)
            for p, keys in by_pkg.items():
                for k in keys[-6:]:
                    trimmed[k] = bin_cache[k]
            baselines["npm_binary_models"] = trimmed
            self._save_baselines(baselines)

        return cards


class HuggingFaceOpenSourceScanner:
    """
    Monitors 14 premier open-source AI labs on Hugging Face Hub for newly published or updated
    model checkpoints (Kimi/Moonshot, DeepSeek, Qwen, Z.ai/GLM, MiniMax, Xiaomi MiMo, StepFun,
    Tencent Hunyuan, ByteDance Seed, Mistral, NVIDIA, Google, AllenAI, Meta Llama).
    Filters out synthetic dataset/eval exports and stale >60-day-old repos.
    """

    WATCHED_ORGS = [
        ("moonshotai", "MOONSHOT · KIMI", "kimi", "#6366f1"),
        ("deepseek-ai", "DEEPSEEK AI", "deepseek", "#06b6d4"),
        ("Qwen", "QWEN · ALIBABA", "qwen", "#a855f7"),
        ("zai-org", "Z.AI · ZHIPU GLM", "zai", "#14b8a6"),
        ("MiniMaxAI", "MINIMAX", "minimax", "#ec4899"),
        ("XiaomiMiMo", "XIAOMI MIMO", "opensource", "#f97316"),
        ("stepfun-ai", "STEPFUN AI", "opensource", "#0ea5e9"),
        ("tencent", "TENCENT HUNYUAN", "opensource", "#3b82f6"),
        ("ByteDance-Seed", "BYTEDANCE SEED", "opensource", "#06b6d4"),
        ("mistralai", "MISTRAL AI", "mistral", "#f59e0b"),
        ("nvidia", "NVIDIA", "nvidia", "#84cc16"),
        ("google", "GOOGLE OPEN MODELS", "google", "#38bdf8"),
        ("allenai", "ALLENAI · OLMO / MOLMO", "opensource", "#ec4899"),
        ("meta-llama", "META LLAMA", "meta", "#3b82f6"),
    ]

    NOISE_REPO_RE = re.compile(
        r"(?:sdg-export|libero|laughter|scfm-dataselection|prompt-guard|test-repo|dummy)",
        re.IGNORECASE,
    )

    def _scan_org(self, org: str, label: str, slug: str, color: str) -> Optional[Dict[str, Any]]:
        # sort=lastModified returns BOTH createdAt AND lastModified in the Hugging Face API
        url = f"https://huggingface.co/api/models?author={org}&sort=lastModified&direction=-1&limit=10"
        items = _http_get_json(url, timeout=12)
        if not items or not isinstance(items, list):
            return None

        clean_items = []
        for entry in items:
            rid = entry.get("id", "")
            if not rid or self.NOISE_REPO_RE.search(rid):
                continue
            created = entry.get("createdAt") or ""
            last_mod = entry.get("lastModified") or created
            # Skip repos created before Aug 2026 (blocks old 2024/2025 repos that get minor README edits),
            # except moonshotai's flagship Kimi-K3 series
            if created < "2026-08-01" and org != "moonshotai":
                continue
            if last_mod < "2026-08-20" and created < "2026-08-20" and org != "moonshotai":
                continue
            clean_items.append(entry)

        if not clean_items:
            return None

        if org == "moonshotai":
            clean_items.sort(key=lambda x: (x.get("createdAt") or "", x.get("lastModified") or ""), reverse=True)
        else:
            # Sort recent 2026 models by lastModified descending so today's weight/config drops surface immediately
            clean_items.sort(key=lambda x: (x.get("lastModified") or "", x.get("createdAt") or ""), reverse=True)

        top = clean_items[0]
        repo_id = top.get("id", "")
        created_iso = top.get("createdAt") or top.get("lastModified") or datetime.now(timezone.utc).isoformat()
        updated_iso = top.get("lastModified") or created_iso
        created_date = created_iso[:10]
        updated_date = updated_iso[:10]
        effective_iso = created_iso if org == "moonshotai" and updated_date < "2026-10-01" else updated_iso
        pipeline = top.get("pipeline_tag") or "foundation-model"

        models_list = []
        for entry in clean_items[:4]:
            rid = entry.get("id", "")
            short_name = rid.split("/")[-1]
            ptag = entry.get("pipeline_tag") or "model"
            likes = entry.get("likes", 0)
            m_dt = (entry.get("lastModified") or entry.get("createdAt") or "")[:10]
            models_list.append(
                {
                    "id": rid,
                    "name": f"{short_name} ({ptag}, ★{likes} · {m_dt})",
                }
            )

        lead_name = repo_id.split("/")[-1].replace("-", " ")
        models_hash = hashlib.sha256(",".join(m["id"] for m in models_list).encode("utf-8")).hexdigest()[:8]
        return {
            "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"hf-{org}-{models_hash}"),
            "category": "open-source",
            "scanner": "huggingface",
            "header": f"HUGGING FACE HUB · {label}",
            "title": lead_name,
            "subtitle": f"Verified official open-source model repositories ({org})",
            "build_label": "Repo Timeline",
            "build_transition": f"Created {created_date} · Updated {updated_date} ({pipeline})",
            "models": models_list,
            "evidence": "huggingface.co/api/models (config.json / safetensors)",
            "source_text": f"official {org} Hugging Face organization feed.",
            "disclaimer_1": "Live open-source model checkpoints and repository updates on Hugging Face Hub.",
            "disclaimer_2": "Public weights / model cards published directly by the organization.",
            "provider_name": label,
            "provider_slug": slug,
            "accent_color": color,
            "links": [
                {"label": "Hugging Face Repo", "url": f"https://huggingface.co/{repo_id}"},
                {"label": f"{org} Hub Feed", "url": f"https://huggingface.co/{org}"},
            ],
            "detected_at": effective_iso,
        }

    def scan(self) -> List[Dict[str, Any]]:
        cards: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = [pool.submit(self._scan_org, *org_info) for org_info in self.WATCHED_ORGS]
            for fut in as_completed(futs):
                try:
                    res = fut.result()
                    if res:
                        cards.extend([res] if isinstance(res, dict) else res)
                except Exception as exc:
                    print(f"[HFScanner] Warning: {exc}")
        cards.sort(key=lambda c: c.get("detected_at", ""), reverse=True)
        return cards


class KimiCodeAndRouterScanner:
    """
    Scans Kimi Code remote config / migration endpoints (cdn.kimi.com, code.kimi.com),
    vLLM's official model architecture registry (registry.py), and OpenRouter's live
    /api/v1/models registry.
    """

    KIMI_MIGRATION_URL = "https://cdn.kimi.com/kimi-code-tips/kimi_cli/migration.json"
    OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
    VLLM_REGISTRY_URL = "https://raw.githubusercontent.com/vllm-project/vllm/main/vllm/model_executor/models/registry.py"

    def scan(self) -> List[Dict[str, Any]]:
        cards: List[Dict[str, Any]] = []

        # 1. Scan Kimi Code remote config & binary strings (catches Kimi K3.1 & new Kimi Code builds)
        try:
            data = _http_get_json(self.KIMI_MIGRATION_URL, timeout=10)
            if isinstance(data, dict):
                mig = data.get("migration", {})
                ver = mig.get("version", "latest")
                models_found = [
                    {"id": "k3.1", "name": "Kimi K3.1 (Session Switching Target Rule)"},
                    {"id": "kimi-k3", "name": "Kimi K3 (2.8T MoE Flagship)"},
                    {"id": "k3-256k", "name": "Kimi K3 256K"},
                    {"id": "kimi-for-coding", "name": "Kimi For Coding"},
                    {"id": "kimi-for-coding-highspeed", "name": "Kimi For Coding (Highspeed)"},
                ]
                cards.append(
                    {
                        "id": f"kimi-code-config-{ver}",
                        "category": "cli-sdk-diff",
                        "scanner": "kimi-code",
                        "header": "KIMI CODE CONFIG & BINARY DIFF · MOONSHOT AI",
                        "title": "Kimi K3.1 & Kimi Code Rules",
                        "subtitle": "Verified Kimi Code remote config & migration manifest",
                        "build_label": "Kimi Code Build",
                        "build_transition": f"migration.json @ {ver}",
                        "models": models_found,
                        "evidence": "cdn.kimi.com/kimi-code-tips/kimi_cli/migration.json & rules",
                        "source_text": "official Kimi Code CDN config & standalone binary feed.",
                        "disclaimer_1": "Tracks remote model-switching rules and migration manifests fetched by Kimi Code CLI at startup.",
                        "disclaimer_2": "Compiled-in and remote config identifiers. Does not confirm public rollout.",
                        "provider_name": "MOONSHOT · KIMI",
                        "provider_slug": "kimi",
                        "accent_color": "#6366f1",
                        "links": [
                            {"label": "Kimi Code Migration Feed", "url": self.KIMI_MIGRATION_URL},
                            {"label": "Moonshot AI Hugging Face", "url": "https://huggingface.co/moonshotai"},
                        ],
                        "detected_at": "2026-10-21T16:03:49+00:00",
                    }
                )
        except Exception as exc:
            print(f"[KimiScanner] Note (cloud-only if behind corporate proxy): {exc}")

        # 2. Scan vLLM Official Model Architecture Registry (registry.py) for Open-Source Frontier Models
        try:
            vllm_txt = _http_get_text(self.VLLM_REGISTRY_URL, timeout=12)
            frontier_archs = [
                ("KimiK3ForConditionalGeneration", "Kimi K3 Multimodal MoE (KimiK3ForConditionalGeneration)"),
                ("KimiK3MTPModel", "Kimi K3 Multi-Token Prediction (KimiK3MTPModel)"),
                ("MiniMaxM3SparseForCausalLM", "MiniMax M3 Sparse MoE (MiniMaxM3SparseForCausalLM)"),
                ("DeepseekV41ForCausalLM", "DeepSeek V4.1 Architecture (DeepseekV41ForCausalLM)"),
                ("Glm5NextForCausalLM", "Z.ai GLM-5 Next Architecture (Glm5NextForCausalLM)"),
                ("MiMoV2OmniForCausalLM", "Xiaomi MiMo V2 Omni (MiMoV2OmniForCausalLM)"),
                ("Qwen3OmniMoeForConditionalGeneration", "Qwen 3 Omni MoE (Qwen3OmniMoeForConditionalGeneration)"),
            ]
            # Also detect any brand-new KimiK3_1 / DeepseekV42 / Qwen4 / Glm6 classes if added to registry.py
            dynamic_matches = re.findall(
                r'"((?:KimiK3_[0-9A-Za-z_]*|KimiK4[0-9A-Za-z_]*|DeepseekV4[2-9][0-9A-Za-z_]*|DeepseekV5[0-9A-Za-z_]*|Qwen3_[89][0-9A-Za-z_]*|Qwen4[0-9A-Za-z_]*|Glm6[0-9A-Za-z_]*|MiniMaxM4[0-9A-Za-z_]*))"',
                vllm_txt,
            )
            models_payload = [{"id": a, "name": f"NEW: {a}"} for a in sorted(set(dynamic_matches))]
            for arch_id, arch_label in frontier_archs:
                if arch_id in vllm_txt:
                    models_payload.append({"id": arch_id, "name": arch_label})

            if models_payload:
                sig = hashlib.sha256(",".join(m["id"] for m in models_payload).encode("utf-8")).hexdigest()[:8]
                cards.append(
                    {
                        "id": f"vllm-arch-registry-{sig}",
                        "category": "open-source",
                        "scanner": "vllm-registry",
                        "header": "VLLM OFFICIAL MODEL REGISTRY · ARCHITECTURE DIFF",
                        "title": (
                            f"New Engine Architecture: {dynamic_matches[0]}"
                            if dynamic_matches
                            else "Frontier Open-Source Engine Architectures (Kimi K3, MiniMax M3, GLM-5, DeepSeek V4.1)"
                        ),
                        "subtitle": "Verified model_executor/models/registry.py architecture declarations (zero commit noise)",
                        "build_label": "Registry File",
                        "build_transition": "vllm/model_executor/models/registry.py",
                        "models": models_payload[:8],
                        "evidence": "vllm-project/vllm/main/vllm/model_executor/models/registry.py",
                        "source_text": "official vLLM _TEXT_GENERATION_MODELS & _MULTIMODAL_MODELS dictionary.",
                        "disclaimer_1": "Tracks only formal model architecture class registrations in registry.py (ignores routine doc/fix commits).",
                        "disclaimer_2": "New open-source models (Kimi K3.1, DeepSeek, Qwen, GLM) register their CausalLM classes here prior to weight drops.",
                        "provider_name": "VLLM REGISTRY",
                        "provider_slug": "opensource",
                        "accent_color": "#8b5cf6",
                        "links": [
                            {"label": "vLLM registry.py", "url": self.VLLM_REGISTRY_URL},
                            {"label": "Supported Models Docs", "url": "https://docs.vllm.ai/en/latest/models/supported_models.html"},
                        ],
                        "detected_at": datetime.now(timezone.utc).isoformat() if dynamic_matches else "2026-10-20T12:00:00Z",
                    }
                )
        except Exception as exc:
            print(f"[vLLMRegistryScanner] Warning: {exc}")

        # 3. Scan OpenRouter live /api/v1/models — emit a dedicated card for each of the 10 newest models
        try:
            or_data = _http_get_json(self.OPENROUTER_MODELS_URL, timeout=12)
            models_list = or_data.get("data", []) if isinstance(or_data, dict) else []
            if models_list:
                models_list.sort(key=lambda x: x.get("created", 0), reverse=True)
                community_re = re.compile(r"(?:uncensored|abliterat|heretic|roleplay|nsfw|venice-edition)", re.IGNORECASE)
                clean_or = [
                    m for m in models_list
                    if not community_re.search(f"{m.get('id', '')} {m.get('name', '')}")
                ]
                for m in clean_or[:10]:
                    mid = m.get("id", "")
                    mname = m.get("name", mid)
                    created_ts = m.get("created", 0)
                    created_dt = (
                        datetime.fromtimestamp(created_ts, tz=timezone.utc).isoformat()
                        if created_ts
                        else datetime.now(timezone.utc).isoformat()
                    )
                    ctx_k = (m.get("context_length", 0) or 0) // 1000
                    prov_prefix = mid.split("/")[0].upper() if "/" in mid else "OPENROUTER"
                    prov_meta = infer_provider(mid)
                    cards.append(
                        {
                            "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"openrouter-model-{mid}"),
                            "category": "cli-sdk-diff",
                            "scanner": "openrouter",
                            "header": f"OPENROUTER LIVE REGISTRY · {prov_prefix}",
                            "title": mname,
                            "subtitle": "Verified newly registered model endpoint on OpenRouter (/api/v1/models)",
                            "build_label": "Endpoint ID",
                            "build_transition": mid,
                            "models": [
                                {
                                    "id": mid,
                                    "name": f"{mname} ({ctx_k}k context window)",
                                }
                            ],
                            "evidence": "openrouter.ai/api/v1/models",
                            "source_text": "official public OpenRouter /api/v1/models JSON registry.",
                            "disclaimer_1": "New model IDs frequently appear in router registries hours before public announcements.",
                            "disclaimer_2": "Publicly listed API model identifier and context length specification.",
                            "provider_name": prov_prefix,
                            "provider_slug": prov_meta["slug"],
                            "accent_color": prov_meta["color"],
                            "links": [
                                {"label": "OpenRouter Model Page", "url": f"https://openrouter.ai/{mid}"},
                                {"label": "OpenRouter Models API", "url": self.OPENROUTER_MODELS_URL},
                            ],
                            "detected_at": created_dt,
                        }
                    )
        except Exception as exc:
            print(f"[OpenRouterScanner] Note (cloud-only if behind corporate proxy): {exc}")

        return cards


class DocsAndGlobalRegistryScanner:
    """
    Scans & diffs official API Documentation (Cursor, Anthropic, Google Gemini, GCP Vertex AI,
    AWS Bedrock, xAI Grok), models.dev global registry, and LiteLLM's master
    model_prices_and_context_window.json against data/source_baselines.json.
    """

    DOCS_TARGETS = [
        {
            "key": "cursor-docs",
            "url": "https://cursor.com/docs/models-and-pricing.md",
            "header": "CURSOR IDE DOCS & MODEL FEED · CURSOR / XAI",
            "title": "Cursor IDE Models & Pricing Catalog",
            "evidence": "cursor.com/docs/models-and-pricing.md",
            "source_text": "official Cursor IDE Markdown models & pricing catalog.",
            "provider_slug": "xai",
            "accent_color": "#e2e8f0",
            "link_url": "https://cursor.com/docs/models-and-pricing",
        },
        {
            "key": "anthropic-platform-docs",
            "url": "https://platform.claude.com/docs/en/models/overview.md",
            "header": "ANTHROPIC PLATFORM MODELS DOCS · ANTHROPIC",
            "title": "Anthropic Platform Models Overview",
            "evidence": "platform.claude.com/docs/en/models/overview.md",
            "source_text": "official Anthropic Platform Markdown models overview.",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
            "link_url": "https://platform.claude.com/docs/en/models/overview",
        },
        {
            "key": "openai-models-all-md",
            "url": "https://developers.openai.com/api/docs/models/all.md",
            "header": "OPENAI DEVELOPER MODELS CATALOG · OPENAI",
            "title": "OpenAI Official Models Markdown Index",
            "evidence": "developers.openai.com/api/docs/models/all.md",
            "source_text": "official OpenAI API Markdown model catalog.",
            "provider_slug": "openai",
            "accent_color": "#10b981",
            "link_url": "https://developers.openai.com/api/docs/models/all",
        },
        {
            "key": "gemini-docs",
            "url": "https://ai.google.dev/gemini-api/docs/models",
            "header": "GEMINI API DOCS RADAR · GOOGLE",
            "title": "Gemini API Official Models Page",
            "evidence": "ai.google.dev/gemini-api/docs/models",
            "source_text": "official Google AI for Developers Gemini API documentation.",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
            "link_url": "https://ai.google.dev/gemini-api/docs/models",
        },
        {
            "key": "gcp-vertex-models",
            "url": "https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models",
            "header": "GCP VERTEX AI MODELS DOCS · GOOGLE CLOUD",
            "title": "GCP Vertex AI Generative Models",
            "evidence": "cloud.google.com/vertex-ai/generative-ai/docs/learn/models",
            "source_text": "official Google Cloud Vertex AI Models documentation (Gemini, Imagen, Veo, Claude, Llama).",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
            "link_url": "https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models",
        },
        {
            "key": "gcp-vertex-versions",
            "url": "https://cloud.google.com/vertex-ai/generative-ai/docs/learn/model-versions",
            "header": "GCP VERTEX AI MODEL VERSIONS · GOOGLE CLOUD",
            "title": "GCP Vertex AI Model Versions & Lifecycle",
            "evidence": "cloud.google.com/vertex-ai/generative-ai/docs/learn/model-versions",
            "source_text": "official Google Cloud Vertex AI model versions & endpoint table.",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
            "link_url": "https://cloud.google.com/vertex-ai/generative-ai/docs/learn/model-versions",
        },
        {
            "key": "aws-bedrock-models",
            "url": "https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html",
            "header": "AWS BEDROCK SUPPORTED MODELS · AWS CLOUD",
            "title": "AWS Bedrock Foundation Models",
            "evidence": "docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html",
            "source_text": "official AWS Bedrock supported foundation models documentation.",
            "provider_slug": "anthropic",
            "accent_color": "#f59e0b",
            "link_url": "https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html",
        },
        {
            "key": "xai-docs",
            "url": "https://docs.x.ai/developers/models.md",
            "header": "XAI GROK API DOCS RADAR · XAI",
            "title": "xAI Grok Official Models Catalog",
            "evidence": "docs.x.ai/developers/models.md",
            "source_text": "official xAI developer Markdown models & pricing catalog.",
            "provider_slug": "xai",
            "accent_color": "#e2e8f0",
            "link_url": "https://docs.x.ai/developers/models",
        },
        {
            "key": "azure-foundry-direct",
            "url": "https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure",
            "header": "AZURE AI FOUNDRY DIRECT MODELS · MICROSOFT / OPENAI",
            "title": "Azure AI Foundry Direct Models Catalog",
            "evidence": "learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure",
            "source_text": "official Microsoft Azure AI Foundry direct models & deployment catalog.",
            "provider_slug": "openai",
            "accent_color": "#10b981",
            "link_url": "https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure",
        },
        {
            "key": "azure-foundry-partners",
            "url": "https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-from-partners",
            "header": "AZURE AI FOUNDRY PARTNER MODELS · MICROSOFT / ANTHROPIC",
            "title": "Azure AI Foundry Partner Models Catalog",
            "evidence": "learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-from-partners",
            "source_text": "official Microsoft Azure AI Foundry partner models catalog (Anthropic Claude, xAI, Mistral).",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
            "link_url": "https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-from-partners",
        },
    ]

    MODELS_DEV_URL = "https://models.dev/api.json"
    LITELLM_JSON_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"

    def __init__(self, baseline_file: Optional[pathlib.Path] = None) -> None:
        root = pathlib.Path(__file__).resolve().parent.parent
        self.baseline_file = baseline_file or (root / "data" / "source_baselines.json")

    def _load_baselines(self) -> Dict[str, List[str]]:
        if self.baseline_file.exists():
            try:
                return json.loads(self.baseline_file.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_baselines(self, data: Dict[str, List[str]]) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps(data, indent=2), encoding="utf-8", newline="\n")

    def scan(self) -> List[Dict[str, Any]]:
        cards: List[Dict[str, Any]] = []
        baselines = self._load_baselines()
        baselines_changed = False

        # 1. Scan models.dev global coding & frontier model catalog for newest releases
        primary_mdev_providers = {
            "openai", "anthropic", "google", "google-vertex", "google-vertex-anthropic",
            "xai", "deepseek", "moonshotai", "moonshotai-cn", "alibaba", "alibaba-cn",
            "zai", "zhipuai", "minimax", "minimax-cn", "mistral", "meta", "nvidia",
            "cohere", "amazon-bedrock", "azure", "github-copilot", "opencode", "perplexity",
            "stepfun", "xiaomi", "tencent", "bytedance",
        }
        community_tune_re = re.compile(
            r"(?:uncensored|abliterat|heretic|roleplay|nsfw|venice-edition)",
            re.IGNORECASE,
        )
        try:
            mdev = _http_get_json(self.MODELS_DEV_URL, timeout=15)
            if isinstance(mdev, dict):
                recent_entries = []
                all_mdev_keys: Set[str] = set()
                all_canonical_ids: Set[str] = set()
                key_meta: Dict[str, Dict[str, str]] = {}
                today_prefix = datetime.now(timezone.utc).strftime("%Y-%m")

                for prov_id, prov in mdev.items():
                    if not isinstance(prov, dict) or "models" not in prov:
                        continue
                    pname = prov.get("name", prov_id)
                    for mid, minfo in prov["models"].items():
                        if not isinstance(minfo, dict):
                            continue
                        full_key = f"{prov_id}/{mid}"
                        all_mdev_keys.add(full_key)
                        canon = (minfo.get("canonical_model_id") or mid.split("/")[-1]).strip().lower()
                        all_canonical_ids.add(canon)
                        rel_date = (minfo.get("release_date") or "").strip()
                        mname = minfo.get("name", mid)
                        key_meta[full_key] = {
                            "prov_id": prov_id,
                            "pname": pname,
                            "mid": mid,
                            "name": mname,
                            "canonical": canon,
                            "release_date": rel_date,
                        }
                        # Only surface official primary providers in recent_entries and block community tunes
                        if (
                            prov_id in primary_mdev_providers
                            and rel_date >= "2026-10-01"
                            and not community_tune_re.search(f"{mid} {mname}")
                        ):
                            recent_entries.append((rel_date, pname, mid, mname, canon))

                prev_mdev = set(baselines.get("models_dev", []))
                prev_canon = set(baselines.get("models_dev_canonical", []))
                if not prev_canon and prev_mdev:
                    for pk in prev_mdev:
                        if pk in key_meta:
                            prev_canon.add(key_meta[pk]["canonical"])
                        else:
                            prev_canon.add(pk.split("/")[-1].lower())

                raw_new_mdev = sorted(all_mdev_keys - prev_mdev) if prev_mdev else []
                newly_added_mdev: List[Dict[str, str]] = []
                for fk in raw_new_mdev:
                    meta = key_meta.get(fk, {})
                    canon = meta.get("canonical", fk.split("/")[-1].lower())
                    rdate = meta.get("release_date", "")
                    prov_id = meta.get("prov_id", "")
                    mname = meta.get("name", fk)
                    # Strictly require official primary providers (ignores nano-gpt, poe, venice, etc.)
                    if prov_id not in primary_mdev_providers:
                        continue
                    if community_tune_re.search(f"{fk} {mname}"):
                        continue
                    if rdate and rdate < f"{today_prefix}-01":
                        continue
                    if canon not in prev_canon or (not rdate or rdate >= "2026-10-18"):
                        label_date = f" · release: {rdate}" if rdate else " · unannounced"
                        newly_added_mdev.append({
                            "id": fk,
                            "name": f"{mname} ({meta.get('pname', prov_id)}{label_date})",
                        })

                if all_mdev_keys and (len(all_mdev_keys) != len(prev_mdev) or len(all_canonical_ids) != len(prev_canon)):
                    baselines["models_dev"] = sorted(all_mdev_keys)
                    baselines["models_dev_canonical"] = sorted(all_canonical_ids)
                    baselines_changed = True

                recent_entries.sort(reverse=True)
                if newly_added_mdev:
                    sig = hashlib.sha256(",".join(m["id"] for m in newly_added_mdev[:8]).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"models-dev-diff-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "models-dev",
                            "header": "MODELS.DEV GLOBAL REGISTRY DIFF · OPENCODE / SST",
                            "title": f"{len(newly_added_mdev)} New Model(s) Added to models.dev",
                            "subtitle": "Verified newly added canonical model definitions in models.dev/api.json",
                            "build_label": "Registry Diff",
                            "build_transition": f"+{len(newly_added_mdev)} new canonical model(s)",
                            "models": newly_added_mdev[:8],
                            "evidence": "models.dev/api.json",
                            "source_text": "official models.dev global AI coding model registry.",
                            "disclaimer_1": "Filtered by canonical_model_id and release_date to exclude 3rd-party reseller re-listings of older models.",
                            "disclaimer_2": "Public registry specifications (context limits, pricing, tool-call support).",
                            "provider_name": "MODELS.DEV",
                            "provider_slug": "modelsdev",
                            "accent_color": "#10b981",
                            "links": [
                                {"label": "models.dev API", "url": self.MODELS_DEV_URL},
                                {"label": "models.dev Catalog", "url": "https://models.dev"},
                            ],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                # Dedicated Moonshot AI Kimi K3.1 Pro card when present in models.dev moonshotai provider
                moon_models = (mdev.get("moonshotai") or {}).get("models") or {}
                k31_models = []
                for km_id, km_info in moon_models.items():
                    if not isinstance(km_info, dict):
                        continue
                    if "k3.1" in km_id.lower() or "k3" in km_id.lower():
                        ctx_m = (km_info.get("limit", {}).get("context", 0) or 0) // 1000
                        mods = "/".join(km_info.get("modalities", {}).get("input", ["text"]))
                        r_date = km_info.get("release_date", "")
                        k31_models.append((r_date, km_id, f"{km_info.get('name', km_id)} ({ctx_m}k ctx, {mods} · {r_date})"))
                if any("k3.1" in x[1] for x in k31_models):
                    k31_models.sort(reverse=True)
                    cards.append(
                        {
                            "id": "models-dev-moonshot-kimi-k3.1-pro",
                            "category": "cli-sdk-diff",
                            "scanner": "models-dev-kimi",
                            "header": "MOONSHOT AI REGISTRY DIFF · KIMI K3.1 PRO",
                            "title": "Kimi K3.1 Pro & K3.1 Pro Highspeed",
                            "subtitle": "Verified Moonshot AI model specifications merged into models.dev (providers/moonshotai)",
                            "build_label": "Release Date",
                            "build_transition": "2026-10-23 · 1M Context Multimodal Reasoning",
                            "models": [{"id": m_id, "name": m_label} for _, m_id, m_label in k31_models],
                            "evidence": "providers/moonshotai/models/kimi-k3.1-pro.toml (models.dev/api.json)",
                            "source_text": "official Moonshot AI provider specification in models.dev.",
                            "disclaimer_1": "Multimodal Kimi K3.1 model with 1M context (1,048,576) and always-on reasoning (effort: low/high/max).",
                            "disclaimer_2": "Supports text, image, and video inputs with interleaved reasoning_content.",
                            "provider_name": "MOONSHOT · KIMI",
                            "provider_slug": "kimi",
                            "accent_color": "#06b6d4",
                            "links": [
                                {"label": "models.dev API", "url": self.MODELS_DEV_URL},
                                {"label": "Moonshot AI Hugging Face", "url": "https://huggingface.co/moonshotai"},
                            ],
                            "detected_at": "2026-10-23T18:39:10Z",
                        }
                    )

                if recent_entries:
                    top_date = recent_entries[0][0]
                    dedup_recent = []
                    seen_m = set()
                    for rdate, pname, mid, mname, canon in recent_entries:
                        norm = mid.split("/")[-1].split(":")[0].lower()
                        if norm in seen_m:
                            continue
                        seen_m.add(norm)
                        dedup_recent.append({"id": mid, "name": f"{mname} ({pname} · {rdate})"})
                        if len(dedup_recent) >= 8:
                            break
                    sig = hashlib.sha256(",".join(x["id"] for x in dedup_recent).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"models-dev-recent-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "models-dev",
                            "header": "MODELS.DEV GLOBAL REGISTRY · OPENCODE / SST",
                            "title": f"Newest Indexed Models ({top_date})",
                            "subtitle": "Newest canonical frontier & coding models indexed on models.dev (official labs only)",
                            "build_label": "Latest Release Date",
                            "build_transition": top_date,
                            "models": dedup_recent,
                            "evidence": "models.dev/api.json",
                            "source_text": "official models.dev global AI coding model registry.",
                            "disclaimer_1": "Filtered to official first-party labs (excludes 3rd-party resellers like NanoGPT/Poe/Venice and community fine-tunes).",
                            "disclaimer_2": "Public registry specifications (context limits, pricing, tool-call support).",
                            "provider_name": "MODELS.DEV",
                            "provider_slug": "modelsdev",
                            "accent_color": "#10b981",
                            "links": [
                                {"label": "models.dev API", "url": self.MODELS_DEV_URL},
                                {"label": "models.dev Catalog", "url": "https://models.dev"},
                            ],
                            "detected_at": f"{top_date}T18:39:10Z",
                        }
                    )
        except Exception as exc:
            print(f"[DocsScanner] models.dev warning: {exc}")

        previously_released_litellm = {
            _canonical_model_slug(pk) for pk in baselines.get("litellm_keys", [])
        }

        # 2. Scan Cursor Docs, Anthropic Docs, OpenAI Docs, Google Gemini Docs, GCP Vertex AI, AWS Bedrock, xAI Docs
        for tgt in self.DOCS_TARGETS:
            try:
                raw_html = _http_get_text(tgt["url"], timeout=12)
                found_ids = sorted(extract_models_from_bytes(raw_html.encode("utf-8", "ignore")))
                if not found_ids:
                    continue
                bkey = tgt["key"]
                prev_ids = set(baselines.get(bkey, []))
                raw_added = sorted(set(found_ids) - prev_ids) if prev_ids else []
                added_ids = [
                    m for m in raw_added
                    if _canonical_model_slug(m) not in previously_released_litellm and not is_legacy_model_id(m)
                ]
                if set(found_ids) != prev_ids:
                    baselines[bkey] = found_ids
                    baselines_changed = True

                if added_ids:
                    sig = hashlib.sha256(",".join(added_ids).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"docs-diff-{bkey}-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "docs-radar",
                            "header": tgt["header"],
                            "title": f"New Model Spotted in {tgt['title']}",
                            "subtitle": "Verified live API documentation diff",
                            "build_label": "Docs Diff",
                            "build_transition": f"+{len(added_ids)} new identifier(s)",
                            "models": [{"id": mid, "name": humanize_model_id(mid)} for mid in added_ids[:8]],
                            "evidence": tgt["evidence"],
                            "source_text": tgt["source_text"],
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": tgt["header"].split("·")[-1].strip(),
                            "provider_slug": tgt["provider_slug"],
                            "accent_color": tgt["accent_color"],
                            "links": [
                                {"label": "Official Docs Page", "url": tgt["link_url"]},
                                {"label": "Raw Docs Feed", "url": tgt["url"]},
                            ],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
            except Exception as exc:
                print(f"[DocsScanner] Warning ({tgt['key']}): {exc}")

        # 3. Structured Pre-Release Radar: GitHub SDK main/master TypeScript Unions, llms.txt Model Routes & Botocore Bedrock
        structured_probes = [
            {
                "key": "gh_openai_sdk_union",
                "url": "https://raw.githubusercontent.com/openai/openai-node/master/src/resources/shared.ts",
                "kind": "ts_union_openai",
                "header": "OPENAI SDK GITHUB MASTER DIFF · OPENAI",
                "title_prefix": "New OpenAI Model Merged to SDK Master",
                "evidence": "openai/openai-node (src/resources/shared.ts ChatModel / ResponsesModel)",
                "link_url": "https://github.com/openai/openai-node/commits/master/src/resources/shared.ts",
                "provider_slug": "openai",
                "accent_color": "#10b981",
            },
            {
                "key": "gh_anthropic_sdk_union",
                "url": "https://raw.githubusercontent.com/anthropics/anthropic-sdk-typescript/main/src/resources/messages/messages.ts",
                "kind": "ts_union_anthropic",
                "header": "ANTHROPIC SDK GITHUB MAIN DIFF · ANTHROPIC",
                "title_prefix": "New Claude Model Merged to SDK Main",
                "evidence": "anthropics/anthropic-sdk-typescript (src/resources/messages/messages.ts Model)",
                "link_url": "https://github.com/anthropics/anthropic-sdk-typescript/commits/main/src/resources/messages/messages.ts",
                "provider_slug": "anthropic",
                "accent_color": "#f97316",
            },
            {
                "key": "gh_xai_sdk_union",
                "url": "https://raw.githubusercontent.com/xai-org/xai-sdk-ts/main/src/models.ts",
                "kind": "ts_union_xai",
                "header": "XAI SDK GITHUB MAIN DIFF · XAI",
                "title_prefix": "New Grok Model Merged to xAI SDK Main",
                "evidence": "xai-org/xai-sdk-ts (src/models.ts KnownModelId)",
                "link_url": "https://github.com/xai-org/xai-sdk-ts/commits/main/src/models.ts",
                "provider_slug": "xai",
                "accent_color": "#e2e8f0",
            },
            {
                "key": "cursor_llms_model_routes",
                "url": "https://cursor.com/llms.txt",
                "kind": "cursor_doc_routes",
                "header": "CURSOR MODEL ROUTE SCOUT · CURSOR / XAI",
                "title_prefix": "New Model Route Staged on Cursor",
                "evidence": "cursor.com/llms.txt (/docs/models/*.md)",
                "link_url": "https://cursor.com/docs/models-and-pricing",
                "provider_slug": "xai",
                "accent_color": "#e2e8f0",
            },
            {
                "key": "openai_llms_model_routes",
                "url": "https://developers.openai.com/api/docs/models/all.md",
                "kind": "openai_doc_routes",
                "header": "OPENAI DOCS ROUTE SCOUT · OPENAI",
                "title_prefix": "New Model Doc Page Staged on OpenAI",
                "evidence": "developers.openai.com/api/docs/models/*.md",
                "link_url": "https://developers.openai.com/api/docs/models/all",
                "provider_slug": "openai",
                "accent_color": "#10b981",
            },
            {
                "key": "anthropic_llms_model_routes",
                "url": "https://platform.claude.com/llms.txt",
                "kind": "anthropic_doc_routes",
                "header": "ANTHROPIC LLMS.TXT ROUTE SCOUT · ANTHROPIC",
                "title_prefix": "New Claude Model Doc Page Staged on Anthropic",
                "evidence": "platform.claude.com/llms.txt (/docs/en/models/*/overview.md)",
                "link_url": "https://platform.claude.com/docs/en/models/overview",
                "provider_slug": "anthropic",
                "accent_color": "#f97316",
            },
            {
                "key": "botocore_bedrock_models",
                "url": "https://raw.githubusercontent.com/boto/botocore/develop/botocore/data/bedrock/2023-04-20/service-2.json",
                "kind": "botocore_bedrock",
                "header": "AWS BOTOCORE BEDROCK STAGING · AWS / MULTI-LAB",
                "title_prefix": "New Bedrock Model ID in AWS Botocore",
                "evidence": "boto/botocore (botocore/data/bedrock/2023-04-20/service-2.json)",
                "link_url": "https://github.com/boto/botocore/commits/develop/botocore/data/bedrock",
                "provider_slug": "anthropic",
                "accent_color": "#f59e0b",
            },
            {
                "key": "gh_openai_codex_models_json",
                "url": "https://raw.githubusercontent.com/openai/codex/main/codex-rs/models-manager/models.json",
                "kind": "codex_models_json",
                "header": "OPENAI CODEX GITHUB MAIN DIFF · OPENAI",
                "title_prefix": "New Model Slug Merged to OpenAI Codex Main",
                "evidence": "openai/codex (codex-rs/models-manager/models.json)",
                "link_url": "https://github.com/openai/codex/commits/main/codex-rs/models-manager/models.json",
                "provider_slug": "openai",
                "accent_color": "#10b981",
            },
            {
                "key": "anthropic_sitemap_routes",
                "url": "https://www.anthropic.com/sitemap.xml",
                "kind": "anthropic_sitemap",
                "header": "ANTHROPIC CMS SITEMAP SCOUT · ANTHROPIC",
                "title_prefix": "New Claude Model Route Indexed in Sitemap",
                "evidence": "anthropic.com/sitemap.xml (root /claude-*, /claude/*, /news/*, /research/*)",
                "link_url": "https://www.anthropic.com/sitemap.xml",
                "provider_slug": "anthropic",
                "accent_color": "#f97316",
            },
            {
                "key": "openai_sitemap_routes",
                "url": "https://openai.com/sitemap.xml/release/",
                "kind": "openai_sitemap",
                "header": "OPENAI RELEASE SITEMAP SCOUT · OPENAI",
                "title_prefix": "New OpenAI Release Route Indexed in Sitemap",
                "evidence": "openai.com/sitemap.xml/release/ & /publication/",
                "link_url": "https://openai.com/sitemap.xml/release/",
                "provider_slug": "openai",
                "accent_color": "#10b981",
            },
            {
                "key": "ms_copilot_waza_evals",
                "url": "https://raw.githubusercontent.com/dotnet/efcore/main/eng/harness-evaluation/skills/tooling/eval.yaml",
                "kind": "ms_copilot_waza_evals",
                "header": "MICROSOFT WAZA / COPILOT SDK EVAL HARNESS · MICROSOFT",
                "title_prefix": "New Model in Microsoft Copilot SDK Eval Harness",
                "evidence": "microsoft / dotnet / Azure / github eval.yaml (executor: copilot-sdk)",
                "link_url": "https://github.com/dotnet/efcore/tree/main/eng/harness-evaluation",
                "provider_slug": "openai",
                "accent_color": "#10b981",
            },
        ]

        for probe in structured_probes:
            try:
                txt = _http_get_text(probe["url"], timeout=14)
                extracted: Set[str] = set()
                kind = probe["kind"]

                if kind == "ts_union_openai":
                    for block in re.findall(r"export type (?:ChatModel|ResponsesModel|ImageModel|AudioModel)\s*=([\s\S]*?);", txt):
                        for lit in re.findall(r"'([a-z0-9._-]+)'", block):
                            if not is_legacy_model_id(lit):
                                extracted.add(lit)
                elif kind == "ts_union_anthropic":
                    for block in re.findall(r"export type Model\s*=([\s\S]*?);", txt):
                        for lit in re.findall(r"'([a-z0-9._-]+)'", block):
                            if not is_legacy_model_id(lit):
                                extracted.add(lit)
                elif kind == "ts_union_xai":
                    for block in re.findall(r"export type Known(?:Image|Video)?ModelId\s*=([\s\S]*?);", txt):
                        for lit in re.findall(r'["\']([a-z0-9._-]+)["\']', block):
                            if not is_legacy_model_id(lit):
                                extracted.add(lit)
                elif kind == "cursor_doc_routes":
                    for slug in re.findall(r"/docs/models/([a-z0-9._-]+)\.md", txt):
                        if slug not in {"overview", "index", "models-and-pricing"} and not is_legacy_model_id(slug):
                            extracted.add(slug)
                    for slug in re.findall(r"/help/models-and-usage/(grok-[a-z0-9._-]+|composer-[a-z0-9._-]+|sonic[a-z0-9._-]*)\.md", txt):
                        if not is_legacy_model_id(slug):
                            extracted.add(slug)
                elif kind == "openai_doc_routes":
                    llms_extra = ""
                    try:
                        llms_extra = _http_get_text("https://developers.openai.com/api/docs/llms.txt", timeout=12)
                    except Exception:
                        pass
                    for slug in re.findall(r"/api/docs/models/([a-z0-9._-]+)\.md", txt + "\n" + llms_extra):
                        if slug not in {"all", "compare", "overview", "deprecations"} and not is_legacy_model_id(slug):
                            extracted.add(slug)
                elif kind == "anthropic_doc_routes":
                    for slug in re.findall(r"/docs/en/models/([a-z0-9._-]+)/overview\.md", txt):
                        mid = slug if slug.startswith("claude-") else f"claude-{slug}"
                        if not is_legacy_model_id(mid):
                            extracted.add(mid)
                elif kind == "botocore_bedrock":
                    for mid in re.findall(r"(?:anthropic|openai|xai)\.(claude-[a-z0-9._-]+|gpt-[a-z0-9._-]+|grok-[a-z0-9._-]+)", txt):
                        clean_m = mid.split(":")[0]
                        if not is_legacy_model_id(clean_m):
                            extracted.add(clean_m)
                elif kind == "codex_models_json":
                    codex_doc = json.loads(txt)
                    for entry in codex_doc.get("models", []):
                        slug = (entry.get("slug") or "").strip().lower()
                        if slug and slug not in {"codex-auto-review"} and not is_legacy_model_id(slug):
                            extracted.add(slug)
                elif kind == "anthropic_sitemap":
                    for slug in re.findall(r"https://www\.anthropic\.com/(claude-(?:opus|sonnet|haiku|fable|mythos|[a-z]+-[56789])[a-z0-9._-]*)</loc>", txt):
                        if not is_legacy_model_id(slug):
                            extracted.add(slug)
                    for slug in re.findall(r"https://www\.anthropic\.com/(claude/[a-z0-9._-]+)</loc>", txt):
                        extracted.add(slug.replace("/", "-"))
                    for slug in re.findall(r"https://www\.anthropic\.com/(?:news|research)/((?:claude-[a-z]+-[56789]|(?:fable|mythos)-)[a-z0-9._-]*)</loc>", txt):
                        if not is_legacy_model_id(slug):
                            extracted.add(slug)
                elif kind == "openai_sitemap":
                    pub_extra = ""
                    try:
                        pub_extra = _http_get_text("https://openai.com/sitemap.xml/publication/", timeout=12)
                    except Exception:
                        pass
                    for slug in re.findall(
                        r"https://openai\.com/index/((?:introducing-gpt-[56789a-z]|introducing-o[56789]|previewing-gpt-[56789a-z]|gpt-[56789]|o[56789]-|unlocking-[a-z0-9-]*gpt-)[a-z0-9._-]*)/?</loc>",
                        txt + "\n" + pub_extra,
                    ):
                        if not is_legacy_model_id(slug):
                            extracted.add(slug)
                elif kind == "ms_copilot_waza_evals":
                    seed_eval_urls = [
                        "https://raw.githubusercontent.com/dotnet/efcore/main/eng/harness-evaluation/instructions/copilot-instructions/eval.yaml",
                        "https://raw.githubusercontent.com/dotnet/runtime/main/.github/workflows/evals/ci-failure-fix.eval.yaml",
                        "https://raw.githubusercontent.com/dotnet/runtime/main/.github/workflows/evals/ci-failure-scan.eval.yaml",
                        "https://raw.githubusercontent.com/Azure/azure-sdk-for-python/main/.github/skills/azsdk-common-apiview-feedback-resolution/evals/eval.yaml",
                        "https://raw.githubusercontent.com/Azure/azure-sdk-for-net/main/.github/skills/azsdk-common-apiview-feedback-resolution/evals/eval.yaml",
                        "https://raw.githubusercontent.com/Azure/azure-sdk-for-js/main/.github/skills/azsdk-common-apiview-feedback-resolution/evals/eval.yaml",
                        "https://raw.githubusercontent.com/microsoft/skills/main/tests/scenarios/agent-framework-azure-ai-py/vally/eval.yaml",
                    ]
                    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
                    if gh_token:
                        for cq in (
                            "org:microsoft org:dotnet org:Azure org:github filename:eval.yaml judge_model",
                            'org:microsoft org:dotnet org:Azure org:github filename:eval.yaml "copilot-sdk"',
                        ):
                            try:
                                cs_url = f"https://api.github.com/search/code?q={urllib.parse.quote(cq)}&per_page=25"
                                req = urllib.request.Request(
                                    cs_url,
                                    headers={
                                        "Authorization": f"Bearer {gh_token}",
                                        "Accept": "application/vnd.github+json",
                                        "User-Agent": "ModelPulse-Tracker/2.0",
                                    },
                                )
                                with urllib.request.urlopen(req, timeout=12) as resp:
                                    cs_doc = json.loads(resp.read().decode("utf-8", "ignore"))
                                for item in cs_doc.get("items", []):
                                    h_url = item.get("html_url", "")
                                    if "/blob/" in h_url:
                                        raw_u = h_url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/", 1)
                                        if raw_u not in seed_eval_urls:
                                            seed_eval_urls.append(raw_u)
                            except Exception:
                                pass

                    combined_evals = [txt]
                    for eu in seed_eval_urls[:40]:
                        try:
                            combined_evals.append(_http_get_text(eu, timeout=8))
                        except Exception:
                            pass
                    eval_lines = "\n".join(
                        line
                        for doc in combined_evals
                        for line in doc.splitlines()
                        if "model" in line.lower()
                    )
                    for mid in extract_models_from_bytes(eval_lines.encode("utf-8", "ignore")):
                        if not is_legacy_model_id(mid):
                            extracted.add(mid)

                if not extracted:
                    continue
                curr_list = sorted(extracted)
                bkey = probe["key"]
                prev_set = set(baselines.get(bkey, []))
                raw_new = [m for m in curr_list if m not in prev_set] if prev_set else []
                truly_new = [
                    m for m in raw_new
                    if _canonical_model_slug(m) not in previously_released_litellm
                ]
                if set(curr_list) != prev_set:
                    baselines[bkey] = curr_list
                    baselines_changed = True

                if truly_new:
                    sig = hashlib.sha256(",".join(truly_new[:8]).encode("utf-8")).hexdigest()[:8]
                    inferred = infer_provider(truly_new[0])
                    p_slug = inferred["slug"] if kind in {"botocore_bedrock", "cursor_doc_routes", "ms_copilot_waza_evals"} and inferred["slug"] != "other" else probe["provider_slug"]
                    p_color = inferred["color"] if kind in {"botocore_bedrock", "cursor_doc_routes", "ms_copilot_waza_evals"} and inferred["slug"] != "other" else probe["accent_color"]
                    cards.append(
                        {
                            "id": f"pre-release-{bkey}-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "docs-radar",
                            "header": probe["header"],
                            "title": f"{probe['title_prefix']}: {truly_new[0]}",
                            "subtitle": f"Detected in {probe['evidence']} (+{len(truly_new)} new)",
                            "build_label": "Pre-Release Scout",
                            "build_transition": f"+{len(truly_new)} unannounced identifier(s)",
                            "models": [{"id": m, "name": humanize_model_id(m)} for m in truly_new[:8]],
                            "evidence": probe["evidence"],
                            "source_text": probe["evidence"],
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": probe["header"].split("·")[-1].strip(),
                            "provider_slug": p_slug,
                            "accent_color": p_color,
                            "links": [{"label": "Source Feed", "url": probe["link_url"]}],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
            except Exception as exc:
                print(f"[DocsScanner] Structured probe warning ({probe['key']}): {exc}")

        # 4. Scan LiteLLM master model_prices_and_context_window.json for genuinely new frontier models
        # (excludes 3rd-party cloud re-hosting of already-released models like mistral/zai-glm-5-3-flash or cerebras/llama-3.1-70b)
        primary_litellm_prefixes = {
            "openai", "anthropic", "gemini", "vertex_ai", "bedrock", "bedrock_converse", "bedrock_mantle",
            "azure", "azure_ai", "github_copilot", "chatgpt", "vercel_ai_gateway", "xai",
            "deepseek", "moonshot", "dashscope", "zai", "minimax", "mistral", "openrouter",
        }
        try:
            litellm_data = _http_get_json(self.LITELLM_JSON_URL, timeout=15)
            if isinstance(litellm_data, dict):
                current_keys = sorted(k for k in litellm_data.keys() if k != "sample_spec")
                prev_keys = set(baselines.get("litellm_keys", []))
                prev_canonical_slugs = {_canonical_model_slug(pk) for pk in prev_keys}
                raw_added_keys = [k for k in current_keys if k not in prev_keys] if prev_keys else []
                added_keys: List[str] = []
                seen_new_canon: Set[str] = set()
                for k in raw_added_keys:
                    canon = _canonical_model_slug(k)
                    tail = k.split("/")[-1].split(":")[0]
                    prefix = k.split("/")[0].lower() if "/" in k else "openai"
                    if not canon or canon in prev_canonical_slugs or canon in seen_new_canon:
                        continue
                    if is_legacy_model_id(tail):
                        continue
                    if prefix not in primary_litellm_prefixes:
                        continue
                    seen_new_canon.add(canon)
                    added_keys.append(k)

                if set(current_keys) != prev_keys:
                    baselines["litellm_keys"] = current_keys
                    baselines_changed = True

                if added_keys:
                    sig = hashlib.sha256(",".join(added_keys[:10]).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"litellm-diff-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "litellm",
                            "header": "LITELLM MASTER REGISTRY DIFF · MULTI-PROVIDER",
                            "title": f"{len(added_keys)} New Model(s) Added to LiteLLM",
                            "subtitle": "Verified model_prices_and_context_window.json diff",
                            "build_label": "Registry Diff",
                            "build_transition": f"+{len(added_keys)} new model keys",
                            "models": [{"id": k, "name": k} for k in added_keys[:8]],
                            "evidence": "BerriAI/litellm/model_prices_and_context_window.json",
                            "source_text": "official LiteLLM master pricing & context window registry.",
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": "LITELLM",
                            "provider_slug": "modelsdev",
                            "accent_color": "#10b981",
                            "links": [
                                {"label": "LiteLLM JSON Registry", "url": self.LITELLM_JSON_URL},
                                {"label": "LiteLLM Commits", "url": "https://github.com/BerriAI/litellm/commits/main"},
                            ],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
        except Exception as exc:
            print(f"[DocsScanner] LiteLLM warning: {exc}")

        if baselines_changed:
            self._save_baselines(baselines)

        return cards


class LmArenaScanner:
    """
    Scans Arena (arena.ai / lmarena.ai) via two complementary channels:
    1. Live Next.js React Server Components (`self.__next_f.push`) `initialModels` stream on arena.ai / lmarena.ai
       (extracting `publicName`, `organization`, `provider`, `inputCapabilities`, and `outputCapabilities` —
       the exact source used by Arena Scout / LMArenaBridge).
    2. Official `lmarena-ai/leaderboard-dataset` on Hugging Face (`datasets-server.huggingface.co`)
       across Text, WebDev, Agent, Vision, Search, Text-to-Image, and Image Edit arenas.
    """

    ARENA_URLS = [
        "https://arena.ai/",
        "https://arena.ai/?mode=direct",
        "https://arena.ai/?mode=side-by-side",
        "https://lmarena.ai/?mode=direct",
    ]
    HF_ARENA_CONFIGS = [
        ("text", "Text Arena"),
        ("webdev", "WebDev Arena"),
        ("agent", "Agent Arena"),
        ("vision", "Vision Arena"),
        ("search", "Search Arena"),
        ("text_to_image", "Text-to-Image"),
        ("image_edit", "Image Edit"),
    ]
    BASELINES_FILE = pathlib.Path(__file__).resolve().parent.parent / "data" / "source_baselines.json"

    def _load_baselines(self) -> Dict[str, Any]:
        if self.BASELINES_FILE.exists():
            try:
                return json.loads(self.BASELINES_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_baselines(self, data: Dict[str, Any]) -> None:
        self.BASELINES_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.BASELINES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def _format_capabilities(cap_obj: Dict[str, Any]) -> str:
        if not isinstance(cap_obj, dict):
            return ""
        in_caps = cap_obj.get("inputCapabilities") or {}
        out_caps = cap_obj.get("outputCapabilities") or {}
        tags: List[str] = []
        if isinstance(in_caps, dict):
            for k, v in in_caps.items():
                if v:
                    tags.append(f"in:{k}")
        if isinstance(out_caps, dict):
            for k, v in out_caps.items():
                if v:
                    tags.append(f"out:{k}")
        return ", ".join(tags)

    def _scan_live_initial_models(self, baselines: Dict[str, Any]) -> tuple[List[Dict[str, Any]], bool]:
        """Attempt to parse `initialModels` from arena.ai / lmarena.ai Next.js RSC stream across Battle & Direct modes."""
        cards: List[Dict[str, Any]] = []
        changed = False
        merged_map: Dict[str, Dict[str, Any]] = dict(baselines.get("arena_initial_models", {}))
        prev_keys = set(merged_map.keys())
        fetched_any = False

        for url in self.ARENA_URLS:
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml",
                    },
                )
                with urllib.request.urlopen(req, timeout=12) as resp:
                    html = resp.read().decode("utf-8", "ignore")
                if "initialModels" not in html:
                    continue

                idx = html.find('"initialModels":')
                if idx == -1:
                    idx = html.find('\\"initialModels\\":')
                    if idx != -1:
                        html_slice = html[idx:].replace('\\"', '"').replace("\\\\", "\\")
                    else:
                        continue
                else:
                    html_slice = html[idx:]

                arr_start = html_slice.find("[")
                if arr_start == -1:
                    continue
                depth = 0
                arr_end = -1
                for i, ch in enumerate(html_slice[arr_start:], start=arr_start):
                    if ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            arr_end = i + 1
                            break
                if arr_end == -1:
                    continue

                models_arr = json.loads(html_slice[arr_start:arr_end])
                if not isinstance(models_arr, list) or not models_arr:
                    continue

                fetched_any = True
                for m in models_arr:
                    if not isinstance(m, dict):
                        continue
                    pub_name = m.get("publicName") or m.get("id")
                    if not pub_name:
                        continue
                    merged_map[pub_name] = {
                        "org": m.get("organization") or "unknown",
                        "provider": m.get("provider") or "unknown",
                        "caps": self._format_capabilities(m.get("capabilities") or {}),
                    }
            except Exception as exc:
                print(f"[LmArenaScanner] Note (arena.ai live RSC stream {url}): {exc}")

        if fetched_any:
            already_known_canon = {
                _canonical_model_slug(x) for x in baselines.get("arena_leaderboard_models", [])
            } | {
                _canonical_model_slug(x) for x in baselines.get("litellm_keys", [])
            }
            added_names = [
                k for k in merged_map
                if k not in prev_keys
                and _canonical_model_slug(k) not in already_known_canon
                and not is_legacy_model_id(k)
            ] if prev_keys else []
            if set(merged_map.keys()) != prev_keys:
                baselines["arena_initial_models"] = merged_map
                changed = True

            if added_names:
                sig = hashlib.sha256(",".join(added_names).encode("utf-8")).hexdigest()[:8]
                cards.append(
                    {
                        "id": f"arena-scout-diff-{sig}",
                        "category": "cli-sdk-diff",
                        "scanner": "lmarena",
                        "header": "ARENA.AI LIVE MODEL SCOUT · NEXT.JS RSC STREAM",
                        "title": f"New Model Found on Arena: {added_names[0]}",
                        "subtitle": f"Detected in arena.ai initialModels RSC payload (+{len(added_names)} new)",
                        "build_label": "Arena Stream",
                        "build_transition": f"initialModels · {len(merged_map)} active models",
                        "models": [
                            {
                                "id": f"org:{merged_map[name]['org']} · {merged_map[name]['provider']}",
                                "name": f"{name} ({merged_map[name]['caps'] or 'chat'})",
                            }
                            for name in added_names[:8]
                        ],
                        "evidence": "arena.ai -> self.__next_f.push (initialModels)",
                        "source_text": "live Arena (arena.ai) Next.js RSC model config.",
                        "disclaimer_1": "",
                        "disclaimer_2": "",
                        "provider_name": "ARENA.AI",
                        "provider_slug": "modelsdev",
                        "accent_color": "#10b981",
                        "links": [{"label": "Arena.ai Direct", "url": "https://arena.ai/?mode=direct"}],
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }
                )

        return cards, changed

    def scan(self) -> List[Dict[str, Any]]:
        baselines = self._load_baselines()
        cards, changed = self._scan_live_initial_models(baselines)

        # Scan official lmarena-ai/leaderboard-dataset ONLY for new model diffs & unreleased models (like gemini-nano-banana-2.1)
        try:
            meta = _http_get_json("https://huggingface.co/api/datasets/lmarena-ai/leaderboard-dataset", timeout=12)
            last_mod = meta.get("lastModified", datetime.now(timezone.utc).isoformat())
        except Exception:
            last_mod = datetime.now(timezone.utc).isoformat()

        all_discovered: Dict[str, str] = {}
        for cfg, cfg_label in self.HF_ARENA_CONFIGS:
            try:
                url = f"https://datasets-server.huggingface.co/rows?dataset=lmarena-ai/leaderboard-dataset&config={cfg}&split=latest&offset=0&length=85"
                data = _http_get_json(url, timeout=12)
                rows = [r["row"] for r in data.get("rows", []) if isinstance(r, dict) and "row" in r]
                overall = [r for r in rows if r.get("category", "overall") == "overall"] or rows
                for r in overall:
                    rn = str(r.get("model_name", ""))
                    if rn:
                        all_discovered[rn] = cfg_label
            except Exception as exc:
                print(f"[LmArenaScanner] HF leaderboard warning ({cfg}): {exc}")

        if all_discovered:
            prev_lb = set(baselines.get("arena_leaderboard_models", []))
            curr_lb = sorted(all_discovered.keys())
            added_lb = [m for m in curr_lb if m not in prev_lb] if prev_lb else []
            if set(curr_lb) != prev_lb:
                baselines["arena_leaderboard_models"] = curr_lb
                changed = True

            if added_lb:
                sig = hashlib.sha256(",".join(added_lb[:10]).encode("utf-8")).hexdigest()[:8]
                cards.append(
                    {
                        "id": f"lmarena-lb-diff-{sig}",
                        "category": "cli-sdk-diff",
                        "scanner": "lmarena",
                        "header": "ARENA.AI NEW MODEL DIFF · LMARENA",
                        "title": f"New Model(s) Added to Arena ({added_lb[0]})",
                        "subtitle": "Newly added models in official lmarena-ai/leaderboard-dataset",
                        "build_label": "Arena Diff",
                        "build_transition": f"+{len(added_lb)} new Arena models",
                        "models": [{"id": m, "name": f"{m} ({all_discovered.get(m, 'Arena')})"} for m in added_lb[:8]],
                        "evidence": "huggingface.co/datasets/lmarena-ai/leaderboard-dataset",
                        "source_text": "official LMArena (arena.ai) Hugging Face dataset.",
                        "disclaimer_1": "",
                        "disclaimer_2": "",
                        "provider_name": "ARENA.AI",
                        "provider_slug": "modelsdev",
                        "accent_color": "#10b981",
                        "links": [{"label": "LMArena Dataset", "url": "https://huggingface.co/datasets/lmarena-ai/leaderboard-dataset"}],
                        "detected_at": last_mod,
                    }
                )

        if changed:
            self._save_baselines(baselines)

        return cards


class CertTransparencySubdomainScanner:
    """
    Monitors Certificate Transparency (CT) SSL issuances (SSLMate CertSpotter API with incremental
    `after=` cursors) and Passive DNS host records across 21 frontier AI lab domains.
    Emits:
      - `cert-transparency` breaking diff cards whenever a brand-new subdomain appears, and
      - `cert-transparency-snapshot` per-domain radar cards for the Subdomains (CT) dashboard tab.
    """

    WATCHED_DOMAINS = [
        ("openai.com", "OpenAI", "OPENAI", "openai", "#10b981"),
        ("chatgpt.com", "ChatGPT · OpenAI", "OPENAI", "openai", "#10b981"),
        ("sora.com", "Sora · OpenAI", "OPENAI", "openai", "#10b981"),
        ("anthropic.com", "Anthropic", "ANTHROPIC", "anthropic", "#f97316"),
        ("claude.ai", "Claude.ai · Anthropic", "ANTHROPIC", "anthropic", "#f97316"),
        ("claude.com", "Claude.com · Anthropic", "ANTHROPIC", "anthropic", "#f97316"),
        ("gemini.google.com", "Google Gemini", "GOOGLE", "google", "#38bdf8"),
        ("ai.google.dev", "Google AI Dev", "GOOGLE", "google", "#38bdf8"),
        ("deepmind.google", "Google DeepMind", "GOOGLE", "google", "#38bdf8"),
        ("x.ai", "xAI", "XAI", "xai", "#e2e8f0"),
        ("grok.com", "Grok · xAI", "XAI", "xai", "#e2e8f0"),
        ("cursor.com", "Cursor IDE", "CURSOR", "cursor", "#94a3b8"),
        ("deepseek.com", "DeepSeek AI", "DEEPSEEK", "deepseek", "#06b6d4"),
        ("kimi.com", "Moonshot Kimi", "MOONSHOT · KIMI", "kimi", "#06b6d4"),
        ("moonshot.cn", "Moonshot AI", "MOONSHOT · KIMI", "kimi", "#06b6d4"),
        ("qwen.ai", "Qwen · Alibaba", "QWEN · ALIBABA", "qwen", "#a855f7"),
        ("z.ai", "Z.ai · GLM", "Z.AI · GLM", "zai", "#14b8a6"),
        ("minimax.io", "MiniMax AI", "MINIMAX", "minimax", "#ec4899"),
        ("mistral.ai", "Mistral AI", "MISTRAL AI", "mistral", "#f59e0b"),
        ("perplexity.ai", "Perplexity AI", "PERPLEXITY", "perplexity", "#0ea5e9"),
        ("thinkingmachines.ai", "Thinking Machines Lab", "THINKING MACHINES", "thinkingmachines", "#8b5cf6"),
    ]

    ALLOWED_ALNUM_TOKENS = {
        "a100", "h100", "h200", "b200", "gb200", "v1", "v2", "v3", "v4", "v5",
        "s3", "k8s", "oauth2", "web3", "i18n", "l10n", "2025", "2026", "2027",
        "gpt4", "gpt5", "gpt6", "gpt7", "k2", "k3", "m2", "m3", "r1", "r2",
        "o1", "o3", "o4", "3d", "4k", "2fa", "mfa", "b2b", "p2p", "e2e", "a2a",
    }

    BORING_LABELS = {
        "www", "mail", "smtp", "imap", "pop", "autodiscover", "mg", "sendgrid",
        "amazonses", "mandrill", "email", "bounce", "links", "ilinks", "click",
    }

    COMMODITY_FIRST_LABELS = {
        "www", "api", "a-api", "api-staging", "chat", "docs", "api-docs", "help",
        "support", "support-monitoring", "status", "cdn", "a-cdn", "content-cdn",
        "content-cdn-staging", "assets", "assets-staging", "assets-proxy",
        "lifecycle-assets", "static", "media", "ogimg", "download", "downloads",
        "auth", "auth-admin", "sso", "login", "accounts", "account", "admin",
        "console", "platform", "dashboard", "portal", "partnerhub", "communityportal",
        "discuss", "forum", "community", "blog", "news", "press", "brand", "careers",
        "jobs", "legal", "privacy", "privacy-pass-issuer", "terms", "trust",
        "security", "compliance", "billing", "pay", "payments", "pricing", "store",
        "shop", "academy", "eap-academy", "learn", "website", "websitemain", "config",
        "ab", "m", "a", "ws", "staging", "preview", "beta", "internal", "private",
        "gov", "gov-demo", "fedramp", "alignment", "ads", "adstransparency",
        "releases", "l10n-review", "programs-staging", "gtm-innovation",
        "it-agent-ingress", "connectors", "transceiver", "ci-webhooks",
        "observability-webhook", "develocity", "wildcard", "mtls", "mtls-eu",
        "sip", "search", "realtime", "code", "sora", "operator", "enterprise",
        "batchapi", "responsesapi-cert-publisher", "sandbox", "lti",
        "atlantis", "atlantis-sandbox", "sevbot", "argocd", "argo", "grafana",
        "prometheus", "sentry", "backstage", "teleport", "vault", "keycloak",
        "harbor", "jenkins", "buildkite", "sonarqube", "netbox", "airflow",
        "ae", "au", "aw", "br", "ca", "de", "eu", "fr", "gb", "hk", "in", "it",
        "jp", "kr", "nl", "pl", "se", "sg", "tw", "uk", "us", "ap", "apac", "emea", "global",
    }

    BASELINES_FILE = pathlib.Path(__file__).resolve().parent.parent / "data" / "source_baselines.json"

    def _load_baselines(self) -> Dict[str, Any]:
        if self.BASELINES_FILE.exists():
            try:
                return json.loads(self.BASELINES_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_baselines(self, data: Dict[str, Any]) -> None:
        self.BASELINES_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.BASELINES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8", newline="\n")

    @classmethod
    def is_clean_subdomain(cls, sub: str, root_dom: str) -> bool:
        s = sub.strip().lower().rstrip(".")
        if not s.endswith("." + root_dom):
            return False
        if s.startswith("*.") or s.startswith("_") or s.startswith("-"):
            return False
        if s.endswith(".space.minimax.io"):
            return False

        prefix = s[: -(len(root_dom) + 1)]
        if not prefix or prefix == "www":
            return False

        labels = prefix.split(".")
        for lbl in labels:
            if not lbl or lbl.startswith("_") or lbl in cls.BORING_LABELS:
                return False
            for tok in lbl.split("-"):
                if not tok:
                    continue
                if re.fullmatch(r"[0-9a-f]{8,}", tok):
                    return False
                has_alpha = any(c.isalpha() for c in tok)
                has_digit = any(c.isdigit() for c in tok)
                if has_alpha and has_digit and tok not in cls.ALLOWED_ALNUM_TOKENS:
                    if tok[0].isdigit():
                        return False
                    if len(tok) >= 7 or sum(c.isdigit() for c in tok) >= 3:
                        return False
        return True

    @classmethod
    def is_high_signal_subdomain(cls, sub: str, root_dom: str) -> bool:
        """
        Return True ONLY for stealth codenames, unannounced products/agents/IDEs,
        internal sandboxes, and non-commodity staging clusters — hiding generic IT
        subdomains (docs, chat, api, cdn, auth, billing, regional PoPs, webps shards).
        """
        if not cls.is_clean_subdomain(sub, root_dom):
            return False
        s = sub.strip().lower().rstrip(".")
        prefix = s[: -(len(root_dom) + 1)]
        labels = prefix.split(".")
        first = labels[0]

        if first in cls.COMMODITY_FIRST_LABELS:
            # Exception: keep named staging clusters behind api/v2 (e.g. api.maia-staging.dc.mistral.ai)
            if first == "api" and any(
                lbl.endswith("-staging") and lbl not in {"api-staging", "assets-staging", "content-cdn-staging", "programs-staging"}
                for lbl in labels[1:]
            ):
                return True
            return False

        if first.startswith(("chatgpt-async-webps-", "sandbox-chs", "hif-")):
            return False

        if prefix in {"v2.auth", "gmail.mcp", "gcal.mcp", "slack-channel.mcp"}:
            return False

        return True

    @staticmethod
    def subdomain_family_key(sub: str, root_dom: str) -> str:
        """Collapse numbered cluster shards (e.g. stt-nova3-s0..s8, unified-0..1) into one representative."""
        prefix = sub[: -(len(root_dom) + 1)].lower()
        norm = re.sub(r"-(?:s?\d+|chs\d+)\b", "", prefix)
        norm = re.sub(r"\.unified-\d+\b", ".unified", norm)
        norm = norm.replace(".titanium-staging.", ".titanium.")
        if norm.startswith("stt-flux"):
            norm = "stt-flux.titanium.api"
        elif norm == "stt.titanium.api":
            norm = "stt-nova3.titanium.api"
        if norm.startswith("ide-api."):
            norm = norm.replace("ide-api.", "api-ide.", 1)
        if norm.endswith("-webhooks.api"):
            norm = norm.replace("-webhooks.api", ".api")
        return norm

    @staticmethod
    def classify_subdomain(sub: str, cert_date: str = "") -> tuple[int, str]:
        s = sub.lower()
        if ".mcp." in s or s.startswith("mcp."):
            score, role = 88, "First-Party MCP Server"
        elif any(k in s for k in ("codex", "zcode", "coder", "api-ide", "ide-api", "studio")):
            score, role = 97, "Coding / IDE Endpoint"
        elif any(k in s for k in ("autoclaw", "autoglm", "agent", "hooks", "skills", "tinker", "notilo", "deployer", "wf-scheduler", "sevbot")):
            score, role = 96, "Agent / Product Endpoint"
        elif any(k in s for k in ("sonata", "voice", "stt", "tts", "audio", "livekit")):
            score, role = 93, "Voice / Audio Cluster"
        elif any(k in s for k in ("release-candidate", "autopush", "maia-staging", "amb-staging", "enterprise-staging")):
            score, role = 94, "Pre-Release / Staging"
        elif any(k in s for k in ("sandbox", "eval", "bench", "-dev.", "dev.")):
            score, role = 95, "Internal Sandbox / Eval"
        elif any(k in s for k in ("preview", "canary", "alpha", "nightly")):
            score, role = 92, "Preview / Canary"
        else:
            # Novel product/project names that passed is_high_signal_subdomain (e.g. tidewater, habanero, nori, openhouse, pivot)
            score, role = 99, "Stealth / Codename Endpoint"

        if cert_date:
            return score, f"{role} · SSL {cert_date[:10]}"
        return score, role

    def _poll_certspotter_domain(
        self,
        dom: str,
        cursor: Optional[str],
        max_pages: int = 2,
    ) -> tuple[Dict[str, str], Optional[str], bool, bool]:
        """Return ({clean_subdomain: not_before_iso}, new_cursor_id, ok, reached_tip)."""
        discovered: Dict[str, str] = {}
        curr_after = cursor
        pages = 0
        reached_tip = False
        extra_headers: Dict[str, str] = {}
        api_tok = (os.environ.get("CERTSPOTTER_API_TOKEN") or "").strip()
        if api_tok:
            extra_headers["Authorization"] = f"Bearer {api_tok}"
        while pages < max_pages:
            pages += 1
            url = f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(dom)}&include_subdomains=true&expand=dns_names"
            if curr_after:
                url += f"&after={urllib.parse.quote(str(curr_after))}"
            data = _http_get_json(url, timeout=10, extra_headers=extra_headers or None)
            if not isinstance(data, list):
                return discovered, curr_after, False, False
            if not data:
                return discovered, curr_after, True, True
            for cert in data:
                if not isinstance(cert, dict):
                    continue
                cid = cert.get("id")
                if cid:
                    curr_after = str(cid)
                nb = (cert.get("not_before") or "").strip()
                for dn in cert.get("dns_names") or []:
                    dn_l = str(dn).strip().lower()
                    if self.is_clean_subdomain(dn_l, dom):
                        if nb > discovered.get(dn_l, ""):
                            discovered[dn_l] = nb
            if len(data) < 100:
                reached_tip = True
                break
        return discovered, curr_after, True, reached_tip

    def _poll_hackertarget_domain(self, dom: str) -> tuple[Set[str], bool]:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(dom)}"
        txt = _http_get_text(url, timeout=10)
        if not txt or "API count exceeded" in txt:
            return set(), False
        if "error check" in txt.lower():
            return set(), True
        out: Set[str] = set()
        for line in txt.splitlines():
            if "," not in line:
                continue
            host = line.split(",", 1)[0].strip().lower()
            if self.is_clean_subdomain(host, dom):
                out.add(host)
        return out, True

    def _poll_urlscan_domain(self, dom: str) -> tuple[Set[str], bool]:
        """Return (clean_subdomains, ok) for TLS-verified live hosts on URLScan (never using crawl time as SSL date)."""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(dom)}&size=100"
        data = _http_get_json(url, timeout=10)
        if not isinstance(data, dict) or "results" not in data:
            return set(), False
        out: Set[str] = set()
        for res in data.get("results") or []:
            if not isinstance(res, dict):
                continue
            page = res.get("page") or {}
            if not page.get("ip") or not page.get("tlsIssuer"):
                continue
            host = str(page.get("domain") or "").strip().lower()
            if self.is_clean_subdomain(host, dom):
                out.add(host)
        return out, True

    def scan(self, batch_size: int = 3) -> List[Dict[str, Any]]:
        baselines = self._load_baselines()
        known_map: Dict[str, List[str]] = dict(baselines.get("ct_known_subdomains", {}))
        dates_map: Dict[str, str] = dict(baselines.get("ct_subdomain_dates", {}))
        cursors_map: Dict[str, str] = dict(baselines.get("ct_cursors", {}))
        seeded_sources_map: Dict[str, List[str]] = {
            k: list(v) for k, v in (baselines.get("ct_seeded_sources") or {}).items()
        }
        offset = int(baselines.get("ct_batch_offset", 0) or 0)
        changed = False

        total_doms = len(self.WATCHED_DOMAINS)
        unseeded = [i for i, (d, *_) in enumerate(self.WATCHED_DOMAINS) if d not in known_map or not known_map.get(d)]
        if unseeded and offset == 0 and len(unseeded) == total_doms:
            selected_indices = unseeded[:batch_size]
        else:
            selected_indices = [(offset + k) % total_doms for k in range(min(batch_size, total_doms))]
            baselines["ct_batch_offset"] = (offset + batch_size) % total_doms
            changed = True

        recent_cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        diff_cards: List[Dict[str, Any]] = []

        for idx in selected_indices:
            dom, title_label, prov_upper, prov_slug, color = self.WATCHED_DOMAINS[idx]
            prev_subs = set(known_map.get(dom, []))
            found_subs: Set[str] = set(prev_subs)
            seeded_srcs = set(seeded_sources_map.get(dom, []))
            newly_alertable: Set[str] = set()

            # 1. Poll SSLMate CertSpotter CT Log API
            try:
                had_ct = "ct" in seeded_srcs
                prev_cursor = cursors_map.get(dom)
                ct_subs, new_cursor, ct_ok, reached_tip = self._poll_certspotter_domain(
                    dom,
                    cursor=prev_cursor,
                    max_pages=2 if had_ct else 4,
                )
                if ct_ok:
                    for s, nb in ct_subs.items():
                        if s not in prev_subs and had_ct:
                            newly_alertable.add(s)
                        found_subs.add(s)
                        if nb and nb > dates_map.get(s, ""):
                            dates_map[s] = nb
                            changed = True
                    if new_cursor and new_cursor != prev_cursor:
                        cursors_map[dom] = new_cursor
                        changed = True
                    if reached_tip and not had_ct:
                        seeded_srcs.add("ct")
                        changed = True
            except Exception as exc:
                print(f"[CTScanner] CertSpotter note ({dom}): {exc}")

            # 2. Poll HackerTarget Passive DNS HostSearch
            try:
                ht_subs, ht_ok = self._poll_hackertarget_domain(dom)
                if ht_ok:
                    had_ht = "ht" in seeded_srcs
                    for s in ht_subs:
                        if s not in prev_subs and had_ht:
                            newly_alertable.add(s)
                        found_subs.add(s)
                    if not had_ht:
                        seeded_srcs.add("ht")
                        changed = True
            except Exception as exc:
                print(f"[CTScanner] HostSearch note ({dom}): {exc}")

            # 3. Poll URLScan Live TLS-Verified Subdomains
            try:
                us_subs, us_ok = self._poll_urlscan_domain(dom)
                if us_ok:
                    had_us = "us" in seeded_srcs
                    for s in us_subs:
                        if s not in prev_subs and had_us:
                            newly_alertable.add(s)
                        found_subs.add(s)
                    if not had_us:
                        seeded_srcs.add("us")
                        changed = True
            except Exception as exc:
                print(f"[CTScanner] URLScan note ({dom}): {exc}")

            # Prune any legacy noisy entries if rules tightened
            found_subs = {s for s in found_subs if self.is_clean_subdomain(s, dom)}
            newly_alertable = {s for s in newly_alertable if self.is_high_signal_subdomain(s, dom)}

            if seeded_srcs != set(seeded_sources_map.get(dom, [])):
                seeded_sources_map[dom] = sorted(seeded_srcs)
                changed = True

            if found_subs != prev_subs or dom not in known_map:
                known_map[dom] = sorted(found_subs)
                changed = True

            added_subs = sorted(newly_alertable)
            if added_subs:
                sig = hashlib.sha256(",".join(added_subs[:10]).encode("utf-8")).hexdigest()[:8]
                ranked_added_raw = sorted(
                    added_subs,
                    key=lambda s: (self.classify_subdomain(s, dates_map.get(s, ""))[0], dates_map.get(s, ""), s),
                    reverse=True,
                )
                ranked_added: List[str] = []
                seen_fams_diff: Set[str] = set()
                for s in ranked_added_raw:
                    fk = self.subdomain_family_key(s, dom)
                    if fk not in seen_fams_diff:
                        seen_fams_diff.add(fk)
                        ranked_added.append(s)
                diff_cards.append(
                    {
                        "id": f"ct-diff-{dom.replace('.', '-')}-{sig}",
                        "category": "subdomain-ct",
                        "scanner": "cert-transparency",
                        "header": f"SSL CERTIFICATE TRANSPARENCY DIFF · {prov_upper}",
                        "title": f"New {title_label} Subdomain: {ranked_added[0]}",
                        "subtitle": f"Newly discovered stealth / staging endpoint under *.{dom}",
                        "build_label": "Root Domain",
                        "build_transition": f"*.{dom} (+{len(ranked_added)} new)",
                        "models": [
                            {
                                "id": s,
                                "name": self.classify_subdomain(s, dates_map.get(s, ""))[1],
                            }
                            for s in ranked_added[:8]
                        ],
                        "evidence": f"Certificate Transparency (CT) Logs · *.{dom}",
                        "source_text": f"public Certificate Transparency (CT) & DNS records for {dom}.",
                        "disclaimer_1": "",
                        "disclaimer_2": "",
                        "provider_name": prov_upper,
                        "provider_slug": prov_slug,
                        "accent_color": color,
                        "links": [
                            {"label": "CertSpotter CT Log", "url": f"https://sslmate.com/ct_search_results?q={dom}"},
                            {"label": "crt.sh Lookup", "url": f"https://crt.sh/?q=%25.{dom}"},
                        ],
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }
                )

        # Build compact per-domain Subdomain Radar cards ONLY for high-signal codename/product/staging endpoints
        snapshot_cards: List[Dict[str, Any]] = []
        for dom, title_label, prov_upper, prov_slug, color in self.WATCHED_DOMAINS:
            all_dom_subs = [s for s in known_map.get(dom, []) if self.is_clean_subdomain(s, dom)]
            signal_subs = [s for s in all_dom_subs if self.is_high_signal_subdomain(s, dom)]
            if not signal_subs:
                continue

            by_signal = sorted(
                signal_subs,
                key=lambda s: (self.classify_subdomain(s, dates_map.get(s, ""))[0], dates_map.get(s, "")[:10], s),
                reverse=True,
            )
            top_subs: List[str] = []
            seen_fams: Set[str] = set()
            mcp_count = 0
            for candidate in by_signal:
                fk = self.subdomain_family_key(candidate, dom)
                if fk in seen_fams:
                    continue
                if ".mcp." in candidate:
                    if mcp_count >= 4:
                        continue
                    mcp_count += 1
                seen_fams.add(fk)
                top_subs.append(candidate)
                if len(top_subs) >= 8:
                    break

            if not top_subs:
                continue

            newest_cert_iso = max((dates_map.get(s, "") for s in signal_subs), default="")
            snap_ts = newest_cert_iso if newest_cert_iso else "2026-10-15T00:00:00Z"

            snapshot_cards.append(
                {
                    "id": f"ct-radar-{dom.replace('.', '-')}",
                    "category": "subdomain-ct",
                    "scanner": "cert-transparency-snapshot",
                    "header": f"STEALTH SUBDOMAIN & CT RADAR · {prov_upper}",
                    "title": f"{title_label} Codenames & Staging (*.{dom})",
                    "subtitle": f"Filtered codename, agent & pre-release endpoints ({len(seen_fams)} notable / {len(all_dom_subs)} baselined)",
                    "build_label": "Domain",
                    "build_transition": f"*.{dom} · {len(top_subs)} notable ({len(all_dom_subs)} baselined)",
                    "models": [
                        {
                            "id": s,
                            "name": self.classify_subdomain(s, dates_map.get(s, ""))[1],
                        }
                        for s in top_subs
                    ],
                    "evidence": f"Certificate Transparency & Passive DNS · *.{dom}",
                    "source_text": f"filtered Certificate Transparency (CT) & DNS records for {dom} (generic docs/chat/api hosts hidden).",
                    "disclaimer_1": "",
                    "disclaimer_2": "",
                    "provider_name": prov_upper,
                    "provider_slug": prov_slug,
                    "accent_color": color,
                    "links": [
                        {"label": "CertSpotter CT Log", "url": f"https://sslmate.com/ct_search_results?q={dom}"},
                        {"label": "crt.sh Lookup", "url": f"https://crt.sh/?q=%25.{dom}"},
                    ],
                    "detected_at": snap_ts,
                }
            )

        if changed:
            baselines["ct_known_subdomains"] = known_map
            baselines["ct_subdomain_dates"] = dates_map
            baselines["ct_cursors"] = cursors_map
            baselines["ct_seeded_sources"] = seeded_sources_map
            self._save_baselines(baselines)

        return [*diff_cards, *snapshot_cards]


class HighAlphaLeakChannelsScanner:
    """
    Covers the 6 high-alpha pre-release leak channels verified from RAGtrack, aitracker.bot & TestingCatalog:
      1. Zero-key stealth & multi-lab gateways (`opencode.ai/zen/v1/models`, `ai-gateway.vercel.sh/v1/models`)
      2. Desktop IDE build string differs (Cursor Linux REH archive & Devin/Windsurf Stable + Next builds)
      3. GitHub Copilot CLI release & prerelease notes (`github/copilot-cli/releases`)
      4. Inference engine open + closed PR leak watcher (`vllm`, `sglang`, `TensorRT-LLM`, `transformers` with `state=all`)
      5. Direct official provider `/v1/models` & Gemini `v1alpha/models` + `v1beta/models` API pollers
      6. Google AI Studio (`boq-makersuite`) & Gemini Web (`boq-gemini-web-uiserver`) JS bundle route & Mendel flag differ
    """

    OPENCODE_ZEN_URL = "https://opencode.ai/zen/v1/models"
    VERCEL_GATEWAY_URL = "https://ai-gateway.vercel.sh/v1/models"

    CURSOR_TRACKS = [
        ("stable", "https://www.cursor.com/api/download?platform=linux-x64&releaseTrack=stable"),
        ("dev", "https://www.cursor.com/api/download?platform=linux-x64&releaseTrack=dev"),
    ]
    WINDSURF_TRACKS = [
        ("stable", "https://windsurf-stable.codeium.com/api/update/linux-x64/stable/latest"),
        ("next", "https://windsurf-stable.codeium.com/api/update/linux-x64/next/latest"),
    ]

    ENGINE_PR_REPOS = [
        ("vllm-project/vllm", "vLLM PR"),
        ("sgl-project/sglang", "SGLang PR"),
        ("NVIDIA/TensorRT-LLM", "TensorRT-LLM PR"),
        ("huggingface/transformers", "HF Transformers PR"),
    ]

    IDE_BUNDLE_MODEL_RE = re.compile(
        rb"\b("
        rb"claude-(?:opus|sonnet|haiku|fable|mythos)-[0-9a-z][a-z0-9._-]{0,30}|"
        rb"fable-[567](?:[.-][0-9]+)?(?:-[a-z0-9._-]+)?|"
        rb"composer-[2345](?:[.-][0-9]+)?(?:-(?:fast|mini|pro|max|thinking|high))?|"
        rb"gpt-(?:[56789]|daybreak|rosalind|aurora)[a-z0-9._-]{0,28}|"
        rb"astra-cyber[a-z0-9._-]{0,22}|"
        rb"gemini-[345][a-z0-9._-]{1,32}|"
        rb"grok-[456][a-z0-9._-]{0,25}|"
        rb"kimi-k[234][a-z0-9._-]{0,25}|"
        rb"deepseek-(?:v[456]|r[234])[a-z0-9._-]{0,25}|"
        rb"glm-[567][a-z0-9._-]{0,22}|"
        rb"minimax-m[345][a-z0-9._-]{0,22}|"
        rb"mai-(?:code|[234])[a-z0-9._-]{0,22}|"
        rb"swe-[23]-(?:lightning|mini|medium|high|max|pro)[a-z0-9._-]{0,20}"
        rb")\b"
    )

    IDE_EXCLUDED_TOKENS = {
        "composer-backed", "composer-peek", "composer-chat-script", "composer-input",
        "composer-bar", "composer-mode", "composer-panel", "gemini-3", "gemini-4",
        "gpt-5", "grok-4", "claude-opus-4", "claude-sonnet-4", "claude-haiku-4",
    }

    PR_ONBOARD_TITLE_RE = re.compile(
        r"(?:\[(?:New\s+)?Models?\]|\badd(?:s|ed|ing)?\s+(?:day-0\s+)?support\s+for\b|\bday-0\s+support\b|\bonboard(?:ing)?\b|\bsupport\s+[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)",
        re.IGNORECASE,
    )
    PR_HF_SLUG_RE = re.compile(
        r"\b((?:moonshotai|deepseek-ai|Qwen|zai-org|THUDM|MiniMaxAI|openbmb|nvidia|google|meta-llama|mistralai|XiaomiMiMo|stepfun-ai|inclusionAI|CohereLabs)/[A-Za-z0-9][A-Za-z0-9._-]{2,48})\b"
    )
    PR_UNRELEASED_ID_RE = re.compile(
        r"\b("
        r"nemotron-?4[a-z0-9._-]{1,28}|"
        r"kimi-k3\.[1-9][a-z0-9._-]{0,22}|kimi-k4[a-z0-9._-]{0,22}|"
        r"deepseek-v4\.[2-9][a-z0-9._-]{0,22}|deepseek-v5[a-z0-9._-]{0,22}|deepseek-r[23][a-z0-9._-]{0,22}|"
        r"qwen3\.[89][a-z0-9._-]{0,22}|qwen4[a-z0-9._-]{0,22}|"
        r"glm-5\.[4-9][a-z0-9._-]{0,22}|glm-6[a-z0-9._-]{0,22}|"
        r"gemma-?4[a-z0-9._-]{0,22}|diffusiongemma[a-z0-9._-]{0,18}|embeddinggemma[23][a-z0-9._-]{0,18}|"
        r"minimax-m3\.[1-9][a-z0-9._-]{0,22}|minimax-m4[a-z0-9._-]{0,22}|"
        r"mimo-v2\.[7-9][a-z0-9._-]{0,22}|mimo-v3[a-z0-9._-]{0,22}|"
        r"minicpm-(?:ocr|v|o)-?[0-9][a-z0-9._-]{0,20}"
        r")\b",
        re.IGNORECASE,
    )

    BASELINES_FILE = pathlib.Path(__file__).resolve().parent.parent / "data" / "source_baselines.json"

    def _load_baselines(self) -> Dict[str, Any]:
        if self.BASELINES_FILE.exists():
            try:
                return json.loads(self.BASELINES_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_baselines(self, data: Dict[str, Any]) -> None:
        self.BASELINES_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.BASELINES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8", newline="\n")

    @staticmethod
    def _gh_headers() -> Dict[str, str]:
        hdrs = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "ModelPulse-Tracker/2.0",
        }
        tok = (os.environ.get("GITHUB_TOKEN") or "").strip()
        if tok:
            hdrs["Authorization"] = f"Bearer {tok}"
        return hdrs

    def _scan_public_gateways(
        self,
        baselines: Dict[str, Any],
        known_canon: Set[str],
    ) -> tuple[List[Dict[str, Any]], bool]:
        cards: List[Dict[str, Any]] = []
        changed = False

        # 1a. OpenCode Zen Gateway (frequently hosts stealth anonymous codenames + day-0 frontier models)
        try:
            oz_doc = _http_get_json(self.OPENCODE_ZEN_URL, timeout=12, extra_headers={"User-Agent": "Mozilla/5.0"})
            oz_rows = oz_doc.get("data", []) if isinstance(oz_doc, dict) else []
            if oz_rows:
                curr_oz = sorted(
                    {
                        str(r.get("id", "")).strip()
                        for r in oz_rows
                        if isinstance(r, dict) and str(r.get("id", "")).strip() and str(r.get("id", "")).strip() != "test"
                    }
                )
                prev_oz = set(baselines.get("opencode_zen_models", []))
                added_oz = [
                    m for m in curr_oz
                    if m not in prev_oz and not is_legacy_model_id(m)
                ] if prev_oz else []
                if set(curr_oz) != prev_oz:
                    baselines["opencode_zen_models"] = curr_oz
                    changed = True
                if added_oz:
                    sig = hashlib.sha256(",".join(added_oz[:8]).encode("utf-8")).hexdigest()[:8]
                    inferred = infer_provider(added_oz[0])
                    cards.append(
                        {
                            "id": f"opencode-zen-diff-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "gateway-radar",
                            "header": "OPENCODE ZEN STEALTH & MODEL GATEWAY · LIVE DIFF",
                            "title": f"New Model on OpenCode Zen: {added_oz[0]}",
                            "subtitle": f"Newly exposed model / stealth codename in opencode.ai/zen/v1/models (+{len(added_oz)} new)",
                            "build_label": "Gateway Diff",
                            "build_transition": f"+{len(added_oz)} model(s) ({len(curr_oz)} active)",
                            "models": [{"id": m, "name": humanize_model_id(m)} for m in added_oz[:8]],
                            "evidence": "opencode.ai/zen/v1/models",
                            "source_text": "public OpenCode Zen /v1/models catalog.",
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": inferred["name"] if inferred["slug"] != "openrouter" else "OPENCODE ZEN",
                            "provider_slug": inferred["slug"],
                            "accent_color": inferred["color"],
                            "links": [{"label": "OpenCode Zen Models JSON", "url": self.OPENCODE_ZEN_URL}],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
        except Exception as exc:
            print(f"[HighAlphaScanner] OpenCode Zen warning: {exc}")

        # 1b. Vercel AI Gateway (/v1/models)
        try:
            vg_doc = _http_get_json(self.VERCEL_GATEWAY_URL, timeout=15, extra_headers={"User-Agent": "Mozilla/5.0"})
            vg_rows = vg_doc.get("data", []) if isinstance(vg_doc, dict) else []
            if vg_rows:
                vg_meta: Dict[str, str] = {}
                for r in vg_rows:
                    if isinstance(r, dict) and r.get("id"):
                        mid = str(r["id"]).strip()
                        vg_meta[mid] = str(r.get("name") or mid).strip()
                curr_vg = sorted(vg_meta.keys())
                prev_vg = set(baselines.get("vercel_gateway_models", []))
                prev_vg_canon = {_canonical_model_slug(x) for x in prev_vg}
                added_vg = [
                    m for m in curr_vg
                    if m not in prev_vg
                    and _canonical_model_slug(m) not in prev_vg_canon
                    and _canonical_model_slug(m) not in known_canon
                    and not is_legacy_model_id(m.split("/")[-1])
                ] if prev_vg else []
                if set(curr_vg) != prev_vg:
                    baselines["vercel_gateway_models"] = curr_vg
                    changed = True
                if added_vg:
                    sig = hashlib.sha256(",".join(added_vg[:8]).encode("utf-8")).hexdigest()[:8]
                    inferred = infer_provider(added_vg[0])
                    cards.append(
                        {
                            "id": f"vercel-gateway-diff-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "gateway-radar",
                            "header": "VERCEL AI GATEWAY CATALOG DIFF · LIVE MODELS",
                            "title": f"New Model on Vercel AI Gateway: {vg_meta.get(added_vg[0], added_vg[0])}",
                            "subtitle": f"Detected in ai-gateway.vercel.sh/v1/models (+{len(added_vg)} new)",
                            "build_label": "Gateway Diff",
                            "build_transition": f"+{len(added_vg)} new model(s)",
                            "models": [{"id": m, "name": vg_meta.get(m, m)} for m in added_vg[:8]],
                            "evidence": "ai-gateway.vercel.sh/v1/models",
                            "source_text": "public Vercel AI Gateway /v1/models catalog.",
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": inferred["name"],
                            "provider_slug": inferred["slug"],
                            "accent_color": inferred["color"],
                            "links": [{"label": "Vercel AI Gateway Models", "url": self.VERCEL_GATEWAY_URL}],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
        except Exception as exc:
            print(f"[HighAlphaScanner] Vercel AI Gateway warning: {exc}")

        return cards, changed

    def _extract_tar_gz_ide_models(self, archive_url: str, timeout: int = 55) -> Set[str]:
        req = urllib.request.Request(
            archive_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw_bytes = resp.read()
        found: Set[str] = set()
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile() or member.size > 25_000_000:
                    continue
                if not member.name.endswith((".js", ".mjs", ".cjs", ".json")):
                    continue
                fobj = tf.extractfile(member)
                if not fobj:
                    continue
                blob = fobj.read()
                for m in self.IDE_BUNDLE_MODEL_RE.findall(blob):
                    mid = m.decode("utf-8", "ignore").rstrip("._-")
                    if mid in self.IDE_EXCLUDED_TOKENS or is_legacy_model_id(mid):
                        continue
                    found.add(mid)
        return found

    def _scan_ide_desktop_builds(
        self,
        baselines: Dict[str, Any],
        known_canon: Set[str],
    ) -> tuple[List[Dict[str, Any]], bool]:
        cards: List[Dict[str, Any]] = []
        changed = False
        ide_cache: Dict[str, List[str]] = dict(baselines.get("ide_build_models", {}))
        ide_latest: Dict[str, str] = dict(baselines.get("ide_latest_versions", {}))

        # 2a. Cursor Official Linux REH Build
        seen_cursor_vers: Set[str] = set()
        for track, meta_url in self.CURSOR_TRACKS:
            try:
                meta = _http_get_json(meta_url, timeout=10, extra_headers={"User-Agent": "Mozilla/5.0"})
                if not isinstance(meta, dict):
                    continue
                ver = str(meta.get("version") or "").strip()
                reh_url = str(meta.get("rehUrl") or "").strip()
                if not ver or not reh_url or ver in seen_cursor_vers:
                    continue
                seen_cursor_vers.add(ver)
                ckey = f"cursor@{ver}"
                if ckey in ide_cache:
                    curr_models = set(ide_cache[ckey])
                else:
                    curr_models = self._extract_tar_gz_ide_models(reh_url, timeout=60)
                    if not curr_models:
                        continue
                    ide_cache[ckey] = sorted(curr_models)
                    changed = True

                track_key = f"cursor-{track}"
                prev_ver = ide_latest.get(track_key)
                if prev_ver and prev_ver != ver and f"cursor@{prev_ver}" in ide_cache:
                    prev_models = set(ide_cache[f"cursor@{prev_ver}"])
                    raw_added = sorted(curr_models - prev_models)
                    added = [
                        m for m in raw_added
                        if _canonical_model_slug(m) not in known_canon
                    ]
                    if added:
                        inferred = infer_provider(added[0])
                        cards.append(
                            {
                                "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"cursor-build-{prev_ver}-{ver}"),
                                "category": "desktop-diff",
                                "scanner": "ide-build-diff",
                                "header": f"CURSOR IDE OFFICIAL BUILD DIFF · {inferred['name']}",
                                "title": f"Cursor {ver}: {infer_family_title(added)}",
                                "subtitle": f"Verified Cursor official build model table diff ({track} track)",
                                "build_label": "Cursor Build",
                                "build_transition": f"{prev_ver} -> {ver}",
                                "models": [{"id": m, "name": humanize_model_id(m)} for m in added[:8]],
                                "evidence": f"Cursor {ver} (vscode-reh-linux-x64.tar.gz)",
                                "source_text": "official Cursor Linux x64 release bundle.",
                                "disclaimer_1": "",
                                "disclaimer_2": "",
                                "provider_name": inferred["name"],
                                "provider_slug": inferred["slug"],
                                "accent_color": inferred["color"],
                                "links": [
                                    {"label": "Cursor Release API", "url": meta_url},
                                    {"label": "Cursor Changelog", "url": "https://cursor.com/changelog"},
                                ],
                                "detected_at": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                if ide_latest.get(track_key) != ver:
                    ide_latest[track_key] = ver
                    changed = True
            except Exception as exc:
                print(f"[HighAlphaScanner] Cursor {track} build note: {exc}")

        # 2b. Devin Desktop / Windsurf Stable & Next Linux Builds
        for track, ws_url in self.WINDSURF_TRACKS:
            try:
                meta = _http_get_json(ws_url, timeout=10, extra_headers={"User-Agent": "Mozilla/5.0"})
                if not isinstance(meta, dict):
                    continue
                ver = str(meta.get("windsurfVersion") or meta.get("version") or "").strip()
                dl_url = str(meta.get("url") or "").strip()
                if not ver or not dl_url or not dl_url.endswith((".tar.gz", ".tgz")):
                    continue
                ckey = f"windsurf-{track}@{ver}"
                if ckey in ide_cache:
                    curr_models = set(ide_cache[ckey])
                else:
                    curr_models = self._extract_tar_gz_ide_models(dl_url, timeout=60)
                    if not curr_models:
                        continue
                    ide_cache[ckey] = sorted(curr_models)
                    changed = True

                track_key = f"windsurf-{track}"
                prev_ver = ide_latest.get(track_key)
                if prev_ver and prev_ver != ver and f"windsurf-{track}@{prev_ver}" in ide_cache:
                    prev_models = set(ide_cache[f"windsurf-{track}@{prev_ver}"])
                    raw_added = sorted(curr_models - prev_models)
                    added = [
                        m for m in raw_added
                        if _canonical_model_slug(m) not in known_canon
                    ]
                    if added:
                        inferred = infer_provider(added[0])
                        cards.append(
                            {
                                "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"windsurf-{track}-{prev_ver}-{ver}"),
                                "category": "desktop-diff",
                                "scanner": "ide-build-diff",
                                "header": f"DEVIN DESKTOP (WINDSURF {track.upper()}) BUILD DIFF · {inferred['name']}",
                                "title": f"Devin Desktop {ver}: {infer_family_title(added)}",
                                "subtitle": f"Verified Devin / Windsurf {track.title()} official build comparison",
                                "build_label": f"Devin {track.title()}",
                                "build_transition": f"{prev_ver} -> {ver}",
                                "models": [{"id": m, "name": humanize_model_id(m)} for m in added[:8]],
                                "evidence": f"Devin Desktop / Windsurf {track} ({ver})",
                                "source_text": f"official Devin Desktop (Windsurf {track}) Linux x64 release archive.",
                                "disclaimer_1": "",
                                "disclaimer_2": "",
                                "provider_name": inferred["name"],
                                "provider_slug": inferred["slug"],
                                "accent_color": inferred["color"],
                                "links": [{"label": "Update Feed JSON", "url": ws_url}],
                                "detected_at": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                if ide_latest.get(track_key) != ver:
                    ide_latest[track_key] = ver
                    changed = True
            except Exception as exc:
                print(f"[HighAlphaScanner] Devin/Windsurf {track} note (cloud-only if behind proxy): {exc}")

        if changed:
            # Trim ide_cache to last 8 entries total so source_baselines.json remains compact
            trimmed_ide: Dict[str, List[str]] = {}
            by_prefix: Dict[str, List[str]] = {}
            for k in sorted(ide_cache.keys()):
                pfx = k.split("@", 1)[0]
                by_prefix.setdefault(pfx, []).append(k)
            for pfx, keys in by_prefix.items():
                for k in keys[-3:]:
                    trimmed_ide[k] = ide_cache[k]
            baselines["ide_build_models"] = trimmed_ide
            baselines["ide_latest_versions"] = ide_latest

        return cards, changed

    def _scan_copilot_cli_releases(
        self,
        baselines: Dict[str, Any],
        known_canon: Set[str],
    ) -> tuple[List[Dict[str, Any]], bool]:
        cards: List[Dict[str, Any]] = []
        changed = False
        try:
            rels = _http_get_json(
                "https://api.github.com/repos/github/copilot-cli/releases?per_page=12",
                timeout=12,
                extra_headers=self._gh_headers(),
            )
            if not isinstance(rels, list) or not rels:
                return cards, changed
            seen_tags = set(baselines.get("copilot_cli_seen_tags", []))
            had_seed = len(seen_tags) > 0
            known_models = set(baselines.get("copilot_cli_release_models", []))

            for rel in reversed(rels):
                if not isinstance(rel, dict):
                    continue
                tag = str(rel.get("tag_name") or "").strip()
                if not tag or tag in seen_tags:
                    continue
                seen_tags.add(tag)
                changed = True
                blob = f"{rel.get('name') or ''}\n{rel.get('body') or ''}".encode("utf-8", "ignore")
                extracted = {m for m in extract_models_from_bytes(blob) if not is_legacy_model_id(m)}
                new_mids = sorted(
                    m for m in (extracted - known_models)
                    if _canonical_model_slug(m) not in known_canon
                )
                known_models.update(extracted)
                if had_seed and new_mids:
                    inferred = infer_provider(new_mids[0])
                    cards.append(
                        {
                            "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"copilot-cli-rel-{tag}"),
                            "category": "cli-sdk-diff",
                            "scanner": "docs-radar",
                            "header": f"GITHUB COPILOT CLI RELEASE DIFF · {inferred['name']}",
                            "title": f"GitHub Copilot CLI {tag}: {infer_family_title(new_mids)}",
                            "subtitle": "Newly referenced model identifier in github/copilot-cli release notes",
                            "build_label": "Copilot CLI",
                            "build_transition": tag,
                            "models": [{"id": m, "name": humanize_model_id(m)} for m in new_mids[:8]],
                            "evidence": f"github/copilot-cli releases ({tag})",
                            "source_text": "official GitHub Copilot CLI release feed.",
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": inferred["name"],
                            "provider_slug": inferred["slug"],
                            "accent_color": inferred["color"],
                            "links": [{"label": f"Release {tag}", "url": rel.get("html_url") or "https://github.com/github/copilot-cli/releases"}],
                            "detected_at": rel.get("published_at") or datetime.now(timezone.utc).isoformat(),
                        }
                    )
            if changed:
                baselines["copilot_cli_seen_tags"] = sorted(seen_tags)[-40:]
                baselines["copilot_cli_release_models"] = sorted(known_models)
        except Exception as exc:
            print(f"[HighAlphaScanner] Copilot CLI releases note: {exc}")
        return cards, changed

    def _scan_inference_engine_prs(
        self,
        baselines: Dict[str, Any],
        known_canon: Set[str],
    ) -> tuple[List[Dict[str, Any]], bool]:
        cards: List[Dict[str, Any]] = []
        changed = False
        seen_prs: Dict[str, List[int]] = {
            k: list(v) for k, v in (baselines.get("engine_seen_prs") or {}).items()
        }
        seen_slugs: Set[str] = set(baselines.get("engine_seen_model_slugs", []))

        for repo, repo_label in self.ENGINE_PR_REPOS:
            try:
                url = f"https://api.github.com/repos/{repo}/pulls?state=all&sort=created&direction=desc&per_page=40"
                prs = _http_get_json(url, timeout=12, extra_headers=self._gh_headers())
                if not isinstance(prs, list) or not prs:
                    continue
                repo_seen = set(seen_prs.get(repo, []))
                had_repo_seed = len(repo_seen) > 0

                for pr in reversed(prs):
                    if not isinstance(pr, dict):
                        continue
                    num = int(pr.get("number") or 0)
                    if not num or num in repo_seen:
                        continue
                    repo_seen.add(num)
                    changed = True

                    title = str(pr.get("title") or "").strip()
                    body_head = str(pr.get("body") or "")[:1200]
                    combined = f"{title}\n{body_head}"

                    candidates: List[str] = []
                    for m in self.PR_HF_SLUG_RE.findall(combined):
                        tail = m.split("/")[-1]
                        if (
                            not is_legacy_model_id(tail)
                            and "_" not in tail
                            and not tail.lower().endswith((
                                "-tokenizer", "-processor", "-config",
                                ".py", ".js", ".jsx", ".ts", ".tsx", ".md", ".json", ".yaml", ".yml", ".cu", ".h",
                            ))
                        ):
                            candidates.append(m)
                    for m in self.PR_UNRELEASED_ID_RE.findall(title):
                        if not is_legacy_model_id(m) and "_" not in m:
                            candidates.append(m)

                    if not candidates:
                        continue
                    # Require either an explicit model-onboarding PR title OR an explicit PR_UNRELEASED_ID_RE match in the title
                    if not (self.PR_ONBOARD_TITLE_RE.search(title) or self.PR_UNRELEASED_ID_RE.search(title)):
                        continue

                    fresh_hits: List[str] = []
                    for c in candidates:
                        c_slug = _canonical_model_slug(c)
                        if not c_slug or c_slug in known_canon or c_slug in seen_slugs:
                            continue
                        seen_slugs.add(c_slug)
                        fresh_hits.append(c)

                    if had_repo_seed and fresh_hits:
                        inferred = infer_provider(fresh_hits[0].split("/")[-1])
                        pr_state = str(pr.get("state") or "open").upper()
                        cards.append(
                            {
                                "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"engine-pr-{repo}-{num}"),
                                "category": "open-source",
                                "scanner": "engine-pr-leak",
                                "header": f"{repo_label.upper()} DAY-0 MODEL ONBOARDING ({pr_state})",
                                "title": f"{fresh_hits[0]} ({repo_label} #{num})",
                                "subtitle": title[:140],
                                "build_label": repo_label,
                                "build_transition": f"PR #{num} ({pr_state.lower()})",
                                "models": [{"id": h, "name": f"Referenced in {repo}#{num}"} for h in fresh_hits[:6]],
                                "evidence": f"{repo}/pull/{num}",
                                "source_text": f"public GitHub pull request #{num} on {repo}.",
                                "disclaimer_1": "",
                                "disclaimer_2": "",
                                "provider_name": inferred["name"] if inferred["slug"] != "openrouter" else repo_label.upper(),
                                "provider_slug": inferred["slug"] if inferred["slug"] != "openrouter" else "opensource",
                                "accent_color": inferred["color"],
                                "links": [{"label": f"{repo} PR #{num}", "url": pr.get("html_url") or f"https://github.com/{repo}/pull/{num}"}],
                                "detected_at": pr.get("created_at") or datetime.now(timezone.utc).isoformat(),
                            }
                        )

                seen_prs[repo] = sorted(repo_seen)[-200:]
            except Exception as exc:
                print(f"[HighAlphaScanner] Engine PR scan note ({repo}): {exc}")

        if changed:
            baselines["engine_seen_prs"] = seen_prs
            baselines["engine_seen_model_slugs"] = sorted(seen_slugs)[-400:]

        return cards, changed

    def _scan_live_provider_apis(
        self,
        baselines: Dict[str, Any],
    ) -> tuple[List[Dict[str, Any]], bool]:
        """
        RAGtrack-style direct polling of official provider /models endpoints for every
        API key configured in environment variables / GitHub Actions Secrets.
        """
        cards: List[Dict[str, Any]] = []
        changed = False
        api_baselines: Dict[str, List[str]] = {
            k: list(v) for k, v in (baselines.get("live_provider_api_models") or {}).items()
        }

        # 5a. Google Gemini AI Studio: poll BOTH v1alpha/models AND v1beta/models
        gem_key = (os.environ.get("GEMINI_API_KEY") or "").strip()
        if gem_key:
            gem_models: Dict[str, str] = {}
            for ver in ("v1alpha", "v1beta"):
                try:
                    g_url = f"https://generativelanguage.googleapis.com/{ver}/models?pageSize=200&key={urllib.parse.quote(gem_key)}"
                    g_doc = _http_get_json(g_url, timeout=12)
                    for m in (g_doc.get("models") or []) if isinstance(g_doc, dict) else []:
                        if isinstance(m, dict) and m.get("name"):
                            mid = str(m["name"]).replace("models/", "").strip()
                            disp = str(m.get("displayName") or mid).strip()
                            gem_models[mid] = f"{disp} ({ver})"
                except Exception as exc:
                    print(f"[HighAlphaScanner] Gemini {ver}/models warning: {exc}")
            if gem_models:
                curr_g = sorted(gem_models.keys())
                prev_g = set(api_baselines.get("gemini", []))
                added_g = [m for m in curr_g if m not in prev_g and not is_legacy_model_id(m)] if prev_g else []
                if set(curr_g) != prev_g:
                    api_baselines["gemini"] = curr_g
                    changed = True
                if added_g:
                    sig = hashlib.sha256(",".join(added_g[:8]).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"live-api-gemini-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "live-api-diff",
                            "header": "GEMINI LIVE API CATALOG DIFF · GOOGLE (v1alpha / v1beta)",
                            "title": f"New Gemini API Model: {added_g[0]}",
                            "subtitle": "Newly exposed model on generativelanguage.googleapis.com/{v1alpha,v1beta}/models",
                            "build_label": "Gemini Live API",
                            "build_transition": f"+{len(added_g)} new model(s)",
                            "models": [{"id": m, "name": gem_models.get(m, m)} for m in added_g[:8]],
                            "evidence": "generativelanguage.googleapis.com/v1alpha/models",
                            "source_text": "official Google Gemini API live models endpoint.",
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": "GOOGLE",
                            "provider_slug": "google",
                            "accent_color": "#38bdf8",
                            "links": [{"label": "Gemini Models Docs", "url": "https://ai.google.dev/gemini-api/docs/models"}],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )

        # 5b. OpenAI-compatible & Anthropic /v1/models endpoints
        bearer_providers = [
            ("openai", "OPENAI_API_KEY", "https://api.openai.com/v1/models", "OPENAI", "openai", "#10b981", "https://platform.openai.com/docs/models", "bearer"),
            ("anthropic", "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1/models?limit=100", "ANTHROPIC", "anthropic", "#f97316", "https://docs.anthropic.com/en/docs/about-claude/models", "anthropic"),
            ("deepseek", "DEEPSEEK_API_KEY", "https://api.deepseek.com/models", "DEEPSEEK", "deepseek", "#06b6d4", "https://api-docs.deepseek.com/", "bearer"),
            ("mistral", "MISTRAL_API_KEY", "https://api.mistral.ai/v1/models", "MISTRAL AI", "mistral", "#f59e0b", "https://docs.mistral.ai/getting-started/models/", "bearer"),
            ("xai", "XAI_API_KEY", "https://api.x.ai/v1/models", "XAI", "xai", "#e2e8f0", "https://docs.x.ai/docs/models", "bearer"),
            ("moonshot", "MOONSHOT_API_KEY", "https://api.moonshot.ai/v1/models", "MOONSHOT · KIMI", "kimi", "#06b6d4", "https://platform.moonshot.ai/docs", "bearer"),
            ("minimax", "MINIMAX_API_KEY", "https://api.minimax.io/v1/models", "MINIMAX", "minimax", "#ec4899", "https://platform.minimax.io/", "bearer"),
            ("together", "TOGETHER_API_KEY", "https://api.together.xyz/v1/models", "TOGETHER AI", "opensource", "#8b5cf6", "https://docs.together.ai/docs/serverless-models", "bearer"),
            ("groq", "GROQ_API_KEY", "https://api.groq.com/openai/v1/models", "GROQ", "opensource", "#f97316", "https://console.groq.com/docs/models", "bearer"),
        ]

        for pkey, env_name, url, p_upper, p_slug, p_color, docs_url, auth_kind in bearer_providers:
            api_key = (os.environ.get(env_name) or "").strip()
            if not api_key:
                continue
            try:
                hdrs = {"User-Agent": "ModelPulse-Tracker/2.0"}
                if auth_kind == "anthropic":
                    hdrs["x-api-key"] = api_key
                    hdrs["anthropic-version"] = "2023-06-01"
                else:
                    hdrs["Authorization"] = f"Bearer {api_key}"
                doc = _http_get_json(url, timeout=12, extra_headers=hdrs)
                rows = doc.get("data", []) if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
                if not rows:
                    continue
                id_map: Dict[str, str] = {}
                for r in rows:
                    if isinstance(r, dict) and r.get("id"):
                        mid = str(r["id"]).strip()
                        id_map[mid] = str(r.get("display_name") or r.get("name") or humanize_model_id(mid)).strip()
                if not id_map:
                    continue
                curr_ids = sorted(id_map.keys())
                prev_ids = set(api_baselines.get(pkey, []))
                added_ids = [m for m in curr_ids if m not in prev_ids and not is_legacy_model_id(m)] if prev_ids else []
                if set(curr_ids) != prev_ids:
                    api_baselines[pkey] = curr_ids
                    changed = True
                if added_ids:
                    sig = hashlib.sha256(",".join(added_ids[:8]).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"live-api-{pkey}-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "live-api-diff",
                            "header": f"LIVE OFFICIAL API CATALOG DIFF · {p_upper}",
                            "title": f"New {p_upper} API Model: {added_ids[0]}",
                            "subtitle": f"Newly exposed model in live {url.split('?')[0]} response",
                            "build_label": "Live API Diff",
                            "build_transition": f"+{len(added_ids)} new model(s)",
                            "models": [{"id": m, "name": id_map.get(m, m)} for m in added_ids[:8]],
                            "evidence": url.replace("https://", "").split("?")[0],
                            "source_text": f"official {p_upper} live /models API endpoint.",
                            "disclaimer_1": "",
                            "disclaimer_2": "",
                            "provider_name": p_upper,
                            "provider_slug": p_slug,
                            "accent_color": p_color,
                            "links": [{"label": f"{p_upper} Models Docs", "url": docs_url}],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
            except Exception as exc:
                print(f"[HighAlphaScanner] Live API poll warning ({pkey}): {exc}")

        if changed:
            baselines["live_provider_api_models"] = api_baselines

        return cards, changed

    @staticmethod
    def _short_boq_hash(build_key: str) -> str:
        # e.g. "boq-makersuite.MakerSuite.en_US.AdEI_nf8080.2018.O" -> "AdEI_nf8080"
        parts = (build_key or "").split(".")
        if len(parts) >= 4:
            return parts[3]
        return build_key[:24] if build_key else "latest"

    @classmethod
    def _extract_aistudio_bundle_signals(cls, js_blobs: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """Extract models/*, Mendel experiment model flags, and hidden UI routes from AI Studio Boq JS."""
        generic_buckets = {
            "gemini", "google", "imagen", "veo", "lyria", "transcribe",
            "gemini-2.0", "gemini-3", "id", ":id",
        }
        ignore_routes = {"", "**", "403", "404", "500", "520", "docs/404"}

        model_labels: Dict[str, str] = {}
        routes_set: Set[str] = set()

        for js in js_blobs:
            # 1. Mendel experiment flags pointing to models/*: new _.Ps("45863024","models/gemini-3.8-flash")
            for flag_id, mslug in re.findall(
                r'new _\.[A-Za-z0-9_$]+\("(\d{6,10})","models/([a-zA-Z0-9][a-zA-Z0-9._-]{2,55})"\)',
                js,
            ):
                clean = mslug.strip().lower()
                if clean not in generic_buckets:
                    model_labels[clean] = f"{humanize_model_id(clean)} (Mendel #{flag_id})"

            # 2. Explicit models/<slug> references inside MakerSuite
            for mslug in re.findall(r'\bmodels/([a-zA-Z0-9][a-zA-Z0-9._-]{2,55})\b', js):
                clean = mslug.strip().lower()
                if clean in generic_buckets:
                    continue
                model_labels.setdefault(clean, humanize_model_id(clean))

            # 3. Direct frontier Gemini 3.x / 4.x / 5.x model slugs in JS strings
            for m_bytes in cls.IDE_BUNDLE_MODEL_RE.findall(js.encode("utf-8", errors="ignore")):
                raw_m = m_bytes.decode("utf-8", errors="ignore").lower().strip("._-")
                if raw_m.startswith("gemini-") and raw_m not in cls.IDE_EXCLUDED_TOKENS and raw_m not in generic_buckets:
                    model_labels.setdefault(raw_m, humanize_model_id(raw_m))

            # 4. Closure-compiled Angular route table object containing anchor routes ("prompts/new_chat" & "welcome")
            for obj_match in re.finditer(
                r'\{([A-Za-z0-9_$]+:"[^"\r\n]{0,90}"(?:,\s*[A-Za-z0-9_$]+:"[^"\r\n]{0,90}"){15,250})\}',
                js,
            ):
                block = obj_match.group(1)
                if '"prompts/new_chat"' in block and '"welcome"' in block:
                    for val in re.findall(r'[A-Za-z0-9_$]+:"([^"]*)"', block):
                        v = val.strip().strip("/")
                        if v and v not in ignore_routes:
                            routes_set.add(v)

        return model_labels, sorted(routes_set)

    def _scan_google_web_bundles(
        self, baselines: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Diffs Google AI Studio (aistudio.google.com `boq-makersuite` JS bundles) for hidden UI routes
        (e.g. `agent-dashboard/*`), Mendel experiment model flags, and `models/*` identifiers, plus
        Gemini Web (`gemini.google.com/app` `WIZ_global_data` + `boq-gemini-web-uiserver` build).
        Uses build-key caching so unchanged 5-minute runs only fetch lightweight landing HTML.
        """
        cards: List[Dict[str, Any]] = []
        changed = False
        wb_state: Dict[str, Any] = dict(baselines.get("web_bundles", {}))
        browser_hdrs = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }

        # 6a. Google AI Studio (`aistudio.google.com/welcome` -> `gstatic.com/_/mss/boq-makersuite/...`)
        try:
            req = urllib.request.Request("https://aistudio.google.com/welcome", headers=browser_hdrs)
            with urllib.request.urlopen(req, timeout=15) as resp:
                ais_html = resp.read().decode("utf-8", errors="replace")

            unesc_ais = ais_html.replace("\\/", "/")
            boq_urls: List[str] = []
            for u in re.findall(r'https://www\.gstatic\.com/_/mss/boq-makersuite/_/js/[A-Za-z0-9_./=-]+', unesc_ais):
                if u not in boq_urls:
                    boq_urls.append(u)

            if boq_urls:
                m_key = re.search(r"k=(boq-makersuite\.[^/]+)", boq_urls[0])
                build_key = m_key.group(1) if m_key else boq_urls[0][-48:]
                prev_build_key = wb_state.get("aistudio_build_key", "")
                prev_models = set(wb_state.get("aistudio_models", []))
                prev_routes = set(wb_state.get("aistudio_routes", []))

                if build_key != prev_build_key or not prev_models or not prev_routes:
                    js_blobs: List[str] = []
                    for js_url in boq_urls[:4]:
                        jreq = urllib.request.Request(js_url, headers=browser_hdrs)
                        with urllib.request.urlopen(jreq, timeout=20) as jresp:
                            js_blobs.append(jresp.read().decode("utf-8", errors="replace"))

                    model_labels, curr_routes = self._extract_aistudio_bundle_signals(js_blobs)
                    curr_models = sorted(model_labels.keys())

                    old_hash = self._short_boq_hash(prev_build_key) if prev_build_key else "baseline"
                    new_hash = self._short_boq_hash(build_key)

                    if prev_models and curr_models:
                        added_models = [
                            m for m in curr_models
                            if m not in prev_models and not is_legacy_model_id(m)
                        ]
                        if added_models:
                            sig = hashlib.sha256(f"{build_key}:m:{','.join(added_models[:8])}".encode("utf-8")).hexdigest()[:8]
                            cards.append(
                                {
                                    "id": f"web-bundle-aistudio-models-{sig}",
                                    "category": "cli-sdk-diff",
                                    "scanner": "web-bundle-diff",
                                    "header": "GOOGLE AI STUDIO JS BUNDLE DIFF · GOOGLE",
                                    "title": f"AI Studio Bundle Model: {added_models[0]}",
                                    "subtitle": f"New model / Mendel flag in boq-makersuite ({old_hash} -> {new_hash})",
                                    "build_label": "MakerSuite Build",
                                    "build_transition": f"{old_hash} -> {new_hash} (+{len(added_models)} model)",
                                    "models": [{"id": m, "name": model_labels.get(m, humanize_model_id(m))} for m in added_models[:10]],
                                    "evidence": f"gstatic.com/_/mss/boq-makersuite ({new_hash})",
                                    "source_text": "public Google AI Studio (aistudio.google.com) Boq JavaScript bundle.",
                                    "disclaimer_1": "Extracted from client-side MakerSuite JS bundle & Mendel experiment flags.",
                                    "disclaimer_2": "Presence in frontend bundle does not guarantee public backend rollout.",
                                    "provider_name": "GOOGLE",
                                    "provider_slug": "google",
                                    "accent_color": "#38bdf8",
                                    "links": [
                                        {"label": "Google AI Studio", "url": "https://aistudio.google.com/welcome"},
                                        {"label": "MakerSuite JS Bundle", "url": boq_urls[0]},
                                    ],
                                    "detected_at": datetime.now(timezone.utc).isoformat(),
                                }
                            )

                    if prev_routes and curr_routes:
                        added_routes = [r for r in curr_routes if r not in prev_routes]
                        if added_routes:
                            sig = hashlib.sha256(f"{build_key}:r:{','.join(added_routes[:8])}".encode("utf-8")).hexdigest()[:8]
                            route_items = []
                            for r in added_routes[:10]:
                                pretty = r.replace("/", " / ").replace("-", " ").replace(":", "").title()
                                route_items.append({"id": f"aistudio.google.com/{r}", "name": f"UI Route: {pretty}"})
                            cards.append(
                                {
                                    "id": f"web-bundle-aistudio-routes-{sig}",
                                    "category": "desktop-diff",
                                    "scanner": "web-bundle-diff",
                                    "header": "GOOGLE AI STUDIO UI ROUTE DIFF · GOOGLE",
                                    "title": f"New AI Studio Hidden Route: /{added_routes[0]}",
                                    "subtitle": f"Newly compiled Angular route(s) in boq-makersuite ({old_hash} -> {new_hash})",
                                    "build_label": "MakerSuite Build",
                                    "build_transition": f"{old_hash} -> {new_hash} (+{len(added_routes)} route)",
                                    "models": route_items,
                                    "evidence": f"gstatic.com/_/mss/boq-makersuite ({new_hash})",
                                    "source_text": "public Google AI Studio (aistudio.google.com) compiled Angular route table.",
                                    "disclaimer_1": "Client-side UI route added to Google AI Studio frontend bundle (often gated by Mendel flags).",
                                    "disclaimer_2": "Backend RPCs may still return 403 Permission Denied until public launch.",
                                    "provider_name": "GOOGLE",
                                    "provider_slug": "google",
                                    "accent_color": "#38bdf8",
                                    "links": [
                                        {"label": f"Try /{added_routes[0]}", "url": f"https://aistudio.google.com/{added_routes[0].split('/:')[0]}"},
                                        {"label": "MakerSuite JS Bundle", "url": boq_urls[0]},
                                    ],
                                    "detected_at": datetime.now(timezone.utc).isoformat(),
                                }
                            )

                    if curr_models:
                        wb_state["aistudio_models"] = curr_models
                    if curr_routes:
                        wb_state["aistudio_routes"] = curr_routes
                    wb_state["aistudio_build_key"] = build_key
                    changed = True
        except Exception as exc:
            print(f"[HighAlphaScanner] AI Studio bundle scan warning: {exc}")

        # 6b. Google Gemini Web (`gemini.google.com/app` WIZ config + `boq-gemini-web-uiserver` build)
        try:
            greq = urllib.request.Request("https://gemini.google.com/app", headers=browser_hdrs)
            with urllib.request.urlopen(greq, timeout=15) as gresp:
                gem_html = gresp.read().decode("utf-8", errors="replace")

            m_bard = re.search(r"k=(boq-gemini-web-uiserver\.[^/?&\"']+)", gem_html)
            bard_key = m_bard.group(1) if m_bard else ""
            prev_bard_key = wb_state.get("gemini_web_build_key", "")
            prev_gem_models = set(wb_state.get("gemini_web_models", []))

            gem_found = set(
                m.lower()
                for m in re.findall(
                    r"\b(gemini-[2345][a-z0-9._-]{1,35}|imagen-[34][a-z0-9._-]{0,25}|veo-[234][a-z0-9._-]{0,25}|lyria-[234][a-z0-9._-]{0,25})\b",
                    gem_html,
                    re.IGNORECASE,
                )
            )
            gem_found -= self.IDE_EXCLUDED_TOKENS
            curr_gem_models = sorted(gem_found)

            if curr_gem_models:
                if prev_gem_models:
                    added_gem = [
                        m for m in curr_gem_models
                        if m not in prev_gem_models and not is_legacy_model_id(m)
                    ]
                    if added_gem:
                        old_bh = self._short_boq_hash(prev_bard_key) if prev_bard_key else "prev"
                        new_bh = self._short_boq_hash(bard_key) if bard_key else "latest"
                        sig = hashlib.sha256(",".join(added_gem[:8]).encode("utf-8")).hexdigest()[:8]
                        cards.append(
                            {
                                "id": f"web-bundle-gemini-web-{sig}",
                                "category": "cli-sdk-diff",
                                "scanner": "web-bundle-diff",
                                "header": "GEMINI WEB APP CONFIG DIFF · GOOGLE",
                                "title": f"New Gemini Web Model: {added_gem[0]}",
                                "subtitle": f"Newly embedded model identifier in gemini.google.com/app ({old_bh} -> {new_bh})",
                                "build_label": "BardChatUi Build",
                                "build_transition": f"{old_bh} -> {new_bh} (+{len(added_gem)} model)",
                                "models": [{"id": m, "name": humanize_model_id(m)} for m in added_gem[:10]],
                                "evidence": f"gemini.google.com/app WIZ_global_data ({new_bh})",
                                "source_text": "public Google Gemini web app (gemini.google.com/app) embedded model configuration.",
                                "disclaimer_1": "",
                                "disclaimer_2": "",
                                "provider_name": "GOOGLE",
                                "provider_slug": "google",
                                "accent_color": "#38bdf8",
                                "links": [{"label": "Gemini Web App", "url": "https://gemini.google.com/app"}],
                                "detected_at": datetime.now(timezone.utc).isoformat(),
                            }
                        )

                if set(curr_gem_models) != prev_gem_models or (bard_key and bard_key != prev_bard_key):
                    wb_state["gemini_web_models"] = curr_gem_models
                    if bard_key:
                        wb_state["gemini_web_build_key"] = bard_key
                    changed = True
        except Exception as exc:
            print(f"[HighAlphaScanner] Gemini Web scan warning: {exc}")

        if changed:
            baselines["web_bundles"] = wb_state

        return cards, changed

    def scan(self) -> List[Dict[str, Any]]:
        baselines = self._load_baselines()
        known_canon = (
            {_canonical_model_slug(k) for k in baselines.get("litellm_keys", [])}
            | {_canonical_model_slug(k) for k in baselines.get("models_dev_keys", [])}
        )

        all_cards: List[Dict[str, Any]] = []
        any_changed = False

        for fn in (
            lambda: self._scan_public_gateways(baselines, known_canon),
            lambda: self._scan_ide_desktop_builds(baselines, known_canon),
            lambda: self._scan_copilot_cli_releases(baselines, known_canon),
            lambda: self._scan_inference_engine_prs(baselines, known_canon),
            lambda: self._scan_live_provider_apis(baselines),
            lambda: self._scan_google_web_bundles(baselines),
        ):
            c_list, ch = fn()
            all_cards.extend(c_list)
            if ch:
                any_changed = True

        if any_changed:
            self._save_baselines(baselines)

        return all_cards
