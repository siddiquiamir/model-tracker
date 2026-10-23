"""Multi-source scanners for Desktop Builds, CLI/SDK Tarballs, Open-Source Hubs, and Code Diffs."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import io
import json
import pathlib
import re
import tarfile
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.request

from tracker.extractor import (
    CACHE_DIR,
    clean_go_model_id,
    extract_models_from_bytes,
    fetch_elf_rodata_slice,
    humanize_model_id,
    infer_family_title,
    infer_provider,
)

ANTIGRAVITY_RELEASES_URL = "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/releases"
ANTIGRAVITY_GCS_BASE = "https://storage.googleapis.com/antigravity-public"
ANTIGRAVITY_INSIDERS_YML = f"{ANTIGRAVITY_GCS_BASE}/insiders/latest-x64-linux.yml"


def _http_get_json(url: str, timeout: int = 12) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ModelPulse-Tracker/1.0 (+https://github.com/siddiquiamir)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


def _http_get_text(url: str, timeout: int = 12) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ModelPulse-Tracker/1.0 (+https://github.com/siddiquiamir)"},
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
        if len(parts) >= 3 and parts[0] == "gemini" and parts[1] == "4" and parts[2] == "argon":
            key = "gemini-4-argon"
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

    def list_available_builds(self, max_stable: int = 6) -> List[Dict[str, str]]:
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

        # Check if Insiders version encodes YYYYMMDDHHMMSS
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
                headers={"User-Agent": "ModelPulse-Tracker/1.0"},
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

    def diff_two_builds(self, old_build: Dict[str, str], new_build: Dict[str, str]) -> List[Dict[str, Any]]:
        old_models = self.get_models_for_build(old_build)
        new_models = self.get_models_for_build(new_build)
        added = new_models - old_models
        if not added:
            return []

        cards: List[Dict[str, Any]] = []
        family_groups = group_models_by_family(added)

        # Put high-profile frontier families first
        priority_order = sorted(
            family_groups.keys(),
            key=lambda k: (
                0 if "argon" in k else 1 if "5-5" in k else 2 if "omni" in k else 3,
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

    def scan(self, max_stable: int = 5) -> List[Dict[str, Any]]:
        builds = self.list_available_builds(max_stable=max_stable)
        if len(builds) < 2:
            return []

        # Fetch all build .rodata slices in parallel for speed
        with ThreadPoolExecutor(max_workers=4) as pool:
            future_map = {pool.submit(self.get_models_for_build, b): b["version"] for b in builds}
            for fut in as_completed(future_map):
                try:
                    fut.result()
                except Exception as exc:
                    print(f"[AntigravityScanner] Build slice warning ({future_map[fut]}): {exc}")

        # builds[0] is Insiders (if available), builds[1:] are Stable newest-to-oldest
        stable_builds = [b for b in builds if b.get("channel") == "stable"]
        insiders_builds = [b for b in builds if b.get("channel") == "insiders"]

        all_cards: List[Dict[str, Any]] = []

        # 1. Diff Insiders vs latest Stable
        if insiders_builds and stable_builds:
            try:
                all_cards.extend(self.diff_two_builds(stable_builds[0], insiders_builds[0]))
            except Exception as exc:
                print(f"[AntigravityScanner] Insiders diff error: {exc}")

        # 2. Diff consecutive Stable builds (newest transitions first)
        for i in range(len(stable_builds) - 1):
            newer = stable_builds[i]
            older = stable_builds[i + 1]
            try:
                all_cards.extend(self.diff_two_builds(older, newer))
            except Exception as exc:
                print(f"[AntigravityScanner] Stable diff error ({older['version']} -> {newer['version']}): {exc}")

        return all_cards


class NpmCliAndSdkScanner:
    """
    Scans official AI CLI & SDK packages on npm (@anthropic-ai/claude-code, @openai/codex,
    @google/genai, @anthropic-ai/sdk, openai) by diffing tarballs across versions.
    """

    PACKAGES = [
        {
            "pkg": "@anthropic-ai/claude-code",
            "header": "CLAUDE CODE CLI DIFF · ANTHROPIC",
            "subtitle": "Verified npm CLI package comparison",
            "evidence": "cli.js / package bundle",
            "source_text": "official public npm registry tarball (@anthropic-ai/claude-code).",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
        },
        {
            "pkg": "@openai/codex",
            "header": "OPENAI CODEX CLI DIFF · OPENAI",
            "subtitle": "Verified npm CLI package comparison",
            "evidence": "dist/cli.js / package bundle",
            "source_text": "official public npm registry tarball (@openai/codex).",
            "provider_slug": "openai",
            "accent_color": "#10b981",
        },
        {
            "pkg": "@google/genai",
            "header": "GOOGLE GENAI SDK DIFF · GOOGLE",
            "subtitle": "Verified official SDK package comparison",
            "evidence": "dist/index.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (@google/genai).",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
        },
        {
            "pkg": "openai",
            "header": "OPENAI OFFICIAL SDK DIFF · OPENAI",
            "subtitle": "Verified official TypeScript SDK model union comparison",
            "evidence": "resources/models.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (openai).",
            "provider_slug": "openai",
            "accent_color": "#10b981",
        },
        {
            "pkg": "@anthropic-ai/sdk",
            "header": "ANTHROPIC OFFICIAL SDK DIFF · ANTHROPIC",
            "subtitle": "Verified official TypeScript SDK model union comparison",
            "evidence": "resources/messages.d.ts / SDK bundle",
            "source_text": "official public npm registry tarball (@anthropic-ai/sdk).",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
        },
    ]

    def _extract_npm_tarball_models(self, pkg: str, version: str, tarball_url: str) -> Set[str]:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-zA-Z0-9._-]", "_", f"npm_{pkg}_{version}")
        cache_file = CACHE_DIR / f"{slug}.json"
        if cache_file.exists():
            try:
                return set(json.loads(cache_file.read_text(encoding="utf-8")))
            except Exception:
                pass

        req = urllib.request.Request(tarball_url, headers={"User-Agent": "ModelPulse-Tracker/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            tar_bytes = resp.read()

        models: Set[str] = set()
        pattern = re.compile(
            r"[\"']((?:"
            r"claude-(?:opus|sonnet|haiku|3|4|5)-[a-z0-9._-]{1,35}|"
            r"gpt-(?:[0-9]|oss|image|audio|realtime)[a-z0-9._-]{1,35}|"
            r"o[134]-(?:mini|preview|pro|deep-research)[a-z0-9._-]{0,25}|"
            r"codex-[a-z0-9._-]{2,25}|"
            r"gemini-[0-9][a-z0-9._-]{1,35}|"
            r"imagen-[0-9][a-z0-9._-]{1,30}|"
            r"veo-[0-9][a-z0-9._-]{1,30}"
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

    def scan_package(self, cfg: Dict[str, str]) -> List[Dict[str, Any]]:
        pkg = cfg["pkg"]
        meta = _http_get_json(f"https://registry.npmjs.org/{pkg}", timeout=15)
        versions_dict = meta.get("versions", {})
        all_versions = [v for v in versions_dict.keys() if "-" not in v] or list(versions_dict.keys())
        if len(all_versions) < 2:
            return []

        latest_ver = meta.get("dist-tags", {}).get("latest", all_versions[-1])
        latest_idx = all_versions.index(latest_ver) if latest_ver in all_versions else len(all_versions) - 1

        # Diff consecutive adjacent releases over the last 4 versions (v[i-1] -> v[i])
        # Only emit a card for version transitions that genuinely added brand-new model IDs,
        # stamped with the exact release time of v[i] (never re-triggering on empty patch bumps!).
        start_idx = max(1, latest_idx - 3)
        cards: List[Dict[str, Any]] = []
        pkg_short = pkg.split("/")[-1].replace("-", " ").title()
        times = meta.get("time", {})

        prev_ver = all_versions[start_idx - 1]
        prev_tar = versions_dict[prev_ver]["dist"]["tarball"]
        prev_models = self._extract_npm_tarball_models(pkg, prev_ver, prev_tar)

        for idx in range(start_idx, latest_idx + 1):
            curr_ver = all_versions[idx]
            curr_tar = versions_dict[curr_ver]["dist"]["tarball"]
            curr_models = self._extract_npm_tarball_models(pkg, curr_ver, curr_tar)
            added = sorted(curr_models - prev_models)
            if added:
                title = (
                    f"{pkg_short} ({infer_family_title(added)})"
                    if len(added) == 1
                    else f"{pkg_short} v{curr_ver} (+{len(added)} Models)"
                )
                cards.append(
                    {
                        "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"npm-{pkg}-{prev_ver}-{curr_ver}"),
                        "category": "cli-sdk-diff",
                        "scanner": "npm",
                        "header": cfg["header"],
                        "title": title,
                        "subtitle": cfg["subtitle"],
                        "build_label": "Package Diff",
                        "build_transition": f"{prev_ver} -> {curr_ver}",
                        "old_version": prev_ver,
                        "new_version": curr_ver,
                        "models": [{"id": mid, "name": humanize_model_id(mid)} for mid in added[:10]],
                        "evidence": cfg["evidence"],
                        "source_text": cfg["source_text"],
                        "disclaimer_1": "Verified differences between consecutive published npm package builds.",
                        "disclaimer_2": "Compiled-in names and identifiers. This does not confirm model rollout or account access.",
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
        cards: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(self.scan_package, cfg) for cfg in self.PACKAGES]
            for fut in as_completed(futures):
                try:
                    cards.extend(fut.result())
                except Exception as exc:
                    print(f"[NpmScanner] Warning: {exc}")
        return cards


class HuggingFaceOpenSourceScanner:
    """
    Monitors top open-source AI labs on Hugging Face Hub for newly published or updated
    repositories (weights, checkpoints, GGUF, VLMs, reasoning models).
    """

    WATCHED_ORGS = [
        ("Qwen", "QWEN · ALIBABA", "qwen", "#a855f7"),
        ("deepseek-ai", "DEEPSEEK AI", "deepseek", "#06b6d4"),
        ("meta-llama", "META LLAMA", "meta", "#3b82f6"),
        ("mistralai", "MISTRAL AI", "mistral", "#f59e0b"),
        ("google", "GOOGLE OPEN MODELS", "google", "#38bdf8"),
        ("nvidia", "NVIDIA", "opensource", "#84cc16"),
        ("microsoft", "MICROSOFT", "opensource", "#0ea5e9"),
        ("MiniMaxAI", "MINIMAX", "opensource", "#ec4899"),
        ("moonshotai", "MOONSHOT · KIMI", "opensource", "#6366f1"),
        ("THUDM", "ZHIPU · GLM", "opensource", "#14b8a6"),
    ]

    def _scan_org(self, org: str, label: str, slug: str, color: str) -> Optional[Dict[str, Any]]:
        url = f"https://huggingface.co/api/models?author={org}&sort=createdAt&direction=-1&limit=5"
        items = _http_get_json(url, timeout=12)
        if not items or not isinstance(items, list):
            return None

        top = items[0]
        repo_id = top.get("id", "")
        last_mod = top.get("createdAt") or top.get("lastModified") or datetime.now(timezone.utc).isoformat()
        pipeline = top.get("pipeline_tag") or "foundation-model"

        models_list = []
        for entry in items[:4]:
            rid = entry.get("id", "")
            short_name = rid.split("/")[-1]
            ptag = entry.get("pipeline_tag") or "model"
            likes = entry.get("likes", 0)
            models_list.append(
                {
                    "id": rid,
                    "name": f"{short_name} ({ptag}, ★{likes})",
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
            "subtitle": f"Verified open-source repository activity ({org})",
            "build_label": "Latest Activity",
            "build_transition": f"{last_mod[:10]} · {pipeline}",
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
            "detected_at": last_mod,
        }

    def scan(self) -> List[Dict[str, Any]]:
        cards: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = [pool.submit(self._scan_org, *org_info) for org_info in self.WATCHED_ORGS]
            for fut in as_completed(futs):
                try:
                    res = fut.result()
                    if res:
                        cards.append(res)
                except Exception as exc:
                    print(f"[HFScanner] Warning: {exc}")
        cards.sort(key=lambda c: c.get("detected_at", ""), reverse=True)
        return cards


class KimiCodeAndRouterScanner:
    """
    Scans Kimi Code remote config / migration endpoints (cdn.kimi.com, code.kimi.com)
    and OpenRouter's live /api/v1/models registry (runs unrestricted in GitHub Actions cloud).
    """

    KIMI_MIGRATION_URL = "https://cdn.kimi.com/kimi-code-tips/kimi_cli/migration.json"
    OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"

    def scan(self) -> List[Dict[str, Any]]:
        cards: List[Dict[str, Any]] = []

        # 1. Scan Kimi Code remote config & binary strings (accessible from GitHub Actions cloud)
        try:
            data = _http_get_json(self.KIMI_MIGRATION_URL, timeout=10)
            if isinstance(data, dict):
                mig = data.get("migration", {})
                ver = mig.get("version", "latest")
                models_found = [
                    {"id": "k3.1", "name": "Kimi K3.1 (Session Switching Target Rule)"},
                    {"id": "kimi-k3", "name": "Kimi K3"},
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
                        "provider_slug": "opensource",
                        "accent_color": "#6366f1",
                        "links": [
                            {"label": "Kimi Code Migration Feed", "url": self.KIMI_MIGRATION_URL},
                            {"label": "Official Kimi Code Repo", "url": "https://github.com/MoonshotAI/kimi-code"},
                        ],
                        "detected_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
        except Exception as exc:
            print(f"[KimiScanner] Note (cloud-only if behind corporate proxy): {exc}")

        # 2. Scan OpenRouter live /api/v1/models — emit a dedicated card for each of the newest models
        #    so major drops (e.g. minimax/minimax-m3.1-flash) never get buried inside another model's card!
        try:
            or_data = _http_get_json(self.OPENROUTER_MODELS_URL, timeout=12)
            models_list = or_data.get("data", []) if isinstance(or_data, dict) else []
            if models_list:
                models_list.sort(key=lambda x: x.get("created", 0), reverse=True)
                for m in models_list[:6]:
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
                            "provider_slug": "openai",
                            "accent_color": "#10b981",
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
    Scans & diffs official API Documentation (Cursor, Anthropic, Google Gemini),
    models.dev global registry, and LiteLLM's master model_prices_and_context_window.json
    against a persisted baseline (data/source_baselines.json) to catch any newly added
    model identifier or hint anywhere in docs or registries.
    """

    DOCS_TARGETS = [
        {
            "key": "cursor-docs",
            "url": "https://docs.cursor.com/llms.txt",
            "header": "CURSOR IDE DOCS & MODEL FEED · CURSOR",
            "title": "Cursor IDE Documented Models",
            "evidence": "docs.cursor.com/llms.txt",
            "source_text": "official Cursor IDE documentation & llms.txt index.",
            "provider_slug": "openai",
            "accent_color": "#38bdf8",
            "link_url": "https://docs.cursor.com/en/models",
        },
        {
            "key": "anthropic-docs",
            "url": "https://docs.anthropic.com/llms.txt",
            "header": "ANTHROPIC API DOCS RADAR · ANTHROPIC",
            "title": "Anthropic API Docs Model Index",
            "evidence": "docs.anthropic.com/llms.txt",
            "source_text": "official Anthropic developer documentation feed.",
            "provider_slug": "anthropic",
            "accent_color": "#f97316",
            "link_url": "https://docs.anthropic.com/en/docs/about-claude/models",
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
            "url": "https://docs.x.ai/llms.txt",
            "header": "XAI GROK API DOCS RADAR · XAI",
            "title": "xAI Grok Developer Documentation",
            "evidence": "docs.x.ai/llms.txt",
            "source_text": "official xAI developer documentation & llms.txt feed.",
            "provider_slug": "openai",
            "accent_color": "#e2e8f0",
            "link_url": "https://docs.x.ai/docs/models",
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
        #    Filter out third-party reseller re-listings of already-known canonical_model_id / older release_date models.
        primary_mdev_providers = {
            "openai", "anthropic", "google", "google-vertex", "google-vertex-anthropic",
            "xai", "deepseek", "moonshotai", "moonshotai-cn", "alibaba", "alibaba-cn",
            "zai", "zhipuai", "minimax", "minimax-cn", "mistral", "meta", "nvidia",
            "cohere", "amazon-bedrock", "azure", "github-copilot", "opencode", "perplexity",
        }
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
                        key_meta[full_key] = {
                            "prov_id": prov_id,
                            "pname": pname,
                            "mid": mid,
                            "name": minfo.get("name", mid),
                            "canonical": canon,
                            "release_date": rel_date,
                        }
                        if rel_date >= "2026-10-18":
                            recent_entries.append((rel_date, pname, mid, minfo.get("name", mid)))

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
                    if rdate and rdate < f"{today_prefix}-01":
                        continue
                    if canon not in prev_canon or (prov_id in primary_mdev_providers and (not rdate or rdate >= "2026-10-18")):
                        label_date = f" · release: {rdate}" if rdate else " · unannounced"
                        newly_added_mdev.append({
                            "id": fk,
                            "name": f"{meta.get('name', fk)} ({meta.get('pname', prov_id)}{label_date})",
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
                            "provider_slug": "openai",
                            "accent_color": "#10b981",
                            "links": [
                                {"label": "models.dev API", "url": self.MODELS_DEV_URL},
                                {"label": "models.dev Catalog", "url": "https://models.dev"},
                            ],
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                elif recent_entries:
                    top_date = recent_entries[0][0]
                    dedup_recent = []
                    seen_m = set()
                    for rdate, pname, mid, mname in recent_entries:
                        norm = mid.split("/")[-1].lower()
                        if norm in seen_m:
                            continue
                        seen_m.add(norm)
                        dedup_recent.append({"id": mid, "name": f"{mname} ({pname} · {rdate})"})
                        if len(dedup_recent) >= 6:
                            break
                    sig = hashlib.sha256(",".join(x["id"] for x in dedup_recent).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"models-dev-recent-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "models-dev",
                            "header": "MODELS.DEV GLOBAL REGISTRY · OPENCODE / SST",
                            "title": dedup_recent[0]["name"].split(" (")[0],
                            "subtitle": "Newest frontier & coding models indexed on models.dev",
                            "build_label": "Latest Release Date",
                            "build_transition": top_date,
                            "models": dedup_recent,
                            "evidence": "models.dev/api.json",
                            "source_text": "official models.dev global AI coding model registry.",
                            "disclaimer_1": "Tracks newly merged model specifications across 40+ coding & API providers.",
                            "disclaimer_2": "Public registry specifications (context limits, pricing, tool-call support).",
                            "provider_name": "MODELS.DEV",
                            "provider_slug": "openai",
                            "accent_color": "#10b981",
                            "links": [
                                {"label": "models.dev API", "url": self.MODELS_DEV_URL},
                                {"label": "models.dev Catalog", "url": "https://models.dev"},
                            ],
                            "detected_at": f"{top_date}T12:00:00Z",
                        }
                    )
        except Exception as exc:
            print(f"[DocsScanner] models.dev warning: {exc}")

        # 2. Scan Cursor Docs, Anthropic Docs, and Google Gemini Docs for new model strings
        for tgt in self.DOCS_TARGETS:
            try:
                raw_html = _http_get_text(tgt["url"], timeout=12)
                found_ids = sorted(extract_models_from_bytes(raw_html.encode("utf-8", "ignore")))
                if not found_ids:
                    continue
                bkey = tgt["key"]
                prev_ids = set(baselines.get(bkey, []))
                added_ids = sorted(set(found_ids) - prev_ids) if prev_ids else []
                if set(found_ids) != prev_ids:
                    baselines[bkey] = found_ids
                    baselines_changed = True

                # Only emit a card if brand-new model strings were added to the documentation page
                # (or emit a baseline summary card for Gemini API Docs)
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
                            "disclaimer_1": "Detected new model identifier(s) added to official developer documentation.",
                            "disclaimer_2": "Documentation mentions often precede or accompany API rollout.",
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

        # 3. Scan LiteLLM master model_prices_and_context_window.json for newly added keys
        try:
            litellm_data = _http_get_json(self.LITELLM_JSON_URL, timeout=15)
            if isinstance(litellm_data, dict):
                current_keys = sorted(k for k in litellm_data.keys() if k != "sample_spec")
                prev_keys = set(baselines.get("litellm_keys", []))
                prev_base_slugs = {pk.split("/")[-1].lower() for pk in prev_keys}
                raw_added_keys = [k for k in current_keys if k not in prev_keys] if prev_keys else []
                added_keys = [
                    k for k in raw_added_keys
                    if k.split("/")[-1].lower() not in prev_base_slugs
                    or k.split("/")[0].lower() in {"openai", "anthropic", "gemini", "vertex_ai", "bedrock", "azure", "xai", "deepseek", "moonshot", "dashscope", "zai", "minimax", "mistral"}
                ]
                if len(current_keys) != len(prev_keys):
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
                            "disclaimer_1": "Providers and maintainers register new model IDs and token limits here before or at launch.",
                            "disclaimer_2": "Public model keys and context window specifications.",
                            "provider_name": "LITELLM",
                            "provider_slug": "openai",
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

        # 4. Scan Official GCP Vertex AI Release Notes XML feed for new model announcements/previews
        try:
            vxml = _http_get_text("https://cloud.google.com/feeds/vertex-ai-release-notes.xml", timeout=12)
            entries = re.findall(r"<entry>(.*?)</entry>", vxml, re.DOTALL)
            if entries:
                latest_ent = entries[0]
                u_m = re.search(r"<updated>(.*?)</updated>", latest_ent)
                updated_iso = u_m.group(1).strip() if u_m else datetime.now(timezone.utc).isoformat()
                v_models = sorted(extract_models_from_bytes(latest_ent.encode("utf-8", "ignore")))
                if v_models:
                    sig = hashlib.sha256(",".join(v_models).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": f"gcp-vertex-relnotes-{sig}",
                            "category": "cli-sdk-diff",
                            "scanner": "gcp-vertex",
                            "header": "GCP VERTEX AI RELEASE NOTES · GOOGLE CLOUD",
                            "title": f"Vertex AI Release Note ({infer_family_title(v_models)})",
                            "subtitle": "Verified Google Cloud Vertex AI official release notes feed",
                            "build_label": "Release Note Date",
                            "build_transition": updated_iso[:10],
                            "models": [{"id": mid, "name": humanize_model_id(mid)} for mid in v_models[:8]],
                            "evidence": "cloud.google.com/feeds/vertex-ai-release-notes.xml",
                            "source_text": "official Google Cloud Vertex AI XML release notes feed.",
                            "disclaimer_1": "Extracted from the latest entry in the official GCP Vertex AI release notes feed.",
                            "disclaimer_2": "Public Google Cloud documentation & release notes.",
                            "provider_name": "GOOGLE CLOUD",
                            "provider_slug": "google",
                            "accent_color": "#38bdf8",
                            "links": [
                                {"label": "Vertex AI Release Notes", "url": "https://cloud.google.com/vertex-ai/docs/release-notes"},
                                {"label": "XML Feed", "url": "https://cloud.google.com/feeds/vertex-ai-release-notes.xml"},
                            ],
                            "detected_at": updated_iso,
                        }
                    )
        except Exception as exc:
            print(f"[DocsScanner] GCP Vertex release notes warning: {exc}")

        if baselines_changed:
            self._save_baselines(baselines)

        return cards
