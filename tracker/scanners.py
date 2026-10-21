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
        all_versions = list(versions_dict.keys())
        if not all_versions:
            return []

        latest_ver = meta.get("dist-tags", {}).get("latest", all_versions[-1])
        latest_idx = all_versions.index(latest_ver) if latest_ver in all_versions else len(all_versions) - 1

        # Compare against a recent prior version (up to 5 releases back to catch recent diffs)
        prev_idx = max(0, latest_idx - 5)
        prev_ver = all_versions[prev_idx]

        latest_tar = versions_dict[latest_ver]["dist"]["tarball"]
        prev_tar = versions_dict[prev_ver]["dist"]["tarball"]

        latest_models = self._extract_npm_tarball_models(pkg, latest_ver, latest_tar)
        prev_models = self._extract_npm_tarball_models(pkg, prev_ver, prev_tar)

        added = latest_models - prev_models
        display_models = sorted(added) if added else sorted(latest_models)[-6:]
        if not display_models:
            return []

        is_diff = bool(added)
        transition = f"{prev_ver} -> {latest_ver}" if is_diff else f"{latest_ver} (Latest Active Identifiers)"
        pkg_short = pkg.split("/")[-1].replace("-", " ").title()
        title = f"{pkg_short} ({infer_family_title(display_models)})" if len(display_models) == 1 else f"{pkg_short} v{latest_ver} Models"

        return [
            {
                "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"npm-{pkg}-{latest_ver}"),
                "category": "cli-sdk-diff",
                "scanner": "npm",
                "header": cfg["header"],
                "title": title,
                "subtitle": cfg["subtitle"] if is_diff else "Verified compiled-in CLI/SDK model identifiers",
                "build_label": "Package",
                "build_transition": transition,
                "old_version": prev_ver,
                "new_version": latest_ver,
                "models": [{"id": mid, "name": humanize_model_id(mid)} for mid in display_models[:10]],
                "evidence": cfg["evidence"],
                "source_text": cfg["source_text"],
                "disclaimer_1": "Verified differences between published npm package builds."
                if is_diff
                else "Verified model identifiers bundled in the latest official npm release.",
                "disclaimer_2": "Compiled-in names and identifiers. This does not confirm model rollout or account access.",
                "provider_name": cfg["header"].split("·")[-1].strip(),
                "provider_slug": cfg["provider_slug"],
                "accent_color": cfg["accent_color"],
                "links": [
                    {"label": "Public npm feed", "url": f"https://www.npmjs.com/package/{pkg}?activeTab=versions"},
                    {"label": "Official tarball", "url": latest_tar},
                ],
                "detected_at": meta.get("time", {}).get(latest_ver, datetime.now(timezone.utc).isoformat()),
            }
        ]

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
        url = f"https://huggingface.co/api/models?author={org}&sort=lastModified&direction=-1&limit=5"
        items = _http_get_json(url, timeout=12)
        if not items or not isinstance(items, list):
            return None

        top = items[0]
        repo_id = top.get("id", "")
        last_mod = top.get("lastModified", datetime.now(timezone.utc).isoformat())
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


class GitHubArchitectureRadarScanner:
    """
    Scans recent commits in huggingface/transformers, vllm-project/vllm, and ggml-org/llama.cpp
    for new model architectures — often the earliest public leak of upcoming open-source models.
    Uses public GitHub .atom feeds to avoid unauthenticated api.github.com 403 rate limits.
    """

    REPOS = [
        ("huggingface/transformers", "main", "TRANSFORMERS ARCHITECTURE RADAR · OPEN SOURCE"),
        ("vllm-project/vllm", "main", "VLLM ENGINE RADAR · OPEN SOURCE"),
        ("ggml-org/llama.cpp", "master", "LLAMA.CPP GGUF RADAR · OPEN SOURCE"),
    ]

    def scan(self) -> List[Dict[str, Any]]:
        cards: List[Dict[str, Any]] = []
        keywords = re.compile(
            r"\b(qwen[0-9a-z._-]*|deepseek[a-z0-9._-]*|llama-?[0-9][a-z0-9._-]*|gemini-?[0-9][a-z0-9._-]*|gemma-?[0-9][a-z0-9._-]*|mistral[a-z0-9._-]*|ministral[a-z0-9._-]*|pixtral[a-z0-9._-]*|glm-?[0-9][a-z0-9._-]*|kimi[a-z0-9._-]*|minimax[a-z0-9._-]*|nemotron[a-z0-9._-]*|hunyuan[a-z0-9._-]*|ernie[a-z0-9._-]*|modeling_[a-z0-9_]+)\b",
            re.IGNORECASE,
        )
        entry_re = re.compile(r"<entry>(.*?)</entry>", re.DOTALL)
        title_re = re.compile(r"<title>(.*?)</title>", re.DOTALL)
        id_re = re.compile(r"<id>.*?Commit/([0-9a-f]{7,40})</id>")
        updated_re = re.compile(r"<updated>(.*?)</updated>")

        for repo, branch, header in self.REPOS:
            try:
                url = f"https://github.com/{repo}/commits/{branch}.atom"
                xml_text = _http_get_text(url, timeout=12)
                entries = entry_re.findall(xml_text)
                if not entries:
                    continue

                matched_models = []
                latest_sha = ""
                latest_date = datetime.now(timezone.utc).isoformat()
                for ent in entries[:20]:
                    t_m = title_re.search(ent)
                    id_m = id_re.search(ent)
                    u_m = updated_re.search(ent)
                    if not t_m or not id_m:
                        continue
                    msg = (
                        t_m.group(1)
                        .strip()
                        .replace("&amp;", "&")
                        .replace("&lt;", "<")
                        .replace("&gt;", ">")
                        .replace("&#39;", "'")
                        .replace("&quot;", '"')
                    )
                    sha = id_m.group(1)[:7]
                    cdate = u_m.group(1).strip() if u_m else latest_date
                    if keywords.search(msg):
                        if not latest_sha:
                            latest_sha = sha
                            latest_date = cdate
                        matched_models.append(
                            {
                                "id": sha,
                                "name": msg[:80] + ("…" if len(msg) > 80 else ""),
                            }
                        )
                if matched_models:
                    top5 = matched_models[:5]
                    shas_sig = hashlib.sha256(",".join(m["id"] for m in top5).encode("utf-8")).hexdigest()[:8]
                    cards.append(
                        {
                            "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"gh-{repo}-{shas_sig}"),
                            "category": "open-source",
                            "scanner": "github-radar",
                            "header": header,
                            "title": f"{repo.split('/')[-1]} Architecture Commits",
                            "subtitle": f"Early-warning architecture & model PR radar ({repo})",
                            "build_label": "HEAD Commit",
                            "build_transition": f"{branch} @ {latest_sha}",
                            "models": matched_models[:5],
                            "evidence": f"github.com/{repo}/commits/{branch}",
                            "source_text": f"official public GitHub commit stream for {repo}.",
                            "disclaimer_1": "Tracks upstream inference engine and architecture commits that frequently precede model releases.",
                            "disclaimer_2": "Commit titles and short SHAs from the default branch.",
                            "provider_name": "OPEN SOURCE",
                            "provider_slug": "opensource",
                            "accent_color": "#8b5cf6",
                            "links": [
                                {"label": "Commit feed", "url": f"https://github.com/{repo}/commits/{branch}"},
                                {"label": "Pull requests", "url": f"https://github.com/{repo}/pulls"},
                            ],
                            "detected_at": latest_date,
                        }
                    )
            except Exception as exc:
                print(f"[GitHubRadar] Warning ({repo}): {exc}")
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

        # 2. Scan OpenRouter live /api/v1/models (top newest models added)
        try:
            or_data = _http_get_json(self.OPENROUTER_MODELS_URL, timeout=12)
            models_list = or_data.get("data", []) if isinstance(or_data, dict) else []
            if models_list:
                models_list.sort(key=lambda x: x.get("created", 0), reverse=True)
                newest_items = models_list[:6]
                top_created = newest_items[0].get("created", 0)
                top_dt = (
                    datetime.fromtimestamp(top_created, tz=timezone.utc).isoformat()
                    if top_created
                    else datetime.now(timezone.utc).isoformat()
                )
                cards.append(
                    {
                        "id": re.sub(r"[^a-zA-Z0-9._-]", "_", f"openrouter-latest-{newest_items[0].get('id', 'models')}"),
                        "category": "cli-sdk-diff",
                        "scanner": "openrouter",
                        "header": "OPENROUTER LIVE MODEL REGISTRY · API DIFF",
                        "title": newest_items[0].get("name", "Newest Router Models"),
                        "subtitle": "Verified newly registered endpoints on OpenRouter (/api/v1/models)",
                        "build_label": "Latest Added",
                        "build_transition": newest_items[0].get("id", "latest"),
                        "models": [
                            {
                                "id": m.get("id", ""),
                                "name": f"{m.get('name', m.get('id', ''))} ({m.get('context_length', 0)//1000}k ctx)",
                            }
                            for m in newest_items
                        ],
                        "evidence": "openrouter.ai/api/v1/models",
                        "source_text": "official public OpenRouter /api/v1/models JSON registry.",
                        "disclaimer_1": "New model IDs frequently appear in router registries hours before public announcements.",
                        "disclaimer_2": "Publicly listed API model identifiers and context lengths.",
                        "provider_name": "OPENROUTER",
                        "provider_slug": "openai",
                        "accent_color": "#10b981",
                        "links": [
                            {"label": "OpenRouter Models API", "url": self.OPENROUTER_MODELS_URL},
                            {"label": "OpenRouter Rankings", "url": "https://openrouter.ai/models?order=newest"},
                        ],
                        "detected_at": top_dt,
                    }
                )
        except Exception as exc:
            print(f"[OpenRouterScanner] Note (cloud-only if behind corporate proxy): {exc}")

        return cards
