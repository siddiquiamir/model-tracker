"""Core orchestration engine for ModelPulse."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import json
import os
import pathlib
import re
import time
from typing import Any, Dict, List, Set

from tracker import novelty, pricing as pricing_mod, stories as story_mod
from tracker.intelligence import DevinCliScanner, DevinDesktopScanner, LiteLlmRegistryScanner, ModelsDevApiScanner, ModelsDevGitScanner, IdentityLedger, classify_known, intelligence_metrics, reconcile_identities
from tracker.notifiers import build_intelligence_embed, build_story_embed, build_x_post_text, send_discord_webhook
from tracker.scanners import (
    BASELINES_FILE,
    AntigravityAcpScanner,
    AntigravityDesktopScanner,
    DocsAndGlobalRegistryScanner,
    HighAlphaLeakChannelsScanner,
    HuggingFaceOpenSourceScanner,
    KimiCodeAndRouterScanner,
    LmArenaScanner,
    NpmCliAndSdkScanner,
    OpenAiApiSpecScanner,
)

RETIRED_CARD_IDS: Set[str] = {
    "litellm-diff-25799099",
    "arena-stealth-codenames",
    "arena-scout-nano-banana-2.1",
    "docs-diff-cursor-docs-8c4ad9e1",
    "docs-diff-gcp-vertex-models-bd26de54",
    "docs-diff-gcp-vertex-versions-bd26de54",
    "npm-_xai-official_grok-linux-x64-0.1.220-1.0.69",
    "docs-diff-anthropic-platform-docs-d86bce0d",
    "docs-diff-azure-foundry-partners-c27df2eb",
    "docs-diff-cursor-docs-ad78a907",
    "docs-diff-gcp-vertex-models-d86bce0d",
    "docs-diff-gcp-vertex-versions-d86bce0d",
    "engine-pr-sgl-project_sglang-46514",
    "engine-pr-sgl-project_sglang-46546",
    "arena-ckpt-swap-700ebed5a4",
    "web-bundle-aistudio-models-e3d81658",
    "google-internal-registry-krypton",
    "devin-cli-3000.12.57-3000.13.4-openai",
}

# Scanners that re-emit their complete card set on every successful run (previous cards are replaced, not retained)
AUTHORITATIVE_SCANNERS: Set[str] = {"antigravity", "antigravity-acp"}
# Status/radar cards that are never "new events" and never notify
SNAPSHOT_SCANNERS: Set[str] = set()
# Cards whose detected_at is the source's own publish timestamp (not first-seen time)
REFRESH_TIMESTAMP_SCANNERS: Set[str] = {"antigravity", "antigravity-acp"}
CARD_RETENTION = timedelta(days=14)
NOTIFY_MAX_AGE = timedelta(hours=48)
STORY_ALERT_VERSION = "alerts:evidence:v1"


def _story_alert_marks(story: Dict[str, Any]) -> Set[str]:
    story_id = story["id"]
    marks = {story_id}
    marks.update(f"{story_id}#evidence:{card_id}" for card_id in story.get("card_ids", []))
    marks.update(f"{story_id}#model:{model['id']}" for model in story.get("models", []) if model.get("id"))
    if story.get("kind") == "release":
        marks.add(story_id + "#release")
    return marks


def _is_retired_card(card: Dict[str, Any]) -> bool:
    """Snapshot-style or hardcoded cards produced by older tracker versions."""
    cid = card.get("id", "")
    scanner = card.get("scanner", "")
    return (
        cid in RETIRED_CARD_IDS
        # Subdomain (CT) and AI Studio Angular UI route cards removed completely
        or scanner in ("cert-transparency", "cert-transparency-snapshot")
        or card.get("category") == "subdomain-ct"
        or cid.startswith("web-bundle-aistudio-routes-")
        or scanner == "models-dev-kimi"
        or cid.startswith(("models-dev-recent-", "vllm-arch-registry-"))
        or (scanner == "huggingface" and card.get("header", "").startswith("HUGGING FACE HUB"))
        or (scanner == "kimi-code" and card.get("title") == "Kimi K3.1 & Kimi Code Rules")
        or (scanner == "openrouter" and card.get("subtitle", "").startswith("Verified newly registered"))
        # Arena top-85-window diffs from before the full-table baseline: re-entries of long-released models
        or (cid.startswith("lmarena-lb-diff-") and (card.get("detected_at") or "") < "2026-10-27T12:00")
    )


def _load_json(path: pathlib.Path, default: Any) -> Any:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                return json.load(stream)
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DOCS_DATA_DIR = ROOT_DIR / "docs" / "data"
FEED_FILE = DATA_DIR / "feed.json"
DOCS_FEED_FILE = DOCS_DATA_DIR / "feed.json"
SEEN_FILE = DATA_DIR / "seen_ids.json"
SCANNER_RUNS_FILE = ROOT_DIR / ".cache" / "scanner_runs.json"
# Baseline lists of model names that are already public (used as codename vocabulary, snapshotted BEFORE scanning
# so a codename that first shows up in this very scan is still flagged)
PUBLIC_NAME_BASELINES = (
    "litellm_keys", "models_dev", "arena_leaderboard_models", "arena_leaderboard_models_v2", "openrouter_models_v2",
    "vercel_gateway_models", "opencode_zen_models",
)


def _public_names_snapshot() -> List[str]:
    base = _load_json(BASELINES_FILE, {})
    names: List[str] = []
    for key in PUBLIC_NAME_BASELINES:
        val = base.get(key)
        if isinstance(val, list):
            names.extend(str(v) for v in val)
    return names


class TrackerEngine:
    """Runs all model scanners, deduplicates cards, preserves first-seen timestamps, and triggers notifications."""

    def __init__(self, github_user: str = "siddiquiamir") -> None:
        self.github_user = github_user
        self.ag_scanner = AntigravityDesktopScanner()
        self.ag_acp_scanner = AntigravityAcpScanner()
        self.npm_scanner = NpmCliAndSdkScanner()
        self.kimi_router_scanner = KimiCodeAndRouterScanner()
        self.docs_scanner = DocsAndGlobalRegistryScanner()
        self.arena_scanner = LmArenaScanner()
        self.hf_scanner = HuggingFaceOpenSourceScanner()
        self.high_alpha_scanner = HighAlphaLeakChannelsScanner()
        self.openai_spec_scanner = OpenAiApiSpecScanner()
        self.intelligence_scanners = [ModelsDevApiScanner(), LiteLlmRegistryScanner(), ModelsDevGitScanner(), DevinCliScanner(), DevinDesktopScanner()]

    def notify_intelligence(self, cards: List[Dict[str, Any]], enabled: bool = True) -> None:
        if not enabled:
            return
        seen = self.load_seen_ids()
        pending = []
        for card in cards:
            marker = f"intel-alert-{card['id']}"
            evidence_path = ROOT_DIR / card.get("evidence_path", "")
            if marker in seen or card.get("backfill") or card.get("candidate_only") or not card.get("evidence_retained"):
                continue
            if not evidence_path.is_file():
                continue
            evidence = _load_json(evidence_path, {})
            if evidence.get("artifact_sha256") != card.get("artifact_sha256"):
                continue
            if card.get("first_seen", "") < (datetime.now(timezone.utc) - NOTIFY_MAX_AGE).isoformat():
                continue
            pending.append(card)
        for card in pending[:20]:
            try:
                if send_discord_webhook([card], github_user=self.github_user, embed_builder=build_intelligence_embed):
                    seen.add(f"intel-alert-{card['id']}")
                    self.save_seen_ids(seen)
            except Exception:
                print("[ModelPulse] Intelligence Discord delivery failed; retained event will retry.")

    def load_seen_ids(self) -> Set[str]:
        if SEEN_FILE.exists():
            try:
                return set(json.loads(SEEN_FILE.read_text(encoding="utf-8")))
            except Exception:
                return set()
        return set()

    def save_seen_ids(self, seen: Set[str]) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SEEN_FILE.write_text(json.dumps(sorted(seen), indent=2), encoding="utf-8")

    def load_previous_timestamps(self) -> Dict[str, str]:
        """Load existing card timestamps from feed.json so repeat scans never reset a card's timestamp."""
        if not FEED_FILE.exists():
            return {}
        try:
            data = json.loads(FEED_FILE.read_text(encoding="utf-8"))
            out: Dict[str, str] = {}
            for c in data.get("cards", []):
                cid = c.get("id")
                ts = c.get("detected_at")
                if cid and ts:
                    out[cid] = ts
            return out
        except Exception:
            return {}

    def load_previous_cards(self) -> List[Dict[str, Any]]:
        if not FEED_FILE.exists():
            return []
        try:
            data = json.loads(FEED_FILE.read_text(encoding="utf-8"))
            return data.get("cards", [])
        except Exception:
            return []

    def run_all_scans(self, notify_discord: bool = True) -> Dict[str, Any]:
        prev_timestamps = self.load_previous_timestamps()
        prev_cards = [
            c for c in self.load_previous_cards()
            if not _is_retired_card(c) and not (c.get("intelligence") and c.get("backfill"))
        ]
        prev_codenames = {c["id"]: c["codenames"] for c in prev_cards if c.get("codenames")}
        scanner_runs = _load_json(SCANNER_RUNS_FILE, {})
        health_path = DATA_DIR / "intelligence/source_health.json"
        source_health = _load_json(health_path, {})
        public_names = _public_names_snapshot()
        now = datetime.now(timezone.utc)

        # (name, callable, min seconds between runs, scanner tags it owns)
        scanner_specs = [
            ("npm", self.npm_scanner.scan, 0, {"npm"}),
            ("antigravity-acp", self.ag_acp_scanner.scan, 0, {"antigravity-acp"}),
            ("docs-registries", self.docs_scanner.scan, 0, {"docs-radar", "models-dev", "litellm"}),
            ("high-alpha", self.high_alpha_scanner.scan, 0, set()),
        ] + [
            (scanner.source, scanner.scan, scanner.poll_interval, {scanner.source}) for scanner in self.intelligence_scanners
        ] + [
            ("antigravity", lambda: self.ag_scanner.scan(max_stable=8), 0, {"antigravity"}),
            ("kimi-vllm-openrouter", self.kimi_router_scanner.scan, 0, {"kimi-code", "vllm-registry", "openrouter"}),
            ("arena", self.arena_scanner.scan, 600, {"lmarena"}),
            ("huggingface", self.hf_scanner.scan, 0, {"huggingface"}),
            ("openai-spec", self.openai_spec_scanner.scan, 0, {"openai-spec"}),
        ]

        fresh_cards: List[Dict[str, Any]] = []
        ran_ok_tags: Set[str] = set()
        intelligence_status: Dict[str, Any] = {name: dict(status) for name, status in source_health.items() if any(scanner.source == name for scanner in self.intelligence_scanners)}
        intelligence_by_source = {scanner.source: scanner for scanner in self.intelligence_scanners}
        self.notify_intelligence([card for card in prev_cards if card.get("intelligence")], notify_discord)
        for name, fn, min_interval, tags in scanner_specs:
            health = source_health.setdefault(name, {})
            health["poll_interval_seconds"] = min_interval or 120
            last_success = health.get("last_success")
            health["stale"] = not last_success or (now - datetime.fromisoformat(last_success)).total_seconds() > max(600, (min_interval or 120) * 3)
            last = scanner_runs.get(name, "")
            if min_interval and last and (now - datetime.fromisoformat(last)).total_seconds() < min_interval:
                print(f"[ModelPulse] {name}: throttled (last run {last})")
                if name in intelligence_by_source:
                    intelligence_status[name] = dict(health)
                continue
            t0 = time.monotonic()
            health["last_attempt"] = datetime.now(timezone.utc).isoformat()
            try:
                cards = fn()
            except Exception as exc:
                print(f"[ModelPulse] {name}: FAILED after {time.monotonic() - t0:.1f}s: {type(exc).__name__}")
                health.update(status="failed", error_type=type(exc).__name__, consecutive_failures=health.get("consecutive_failures", 0) + 1, duration_seconds=round(time.monotonic() - t0, 3))
                if name in intelligence_by_source:
                    intelligence_status[name] = dict(health)
                continue
            completed = datetime.now(timezone.utc).isoformat()
            health.update(status="ok", last_success=completed, error_type=None, consecutive_failures=0, stale=False, duration_seconds=round(time.monotonic() - t0, 3))
            if name == "high-alpha":
                health["subsources"] = dict(self.high_alpha_scanner.source_health)
            print(f"[ModelPulse] {name}: {len(cards)} card(s) in {time.monotonic() - t0:.1f}s")
            if name in intelligence_by_source:
                cards = [card for card in cards if not card.get("backfill")]
                cards = classify_known(cards, public_names)
                health.update(intelligence_by_source[name].status)
                intelligence_status[name] = dict(health)
                self.notify_intelligence(cards, notify_discord)
            elif name == "docs-registries":
                cards = [card for card in cards if card.get("scanner") not in {"litellm", "models-dev"}]
            fresh_cards.extend(cards)
            ran_ok_tags |= tags
            scanner_runs[name] = now.isoformat()
        _save_json(SCANNER_RUNS_FILE, scanner_runs)
        _save_json(health_path, source_health)

        # Carry previous cards forward: snapshot/authoritative scanners only when they did not run this time,
        # every other (event-diff) card for CARD_RETENTION so catches never vanish when a source hiccups.
        cutoff_iso = (now - CARD_RETENTION).isoformat()
        fresh_tags = {c.get("scanner", "") for c in fresh_cards}
        carried: List[Dict[str, Any]] = []
        for pc in prev_cards:
            tag = pc.get("scanner", "")
            if tag in AUTHORITATIVE_SCANNERS:
                if tag not in ran_ok_tags or tag not in fresh_tags:
                    carried.append(pc)
            elif (pc.get("detected_at") or "") >= cutoff_iso:
                carried.append(pc)

        # Deduplicate by card ID and by (scanner, header, model_ids); fresh cards win over carried ones
        all_cards: List[Dict[str, Any]] = []
        seen_card_keys: Set[str] = set()
        for card in [*fresh_cards, *carried]:
            cid = card["id"]
            if cid in RETIRED_CARD_IDS or _is_retired_card(card):
                continue
            if card.get("scanner") == "ide-build-diff" and card.get("models"):
                card["models"] = [
                    m for m in card["models"] if not re.search(r"\.[a-z]", str(m.get("id", "")), re.I)
                ]
                if not card["models"]:
                    continue
            models_sig = ",".join(sorted(m.get("id", "") for m in card.get("models", [])))
            content_key = f"{card.get('scanner')}|{card.get('header')}|{models_sig}"
            if cid in seen_card_keys or content_key in seen_card_keys:
                continue
            seen_card_keys.add(cid)
            seen_card_keys.add(content_key)

            if cid in prev_timestamps and card.get("scanner") not in REFRESH_TIMESTAMP_SCANNERS:
                card["detected_at"] = prev_timestamps[cid]
            if cid in prev_codenames:
                card["codenames"] = sorted(set(card.get("codenames") or []) | set(prev_codenames[cid]))

            all_cards.append(card)

        # Drop models that were already public when the card was detected; flag unknown codename tokens
        n_before = len(all_cards)
        all_cards = novelty.apply(all_cards, novelty.get_catalog(public_names))
        print(f"[ModelPulse] novelty filter: {n_before} -> {len(all_cards)} card(s)")

        # Attach live pricing from Official Docs, LiteLLM, models.dev & OpenRouter to every card and model
        ledger = IdentityLedger(DATA_DIR / "intelligence")
        ledger.enqueue(all_cards)
        reconciliation = _load_json(DATA_DIR / "intelligence/reconciliation.json", {})
        if not reconciliation.get("completed_at") or (now - datetime.fromisoformat(reconciliation["completed_at"])).total_seconds() >= 86400:
            try:
                reconcile_identities(DATA_DIR / "intelligence")
            except Exception as exc:
                print(f"[ModelPulse] Retained evidence reconciliation: {type(exc).__name__}")
        pricing_catalog = pricing_mod.get_pricing_catalog()
        pricing_mod.enrich_cards_with_pricing(all_cards, pricing_catalog)

        for card in all_cards:
            card["x_post_text"] = build_x_post_text(card)

        all_cards.sort(key=lambda c: c.get("detected_at", ""), reverse=True)

        # One story per model across all sources; notify once per story (and once more when a leak ships)
        catalog = novelty.get_catalog(public_names)
        stories = story_mod.build_stories(all_cards, catalog, now=now, pricing_catalog=pricing_catalog)
        for s in stories:
            s["x_post_text"] = story_mod.story_x_text(s)

        seen_ids = self.load_seen_ids()
        first_run = not seen_ids
        story_migration = not any(i.startswith("story-") for i in seen_ids)
        if STORY_ALERT_VERSION not in seen_ids:
            for previous_story in _load_json(FEED_FILE, {}).get("stories", []):
                previous_id = previous_story["id"]
                if previous_id in seen_ids:
                    seen_ids.update(_story_alert_marks(previous_story) - {previous_id, previous_id + "#release"})
            seen_ids.add(STORY_ALERT_VERSION)
        notify_cutoff = (now - NOTIFY_MAX_AGE).isoformat()
        notify_stories: List[Dict[str, Any]] = []
        story_seen_ids: Set[str] = set()
        for s in stories:
            marks = _story_alert_marks(s)
            story_seen_ids |= marks
            if marks <= seen_ids or s["backfill"] or s.get("candidate_only"):
                continue
            if (s.get("updated_at") or "") >= notify_cutoff:
                notify_stories.append(s)
        new_cards = [
            c for c in all_cards
            if c["id"] not in seen_ids and c.get("scanner") not in SNAPSHOT_SCANNERS and not c.get("backfill")
        ]

        notified_ok = True
        if notify_discord and notify_stories and not first_run and not story_migration:
            try:
                notified_ok = send_discord_webhook(
                    notify_stories[:20], github_user=self.github_user, embed_builder=build_story_embed
                )
                print(f"[ModelPulse] Discord: {'sent' if notified_ok else 'not sent'} {min(len(notify_stories), 20)} story alert(s).")
            except Exception as exc:
                notified_ok = False
                print(f"[ModelPulse] Discord notification failed: {exc}")

        # Stories whose Discord alert failed, or didn't fit in this batch, stay unseen so the next scan sends them
        retry_ids: Set[str] = set()
        unsent = notify_stories if (not notified_ok and os.environ.get("DISCORD_WEBHOOK_URL")) else notify_stories[20:]
        if not first_run and not story_migration:
            for s in unsent:
                retry_ids |= _story_alert_marks(s)
        seen_ids.update(c["id"] for c in all_cards)
        seen_ids.update(story_seen_ids - retry_ids)
        self.save_seen_ids(seen_ids)

        day_ago = (now - timedelta(hours=24)).isoformat()
        feed_payload: Dict[str, Any] = {
            "generated_at": now.isoformat(),
            "github_user": self.github_user,
            "stats": {
                "stories": len(stories),
                "leaks": sum(1 for s in stories if s["kind"] == "leak"),
                "releases": sum(1 for s in stories if s["kind"] == "release"),
                "stories_24h": sum(1 for s in stories if (s.get("updated_at") or "") >= day_ago),
                "sources_ok": len(ran_ok_tags),
                "total_cards": len(all_cards),
                "new_in_this_scan": len(new_cards),
            },
            "stories": stories,
            "cards": all_cards,
            "intelligence_status": intelligence_status,
            "source_health": source_health,
            "identities": ledger.summarize(),
            "intelligence_metrics": intelligence_metrics(all_cards, source_health, DATA_DIR / "intelligence"),
        }

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        DOCS_DATA_DIR.mkdir(parents=True, exist_ok=True)

        feed_json = json.dumps(feed_payload, indent=2, ensure_ascii=False)
        FEED_FILE.write_text(feed_json, encoding="utf-8", newline="\n")
        DOCS_FEED_FILE.write_text(feed_json, encoding="utf-8", newline="\n")

        return feed_payload

    def custom_antigravity_diff(self, old_ver: str, new_ver: str) -> List[Dict[str, Any]]:
        """Diff any two Antigravity builds on demand by version string."""
        builds = self.ag_scanner.list_available_builds(max_stable=12)
        by_ver = {b["version"]: b for b in builds}
        for b in builds:
            if b.get("raw_version"):
                by_ver[b["raw_version"]] = b

        if old_ver not in by_ver or new_ver not in by_ver:
            raise ValueError(f"Unknown build version. Available: {list(by_ver.keys())}")

        cards = self.ag_scanner.diff_two_builds(by_ver[old_ver], by_ver[new_ver])
        for c in cards:
            c["x_post_text"] = build_x_post_text(c)
        return cards
