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
from tracker.extractor import is_legacy_model_id
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
    "vertex-quota-kimi-bc14cc95",
    "vertex-quota-google-f3afe98e",
    # 2026-11-18 aggregator route/metadata syncs of old/already-tracked models (models-dev & litellm-intelligence)
    "intel-4ad4c1bab7fc82e03cda",
    "intel-9b0456e9d15ddcef4f33",
    "intel-2abf13489e0d4dc5b8a0",
    "intel-5c86b7c6266cb99073c6",
    "intel-b66a84eb72f7d9114144",
    "intel-42e71477662b03c3a2c6",
    "intel-3b1d856353caa61f8c1b",
    "intel-e8c22353e4f12bdcf3f8",
    "intel-0136f55572d98ec8c80f",
    "intel-7d3c7d4fb0b519fd27f3",
    "intel-492c4ee8fead716b68a8",
    "intel-c49e080e57e806dda351",
    "intel-08ef2fb8857160d3aa17",
    "intel-5d7dadc4e4a322f9238b",
    "intel-936f63c371b01bbad0ec",
    "intel-5c35a9848ab9dc462ead",
    "intel-e2dd2e17da5ab9aad6a5",
    "intel-c385b548213e6fffdadb",
    "intel-94a923745e50bf51ac0f",
    "intel-98a6d84ef84f8589e25f",
    "intel-c9780de0b72d985c03de",
    "intel-ca63235db45fba36bdbe",
    "intel-d2eff29d7acd9ba4d412",
    "intel-656f6b5c6bf6d43f9a5e",
    "intel-97f11ce462d2563cabaa",
    "intel-3f03c1df8b9257b23e71",
    "intel-849bd7f7e59226f36a5b",
    "intel-0d1d9285fcbfe948f976",
    "intel-d4b606d0fcd66e0ba617",
    "intel-5f142ca4239f98b94ec2",
    "intel-02013aa1ae3a49eb0e61",
    "intel-60d19a02b16ad44b2e04",
    "intel-501ffad87dacc940d231",
    "intel-d311ad7a71b32744c74e",
    "intel-1e844aa9325284afb7fc",
    "intel-c2fca4a95ecbf3b0d310",
    "intel-7d7856c62664277f7d1b",
    "intel-f96d43e64ab5c8172ad8",
    "intel-fc3e938aa6d523bfa2d6",
    "intel-c5cadd9a21fb1f7337e5",
    "intel-00e8129a7febdb9f1e8a",
    "intel-277f473c4e61bf78e1eb",
    "intel-0e5a00c77c1a085f2ff1",
    "intel-b1d84fe743d6259d790d",
    "intel-38b25ff67104134add73",
    "intel-c86e1bc490734e56c617",
    "intel-2fefbb483f70e0b8c495",
    "intel-bce809cb3aeb49f08493",
    "intel-5a39a4599e811f902a4f",
    # 2026-11-18 GCP Cloud Billing non-model tier/context/grounding SKUs & legacy Gemini 3/3.1 SKUs
    "cloud-billing-vertex-3a71508b",
    "cloud-billing-vertex-cee49b6c",
    "cloud-billing-vertex-84604e27",
    "cloud-billing-vertex-867aa146",
    "cloud-billing-vertex-3accefe3",
    "cloud-billing-vertex-443c55ca",
    "cloud-billing-vertex-98d84ad8",
    # 2026-11-18 Devin CLI concatenated .rodata neighbor false positive
    "devin-cli-3000.13.4-3000.14.30821-openai",
    # Carried Antigravity ACP diff with truncated/legacy gemini-for & gemini-pro-agent strings
    "ag-acp-1.4.4-1.4.5-diff",
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

    def notify_intelligence(self, cards: List[Dict[str, Any]], enabled: bool = True, catalog: Any = None) -> None:
        if not enabled:
            return
        seen = self.load_seen_ids()
        pending = []
        for card in cards:
            marker = f"intel-alert-{card['id']}"
            evidence_path = ROOT_DIR / card.get("evidence_path", "")
            if (
                marker in seen
                or _is_retired_card(card)
                or card.get("backfill")
                or card.get("candidate_only")
                or card.get("registry_update")
                or card.get("event_label") == "Registry update"
                or not card.get("evidence_retained")
            ):
                continue
            models = card.get("models") or []
            if models:
                det = novelty._parse_dt(card.get("detected_at") or card.get("first_seen") or "")
                cutoff = (det - novelty.RELEASE_GRACE).strftime("%Y-%m-%d")
                if all(
                    novelty.is_old_model(novelty._model_label(m), det, catalog)
                    or (
                        re.match(r"^\d{4}-\d{2}-\d{2}$", str(m.get("released_on") or "")[:10])
                        and str(m.get("released_on"))[:10] < cutoff
                    )
                    or m.get("registry_update")
                    for m in models
                ):
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
                    card["discord_alerted_at"] = datetime.now(timezone.utc).isoformat()
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
        previous_cards_by_id = {card["id"]: card for card in prev_cards}
        prev_codenames = {c["id"]: c["codenames"] for c in prev_cards if c.get("codenames")}
        scanner_runs = _load_json(SCANNER_RUNS_FILE, {})
        health_path = DATA_DIR / "intelligence/source_health.json"
        source_health = _load_json(health_path, {})
        public_names = _public_names_snapshot()
        now = datetime.now(timezone.utc)
        catalog = None
        early_intelligence_ids: Set[str] = set()
        early_delivery_times: Dict[str, str] = {}

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
            for card in cards:
                previous = previous_cards_by_id.get(card["id"])
                if previous is None:
                    card.setdefault("tracker_observed_at", completed)
                else:
                    for field in ("tracker_observed_at", "discord_alerted_at", "artifact_modified_at"):
                        if previous.get(field):
                            card.setdefault(field, previous[field])
            health.update(status="ok", last_success=completed, error_type=None, consecutive_failures=0, stale=False, duration_seconds=round(time.monotonic() - t0, 3))
            if name == "high-alpha":
                health["subsources"] = dict(self.high_alpha_scanner.source_health)
            print(f"[ModelPulse] {name}: {len(cards)} card(s) in {time.monotonic() - t0:.1f}s")
            if name in intelligence_by_source:
                cards = [card for card in cards if not card.get("backfill")]
                cards = classify_known(cards, public_names)
                health.update(intelligence_by_source[name].status)
                intelligence_status[name] = dict(health)
                if notify_discord and name in {"devin-cli", "devin-desktop"} and cards:
                    catalog = catalog or novelty.get_catalog(public_names)
                    early_cards = novelty.apply([dict(card, models=[dict(model) for model in card.get("models", [])]) for card in cards], catalog)
                    self.notify_intelligence(early_cards, catalog=catalog)
                    early_intelligence_ids.update(card["id"] for card in early_cards)
                    early_delivery_times.update({card["id"]: card["discord_alerted_at"] for card in early_cards if card.get("discord_alerted_at")})
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
            if card.get("scanner") == "cloud-billing" and card.get("models"):
                card["models"] = [
                    m for m in card["models"]
                    if not HighAlphaLeakChannelsScanner._BILLING_NON_MODEL_SUFFIX_RE.search(str(m.get("id", "")).lower())
                ]
                if not card["models"]:
                    continue
            if card.get("scanner") == "ide-build-diff" and card.get("models"):
                kept_ide: List[Dict[str, Any]] = []
                removed_ide: List[str] = []
                for m in card["models"]:
                    mid_str = str(m.get("id", ""))
                    stem_toks = re.sub(r"-(?:minimal|low|medium|high|xhigh|max)$", "", mid_str.lower()).split("-")
                    if (
                        re.search(r"\.[a-z]", mid_str, re.I)
                        or is_legacy_model_id(mid_str)
                        or "persiste" in mid_str.lower()
                        or (stem_toks and stem_toks[0] in HighAlphaLeakChannelsScanner._GENERIC_TIER_STEMS)
                    ):
                        removed_ide.append(mid_str)
                    else:
                        kept_ide.append(m)
                card["models"] = kept_ide
                if not card["models"]:
                    continue
                if removed_ide:
                    first_ide = str(kept_ide[0].get("id", ""))
                    for r_id in removed_ide:
                        if r_id and r_id in card.get("title", ""):
                            card["title"] = card["title"].replace(r_id, first_ide)
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
            if cid in early_delivery_times:
                card["discord_alerted_at"] = early_delivery_times[cid]

            all_cards.append(card)

        # Drop models that were already public when the card was detected; flag unknown codename tokens
        n_before = len(all_cards)
        catalog = catalog or novelty.get_catalog(public_names)
        all_cards = novelty.apply(all_cards, catalog)
        print(f"[ModelPulse] novelty filter: {n_before} -> {len(all_cards)} card(s)")
        self.notify_intelligence([c for c in all_cards if c.get("intelligence") and c["id"] not in early_intelligence_ids], notify_discord, catalog=catalog)

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
        stories = story_mod.build_stories(all_cards, catalog, now=now, pricing_catalog=pricing_catalog)
        previous_stories = _load_json(FEED_FILE, {}).get("stories", [])
        deliveries = {story["id"]: story["discord_alerted_at"] for story in previous_stories if story.get("discord_alerted_at")}
        for s in stories:
            if s["id"] in deliveries:
                s["discord_alerted_at"] = deliveries[s["id"]]
            s["x_post_text"] = story_mod.story_x_text(s)

        seen_ids = self.load_seen_ids()
        first_run = not seen_ids
        story_migration = not any(i.startswith("story-") for i in seen_ids)
        if STORY_ALERT_VERSION not in seen_ids:
            for previous_story in previous_stories:
                previous_id = previous_story["id"]
                if previous_id in seen_ids:
                    seen_ids.update(_story_alert_marks(previous_story) - {previous_id, previous_id + "#release"})
            seen_ids.add(STORY_ALERT_VERSION)
        intel_ids_in_feed = {c["id"] for c in all_cards if c.get("intelligence")}
        notify_cutoff = (now - NOTIFY_MAX_AGE).isoformat()
        notify_stories: List[Dict[str, Any]] = []
        story_seen_ids: Set[str] = set()
        for s in stories:
            marks = _story_alert_marks(s)
            story_seen_ids |= marks
            if marks <= seen_ids or s["backfill"] or s.get("candidate_only"):
                continue
            if s.get("kind") == "registry" or s.get("event_label") == "Registry update":
                continue
            s_models = s.get("models") or []
            if s_models:
                s_det = novelty._parse_dt(s.get("detected_at") or "")
                s_cutoff = (s_det - novelty.RELEASE_GRACE).strftime("%Y-%m-%d")
                if all(
                    novelty.is_old_model(str(m.get("id") or ""), s_det, catalog)
                    or (
                        re.match(r"^\d{4}-\d{2}-\d{2}$", str(m.get("released_on") or "")[:10])
                        and str(m.get("released_on"))[:10] < s_cutoff
                    )
                    for m in s_models
                ):
                    continue
            intel_owned_cids = {
                cid for cid in s.get("card_ids", [])
                if cid in intel_ids_in_feed or f"intel-alert-{cid}" in seen_ids
            }
            if intel_owned_cids:
                non_intel_cids = [cid for cid in s.get("card_ids", []) if cid not in intel_owned_cids]
                has_unseen_non_intel = any(f"{s['id']}#evidence:{cid}" not in seen_ids for cid in non_intel_cids)
                is_new_release = s.get("kind") == "release" and f"{s['id']}#release" not in seen_ids
                if not has_unseen_non_intel and not is_new_release:
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
                if notified_ok:
                    delivered_at = datetime.now(timezone.utc).isoformat()
                    for story in notify_stories[:20]:
                        story["discord_alerted_at"] = delivered_at
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
            "scan_completed_at": datetime.now(timezone.utc).isoformat(),
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
