"""Core orchestration engine for ModelPulse."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import pathlib
import time
from typing import Any, Dict, List, Set

from tracker.notifiers import build_x_post_text, send_discord_webhook
from tracker.scanners import (
    AntigravityAcpScanner,
    AntigravityDesktopScanner,
    CertTransparencySubdomainScanner,
    DocsAndGlobalRegistryScanner,
    HighAlphaLeakChannelsScanner,
    HuggingFaceOpenSourceScanner,
    KimiCodeAndRouterScanner,
    LmArenaScanner,
    NpmCliAndSdkScanner,
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
}

# Scanners that re-emit their complete card set on every successful run (previous cards are replaced, not retained)
AUTHORITATIVE_SCANNERS: Set[str] = {"antigravity", "antigravity-acp", "cert-transparency-snapshot"}
# Status/radar cards that are never "new events" and never notify
SNAPSHOT_SCANNERS: Set[str] = {"cert-transparency-snapshot"}
# Cards whose detected_at is the source's own publish timestamp (not first-seen time)
REFRESH_TIMESTAMP_SCANNERS: Set[str] = {"antigravity", "antigravity-acp", "cert-transparency-snapshot"}
CARD_RETENTION = timedelta(days=14)
NOTIFY_MAX_AGE = timedelta(hours=48)


def _is_retired_card(card: Dict[str, Any]) -> bool:
    """Snapshot-style or hardcoded cards produced by older tracker versions."""
    cid = card.get("id", "")
    scanner = card.get("scanner", "")
    return (
        cid in RETIRED_CARD_IDS
        or scanner == "models-dev-kimi"
        or cid.startswith(("models-dev-recent-", "vllm-arch-registry-"))
        or (scanner == "huggingface" and card.get("header", "").startswith("HUGGING FACE HUB"))
        or (scanner == "kimi-code" and card.get("title") == "Kimi K3.1 & Kimi Code Rules")
        or (scanner == "openrouter" and card.get("subtitle", "").startswith("Verified newly registered"))
    )


def _load_json(path: pathlib.Path, default: Any) -> Any:
    try:
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
        self.ct_scanner = CertTransparencySubdomainScanner()
        self.high_alpha_scanner = HighAlphaLeakChannelsScanner()

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
        prev_cards = [c for c in self.load_previous_cards() if not _is_retired_card(c)]
        scanner_runs = _load_json(SCANNER_RUNS_FILE, {})
        now = datetime.now(timezone.utc)

        # (name, callable, min seconds between runs, scanner tags it owns)
        scanner_specs = [
            ("antigravity", lambda: self.ag_scanner.scan(max_stable=8), 0, {"antigravity"}),
            ("antigravity-acp", self.ag_acp_scanner.scan, 0, {"antigravity-acp"}),
            ("npm", self.npm_scanner.scan, 0, {"npm"}),
            ("kimi-vllm-openrouter", self.kimi_router_scanner.scan, 0, {"kimi-code", "vllm-registry", "openrouter"}),
            ("docs-registries", self.docs_scanner.scan, 0, {"docs-radar", "models-dev", "litellm"}),
            ("arena", self.arena_scanner.scan, 600, {"lmarena"}),
            ("huggingface", self.hf_scanner.scan, 0, {"huggingface"}),
            ("cert-transparency", self.ct_scanner.scan, 1800, {"cert-transparency", "cert-transparency-snapshot"}),
            ("high-alpha", self.high_alpha_scanner.scan, 0, set()),
        ]

        fresh_cards: List[Dict[str, Any]] = []
        ran_ok_tags: Set[str] = set()
        for name, fn, min_interval, tags in scanner_specs:
            last = scanner_runs.get(name, "")
            if min_interval and last and (now - datetime.fromisoformat(last)).total_seconds() < min_interval:
                print(f"[ModelPulse] {name}: throttled (last run {last})")
                continue
            t0 = time.monotonic()
            try:
                cards = fn()
            except Exception as exc:
                print(f"[ModelPulse] {name}: FAILED after {time.monotonic() - t0:.1f}s: {exc}")
                continue
            print(f"[ModelPulse] {name}: {len(cards)} card(s) in {time.monotonic() - t0:.1f}s")
            fresh_cards.extend(cards)
            ran_ok_tags |= tags
            scanner_runs[name] = now.isoformat()
        _save_json(SCANNER_RUNS_FILE, scanner_runs)

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
            if cid in RETIRED_CARD_IDS:
                continue
            models_sig = ",".join(sorted(m.get("id", "") for m in card.get("models", [])))
            content_key = f"{card.get('scanner')}|{card.get('header')}|{models_sig}"
            if cid in seen_card_keys or content_key in seen_card_keys:
                continue
            seen_card_keys.add(cid)
            seen_card_keys.add(content_key)

            if cid in prev_timestamps and card.get("scanner") not in REFRESH_TIMESTAMP_SCANNERS:
                card["detected_at"] = prev_timestamps[cid]

            card["x_post_text"] = build_x_post_text(card)
            all_cards.append(card)

        all_cards.sort(key=lambda c: c.get("detected_at", ""), reverse=True)

        seen_ids = self.load_seen_ids()
        first_run = not seen_ids
        new_cards = [
            c for c in all_cards
            if c["id"] not in seen_ids and c.get("scanner") not in SNAPSHOT_SCANNERS and not c.get("backfill")
        ]
        notify_cutoff = (now - NOTIFY_MAX_AGE).isoformat()
        notify_cards = [c for c in new_cards if (c.get("detected_at") or "") >= notify_cutoff]

        notified_ok = True
        if notify_discord and notify_cards and not first_run:
            try:
                notified_ok = send_discord_webhook(notify_cards[:30], github_user=self.github_user)
                print(f"[ModelPulse] Discord: {'sent' if notified_ok else 'not sent'} {min(len(notify_cards), 30)} new card(s).")
            except Exception as exc:
                notified_ok = False
                print(f"[ModelPulse] Discord notification failed: {exc}")

        # Cards whose Discord alert failed stay unseen so the next scan retries them
        retry_ids = {c["id"] for c in notify_cards} if not notified_ok and os.environ.get("DISCORD_WEBHOOK_URL") else set()
        seen_ids.update(c["id"] for c in all_cards if c["id"] not in retry_ids)
        self.save_seen_ids(seen_ids)

        available_builds = self.ag_scanner.list_available_builds(max_stable=8)
        build_models_map = self.ag_scanner.get_build_models_map(max_stable=8)

        oss_count = sum(1 for c in all_cards if c.get("category") == "open-source")
        cli_count = sum(1 for c in all_cards if c.get("category") == "cli-sdk-diff")
        desk_count = sum(1 for c in all_cards if c.get("category") == "desktop-diff")
        ct_count = sum(1 for c in all_cards if c.get("category") == "subdomain-ct")

        feed_payload: Dict[str, Any] = {
            "generated_at": now.isoformat(),
            "github_user": self.github_user,
            "stats": {
                "total_cards": len(all_cards),
                "desktop_diffs": desk_count,
                "cli_sdk_diffs": cli_count,
                "open_source_models": oss_count,
                "subdomain_ct_cards": ct_count,
                "new_in_this_scan": len(new_cards),
                "total_models_indexed": sum(len(c.get("models", [])) for c in all_cards),
            },
            "available_antigravity_builds": [b["version"] for b in available_builds],
            "build_models_map": build_models_map,
            "cards": all_cards,
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
