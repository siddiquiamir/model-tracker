"""Core orchestration engine for ModelPulse."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import pathlib
from typing import Any, Dict, List, Set

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
}

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

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
DOCS_DATA_DIR = ROOT_DIR / "docs" / "data"
FEED_FILE = DATA_DIR / "feed.json"
DOCS_FEED_FILE = DOCS_DATA_DIR / "feed.json"
SEEN_FILE = DATA_DIR / "seen_ids.json"


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
        prev_cards = self.load_previous_cards()

        print("[ModelPulse] Scanning Antigravity Desktop builds (Stable + Insiders)...")
        ag_cards = self.ag_scanner.scan(max_stable=8)

        print("[ModelPulse] Scanning Antigravity ACP Server builds & Discovery Docs on dl.google.com...")
        acp_cards = self.ag_acp_scanner.scan()

        print("[ModelPulse] Scanning npm CLI & SDK packages (Claude Code, Codex, Google GenAI, OpenAI, Anthropic)...")
        npm_cards = self.npm_scanner.scan()

        print("[ModelPulse] Scanning Kimi Code CDN configs, vLLM registry.py & OpenRouter live model registry...")
        kr_cards = self.kimi_router_scanner.scan()
        present_scanners = {c.get("scanner") for c in kr_cards}
        for pc in prev_cards:
            if pc.get("scanner") in {"openrouter", "kimi-code"} and pc.get("scanner") not in present_scanners:
                kr_cards.append(pc)

        print("[ModelPulse] Scanning Cursor Docs, Anthropic/Gemini/Vertex/Bedrock Docs, models.dev & LiteLLM...")
        docs_cards = self.docs_scanner.scan()

        print("[ModelPulse] Scanning Arena.ai (LMArena) live RSC initialModels & Hugging Face leaderboard dataset...")
        arena_cards = self.arena_scanner.scan()

        print("[ModelPulse] Scanning Hugging Face Hub 14 frontier open-source orgs...")
        hf_cards = self.hf_scanner.scan()

        print("[ModelPulse] Scanning Certificate Transparency (CT) & Passive DNS across 21 AI lab domains...")
        ct_cards = self.ct_scanner.scan()

        print("[ModelPulse] Scanning High-Alpha Leak Channels (Gateways, Cursor/Devin Builds, Copilot CLI, Engine PRs, Live APIs)...")
        leak_cards = self.high_alpha_scanner.scan()

        def _ag_sort_key(card: Dict[str, Any]) -> tuple:
            title = card.get("title", "").lower()
            if "gemini 4 argon" in title or "gemini 4 carbon" in title:
                return (0, card.get("id", ""))
            if "claude opus 5.5" in title or "claude sonnet 5.5" in title:
                return (1, card.get("id", ""))
            if "omni" in title or "robotics" in title:
                return (2, card.get("id", ""))
            return (3, card.get("id", ""))

        ag_cards.sort(key=_ag_sort_key)

        # Preserve genuine event-diff cards (docs-radar, litellm, lmarena, cert-transparency, models-dev-diff-*) for 14 days
        # so overnight pre-release catches remain on the dashboard after source_baselines.json updates.
        cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
        retained_event_cards: List[Dict[str, Any]] = []
        for pc in prev_cards:
            pc_id = pc.get("id", "")
            pc_scanner = pc.get("scanner", "")
            pc_ts = pc.get("detected_at", "")
            if pc_id in RETIRED_CARD_IDS:
                continue
            if pc_scanner in {
                "docs-radar",
                "litellm",
                "lmarena",
                "cert-transparency",
                "gateway-radar",
                "ide-build-diff",
                "engine-pr-leak",
                "live-api-diff",
            } or pc_id.startswith("models-dev-diff-"):
                if not pc_ts or pc_ts >= cutoff_iso:
                    retained_event_cards.append(pc)

        raw_cards: List[Dict[str, Any]] = [
            *acp_cards, *ag_cards, *leak_cards, *arena_cards, *kr_cards, *docs_cards, *npm_cards, *retained_event_cards, *hf_cards, *ct_cards
        ]

        # Strict deduplication by card ID and by (scanner, header, model_ids_tuple)
        all_cards: List[Dict[str, Any]] = []
        seen_card_keys: Set[str] = set()
        for card in raw_cards:
            cid = card["id"]
            if cid in RETIRED_CARD_IDS:
                continue
            models_sig = ",".join(sorted(m.get("id", "") for m in card.get("models", [])))
            content_key = f"{card.get('scanner')}|{card.get('header')}|{models_sig}"
            if cid in seen_card_keys or content_key in seen_card_keys:
                continue
            seen_card_keys.add(cid)
            seen_card_keys.add(content_key)

            if cid in prev_timestamps and card.get("scanner") not in {"huggingface", "openrouter", "antigravity", "antigravity-acp", "cert-transparency-snapshot"}:
                card["detected_at"] = prev_timestamps[cid]

            card["x_post_text"] = build_x_post_text(card)
            all_cards.append(card)

        seen_ids = self.load_seen_ids()
        new_cards = [
            c for c in all_cards
            if c["id"] not in seen_ids and c.get("scanner") != "cert-transparency-snapshot"
        ]

        if notify_discord:
            cards_to_send = (
                new_cards
                if new_cards
                else (all_cards[:5] if "__discord_initialized__" not in seen_ids else [])
            )
            if cards_to_send:
                try:
                    sent = send_discord_webhook(cards_to_send[:10], github_user=self.github_user)
                    if sent:
                        seen_ids.add("__discord_initialized__")
                        print(f"[ModelPulse] Sent {min(len(cards_to_send), 10)} diff card(s) to Discord webhook.")
                except Exception as exc:
                    print(f"[ModelPulse] Discord notification skipped/failed: {exc}")

        for c in all_cards:
            seen_ids.add(c["id"])
        self.save_seen_ids(seen_ids)

        available_builds = self.ag_scanner.list_available_builds(max_stable=8)
        build_models_map = self.ag_scanner.get_build_models_map(max_stable=8)

        oss_count = sum(1 for c in all_cards if c.get("category") == "open-source")
        cli_count = sum(1 for c in all_cards if c.get("category") == "cli-sdk-diff")
        desk_count = sum(1 for c in all_cards if c.get("category") == "desktop-diff")
        ct_count = sum(1 for c in all_cards if c.get("category") == "subdomain-ct")

        feed_payload: Dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
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
