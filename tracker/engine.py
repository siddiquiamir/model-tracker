"""Core orchestration engine for ModelPulse."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import pathlib
from typing import Any, Dict, List, Optional, Set

from tracker.notifiers import build_x_post_text, send_discord_webhook
from tracker.scanners import (
    AntigravityDesktopScanner,
    DocsAndGlobalRegistryScanner,
    GitHubArchitectureRadarScanner,
    HuggingFaceOpenSourceScanner,
    KimiCodeAndRouterScanner,
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
        self.npm_scanner = NpmCliAndSdkScanner()
        self.kimi_router_scanner = KimiCodeAndRouterScanner()
        self.docs_scanner = DocsAndGlobalRegistryScanner()
        self.hf_scanner = HuggingFaceOpenSourceScanner()
        self.gh_scanner = GitHubArchitectureRadarScanner()

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

    def run_all_scans(self, notify_discord: bool = True) -> Dict[str, Any]:
        prev_timestamps = self.load_previous_timestamps()

        print("[ModelPulse] Scanning Antigravity Desktop builds (Stable + Insiders)...")
        ag_cards = self.ag_scanner.scan(max_stable=5)

        print("[ModelPulse] Scanning npm CLI & SDK packages (Claude Code, Codex, Google GenAI)...")
        npm_cards = self.npm_scanner.scan()

        print("[ModelPulse] Scanning Kimi Code CDN configs & OpenRouter live model registry...")
        kr_cards = self.kimi_router_scanner.scan()

        print("[ModelPulse] Scanning Cursor Docs, Anthropic/Gemini API Docs, models.dev & LiteLLM...")
        docs_cards = self.docs_scanner.scan()

        print("[ModelPulse] Scanning Hugging Face Hub frontier open-source orgs...")
        hf_cards = self.hf_scanner.scan()

        print("[ModelPulse] Scanning GitHub architecture radar (Transformers, vLLM, llama.cpp, LiteLLM, Azure, GCP, AWS)...")
        gh_cards = self.gh_scanner.scan()

        def _ag_sort_key(card: Dict[str, Any]) -> tuple:
            title = card.get("title", "").lower()
            if "gemini 4 argon" in title:
                return (0, card.get("id", ""))
            if "claude opus 5.5" in title or "claude sonnet 5.5" in title:
                return (1, card.get("id", ""))
            if "omni" in title or "robotics" in title:
                return (2, card.get("id", ""))
            return (3, card.get("id", ""))

        ag_cards.sort(key=_ag_sort_key)

        raw_cards: List[Dict[str, Any]] = [*ag_cards, *kr_cards, *docs_cards, *npm_cards, *hf_cards, *gh_cards]

        # Strict deduplication by card ID and by (scanner, build_transition, model_ids_tuple)
        all_cards: List[Dict[str, Any]] = []
        seen_card_keys: Set[str] = set()
        for card in raw_cards:
            cid = card["id"]
            models_sig = ",".join(sorted(m.get("id", "") for m in card.get("models", [])))
            content_key = f"{card.get('scanner')}|{card.get('header')}|{models_sig}"
            if cid in seen_card_keys or content_key in seen_card_keys:
                continue
            seen_card_keys.add(cid)
            seen_card_keys.add(content_key)

            # Preserve original detected_at if this exact card ID was already recorded
            if cid in prev_timestamps:
                card["detected_at"] = prev_timestamps[cid]

            card["x_post_text"] = build_x_post_text(card)
            all_cards.append(card)

        seen_ids = self.load_seen_ids()
        new_cards = [c for c in all_cards if c["id"] not in seen_ids]

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

        feed_payload: Dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "github_user": self.github_user,
            "stats": {
                "total_cards": len(all_cards),
                "desktop_diffs": len(ag_cards),
                "cli_sdk_diffs": len(npm_cards) + len(kr_cards) + len(docs_cards),
                "open_source_models": len(hf_cards) + len(gh_cards),
                "new_in_this_scan": len(new_cards),
                "total_models_indexed": sum(len(c.get("models", [])) for c in all_cards),
            },
            "available_antigravity_builds": [b["version"] for b in available_builds],
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
