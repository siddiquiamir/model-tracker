"""ModelPulse CLI & Local Dashboard Server (zero external dependencies)."""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pathlib
import sys
from urllib.parse import parse_qs, urlparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from tracker.engine import DOCS_FEED_FILE, ROOT_DIR, TrackerEngine

DOCS_DIR = ROOT_DIR / "docs"


class ModelPulseHandler(SimpleHTTPRequestHandler):
    """Serves docs/ static files plus live /api/scan and /api/diff endpoints."""

    engine = TrackerEngine(github_user=os.environ.get("GITHUB_USER", "siddiquiamir"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DOCS_DIR), **kwargs)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/diff":
            qs = parse_qs(parsed.query)
            old_ver = (qs.get("old") or [""])[0]
            new_ver = (qs.get("new") or [""])[0]
            try:
                cards = self.engine.custom_antigravity_diff(old_ver, new_ver)
                self._send_json({"cards": cards})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            try:
                feed = self.engine.run_all_scans(notify_discord=True)
                self._send_json(feed)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return
        self._send_json({"error": "Not found"}, status=404)


def print_cards_cli(cards: list) -> None:
    for card in cards:
        print("=" * 72)
        print(f"  {card['header']}")
        print(f"  {card['title']}  ({card.get('build_label', 'Build')}: {card['build_transition']})")
        print("-" * 72)
        for m in card.get("models", []):
            print(f"  • {m['name']} — {m['id']}")
        print(f"\n  Evidence: {card['evidence']}")
        print(f"  Source:   {card['source_text']}")
        print("=" * 72 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="ModelPulse — First-to-Report AI Model & Build Diff Tracker")
    parser.add_argument("--scan", action="store_true", help="Run all scanners once, update feed.json, and exit.")
    parser.add_argument("--diff", nargs=2, metavar=("OLD_VER", "NEW_VER"), help="Diff two Antigravity build versions.")
    parser.add_argument("--serve", action="store_true", help="Start local web dashboard server.")
    parser.add_argument("--port", type=int, default=8787, help="Port for local web dashboard (default: 8787).")
    args = parser.parse_args()

    engine = TrackerEngine(github_user=os.environ.get("GITHUB_USER", "siddiquiamir"))

    if args.diff:
        cards = engine.custom_antigravity_diff(args.diff[0], args.diff[1])
        print_cards_cli(cards)
        return

    if args.scan:
        feed = engine.run_all_scans(notify_discord=True)
        print(f"\n[ModelPulse] Scan complete! Generated {len(feed['cards'])} diff cards.")
        print_cards_cli(feed["cards"][:6])
        return

    # Default or --serve: ensure feed exists, then launch server
    if not DOCS_FEED_FILE.exists():
        engine.run_all_scans(notify_discord=False)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), ModelPulseHandler)
    print(f"\n🚀 ModelPulse Live Dashboard running at: http://localhost:{args.port}")
    print("   Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()


if __name__ == "__main__":
    main()
