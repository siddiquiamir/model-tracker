"""Offline unit tests for tracker.release_watcher (Antigravity, Codex CLI, Claude Code)."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from tracker import release_watcher as rw

SAMPLE_ANTIGRAVITY_MD = """# Changelog

## Antigravity App

### [v2.35.2](/releases?tab=hub&version=2.35.2 "View release 2.35.2")

Latest

November 25, 2026

### Switch models while a turn is running

This release lets you change the selected model while a turn is running.

**Fixes:**

*   Fixed an issue where the model selector was locked while a turn was running.

---

### [v2.35.1](/releases?tab=hub&version=2.35.1 "View release 2.35.1")

November 24, 2026

### Resume conversations after restart

**Improvements:**

*   Added automatic resumption on startup for active conversations.
*   Updated plugin panel links to open in the side panel.

**Fixes:**

*   Fixed uncompressed diagnostic uploads.

---

Model launch·November 18, 2026

### Gemini 4 Neon

Model launch blurb that should not pollute v2.35.1.

## Antigravity CLI

### [v1.5.16](/releases?tab=cli&version=1.5.16 "View release 1.5.16")

Latest

November 24, 2026

### Live step checklist and -r alias

**Improvements:**

*   Added `-r` and `--resume` flags.
*   Added live step checklist.
"""

SAMPLE_CODEX_RELEASES = [
    {
        "tag_name": "rust-v0.174.0-alpha.9",
        "name": "0.174.0-alpha.9",
        "draft": False,
        "prerelease": True,
        "published_at": "2026-11-27T16:56:00Z",
        "html_url": "https://github.com/openai/codex/releases/tag/rust-v0.174.0-alpha.9",
        "body": "Alpha stub",
    },
    {
        "tag_name": "rust-v0.172.0",
        "name": "0.172.0",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-11-24T00:03:55Z",
        "html_url": "https://github.com/openai/codex/releases/tag/rust-v0.172.0",
        "body": (
            "## New Features\n\n"
            "- Press `Tab` to complete arguments for supported slash commands. (#62343)\n"
            "- Optional stdio MCP servers start on their first tool call by default. (#62366)\n\n"
            "## Bug Fixes\n\n"
            "- `codex exec resume` restores saved sandbox permissions. (#62194)\n"
        ),
    },
    {
        "tag_name": "rust-v0.171.0-draft",
        "name": "draft",
        "draft": True,
        "prerelease": False,
        "published_at": "2026-11-20T00:00:00Z",
        "html_url": "https://github.com/openai/codex/releases/tag/rust-v0.171.0-draft",
        "body": "Should be ignored",
    },
]


def _make_large_claude_changelog(item_count: int = 155) -> str:
    bullets = [f"- Added item #{i} with complete detail that must not be dropped" for i in range(1, item_count + 1)]
    return (
        "# Changelog\n\n"
        "## 2.1.332\n\n"
        + "\n".join(bullets)
        + "\n\n## 2.1.331\n\n"
        "- Added Code Mode support in terminal sessions\n"
    )


class ReleaseWatcherTests(unittest.TestCase):
    def test_parse_antigravity_all_surfaces_verbatim(self) -> None:
        tracks = rw.parse_antigravity_changelog(SAMPLE_ANTIGRAVITY_MD)
        self.assertIn("antigravity:app", tracks)
        self.assertIn("antigravity:cli", tracks)

        app_releases = tracks["antigravity:app"]
        self.assertEqual([r.version for r in app_releases], ["v2.35.2", "v2.35.1"])
        self.assertEqual(app_releases[0].published_at, "November 25, 2026")
        self.assertEqual(app_releases[0].url, "https://antigravity.google/releases?tab=hub&version=2.35.2")
        self.assertIn("model selector was locked", app_releases[0].body_markdown)
        self.assertNotIn("Model launch blurb", app_releases[1].body_markdown)
        self.assertEqual(len(app_releases[1].bullet_items), 3)

        cli_releases = tracks["antigravity:cli"]
        self.assertEqual(cli_releases[0].version, "v1.5.16")
        self.assertEqual(len(cli_releases[0].bullet_items), 2)

    def test_parse_codex_filters_drafts_and_alphas_by_default(self) -> None:
        stable_only = rw.parse_codex_releases(SAMPLE_CODEX_RELEASES, include_prereleases=False)
        self.assertEqual(list(stable_only.keys()), ["codex:cli"])
        self.assertEqual(len(stable_only["codex:cli"]), 1)
        entry = stable_only["codex:cli"][0]
        self.assertEqual(entry.version, "rust-v0.172.0")
        self.assertEqual(len(entry.bullet_items), 3)
        self.assertIn("#62194", entry.body_markdown)

        with_alphas = rw.parse_codex_releases(SAMPLE_CODEX_RELEASES, include_prereleases=True)
        self.assertIn("codex:cli-alpha", with_alphas)
        self.assertEqual(with_alphas["codex:cli-alpha"][0].version, "rust-v0.174.0-alpha.9")

    def test_parse_claude_code_keeps_every_single_bullet(self) -> None:
        md = _make_large_claude_changelog(155)
        tracks = rw.parse_claude_code_changelog(md, dist_tags={"latest": "2.1.332", "stable": "2.1.326"})
        entries = tracks["claude-code:cli"]
        self.assertEqual([e.version for e in entries], ["v2.1.332", "v2.1.331"])
        self.assertEqual(len(entries[0].bullet_items), 155)
        self.assertIn("Added item #155", entries[0].body_markdown)
        self.assertEqual(entries[0].extra["npm_dist_tags"], ["latest"])

    def test_detect_new_releases_seed_then_chronological_catchup(self) -> None:
        tracks = rw.parse_antigravity_changelog(SAMPLE_ANTIGRAVITY_MD)

        # Initial run seeds only latest per track
        seeded, was_seed = rw.detect_new_releases(tracks, {"tracks": {}})
        self.assertTrue(was_seed)
        self.assertEqual({e.track_key: e.version for e in seeded}, {"antigravity:app": "v2.35.2", "antigravity:cli": "v1.5.16"})

        # When previously on v2.35.0, both v2.35.1 and v2.35.2 should emit oldest -> newest
        prior_state = {
            "tracks": {
                "antigravity:app": {"latest_version": "v2.35.0", "seen_versions": ["v2.35.0"]},
                "antigravity:cli": {"latest_version": "v1.5.16", "seen_versions": ["v1.5.16"]},
            }
        }
        new_items, was_seed2 = rw.detect_new_releases(tracks, prior_state)
        self.assertFalse(was_seed2)
        self.assertEqual([e.version for e in new_items], ["v2.35.1", "v2.35.2"])

    def test_tweet_length_always_within_280_chars(self) -> None:
        ag = rw.parse_antigravity_changelog(SAMPLE_ANTIGRAVITY_MD)["antigravity:app"][0]
        cx = rw.parse_codex_releases(SAMPLE_CODEX_RELEASES)["codex:cli"][0]
        cc = rw.parse_claude_code_changelog(_make_large_claude_changelog(155))["claude-code:cli"][0]

        for entry in (ag, cx, cc):
            tweet = rw.build_release_tweet(entry)
            self.assertLessEqual(len(tweet), 280, f"Tweet exceeded 280 chars for {entry.version}: {tweet}")
            self.assertIn(entry.version, tweet)

    def test_discord_notification_attaches_complete_verbatim_markdown(self) -> None:
        cc = rw.parse_claude_code_changelog(_make_large_claude_changelog(155))["claude-code:cli"][0]
        tweet = rw.build_release_tweet(cc)
        archive_md = rw.render_verbatim_release_markdown(cc, tweet)

        captured: dict = {}

        def fake_post(url: str, data: bytes, content_type: str) -> bool:
            captured["url"] = url
            captured["data"] = data
            captured["content_type"] = content_type
            return True

        ok = rw.send_release_discord_notification(
            cc,
            tweet=tweet,
            archive_content=archive_md,
            webhook_url="https://discord.com/api/webhooks/test/token",
            repo_slug="siddiquiamir/model-tracker",
            archive_relpath="claude-code/v2.1.332.md",
            poster=fake_post,
        )
        self.assertTrue(ok)
        self.assertIn("multipart/form-data; boundary=", captured["content_type"])
        raw_text = captured["data"].decode("utf-8")
        self.assertIn('filename="claude-code-v2.1.332.md"', raw_text)
        self.assertIn("Added item #155", raw_text)
        self.assertIn("Ready X Post Copy", raw_text)

    def test_run_check_writes_archives_index_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            state_file = tmp_path / "data" / "release_state.json"
            releases_dir = tmp_path / "releases"

            def fake_fetcher(include_codex_alphas: bool = False):
                tracks = {}
                tracks.update(rw.parse_antigravity_changelog(SAMPLE_ANTIGRAVITY_MD))
                tracks.update(rw.parse_codex_releases(SAMPLE_CODEX_RELEASES, include_prereleases=include_codex_alphas))
                tracks.update(rw.parse_claude_code_changelog(_make_large_claude_changelog(20)))
                return tracks, []

            res1 = rw.run_check(
                state_file=state_file,
                releases_dir=releases_dir,
                notify_discord=False,
                fetcher=fake_fetcher,
            )
            self.assertTrue(res1["was_initial_seed"])
            self.assertEqual(res1["new_count"], 4)
            self.assertTrue((releases_dir / "INDEX.md").exists())
            self.assertTrue((releases_dir / "antigravity-app" / "v2.35.2.md").exists())
            self.assertTrue((releases_dir / "codex-cli" / "rust-v0.172.0.md").exists())
            cc_archive = (releases_dir / "claude-code" / "v2.1.332.md").read_text(encoding="utf-8")
            self.assertIn("Added item #20", cc_archive)

            # Second run with no changes emits 0 new releases
            res2 = rw.run_check(
                state_file=state_file,
                releases_dir=releases_dir,
                notify_discord=False,
                fetcher=fake_fetcher,
            )
            self.assertFalse(res2["was_initial_seed"])
            self.assertEqual(res2["new_count"], 0)
            saved = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["tracks"]["claude-code:cli"]["latest_version"], "v2.1.332")


if __name__ == "__main__":
    unittest.main()
