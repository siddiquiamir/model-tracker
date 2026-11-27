"""Offline unit tests for tracker.release_watcher and PNG release cards."""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from tracker import card_renderer
from tracker import release_watcher as rw

SAMPLE_ANTIGRAVITY_MD = """# Changelog

## Antigravity App

### [v2.36.0](/releases?tab=hub&version=2.36.0 "View release 2.36.0")

Latest

November 27, 2026

### Floating composer in maximized panels, Auto mode edits, and voice context

This release adds a floating composer with live status inside maximized side panels.

**Improvements:**

*   Added a floating composer pill at the bottom of maximized side panels.
*   Expanded Auto mode to automatically approve safe file edits in other version-controlled repositories.
*   Added discovery for custom skills stored in `~/.agents/skills`, with skills in `~/.gemini` taking precedence.

---

### [v2.35.2](/releases?tab=hub&version=2.35.2 "View release 2.35.2")

November 25, 2026

### Switch models while a turn is running

**Fixes:**

*   Fixed an issue where the model selector was locked while a turn was running before `/btw`.

---

Model launch·November 18, 2026

### Gemini 4 Neon

Model launch blurb that should not pollute v2.35.2.

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
            "- Press `Tab` to complete arguments for supported slash commands like `/mcp`. (#62343)\n"
            "- Optional stdio MCP servers start on their first tool call by default. (#62366)\n\n"
            "## Chores\n\n"
            "- The `code_mode_host_grpc` setting is deprecated in favor of gRPC. (#62476)\n"
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

SAMPLE_CODEX_COMPARE = {
    "ahead_by": 42,
    "html_url": "https://github.com/openai/codex/compare/rust-v0.172.0...rust-v0.174.0-alpha.9",
    "commits": [
        {
            "sha": "1111111abcdef",
            "commit": {"message": "Bump version to 0.174.0-alpha.8"},
            "author": {"login": "bot"},
        },
        {
            "sha": "2222222abcdef",
            "commit": {"message": "Add MCP OAuth refresh support (#63001)\n\nDetailed body"},
            "author": {"login": "oai-dev"},
        },
        {
            "sha": "3333333abcdef",
            "commit": {"message": "Support --worktree flag in codex exec (#63012)"},
            "author": {"login": "oai-dev2"},
        },
    ],
}

SAMPLE_CURSOR_HTML = """
<html><body>
<article>
  <div><p><a href="/changelog/voice-chat"><time dateTime="2026-11-06T00:00:00.000Z">Nov 6, 2026</time></a></p></div>
  <div><div>
    <header><h1><a href="/changelog/voice-chat">Voice Chat with Agents</a></h1></header>
    <div class="prose prose--block">
      <p>You can now talk with your agents in a realtime voice call.</p>
      <h2><a class="anchor-link" href="#start">#</a>Start a call</h2>
      <ul>
        <li>Click <strong>Start voice chat</strong> to talk hands-free with MCP tools.</li>
        <li>Say <code>Hey Siri, call Cursor</code> on iOS.</li>
      </ul>
    </div>
  </div></div>
</article>
</body></html>
"""


def _make_large_claude_changelog(item_count: int = 155) -> str:
    bullets = [
        "- Added skills from MCP servers (beta). They show as `server:skill` in the `/` menu",
        "- Added a `PreSkillShellCommand` hook event that can refuse inline shell commands",
        "- Changed `sonnet` on Google Cloud Agent Platform to read `VERTEX_REGION_CLAUDE_5_5_SONNET` and retired Sonnet 4",
        "- Fixed `--effort` being ignored with `--environment` when using `/autocompact`",
    ]
    while len(bullets) < item_count:
        idx = len(bullets) + 1
        bullets.append(f"- Added item #{idx} with complete detail that must not be dropped")
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
        self.assertEqual([r.version for r in app_releases], ["v2.36.0", "v2.35.2"])
        self.assertEqual(app_releases[0].published_at, "November 27, 2026")
        self.assertIn("~/.agents/skills", app_releases[0].body_markdown)
        self.assertNotIn("Model launch blurb", app_releases[1].body_markdown)

    def test_parse_codex_and_alpha_radar(self) -> None:
        stable_only = rw.parse_codex_releases(SAMPLE_CODEX_RELEASES, include_prereleases=False)
        self.assertEqual(list(stable_only.keys()), ["codex:cli"])
        self.assertEqual(stable_only["codex:cli"][0].version, "rust-v0.172.0")

        radar = rw.build_codex_alpha_radar_entry(
            stable_tag="rust-v0.172.0",
            alpha_tag="rust-v0.174.0-alpha.9",
            alpha_published_at="2026-11-27T16:56:00Z",
            compare_json=SAMPLE_CODEX_COMPARE,
        )
        self.assertIsNotNone(radar)
        assert radar is not None
        self.assertEqual(radar.track_key, "codex:alpha-radar")
        # Version bump commit filtered; 2 real PR commits kept newest-first
        self.assertEqual(len(radar.bullet_items), 2)
        self.assertIn("--worktree", radar.bullet_items[0])
        self.assertIn("MCP OAuth", radar.bullet_items[1])

    def test_parse_cursor_changelog_html(self) -> None:
        tracks = rw.parse_cursor_changelog_html(SAMPLE_CURSOR_HTML)
        self.assertIn("cursor:changelog", tracks)
        entry = tracks["cursor:changelog"][0]
        self.assertEqual(entry.version, "voice-chat")
        self.assertEqual(entry.published_at, "2026-11-06")
        self.assertEqual(entry.title, "Voice Chat with Agents")
        self.assertEqual(entry.url, "https://cursor.com/changelog/voice-chat")
        self.assertIn("realtime voice call", entry.body_markdown)
        self.assertEqual(len(entry.bullet_items), 2)

    def test_parse_claude_code_buried_gems_and_convergence(self) -> None:
        md = _make_large_claude_changelog(155)
        tracks = rw.parse_claude_code_changelog(md, dist_tags={"latest": "2.1.332", "stable": "2.1.326"})
        entry = tracks["claude-code:cli"][0]
        self.assertEqual(len(entry.bullet_items), 155)
        self.assertIn("Added item #155", entry.body_markdown)

        gems = rw.extract_buried_gems(entry)
        self.assertIn("PreSkillShellCommand", gems["hooks_and_keys"])
        self.assertIn("--effort", gems["cli_flags"])
        self.assertIn("/autocompact", gems["slash_commands"])
        self.assertIn("VERTEX_REGION_CLAUDE_5_5_SONNET", gems["env_vars"])
        self.assertTrue(any("retired" in s.lower() for s in gems["model_and_breaking"]))

        tags = rw.extract_convergence_tags(entry)
        self.assertIn("skills", tags)
        self.assertIn("mcp", tags)
        self.assertIn("hooks", tags)

    def test_tweet_length_always_within_280_chars(self) -> None:
        ag = rw.parse_antigravity_changelog(SAMPLE_ANTIGRAVITY_MD)["antigravity:app"][0]
        cx = rw.parse_codex_releases(SAMPLE_CODEX_RELEASES)["codex:cli"][0]
        cc = rw.parse_claude_code_changelog(_make_large_claude_changelog(155))["claude-code:cli"][0]
        cu = rw.parse_cursor_changelog_html(SAMPLE_CURSOR_HTML)["cursor:changelog"][0]

        for entry in (ag, cx, cc, cu):
            tweet = rw.build_release_tweet(entry)
            self.assertLessEqual(len(tweet), 280, f"Tweet exceeded 280 chars for {entry.version}: {tweet}")
            self.assertIn(entry.version, tweet)

    def test_release_card_png_and_discord_dual_attachment(self) -> None:
        cc = rw.parse_claude_code_changelog(_make_large_claude_changelog(155))["claude-code:cli"][0]
        tweet = rw.build_release_tweet(cc)
        gems = rw.extract_buried_gems(cc)
        tags = rw.extract_convergence_tags(cc)
        archive_md = rw.render_verbatim_release_markdown(cc, tweet, gems=gems, convergence_tags=tags)

        if card_renderer.Image is not None:
            png = card_renderer.render_release_card_png(
                display_name=cc.display_name,
                version=cc.version,
                provider_slug="anthropic",
                org_label="Anthropic",
                badge_text="NEW RELEASE",
                item_count=155,
                subtitle="Published 2026-11-28",
                highlights=rw._select_highlight_bullets(cc, 4),
                gem_chips=rw.flatten_gem_chips(gems, 5),
                timestamp_iso="2026-11-28T00:00:00Z",
            )
            self.assertIsNotNone(png)
            assert png is not None
            self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))

        captured: dict = {}

        def fake_post(url: str, data: bytes, content_type: str) -> bool:
            captured["data"] = data
            captured["content_type"] = content_type
            return True

        ok = rw.send_release_discord_notification(
            cc,
            tweet=tweet,
            archive_content=archive_md,
            gems=gems,
            convergence_tags=tags,
            webhook_url="https://discord.com/api/webhooks/test/token",
            repo_slug="siddiquiamir/model-tracker",
            archive_relpath="claude-code/v2.1.332.md",
            attach_png=True,
            poster=fake_post,
        )
        self.assertTrue(ok)
        self.assertIn("multipart/form-data; boundary=", captured["content_type"])
        raw_bytes: bytes = captured["data"]
        self.assertIn(b'filename="claude-code-v2.1.332.md"', raw_bytes)
        self.assertIn(b"Added item #155", raw_bytes)
        if card_renderer.Image is not None:
            self.assertIn(b'filename="statswire-claude-code-v2.1.332.png"', raw_bytes)
            self.assertIn(b"\x89PNG\r\n\x1a\n", raw_bytes)

    def test_run_check_writes_archives_index_state_and_docs_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            state_file = tmp_path / "data" / "release_state.json"
            releases_dir = tmp_path / "releases"
            docs_json = tmp_path / "docs" / "data" / "releases.json"

            def fake_fetcher(include_codex_alphas: bool = True):
                tracks = {}
                tracks.update(rw.parse_antigravity_changelog(SAMPLE_ANTIGRAVITY_MD))
                tracks.update(rw.parse_codex_releases(SAMPLE_CODEX_RELEASES))
                tracks.update(rw.parse_claude_code_changelog(_make_large_claude_changelog(20)))
                tracks.update(rw.parse_cursor_changelog_html(SAMPLE_CURSOR_HTML))
                return tracks, []

            res1 = rw.run_check(
                state_file=state_file,
                releases_dir=releases_dir,
                docs_json_file=docs_json,
                notify_discord=False,
                fetcher=fake_fetcher,
            )
            self.assertTrue(res1["was_initial_seed"])
            self.assertEqual(res1["new_count"], 5)
            self.assertTrue(docs_json.exists())

            radar_data = json.loads(docs_json.read_text(encoding="utf-8"))
            self.assertEqual(len(radar_data["releases"]), 5)
            self.assertTrue(any(a["id"] == "skills" and len(a["releases"]) >= 2 for a in radar_data["convergence_axes"]))
            cc_item = next(r for r in radar_data["releases"] if r["track_key"] == "claude-code:cli")
            self.assertIn("Added item #20", cc_item["body_markdown"])

            # Second run is idempotent
            res2 = rw.run_check(
                state_file=state_file,
                releases_dir=releases_dir,
                docs_json_file=docs_json,
                notify_discord=False,
                fetcher=fake_fetcher,
            )
            self.assertEqual(res2["new_count"], 0)

    def test_parse_xai_grok_build_bot_and_api(self) -> None:
        gb_html = """
        <article>
          <div><time dateTime="2026-11-19">Nov 19, 2026</time><span>v<!-- -->1.0.92</span></div>
          <div>
            <h2 id="v1.0.92-2026-11-19">Grok Build <!-- -->1.0.92</h2>
            <ul>
              <li><span>MCP tool results that contain images now include those images in headless JSON output</span></li>
              <li><span><code>grok inspect</code> now shows loaded hooks with folder trust notes</span></li>
            </ul>
          </div>
        </article>
        """
        gb = rw.parse_xai_changelog_html(
            gb_html,
            track_key="grok:build",
            product_family="grok-build",
            display_name="xAI Grok Build",
            folder_slug="grok-build",
            base_url="https://x.ai/changelog/build",
        )
        self.assertIn("grok:build", gb)
        self.assertEqual(gb["grok:build"][0].version, "v1.0.92")
        self.assertEqual(len(gb["grok:build"][0].bullet_items), 2)

        bot_html = """
        <article>
          <div><time dateTime="2026-11-24">Nov 24, 2026</time><a href="#v1.3.0">v<!-- -->1.3.0</a></div>
          <div>
            <h2 id="v1.3.0">Smarter Slack Bots, restock alerts, org controls</h2>
            <section><h3>New</h3><ul><li><span>Bot handoffs return answers in Slack DMs</span></li></ul></section>
          </div>
        </article>
        """
        bot = rw.parse_xai_changelog_html(
            bot_html,
            track_key="grok:bot",
            product_family="grok-bot",
            display_name="xAI Grok Bot",
            folder_slug="grok-bot",
            base_url="https://x.ai/changelog/bot",
        )
        self.assertEqual(bot["grok:bot"][0].version, "v1.3.0")
        self.assertEqual(bot["grok:bot"][0].title, "Smarter Slack Bots, restock alerts, org controls")

        api_md = "## November\n\n### grok-build-0.1 end of life\n\n`grok-build-0.1` reached end of life on November 19, 2026.\n"
        api = rw.parse_xai_api_release_notes(api_md)
        self.assertIn("grok:api", api)
        self.assertEqual(api["grok:api"][0].title, "grok-build-0.1 end of life")

    def test_parse_deepseek_repo_and_hf_models(self) -> None:
        commit = {
            "sha": "abc1234deadbeef",
            "commit": {"message": "Public release 26/11/26 (#525)", "author": {"date": "2026-11-26T09:25:25Z"}},
        }
        pr = {
            "number": 525,
            "title": "Public release 26/11/26",
            "html_url": "https://github.com/deepseek-ai/DeepGEMM/pull/525",
            "additions": 10505,
            "deletions": 2788,
            "changed_files": 93,
            "body": "- Added `batched_bf16_newton_schulz` and `FP8StochasticRounding`",
        }
        files = [{"status": "added", "additions": 400, "deletions": 0, "filename": "csrc/newton_schulz.cuh"}]
        entry = rw.build_deepseek_repo_entry("DeepGEMM", commit, pr_json=pr, pr_files=files)
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.track_key, "deepseek:deepgemm")
        self.assertIn("batched_bf16_newton_schulz", entry.body_markdown)
        self.assertIn("csrc/newton_schulz.cuh", entry.body_markdown)

        hf = rw.parse_deepseek_hf_models(
            [{"id": "deepseek-ai/DeepSeek-V4.1-Flash-1017", "createdAt": "2026-10-17T02:40:38.000Z", "tags": ["fp8"]}]
        )
        self.assertEqual(hf["deepseek:hf-models"][0].version, "DeepSeek-V4.1-Flash-1017")


if __name__ == "__main__":
    unittest.main()
