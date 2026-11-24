"""Unit tests for provider attribution fixes, @StatsWire card rendering, and Discord PNG delivery."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from tracker.card_renderer import card_filename, render_alert_card_png
from tracker.extractor import infer_provider, is_legacy_model_id
from tracker.notifiers import build_multipart_webhook_body, build_story_embed, send_discord_webhook
from tracker.pricing import PricingCatalog
from tracker.stories import build_stories, story_key


class TestProviderAttributionAndCards(unittest.TestCase):
    def test_google_genie_and_lyria_story_stays_google(self) -> None:
        self.assertEqual(infer_provider("genie-4")["slug"], "google")
        self.assertEqual(infer_provider("lyria-realtime")["slug"], "google")
        self.assertEqual(infer_provider("gemini-4-neon")["slug"], "google")
        self.assertEqual(infer_provider("paper-volcano-vertex")["slug"], "google")
        self.assertEqual(infer_provider("beluga-thinking-high")["slug"], "google")
        self.assertEqual(infer_provider("narwhal")["slug"], "google")
        self.assertEqual(infer_provider("models/cobalt")["slug"], "openrouter")
        self.assertEqual(infer_provider("cobalt-preview")["slug"], "google")
        self.assertEqual(infer_provider("mai-image-2.7")["slug"], "microsoft")

        card = {
            "id": "vertex-quota-google-8ee555ac",
            "category": "cli-sdk-diff",
            "scanner": "vertex-ai-quotas",
            "header": "GOOGLE CLOUD QUOTA REGISTRY · GOOGLE",
            "title": "New GOOGLE Model(s) on Google Gemini API: genie-4, lyria-realtime",
            "models": [
                {"id": "genie-4", "name": "base_model:genie-4"},
                {"id": "lyria-realtime", "name": "base_model:lyria-realtime"},
            ],
            "provider_name": "GOOGLE",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
            "links": [{"label": "GCP Quotas", "url": "https://console.cloud.google.com/iam-admin/quotas"}],
            "detected_at": "2026-11-19T04:02:03+00:00",
        }
        stories = build_stories([card], pricing_catalog=PricingCatalog({}))
        self.assertEqual(len(stories), 1)
        st = stories[0]
        self.assertEqual(st["provider_slug"], "google")
        self.assertEqual(st["provider_name"], "Google")
        self.assertEqual(st["header"], "LEAK · GOOGLE")

    def test_unknown_second_variant_does_not_clobber_single_lab_story(self) -> None:
        card = {
            "id": "gw-gemini-decision",
            "category": "gateway-radar",
            "scanner": "gateway-radar",
            "header": "VERCEL AI GATEWAY CATALOG · GOOGLE",
            "title": "Gemini Decision 1",
            "models": [
                {"id": "gemini-decision-1", "name": "Gemini Decision 1"},
                {"id": "custom-unmapped-alias", "name": "Custom Alias"},
            ],
            "provider_name": "GOOGLE",
            "provider_slug": "google",
            "accent_color": "#38bdf8",
            "links": [{"label": "Vercel AI Gateway", "url": "https://ai-gateway.vercel.sh/v1/models"}],
            "detected_at": "2026-11-19T10:39:36+00:00",
        }
        stories = build_stories([card], pricing_catalog=PricingCatalog({}))
        self.assertEqual(stories[0]["provider_slug"], "google")
        self.assertEqual(stories[0]["provider_name"], "Google")

    def test_render_story_and_diff_cards_produce_valid_png(self) -> None:
        story = {
            "id": "story-genie-4",
            "group": "genie-4",
            "kind": "leak",
            "title": "Genie 4",
            "provider_slug": "google",
            "provider_name": "Google",
            "accent_color": "#38bdf8",
            "detected_at": "2026-11-19T04:02:03+00:00",
            "updated_at": "2026-11-19T04:02:03+00:00",
            "first_source": "Vertex AI Quotas registry",
            "pricing": "$1.50 / $9.00",
            "codenames": ["genie"],
            "models": [
                {"id": "genie-4", "name": "base_model:genie-4"},
                {"id": "lyria-realtime", "name": "base_model:lyria-realtime"},
            ],
            "sources": [
                {
                    "label": "Vertex AI Quotas registry",
                    "scanner": "vertex-ai-quotas",
                    "detected_at": "2026-11-19T04:02:03+00:00",
                    "title": "New GOOGLE Model(s) on Google Gemini API: genie-4, lyria-realtime",
                    "url": "https://console.cloud.google.com/iam-admin/quotas",
                }
            ],
            "source_count": 1,
            "header": "LEAK · GOOGLE",
            "x_post_text": "🚨 LEAK: Genie 4 by Google",
        }
        png = render_alert_card_png(story)
        self.assertIsNotNone(png)
        assert png is not None
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertGreater(len(png), 10_000)
        self.assertEqual(card_filename(story), "statswire-genie-4.png")

    def test_send_discord_webhook_attaches_png_card_multipart(self) -> None:
        story = {
            "id": "story-genie-4",
            "group": "genie-4",
            "kind": "leak",
            "title": "Genie 4",
            "provider_slug": "google",
            "provider_name": "Google",
            "accent_color": "#38bdf8",
            "detected_at": "2026-11-19T04:02:03+00:00",
            "updated_at": "2026-11-19T04:02:03+00:00",
            "first_source": "Vertex AI Quotas registry",
            "models": [{"id": "genie-4", "name": "Genie 4"}],
            "sources": [
                {
                    "label": "Vertex AI Quotas registry",
                    "scanner": "vertex-ai-quotas",
                    "detected_at": "2026-11-19T04:02:03+00:00",
                    "title": "New GOOGLE Model(s) on Google Gemini API: genie-4",
                    "url": "https://console.cloud.google.com/iam-admin/quotas",
                }
            ],
            "source_count": 1,
            "header": "LEAK · GOOGLE",
            "x_post_text": "🚨 LEAK: Genie 4 by Google",
        }

        captured = {}

        class _FakeResp:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def _fake_urlopen(req, timeout=20):
            captured["content_type"] = req.get_header("Content-type")
            captured["data"] = req.data
            return _FakeResp()

        with patch("tracker.notifiers.urllib.request.urlopen", side_effect=_fake_urlopen):
            ok = send_discord_webhook(
                [story],
                webhook_url="https://discord.com/api/webhooks/test/token",
                embed_builder=build_story_embed,
                attach_card=True,
            )

        self.assertTrue(ok)
        self.assertTrue(captured["content_type"].startswith("multipart/form-data; boundary="))
        self.assertIn(b'name="payload_json"', captured["data"])
        self.assertIn(b'name="files[0]"; filename="statswire-genie-4.png"', captured["data"])
        self.assertIn(b"attachment://statswire-genie-4.png", captured["data"])
        self.assertIn(b"\x89PNG\r\n\x1a\n", captured["data"])

        # Verify multipart helper structure directly
        body, ctype = build_multipart_webhook_body({"username": "Test"}, "card.png", b"\x89PNGtest")
        self.assertIn("multipart/form-data; boundary=", ctype)
        self.assertIn(b'"username": "Test"', body)
        self.assertIn(b"\x89PNGtest", body)

    def test_false_flag_guards_prevent_bare_gpt_merge_and_azure_claude_badge(self) -> None:
        # Bare family collisions must not merge gpt-default and gpt-chat-latest into "gpt"
        self.assertNotEqual(story_key("gpt-default"), "gpt")
        self.assertNotEqual(story_key("gpt-chat-latest"), "gpt")
        self.assertNotEqual(story_key("gpt-default"), story_key("gpt-chat-latest"))

        # Legacy / placeholder IDs are blocked from firing false leaks
        for bad in ("gpt-default", "gpt-chat-latest", "mistral-common", "gpt-5-1-codex-max-system-card", "imagen-4.0-generate"):
            self.assertTrue(is_legacy_model_id(bad), f"Expected legacy/placeholder: {bad}")

        # Host reseller (Azure) must not override Anthropic attribution on Claude models
        card = {
            "id": "ide-claude-mythos",
            "scanner": "ide-build-diff",
            "header": "IDE DIFF · AZURE",
            "title": "Claude Mythos 5.3",
            "models": [{"id": "claude-mythos-5-3", "name": "Claude Mythos 5.3"}],
            "provider_name": "Azure",
            "provider_slug": "azure",
            "accent_color": "#38bdf8",
            "detected_at": "2026-11-24T01:00:00+00:00",
        }
        stories = build_stories([card], pricing_catalog=PricingCatalog({}))
        self.assertEqual(stories[0]["provider_slug"], "anthropic")
        self.assertEqual(stories[0]["provider_name"], "Anthropic")


if __name__ == "__main__":
    unittest.main()
