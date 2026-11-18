import io
import json
import hashlib
import os
from contextlib import ExitStack
import tarfile
import pathlib
import tempfile
import struct
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from tracker.intelligence import DevinCliScanner, ModelRegistryScanner, ModelsDevApiScanner, ModelsDevGitScanner, IdentityLedger, archive_members, classify_known, compact_evidence, desktop_builds, evidence_confidence, extract_registry, family, historical_backfill, intelligence_metrics, reconcile_identities, registry_diff, verify_digest, _read, _trusted_url


class CloudBillingTests(unittest.TestCase):
    def test_missing_credentials_are_visible_without_network_requests(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        with patch.dict(os.environ, {}, clear=True), patch.object(scanner, "_mint_gcp_bearer_token", return_value=("", "")), patch("tracker.scanners._http_get_json") as fetch:
            self.assertEqual(scanner._scan_cloud_billing_skus({}, set()), ([], False))
            self.assertEqual(scanner._scan_live_provider_apis({}), ([], False))
        fetch.assert_not_called()
        for source in ("cloud-billing", "gemini-v1alpha", "gemini-v1beta"):
            self.assertEqual(scanner.source_health[source]["status"], "disabled")
            self.assertEqual(scanner.source_health[source]["reason"], "missing_credentials")

    def test_vertex_service_matches_public_catalog(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        self.assertEqual(HighAlphaLeakChannelsScanner.VERTEX_BILLING_SERVICE_ID, "C7E2-9256-1C43")

    def test_billing_words_are_not_model_suffixes(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        for description in ("Generate content input token count gemini 4 carbon text batch", "Gemini 4 Carbon Online Prediction Text Output", "Gemini 4 Carbon audio caching"):
            with self.subTest(description=description):
                self.assertEqual([model.lower() for model in HighAlphaLeakChannelsScanner._BILLING_SKU_MODEL_RE.findall(description)], ["gemini 4 carbon"])
        self.assertEqual(HighAlphaLeakChannelsScanner._BILLING_SKU_MODEL_RE.findall("Gemini 6 Unfamiliar Online Prediction"), ["Gemini 6 Unfamiliar"])
        self.assertEqual(HighAlphaLeakChannelsScanner._BILLING_SKU_MODEL_RE.findall("Gemini 4 Carbon Cyber Permissive Global Text Input - Online Predictions"), ["Gemini 4 Carbon Cyber Permissive"])
        self.assertEqual(HighAlphaLeakChannelsScanner._BILLING_SKU_MODEL_RE.findall("Gemini 4 Carbon Regional Text Input Caching Batch"), ["Gemini 4 Carbon"])

    def test_first_scan_surfaces_unknown_families_when_reference_catalog_exists(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        page = {"skus": [{"description": "Gemini 4 Argon Global Text Input"}, {"description": "Gemini 4 Carbon Cyber Permissive Global Text Input"}]}
        with patch.object(scanner, "_mint_gcp_bearer_token", return_value=("test-token", "test")), patch("tracker.scanners._http_get_json", return_value=page):
            cards, changed = scanner._scan_cloud_billing_skus({}, {"gemini4argon"})
        self.assertTrue(changed)
        self.assertEqual([model["id"] for card in cards for model in card["models"]], ["gemini-4-carbon-cyber-permissive"])

    def test_complete_catalog_aggregates_family_and_qualifies_availability(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        baselines = {"cloud_billing_skus": {"seen_model_families": ["gemini-4-argon"]}}
        pages = [{"skus": [{"description": "Gemini 4 Carbon Online Prediction Text Input"}], "nextPageToken": "second"}, {"skus": [{"description": "Gemini 4 Carbon Batch Prediction Text Output"}]}]
        with patch.object(scanner, "_mint_gcp_bearer_token", return_value=("test-token", "test")), patch("tracker.scanners._http_get_json", side_effect=pages):
            cards, changed = scanner._scan_cloud_billing_skus(baselines, set())
        self.assertTrue(changed)
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["models"][0]["id"], "gemini-4-carbon")
        self.assertEqual(baselines["cloud_billing_skus"]["sku_counts"]["gemini-4-carbon"], 2)
        self.assertEqual(len(cards[0]["sku_samples"]), 2)
        self.assertIn("not confirmation", cards[0]["disclaimer_1"])

    def test_incomplete_pages_do_not_advance_baseline(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        initial = {"cloud_billing_skus": {"seen_model_families": ["gemini-4-argon"], "sku_counts": {"gemini-4-argon": 1}}}
        for last_page in (RuntimeError("temporary failure"), {}, {"skus": "invalid"}):
            with self.subTest(last_page=last_page):
                baselines = json.loads(json.dumps(initial))
                pages = [{"skus": [{"description": "Gemini 4 Carbon"}], "nextPageToken": "second"}, last_page]
                with patch.object(scanner, "_mint_gcp_bearer_token", return_value=("test-token", "test")), patch("tracker.scanners._http_get_json", side_effect=pages):
                    cards, changed = scanner._scan_cloud_billing_skus(baselines, set())
                self.assertEqual(cards, [])
                self.assertFalse(changed)
                self.assertEqual(baselines, initial)

    def test_page_limit_does_not_save_partial_catalog(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        pages = [{"skus": [{"description": "Gemini 4 Carbon"}], "nextPageToken": str(index + 1)} for index in range(15)]
        baselines = {}
        with patch.object(scanner, "_mint_gcp_bearer_token", return_value=("test-token", "test")), patch("tracker.scanners._http_get_json", side_effect=pages):
            cards, changed = scanner._scan_cloud_billing_skus(baselines, set())
        self.assertEqual((cards, changed, baselines), ([], False, {}))

    def test_repeated_page_token_does_not_save_partial_catalog(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        page = {"skus": [{"description": "Gemini 4 Carbon"}], "nextPageToken": "repeated"}
        baselines = {}
        with patch.object(scanner, "_mint_gcp_bearer_token", return_value=("test-token", "test")), patch("tracker.scanners._http_get_json", return_value=page) as fetch:
            cards, changed = scanner._scan_cloud_billing_skus(baselines, set())
        self.assertEqual((cards, changed, baselines), ([], False, {}))
        self.assertEqual(fetch.call_count, 2)

    def test_keyless_public_billing_fallback_preserves_disabled_api_health_and_fails_closed(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        baselines = {"cloud_billing_skus": {"seen_model_families": ["gemini-4-argon"], "sku_counts": {"gemini-4-argon": 1}}}
        with patch.dict(os.environ, {}, clear=True), patch.object(scanner, "_mint_gcp_bearer_token", return_value=("", "")):
            self.assertEqual(scanner._scan_cloud_billing_skus(baselines, set()), ([], False))
            with patch.object(scanner, "_fetch_keyless_public_skus", side_effect=RuntimeError("rpc error")):
                self.assertEqual(scanner._scan_public_cloud_billing_skus(baselines, set()), ([], False))
            self.assertEqual(scanner.source_health["cloud-billing"]["status"], "disabled")
            self.assertEqual(scanner.source_health["cloud-billing-public"]["status"], "failed")
            self.assertEqual(baselines["cloud_billing_skus"]["sku_counts"], {"gemini-4-argon": 1})

            sample_skus = [{"skuId": "sku-1", "rawDescription": "Gemini 4 Carbon Online Prediction Text Input", "description": "Gemini 4 Carbon Online Prediction Text Input ($1.00)"}]
            with patch.object(scanner, "_fetch_keyless_public_skus", return_value=sample_skus):
                cards, changed = scanner._scan_public_cloud_billing_skus(baselines, set())
            self.assertTrue(changed)
            self.assertEqual(scanner.source_health["cloud-billing-public"]["status"], "ok")
            self.assertEqual(cards[0]["models"][0]["id"], "gemini-4-carbon")
            self.assertEqual(baselines["cloud_billing_skus"]["sku_counts"], {"gemini-4-argon": 1, "gemini-4-carbon": 1})


class GoogleNpmTests(unittest.TestCase):
    def test_cli_and_core_are_registered(self):
        from tracker.scanners import NpmCliAndSdkScanner

        packages = {config["pkg"] for config in NpmCliAndSdkScanner.PACKAGES}
        self.assertTrue({"@google/genai", "@google/gemini-cli", "@google/gemini-cli-core"} <= packages)

    def test_single_tag_change_is_detected_once_across_scans(self):
        from tracker.scanners import NpmCliAndSdkScanner

        scanner = NpmCliAndSdkScanner()
        config = next(config for config in scanner.PACKAGES if config["pkg"] == "@google/gemini-cli-core")
        observed = {}
        metadata = {"version": "1.0.0", "dist": {"tarball": "https://registry.npmjs.org/core.tgz"}}
        with patch("tracker.scanners._http_get_json", return_value=metadata), patch.object(scanner, "_extract_npm_tarball_models", return_value={"gemini-4-argon"}):
            self.assertEqual(scanner.scan_package(config, {}, set(), observed), [])
        metadata["version"] = "1.0.1"
        models = {"gemini-4-argon", "gemini-4-carbon", "gemini-4-carbon-preview"}
        with patch("tracker.scanners._http_get_json", return_value=metadata), patch.object(scanner, "_extract_npm_tarball_models", return_value=models):
            cards = scanner.scan_package(config, {}, set(), observed)
            self.assertEqual({model["id"] for model in cards[0]["models"]}, models - {"gemini-4-argon"})
            self.assertEqual(scanner.scan_package(config, {}, set(), observed), [])

    def test_track_changes_do_not_reannounce_models_or_truncate_evidence(self):
        from tracker.scanners import NpmCliAndSdkScanner

        scanner = NpmCliAndSdkScanner()
        config = next(config for config in scanner.PACKAGES if config["pkg"] == "@google/gemini-cli")
        observed = {config["pkg"]: {"version": "1.0.0", "models": ["gemini-4-argon"]}}
        metadata = [{"version": version, "dist": {"tarball": "https://registry.npmjs.org/core.tgz"}} for version in ("1.0.0", "1.1.0-preview", "1.2.0-nightly")]
        added = {f"gemini-4-carbon-variant-{index}" for index in range(12)}
        with patch("tracker.scanners._http_get_json", side_effect=metadata), patch.object(scanner, "_extract_npm_tarball_models", side_effect=[{"gemini-4-argon"}, added, {"gemini-4-argon"}]):
            cards = scanner.scan_package(config, {}, set(), observed)
        self.assertEqual(len(cards), 1)
        self.assertEqual({model["id"] for model in cards[0]["models"]}, added)

    def test_failed_tarball_does_not_consume_pending_identifiers(self):
        from tracker.scanners import NpmCliAndSdkScanner

        scanner = NpmCliAndSdkScanner()
        config = next(config for config in scanner.PACKAGES if config["pkg"] == "@google/gemini-cli")
        observed = {config["pkg"]: {"version": "1.0.0", "models": ["gemini-4-argon"]}}
        initial = json.loads(json.dumps(observed))
        metadata = [{"version": version, "dist": {"tarball": "https://registry.npmjs.org/core.tgz"}} for version in ("1.0.1", "1.1.0-preview", "1.2.0-nightly")]
        with patch("tracker.scanners._http_get_json", side_effect=metadata), patch.object(scanner, "_extract_npm_tarball_models", side_effect=[{"gemini-4-carbon"}, RuntimeError("download failed")]):
            with self.assertRaises(RuntimeError):
                scanner.scan_package(config, {}, set(), observed)
        self.assertEqual(observed, initial)


class GeminiApiTests(unittest.TestCase):
    def test_pagination_catches_later_identifiers_without_leaking_keys(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        added = {f"gemini-4-carbon-variant-{index}" for index in range(12)}
        pages = [{"models": [{"name": "models/gemini-4-argon"}], "nextPageToken": "second"}, {"models": [{"name": "models/" + model} for model in sorted(added)]}, {"models": []}]
        baselines = {"live_provider_api_models": {"gemini": ["gemini-4-argon"]}}
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-credential"}, clear=True), patch("tracker.scanners._http_get_json", side_effect=pages) as fetch:
            cards, changed = scanner._scan_live_provider_apis(baselines)
        self.assertTrue(changed)
        self.assertEqual({model["id"] for model in cards[0]["models"]}, added)
        self.assertIn("pageToken=second", fetch.call_args_list[1].args[0])
        for call in fetch.call_args_list:
            self.assertNotIn("test-credential", call.args[0])
            self.assertEqual(call.kwargs["extra_headers"]["x-goog-api-key"], "test-credential")

    def test_failed_version_does_not_forget_old_sightings_or_save_partial_pages(self):
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        baselines = {"live_provider_api_models": {"gemini": ["gemini-4-argon", "gemini-4-carbon"]}}
        initial = json.loads(json.dumps(baselines))
        pages = [{"models": [{"name": "models/gemini-4-future"}], "nextPageToken": "second"}, RuntimeError("failed page"), {"models": [{"name": "models/gemini-4-argon"}]}]
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-credential"}, clear=True), patch("tracker.scanners._http_get_json", side_effect=pages):
            cards, changed = scanner._scan_live_provider_apis(baselines)
        self.assertEqual((cards, changed, baselines), ([], False, initial))


class StoryAlertTests(unittest.TestCase):
    def test_only_new_evidence_or_identifiers_need_new_receipts(self):
        from tracker.engine import _story_alert_marks

        original = {"id": "story-carbon", "kind": "leak", "card_ids": ["npm-old"], "models": [{"id": "gemini-4-carbon"}]}
        receipts = _story_alert_marks(original)
        self.assertEqual(_story_alert_marks({**original, "updated_at": "later"}), receipts)
        self.assertFalse(_story_alert_marks({**original, "card_ids": ["npm-old", "billing-new"]}) <= receipts)
        self.assertFalse(_story_alert_marks({**original, "models": [{"id": "gemini-4-carbon-preview"}]}) <= receipts)
        self.assertTrue(_story_alert_marks({**original, "card_ids": []}) <= receipts)
        self.assertIn("story-carbon#release", _story_alert_marks({**original, "kind": "release"}))

    def test_existing_intelligence_story_migration_is_silent_and_failed_new_evidence_retries(self):
        from tracker.engine import TrackerEngine

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = pathlib.Path(directory)
            engine = TrackerEngine()
            engine.intelligence_scanners = []
            timestamp = datetime.now(timezone.utc).isoformat()
            story = {"id": "story-carbon", "kind": "unverified", "intelligence_only": True, "card_ids": ["npm-old"], "models": [{"id": "gemini-4-carbon"}], "updated_at": timestamp, "detected_at": timestamp, "backfill": False}
            (root / "data").mkdir()
            (root / "data/feed.json").write_text(json.dumps({"stories": [story], "cards": []}), encoding="utf-8")
            (root / "data/seen_ids.json").write_text(json.dumps([story["id"]]), encoding="utf-8")
            for name, path in {"ROOT_DIR": root, "DATA_DIR": root / "data", "DOCS_DATA_DIR": root / "docs/data", "FEED_FILE": root / "data/feed.json", "DOCS_FEED_FILE": root / "docs/data/feed.json", "SEEN_FILE": root / "data/seen_ids.json", "SCANNER_RUNS_FILE": root / "cache/runs.json"}.items():
                stack.enter_context(patch("tracker.engine." + name, path))
            for attribute in ("ag_scanner", "ag_acp_scanner", "npm_scanner", "kimi_router_scanner", "docs_scanner", "arena_scanner", "hf_scanner", "high_alpha_scanner", "openai_spec_scanner"):
                stack.enter_context(patch.object(getattr(engine, attribute), "scan", return_value=[]))
            stack.enter_context(patch("tracker.engine._public_names_snapshot", return_value=[]))
            stack.enter_context(patch("tracker.engine.novelty.get_catalog", return_value=None))
            pricing = type("Pricing", (), {"lookup": lambda self, raw: ""})()
            stack.enter_context(patch("tracker.engine.pricing_mod.get_pricing_catalog", return_value=pricing))
            stack.enter_context(patch("tracker.engine.pricing_mod.enrich_cards_with_pricing"))
            stack.enter_context(patch("tracker.engine.story_mod.story_x_text", return_value="draft"))
            stories = stack.enter_context(patch("tracker.engine.story_mod.build_stories", return_value=[story]))
            send = stack.enter_context(patch("tracker.engine.send_discord_webhook", side_effect=[False, True]))
            stack.enter_context(patch.dict(os.environ, {"DISCORD_WEBHOOK_URL": "https://example.invalid/webhook"}))
            engine.run_all_scans()
            send.assert_not_called()
            stories.return_value = [{**story, "card_ids": ["npm-old", "billing-new"]}]
            engine.run_all_scans()
            self.assertEqual(send.call_count, 1)
            engine.run_all_scans()
            self.assertEqual(send.call_count, 2)
            engine.run_all_scans()
            self.assertEqual(send.call_count, 2)


class RegistryTests(unittest.TestCase):
    def test_unsupported_krypton_card_is_retired_not_future_sightings(self):
        from tracker.engine import _is_retired_card
        from tracker.extractor import infer_provider

        self.assertTrue(_is_retired_card({"id": "google-internal-registry-krypton", "scanner": "web-bundle-diff"}))
        self.assertFalse(_is_retired_card({"id": "web-bundle-aistudio-models-new", "scanner": "web-bundle-diff", "models": [{"id": "krypton"}]}))
        self.assertNotEqual(infer_provider("krypton")["slug"], "google")
        self.assertNotEqual(infer_provider("krypton-a")["slug"], "google")

    def test_krypton_story_does_not_invent_gemini_generation(self):
        from tracker.stories import build_stories

        card = {"id": "intel-krypton", "scanner": "devin-cli", "intelligence": True, "family": "krypton", "title": "krypton", "header": "NEW IDENTIFIER", "provider_slug": "unknown", "provider_name": "Unattributed", "event_label": "New identifier", "detected_at": datetime.now(timezone.utc).isoformat(), "models": [{"id": "krypton"}], "links": []}
        pricing = type("Pricing", (), {"lookup": lambda self, raw: ""})()
        story = build_stories([card], pricing_catalog=pricing)[0]
        self.assertNotEqual(story["title"], "Gemini 4 Krypton")
        self.assertEqual(story["provider_name"], "Unattributed")

    def test_cross_source_state_is_read_once_per_ingestion(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = ModelRegistryScanner(pathlib.Path(directory))
            scanner.source = "devin-cli"
            scanner.label = "CLI"
            records = {"first": {"file_sha256": "first"}, "second": {"file_sha256": "second"}}
            with patch("tracker.intelligence._read", return_value={}) as read:
                scanner._other_sightings(["first"], records)
                reads = read.call_count
                scanner._other_sightings(["second"], records)
                self.assertEqual(read.call_count, reads)

    @unittest.skipUnless(os.environ.get("MODEL_TRACKER_REPLAY") == "1", "Enable explicitly to replay large retained official artifacts")
    def test_real_historical_cli_artifacts_without_codename_hints(self):
        from tracker.intelligence import ROOT, STATE_DIR, _write

        state = _read(STATE_DIR / "devin-cli.json")
        self.assertTrue(state.get("builds"), "Historical CLI evidence is required for replay")
        known = {}
        discovered = {}
        for version, build in sorted(state["builds"].items(), key=lambda item: item[1]["published_at"]):
            paths = [ROOT / ".cache/intelligence" / (hashlib.sha256((build["url"] + sha + build.get("integrity", "")).encode()).hexdigest() + ".archive") for sha in ("", build["artifact_sha256"])]
            path = next((path for path in paths if path.is_file()), None)
            self.assertIsNotNone(path, "Checksum-matched official archive cache required")
            payload = path.read_bytes()
            verify_digest(payload, build["artifact_sha256"])
            registry = {}
            for member, content in archive_members(payload, build["url"].split("?", 1)[0]):
                registry.update(extract_registry(content, member))
            for base in registry_diff(known, registry):
                discovered.setdefault(base, version)
            known.update(registry)
        expected = {"hyperion": "3000.12.28", "cactus": "3000.12.28", "kraken": "3000.12.28", "claude-mythos-5-1": "3000.11.205", "gpt-5-6-sol-cyber-blue": "3000.11.3"}
        cases = [{"family": base, "expected_build": version, "observed_build": discovered.get(base), "passed": discovered.get(base) == version} for base, version in expected.items()]
        missing = sum(not case["passed"] for case in cases)
        _write(STATE_DIR / "regression_results.json", {"generated_at": datetime.now(timezone.utc).isoformat(), "cases_checked": len(cases), "missed": missing, "cases": cases, "basis": "Checksum-verified cached official CLI archives, generic extractor, chronological diffs; expected names supplied only after extraction", "unverified_historical_cases": ["frantic-ferret"], "synthetic_additional_cases": ["kimi-highspeed"]})
        self.assertEqual(missing, 0, cases)

    def test_registry_metadata_changes_are_not_new_models(self):
        changes = registry_diff({"known-model": {"metadata": {"capabilities": []}}}, {"known-model": {"metadata": {"capabilities": ["tools"]}}})
        self.assertEqual(changes["known-model"]["event_label"], "Registry update")

    def test_reconciliation_never_moves_latest_identity_backwards(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = IdentityLedger(pathlib.Path(directory))
            records = {"model": {"provider": "google", "metadata": {}}}
            ledger.ingest("source", records, {"version": "new", "published_at": "2026-11-02"}, "new.json", "2026-11-03")
            ledger.ingest("source", records, {"version": "old", "published_at": "2026-11-01"}, "old.json", "2026-11-02")
            node = _read(pathlib.Path(directory) / "identities.json")["nodes"]["source:model"]
            self.assertEqual(node["first_seen"], "2026-11-01")
            self.assertEqual(node["build"], "new")

    def test_yaml_registry_and_no_constructor_execution(self):
        records = extract_registry(b'models:\n  unknown-model:\n    provider: google\n', "models.yaml")
        self.assertEqual(records["unknown-model"]["provider"], "google")
        import yaml

        with self.assertRaises(yaml.constructor.ConstructorError):
            extract_registry(b'!!python/object/apply:os.system ["exit"]', "models.yaml")

    def test_metrics_do_not_invent_misses_or_false_positive_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            metrics = intelligence_metrics([], {"source": {"status": "failed", "stale": True}}, pathlib.Path(directory))
            self.assertIsNone(metrics["missed_discoveries"]["missed"])
            self.assertIsNone(metrics["false_positives"]["rate"])
            self.assertEqual(metrics["source_health"]["failed"], 1)

    def test_intelligence_x_draft_does_not_claim_a_release(self):
        from tracker.notifiers import build_intelligence_embed, build_x_post_text

        card = {"intelligence": True, "family": "hyperion", "build": "1", "build_label": "Devin CLI", "models": [{"id": "hyperion-low"}], "source_text": "https://static.devin.ai/a.tgz"}
        draft = build_x_post_text(card)
        self.assertIn("not a model launch", draft)
        self.assertNotIn("releases", draft)
        self.assertEqual(build_intelligence_embed(card)["fields"][0]["value"], draft)

    def test_identity_edges_require_explicit_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = IdentityLedger(pathlib.Path(directory))
            records = extract_registry(json.dumps({"models": [{"id": "kimi-k3-1-highspeed"}, {"id": "kimi-k3.1-pro-highspeed"}, {"id": "hosted-id", "canonical_model_id": "lab/canonical-id"}]}).encode(), "models.json")
            ledger.ingest("source", records, {"version": "1", "published_at": "2026-11-01T00:00:00+00:00"}, "retained.json", "2026-11-02T00:00:00+00:00")
            state = _read(pathlib.Path(directory) / "identities.json")
            self.assertEqual(len(state["nodes"]), 3)
            self.assertEqual([edge["to"] for edge in state["edges"]], ["lab/canonical-id"])

    def test_candidates_remain_pending_and_do_not_establish_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = IdentityLedger(pathlib.Path(directory))
            cards = [{"id": "lead", "scanner": "community-lead", "models": [{"id": "unknown"}], "detected_at": "2026-11-01"}]
            ledger.enqueue(cards)
            self.assertTrue(cards[0]["candidate_only"])
            self.assertEqual(cards[0]["confidence"]["attribution"]["level"], "unknown")
            self.assertEqual(ledger.summarize()["pending_candidates"], 1)

    def test_static_evidence_is_not_serving_availability(self):
        record = {"provider": "openai", "file_path": "tests/models.json", "metadata": {}}
        confidence = evidence_confidence([record], "New identifier")
        self.assertEqual(confidence["availability"]["level"], "unknown")
        self.assertEqual(confidence["attribution"]["level"], "medium")
        self.assertEqual(confidence["novelty"]["level"], "candidate")

    def test_structured_toml_model_keys_preserve_local_metadata(self):
        records = extract_registry(b'[models.unknown-model]\nprovider = "google"\n', "models.toml")
        self.assertEqual(records["unknown-model"]["provider"], "google")

    def test_full_catalog_includes_specialized_and_hosted_models(self):
        data = {"host": {"models": {"frantic-ferret": {"type": "decision", "canonical_model_id": "openai/frantic-ferret"}, "unknown-route": {"name": "Unknown"}}}}
        scanner = ModelsDevApiScanner()
        with patch("tracker.intelligence.fetch", return_value=json.dumps(data).encode()) as fetch:
            build = scanner.list_builds()[0]
            records, _, _ = scanner.get_registry(build)
        self.assertIn("?type=all", fetch.call_args.args[0])
        self.assertEqual(records["host/frantic-ferret"]["provider"], "openai")
        self.assertEqual(records["host/unknown-route"]["provider"], "unknown")

    def test_catalog_source_ids_come_from_filenames_and_base_model(self):
        output = io.BytesIO()
        import zipfile

        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("models-dev-sha/models/openai/frantic-ferret.toml", 'schema = 2\nname = "Frantic Ferret"')
            archive.writestr("models-dev-sha/providers/host/models/ferret-route.toml", 'schema = 2\nbase_model = "openai/frantic-ferret"')
        scanner = ModelsDevGitScanner()
        with patch("tracker.intelligence.fetch", return_value=output.getvalue()):
            records, _, _ = scanner.get_registry({"version": "sha", "url": "https://codeload.github.com/anomalyco/models.dev/zip/sha"})
        self.assertEqual(set(records), {"openai/frantic-ferret", "host/ferret-route"})
        self.assertEqual(records["host/ferret-route"]["provider"], "openai")
        self.assertEqual(records["host/ferret-route"]["canonical_id"], "openai/frantic-ferret")

    def test_unfamiliar_binary_family_is_one_event(self):
        identifiers = ["hyperion", "hyperion-minimal", "hyperion-low", "hyperion-medium", "hyperion-high"]
        registry = extract_registry("\0".join(identifiers).encode(), "bin/devin")
        self.assertEqual(set(registry), set(identifiers))
        self.assertEqual(list(registry_diff({}, registry)), ["hyperion"])
        self.assertTrue(all(record["provider"] == "unknown" for record in registry.values()))

    def test_rust_concatenated_identifiers_use_exact_lengths(self):
        identifiers = ["hyperion", "hyperion-minimal", "hyperion-low", "hyperion-medium", "hyperion-high", "claude-mythos-5-1"]
        table = "".join(identifiers).encode()
        payload = bytearray(1024)
        payload[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", payload, 40, 64)
        struct.pack_into("<HH", payload, 58, 64, 3)
        struct.pack_into("<IIQQQQIIQQ", payload, 128, 0, 1, 2, 0x1000, 256, len(table), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", payload, 192, 0, 1, 3, 0x2000, 512, 16 * len(identifiers), 0, 0, 8, 0)
        payload[256:256 + len(table)] = table
        cursor = 0
        for index, identifier in enumerate(identifiers):
            struct.pack_into("<QQ", payload, 512 + index * 16, 0x1000 + cursor, len(identifier))
            cursor += len(identifier)
        registry = extract_registry(bytes(payload), "bin/devin")
        self.assertTrue(set(identifiers) <= set(registry))
        self.assertEqual(registry["hyperion-high"]["metadata"]["byte_length"], len("hyperion-high"))

    def test_optimized_rust_registry_without_descriptors(self):
        payload = b"gemini-3.5-flashhyperion-minimal\xffgemini-3.5-flash-minimalgemini-3.5-flash-lowgemini-3.5-flash-mediumgemini-3.5-flash-highhyperionhyperion-lowhyperion-mediumhyperion-highgemini-4-argon"
        registry = extract_registry(payload, "bin/devin")
        self.assertEqual({mid for mid in registry if mid.startswith("hyperion")}, {"hyperion", "hyperion-minimal", "hyperion-low", "hyperion-medium", "hyperion-high"})
        self.assertTrue(all(registry[mid]["provider"] == "unknown" for mid in registry if mid.startswith("hyperion")))

    def test_metadata_is_local_not_a_neighboring_provider(self):
        payload = {"models": [{"id": "unfamiliar-sun", "provider": "google"}, {"id": "unfamiliar-moon"}]}
        registry = extract_registry(json.dumps(payload).encode(), "registry.json")
        self.assertEqual(registry["unfamiliar-sun"]["provider"], "google")
        self.assertEqual(registry["unfamiliar-moon"]["provider"], "unknown")

    def test_js_model_field_and_false_positive_filter(self):
        registry = extract_registry(b'const item={modelId:"new-nebula"}; const x="request-high";', "bundle.js")
        self.assertEqual(set(registry), {"new-nebula"})

    def test_js_metadata_is_local_and_model_objects_are_discovered(self):
        payload = b'const models=[{id:"new-nebula",provider:"google"},{modelId:"other-nebula"}];'
        registry = extract_registry(payload, "bundle.js")
        self.assertEqual(registry["new-nebula"]["provider"], "google")
        self.assertEqual(registry["other-nebula"]["provider"], "unknown")

    def test_only_new_variants_after_baseline(self):
        old = {"hyperion": {}, "hyperion-low": {}}
        new = {**old, "hyperion-high": {}}
        self.assertEqual(registry_diff(old, new), {"hyperion": {"event_label": "New variant", "identifiers": ["hyperion-high"]}})
        self.assertEqual(registry_diff(new, new), {})
        self.assertEqual(list(registry_diff(old, {**new, "hyperion-high-fast": {}})), ["hyperion"])

    def test_missed_discovery_family_regressions(self):
        for base in ("hyperion", "cactus", "kraken", "gpt-cyber-blue"):
            identifiers = [base + "-" + effort for effort in ("minimal", "low", "medium", "high", "xhigh", "max", "none")]
            registry = extract_registry("\0".join(identifiers).encode(), "bin/devin")
            self.assertEqual(set(registry), set(identifiers))
            self.assertEqual(list(registry_diff({}, registry)), [base])
        self.assertNotEqual(family("kimi-k3-1-highspeed"), family("kimi-k3.1-pro-highspeed"))
        payload = b'model_id:"claude-mythos-5-1";model_id:"frantic-ferret";model_id:"kimi-k3.1-pro-highspeed"'
        self.assertEqual(set(extract_registry(payload, "registry.js")), {"claude-mythos-5-1", "frantic-ferret", "kimi-k3.1-pro-highspeed"})

    def test_report_only_uses_earliest_retained_snapshot_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scanner = ModelRegistryScanner(root)
            scanner.source = "devin-cli"
            build = {"version": "1", "url": "https://static.devin.ai/a.tgz", "published_at": "2026-10-01T00:00:00Z", "manifest_url": "https://static.devin.ai/manifest.json"}
            registry = extract_registry(b'modelId:"unfamiliar-sun"', "r.js")
            scanner.ingest(build, registry, "a" * 64, "verified", history=True)
            scanner.ingest({**build, "version": "2", "published_at": "2026-11-01T00:00:00Z"}, registry, "b" * 64, "verified", history=True)
            with patch("tracker.intelligence.fetch", side_effect=AssertionError("network should not run")):
                report = historical_backfill(root, report_only=True)
            entry = report["sources"]["devin-cli"]["families"]["unfamiliar-sun"]["identifiers"][0]
            self.assertEqual(entry["build"], "1")
            self.assertIn("a" * 64, entry["evidence_path"])
            self.assertEqual(report["sources"]["devin-desktop"]["status"], "failed")

    def test_checksum_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            verify_digest(b"corrupted", "0" * 64)

    def make_tar(self, name, content=b"data"):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        return output.getvalue()

    def test_archive_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            list(archive_members(self.make_tar("../../bundle.js"), "build.tar.gz"))

    def test_archive_budget_and_no_execution(self):
        payload = self.make_tar("bin/devin", b"hyperion-low\0hyperion-high")
        self.assertEqual(len(list(archive_members(payload, "build.tar.gz"))), 1)
        with patch("tracker.intelligence.MAX_EXPANDED", 1):
            with self.assertRaises(ValueError):
                list(archive_members(payload, "build.tar.gz"))
            self.assertEqual(len(list(archive_members(payload, "build.tar.gz", expanded_limit=128))), 1)

    def test_only_allowlisted_https_sources(self):
        for url in ("http://static.devin.ai/a", "https://evil.example/a", "https://static.devin.ai:444/a"):
            with self.assertRaises(ValueError):
                _trusted_url(url)

    def test_manifest_build_ahead_of_npm_is_not_skipped(self):
        from unittest.mock import MagicMock

        manifest = {"version": "3000.12.99", "platforms": {"x86_64-unknown-linux": {"url": "https://static.devin.ai/new.tgz", "sha256": "a" * 64}}}
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.headers = {"Last-Modified": "Mon, 09 Nov 2026 12:00:00 GMT"}
        with patch("tracker.intelligence.fetch", side_effect=[json.dumps(manifest).encode(), b'{"versions":{},"time":{}}']), patch("tracker.intelligence.urllib.request.build_opener", return_value=opener):
            builds = DevinCliScanner().list_builds()
        self.assertEqual(builds[0]["version"], "3000.12.99")
        self.assertEqual(builds[0]["published_at"], "2026-11-09T12:00:00+00:00")

    def test_desktop_release_association(self):
        builds = desktop_builds("## 3.12.28\nNovember 7, 2026\n[Linux](https://static.devin.ai/desktop/3.12.28/linux-x64.tar.gz)\n## 3.11.1\nOctober 1, 2026\n[Linux](https://static.devin.ai/desktop/3.11.1/linux-x64.tar.gz)")
        self.assertEqual([build["version"] for build in builds], ["3.11.1", "3.12.28"])
        self.assertTrue(builds[1]["published_at"].startswith("2026-11-07"))

    def test_desktop_embedded_mdx_release_literals(self):
        code = 'children:[_jsx(Update,{label:`v3.12.28`,description:`November 7, 2026`,children:_jsx(Release,{linuxX64:`https://windsurf-stable.codeiumdata.com/linux-x64/stable/hash/Devin-linux-x64-3.12.28.tar.gz`})}),_jsx(Update,{label:`v3.11.238`,description:`October 30, 2026`,children:_jsx(Release,{linuxX64:`https://windsurf-stable.codeiumdata.com/linux-x64/stable/old/Devin-linux-x64-3.11.238.tar.gz`})})]'
        page = '<html><script type="application/json">' + json.dumps({"page": {"mdx": {"code": code}}}) + '</script></html>'
        builds = desktop_builds(page)
        self.assertEqual([build["version"] for build in builds], ["3.11.238", "3.12.28"])
        self.assertEqual(builds[1]["sha256"], "")

    def test_durable_evidence_seed_and_reappearance(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = ModelRegistryScanner(pathlib.Path(directory))
            scanner.source = "devin-cli"
            scanner.label = "Devin CLI"
            build = {"version": "1", "url": "https://static.devin.ai/one.tgz", "published_at": "2026-10-01T00:00:00Z", "manifest_url": "https://static.devin.ai/manifest.json"}
            registry = extract_registry(b'modelId:"unfamiliar-sun"', "registry.js")
            events = scanner.ingest(build, registry, "a" * 64, "verified")
            self.assertTrue(events[0]["backfill"])
            self.assertTrue((pathlib.Path(directory) / "evidence/devin-cli" / ("a" * 64 + ".json.gz")).exists())
            next_build = {**build, "version": "2", "published_at": datetime.now(timezone.utc).isoformat()}
            added = extract_registry(b'modelId:"unfamiliar-moon"', "registry.js")
            events = scanner.ingest(next_build, added, "b" * 64, "verified")
            self.assertFalse(events[0]["backfill"])
            self.assertEqual(events[0]["event_label"], "New identifier")
            self.assertEqual(scanner.ingest({**next_build, "version": "3"}, registry, "c" * 64, "verified"), [])
            state = json.loads((pathlib.Path(directory) / "devin-cli.json").read_text())
            self.assertIn("a" * 64, state["known"]["unfamiliar-sun"]["first_seen_evidence_path"])

    def test_bad_evidence_write_never_advances_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = ModelRegistryScanner(pathlib.Path(directory))
            scanner.source = "devin-cli"
            with patch("tracker.intelligence._write", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    scanner.ingest({"version": "1", "url": "https://static.devin.ai/a.tgz", "published_at": "2026-11-08T00:00:00Z"}, {}, "a" * 64, "verified")
            self.assertFalse((pathlib.Path(directory) / "devin-cli.json").exists())

    def test_compaction_preserves_evidence_and_updates_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "evidence/devin-cli/old.json"
            path.parent.mkdir(parents=True)
            snapshot = {"artifact_sha256": "a" * 64, "registry": {"unfamiliar-sun": {"provider": "unknown"}}}
            path.write_text(json.dumps(snapshot))
            (root / "devin-cli.json").write_text(json.dumps({"builds": {"1": {"evidence_path": "evidence/devin-cli/old.json"}}, "events": [{"evidence_path": "data/intelligence/evidence/devin-cli/old.json"}]}))
            self.assertEqual(compact_evidence(root), 1)
            self.assertFalse(path.exists())
            self.assertEqual(_read(path.with_suffix(".json.gz")), snapshot)
            state = _read(root / "devin-cli.json")
            self.assertTrue(state["builds"]["1"]["evidence_path"].endswith(".json.gz"))
            self.assertTrue(state["events"][0]["evidence_path"].endswith(".json.gz"))

    def test_cross_source_sightings_not_repackaged_same_file(self):
        with tempfile.TemporaryDirectory() as directory:
            build = {"version": "1", "url": "https://static.devin.ai/a.tgz", "published_at": datetime.now(timezone.utc).isoformat(), "manifest_url": "https://static.devin.ai/manifest.json"}
            registry = extract_registry(b'modelId:"unfamiliar-sun"', "registry.js")
            registry["unfamiliar-sun"]["file_sha256"] = "a" * 64
            first = ModelRegistryScanner(pathlib.Path(directory))
            first.source = "devin-cli"
            first.ingest(build, registry, "a" * 64, "verified")
            second = ModelRegistryScanner(pathlib.Path(directory))
            second.source = "devin-desktop"
            events = second.ingest(build, registry, "b" * 64, "verified")
            self.assertEqual(events[0]["sightings"], [])
            registry = extract_registry(b'modelId:"unfamiliar-sun"; modelId:"unfamiliar-moon"', "registry.js")
            registry["unfamiliar-sun"]["file_sha256"] = "c" * 64
            third = ModelRegistryScanner(pathlib.Path(directory))
            third.source = "litellm-intelligence"
            events = third.ingest(build, registry, "c" * 64, "verified")
            event = next(event for event in events if event["family"] == "unfamiliar-sun")
            self.assertEqual(event["event_label"], "Multiple sightings")

    def test_old_build_discovered_today_is_backfill(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner = ModelRegistryScanner(pathlib.Path(directory))
            scanner.source = "devin-cli"
            build = {"version": "1", "url": "https://static.devin.ai/a.tgz", "published_at": datetime.now(timezone.utc).isoformat(), "manifest_url": "https://static.devin.ai/manifest.json"}
            scanner.ingest(build, extract_registry(b'modelId:"old-name"', "r.js"), "a" * 64, "verified")
            old = {**build, "version": "2", "published_at": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()}
            events = scanner.ingest(old, extract_registry(b'modelId:"new-name"', "r.js"), "b" * 64, "verified")
            self.assertTrue(events[0]["backfill"])

    def test_story_family_and_attribution_are_not_inferred(self):
        from tracker.stories import build_stories

        card = {"id": "intel-a", "scanner": "devin-cli", "intelligence": True, "family": "hyperion", "title": "hyperion", "header": "NEW IDENTIFIER · MULTI-PROVIDER", "provider_slug": "unknown", "provider_name": "Unattributed", "event_label": "New identifier", "detected_at": datetime.now(timezone.utc).isoformat(), "models": [{"id": "hyperion-low"}, {"id": "hyperion-high"}], "links": []}
        story = build_stories([card], pricing_catalog=type("Pricing", (), {"lookup": lambda self, raw: ""})())[0]
        self.assertEqual(story["id"], "story-hyperion")
        self.assertEqual(story["provider_name"], "Unattributed")
        self.assertEqual(story["kind"], "unverified")
        self.assertEqual(story["event_label"], "New identifier")

    def test_public_model_addition_is_registry_update(self):
        cards = [{"event_label": "New identifier", "family": "known-model", "models": [{"id": "known-model"}]}]
        self.assertEqual(classify_known(cards, ["openai/known-model"])[0]["event_label"], "Registry update")

    def test_failed_alert_retries_and_missing_evidence_blocks(self):
        from tracker.engine import TrackerEngine

        engine = TrackerEngine()
        card = {"id": "intel-a", "first_seen": datetime.now(timezone.utc).isoformat(), "evidence_path": "tests/test_intelligence.py", "evidence_retained": True, "artifact_sha256": "a" * 64}
        with patch.object(engine, "load_seen_ids", return_value=set()), patch.object(engine, "save_seen_ids") as save, patch("tracker.engine._load_json", return_value={"artifact_sha256": "a" * 64}), patch("tracker.engine.send_discord_webhook", side_effect=[False, True]) as send:
            engine.notify_intelligence([card])
            save.assert_not_called()
            engine.notify_intelligence([card])
            self.assertEqual(send.call_count, 2)
            save.assert_called_once_with({"intel-alert-intel-a"})
        with patch.object(engine, "load_seen_ids", return_value=set()), patch("tracker.engine.send_discord_webhook") as send:
            engine.notify_intelligence([{**card, "evidence_path": "missing-evidence.json"}])
            send.assert_not_called()

    def test_engine_publishes_grouped_intelligence_and_failed_source_health(self):
        from tracker.engine import TrackerEngine

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = pathlib.Path(directory)
            engine = TrackerEngine()
            scanner = ModelRegistryScanner(root / "data/intelligence")
            scanner.source = "devin-cli"
            scanner.label = "Devin CLI"
            build = {"version": "1", "url": "https://static.devin.ai/a.tgz", "published_at": datetime.now(timezone.utc).isoformat(), "manifest_url": "https://static.devin.ai/manifest.json"}
            cards = scanner.ingest(build, extract_registry(b"hyperion-low\0hyperion-high", "bin/devin"), "a" * 64, "verified")
            for card in cards:
                card["backfill"] = False
            for name, path in {"ROOT_DIR": root, "DATA_DIR": root / "data", "DOCS_DATA_DIR": root / "docs/data", "FEED_FILE": root / "data/feed.json", "DOCS_FEED_FILE": root / "docs/data/feed.json", "SEEN_FILE": root / "data/seen_ids.json", "SCANNER_RUNS_FILE": root / "cache/runs.json"}.items():
                stack.enter_context(patch("tracker.engine." + name, path))
            for source in engine.intelligence_scanners:
                stack.enter_context(patch.object(source, "scan", return_value=cards if source.source == "devin-cli" else []))
            desktop = next(source for source in engine.intelligence_scanners if source.source == "devin-desktop")
            stack.enter_context(patch.object(desktop, "scan", side_effect=RuntimeError("unavailable")))
            for attribute in ("ag_scanner", "ag_acp_scanner", "npm_scanner", "kimi_router_scanner", "docs_scanner", "arena_scanner", "hf_scanner", "high_alpha_scanner", "openai_spec_scanner"):
                stack.enter_context(patch.object(getattr(engine, attribute), "scan", return_value=[]))
            stack.enter_context(patch("tracker.engine._public_names_snapshot", return_value=[]))
            stack.enter_context(patch("tracker.engine.novelty.get_catalog", return_value=None))
            pricing = type("Pricing", (), {"lookup": lambda self, raw: ""})()
            stack.enter_context(patch("tracker.engine.pricing_mod.get_pricing_catalog", return_value=pricing))
            stack.enter_context(patch("tracker.engine.pricing_mod.enrich_cards_with_pricing"))
            stack.enter_context(patch("tracker.engine.send_discord_webhook", return_value=True))
            notify = stack.enter_context(patch.object(engine, "notify_intelligence"))
            feed = engine.run_all_scans()
            self.assertEqual(len(feed["stories"]), 1)
            self.assertEqual(feed["stories"][0]["id"], "story-hyperion")
            self.assertEqual(feed["intelligence_status"]["devin-desktop"]["status"], "failed")
            self.assertTrue((root / "docs/data/feed.json").exists())
            sent = [call.args[0][0] for call in notify.call_args_list if call.args[0]]
            self.assertEqual(sent[0]["event_label"], "New identifier")


class AntigravityAcpTests(unittest.TestCase):
    def test_python_par_fallback_extracts_catalog_and_fails_closed(self) -> None:
        from tracker.scanners import AntigravityAcpScanner

        scanner = AntigravityAcpScanner()
        meta = {
            "url": "https://dl.google.com/agy-extensions/releases/macos/agy-acp-server-1.5.0-darwin-arm64.zip",
            "zip_size": 100401185,
            "last_modified": "Wed, 11 Nov 2026 17:49:08 GMT",
            "etag": "abc",
            "detected_at": "2026-11-11T17:49:08+00:00",
        }
        payload = (
            b'DEFAULT_MODEL_METADATA_MAP = {\n'
            b'    **_thinking_family("gemini-4-carbon", "Gemini 4 Carbon", []),\n'
            b'    **_thinking_family("gemini-4-argon", "Gemini 4 Argon", []),\n'
            b'}\n'
            b'model = "gemini-decision-eap"\n'
        )
        snap = scanner._extract_python_par_snapshot("1.5.0", meta, payload)
        self.assertIsNotNone(snap)
        self.assertEqual(snap["catalog_mode"], "python-par")
        self.assertIn("gemini-4-carbon", snap["models"])
        self.assertIn("gemini-4-argon", snap["models"])
        self.assertIn("gemini-decision-eap", snap["models"])
        self.assertIsNone(scanner._extract_python_par_snapshot("1.5.0", meta, b"unrelated binary"))


class IdeBuildDiffTests(unittest.TestCase):
    def test_ide_blob_extractor_skips_harness_prose_and_backslash_truncated_slugs(self) -> None:
        from tracker.scanners import HighAlphaLeakChannelsScanner

        scanner = HighAlphaLeakChannelsScanner()
        blob = (
            b'Without the flag, models on the `gpt-5p6-codex` harness get `only` while the '
            b'`cli-gpt6-scripted-tools-only` Unleash flag is active.\n'
            b'find_file_by_namswe-1p5-thinkinggpt-5p4-persiste\\\\\\\\\n'
            b'{"id": "gpt-6-astra", "name": "GPT-6 Astra"}\n'
            b'"silicon-2-low" "silicon-2-medium" "silicon-2-high" "silicon-2-xhigh"\n'
        )
        found = scanner._extract_ide_blob_models(blob)
        self.assertNotIn("gpt-5p6-codex", found)
        self.assertNotIn("gpt-5p4-persiste", found)
        self.assertIn("gpt-6-astra", found)
        self.assertIn("silicon-2-low", found)
        self.assertIn("silicon-2-xhigh", found)

    def test_bootstrap_backfill_events_do_not_bloat_live_scan_feed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scanner = ModelsDevApiScanner(root)
            catalog = {"host": {"models": {f"model-{i}": {"name": f"Model {i}"} for i in range(50)}}}
            with patch("tracker.intelligence.fetch", return_value=json.dumps(catalog).encode()):
                first = scanner.scan()
            self.assertEqual(first, [])
            state = _read(root / "models-dev-api.json")
            self.assertEqual(state["events"], [])
            self.assertEqual(len(state["known"]), 50)
            catalog["host"]["models"]["new-frontier-1"] = {"name": "New Frontier 1"}
            with patch("tracker.intelligence.fetch", return_value=json.dumps(catalog).encode()):
                second = scanner.scan()
            self.assertEqual(len(second), 1)
            self.assertEqual(second[0]["models"][0]["id"], "host/new-frontier-1")
            self.assertFalse(second[0]["backfill"])


if __name__ == "__main__":
    unittest.main()