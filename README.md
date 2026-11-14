<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0F172A,50:10B981,100:2563EB&height=210&section=header&text=ModelPulse&fontSize=46&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=First-to-Report%20AI%20Model%20%26%20Binary%20Diff%20Tracker%20%7C%20Powered%20by%20%40StatsWire&descAlignY=58&descSize=17" width="100%" alt="ModelPulse Banner"/>
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=500&size=19&pause=1000&color=10B981&center=true&vCenter=true&width=760&lines=Real-Time+ELF64+.rodata+Binary+Slicing+%26+Model+ID+Diffing;Tracking+OpenAI%2C+Anthropic%2C+Google+Gemini%2C+xAI%2C+DeepSeek+%26+Qwen;Automated+5-Minute+Cloud+Radar+Built+by+Amir+Siddiqui+(%40StatsWire)" alt="Typing SVG" />
</p>

<p align="center">
  <a href="https://siddiquiamir.github.io/model-tracker/" target="_blank">
    <img src="https://img.shields.io/badge/🟢_LIVE_RADAR_DASHBOARD-10B981?style=for-the-badge&logoColor=white" alt="Live Dashboard"/>
  </a>
  &nbsp;
  <a href="https://x.com/StatsWire" target="_blank">
    <img src="https://img.shields.io/badge/Follow_%40StatsWire_on_X-000000?style=for-the-badge&logo=x&logoColor=white" alt="Follow @StatsWire on X"/>
  </a>
  &nbsp;
  <a href="https://github.com/siddiquiamir/model-tracker/actions" target="_blank">
    <img src="https://img.shields.io/badge/5--Min_Cloud_Scanner-2563EB?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions"/>
  </a>
</p>

---

## ⚡ Overview

**ModelPulse** is an automated Python AI model & binary build diff tracker created by **Amir Siddiqui ([@StatsWire](https://x.com/StatsWire))**. Its worker runs roughly every two minutes, with source-specific polling intervals, to discover identifier changes in public binaries, CLI/SDK packages, cloud documentation and model catalogs. Registry presence alone does not establish model availability or a launch.

---

## 🛰️ Authoritative Intelligence Sources

| Scanner Module | Target Sources | What It Detects |
| :--- | :--- | :--- |
| **`AntigravityDesktopScanner`** | Official Google Antigravity Linux x64 **Stable** (`/releases`) & **Nightly Insiders** (`insiders/latest-x64-linux.yml`) | Uses **ELF64 `.rodata` HTTP Range Slicing** (`Range: bytes=start-end`) on `language_server-linux-x64` to extract newly compiled model strings (e.g. `gemini-4-argon`, `claude-opus-5-5`, `claude-sonnet-5-5`) without downloading full 190 MB archives. |
| **`NpmCliAndSdkScanner`** | `@anthropic-ai/claude-code`, `@openai/codex`, `@google/genai`, `@google/gemini-cli`, `@google/gemini-cli-core`, `openai`, `@anthropic-ai/sdk` | Diffs official npm tarballs, JS bundles, and TypeScript `.d.ts` definitions; retains identifiers across scans and stable/preview/nightly tag changes. |
| **`AntigravityAcpScanner`** | Antigravity ACP npm package versions (probed ahead of publication) | Diffs the embedded discovery doc between every consecutive ACP version. |
| **`KimiCodeAndRouterScanner`** | Kimi Code CDN (`migration.json`), vLLM model registry (`main`), OpenRouter (`/api/v1/models`) | Diff-based: only IDs/architectures not seen before become cards (first sight seeds silently). |
| **`DocsAndGlobalRegistryScanner`** | Cursor, Anthropic, Gemini API, **Vertex AI**, **Bedrock**, xAI docs, `models.dev`, `LiteLLM`, `gemini-cli` `models.ts`, Claude Code `CHANGELOG.md` | Whitelist-free text extraction so unknown codenames are caught, diffed against a per-source baseline. |
| **`HuggingFaceOpenSourceScanner`** | Official lab orgs (`deepseek-ai`, `Qwen`, `meta-llama`, `mistralai`, `google`, `nvidia`, `microsoft`, `MiniMaxAI`, `moonshotai`, `THUDM`, ...) | New repos (`sort=createdAt` + `lastModified`), including ones created private and flipped public later. |
| **`LmArenaScanner`** | LMArena leaderboard | New arena entries and stealth codenames. |

## ⏱️ How it runs

GitHub throttles `*/5` cron schedules to one run every few hours, so the workflow does not rely on cron. Each run targets a `python server.py --scan` cycle every ~2 minutes for ~5.6 hours, sends ordinary story alerts when the scan completes, publishes the feed when there are new cards (or every 30 minutes), then re-dispatches itself. Slow scans lengthen that interval; this is not a two-minute detection guarantee. An hourly cron acts only as a watchdog. A `concurrency` group guarantees a single loop, and a push that changes `tracker/`, `server.py` or `.github/` ends the current loop so the next one runs the new code.

Each scanner is isolated: a failure in one source is logged and its previous cards are kept. Baselines live in `data/source_baselines.json` (atomic writes); Discord alerts are only sent for cards detected within the last 48 h and are retried if the webhook fails.

### Google early-warning coverage

The earliest retained Argon card compares `@google/genai` **2.29.1 -> 2.30.0**, with npm source timestamp **2026-10-15 00:06:41 UTC**. A live replay verified both npm integrity hashes: `gemini-4-argon` is absent from the older archive and present in the newer `dist/genai.d.ts`, `dist/node/node.d.ts` and `dist/web/web.d.ts`. The next retained source is Antigravity ACP 1.4.2 on 23 October. This is the earliest evidence retained here, not a claim of being first globally or before release.

- npm, ACP and public documentation checks run before large desktop collectors. Gemini CLI and its core package poll `latest`, `preview` and `nightly` without downloading the full nightly npm metadata history. Successful package observations persist in `npm_observed_models`; failed artifact downloads do not consume pending discoveries. New npm and Gemini API identifiers are not truncated to a display-sized subset.
- Public GitHub model definitions and Python-GenAI tokenizer maps remain independent monitored sources, alongside AI Studio/Gemini web bundles, Vertex quota dimensions and authenticated Gemini `v1alpha`/`v1beta` model lists.
- The Vertex billing collector uses service **C7E2-9256-1C43**. Billing regions, modalities and processing tiers are excluded from model names, while unfamiliar qualifiers such as `Cyber Permissive` remain intact. Complete billing/API pagination is required before committing an endpoint result; failed pages, repeated tokens and page limits do not advance its baseline. Gemini API sightings are never forgotten when one endpoint fails or removes a model.
- Billing cards retain SKU description samples and explicitly distinguish a billing listing from a public inference model ID or callable API. An initial billing scan surfaces families missing from an available reference catalog; without a reference it seeds silently. Google API keys are sent in headers, not request URLs.
- New evidence cards or exact model IDs can notify again for an already-known story. The one-time receipt migration is silent; timestamp refreshes and evidence removals do not re-alert, and failed deliveries remain pending.

For authenticated Google model polling, configure the GitHub Actions secret `GEMINI_API_KEY`. For billing, use `GCP_BILLING_API_KEY` with Cloud Billing Catalog API access, an existing GCP bearer/service-account setup, or a Gemini key whose project also permits that API. The dedicated billing key takes precedence. Discord requires `DISCORD_WEBHOOK_URL`; no automated X posting is performed. Missing credentials and endpoint failures appear under `source_health.high-alpha.subsources` rather than implying those checks succeeded. Setting a secret does not bypass project permissions or restricted model access.

These are source-change detectors, not inference probes or a launch prediction service. A public SKU, SDK identifier, experiment flag or model-list entry is not proof that everyone can call the model. Transient artifacts published and removed between polls can still be missed. Local edits must be deployed to the GitHub runner before they affect live tracking.

## Binary & Model Registry Intelligence

Five independently scheduled collectors cover Devin CLI, Devin Desktop/Windsurf, LiteLLM, the complete models.dev API (`?type=all`), and commit-pinned models.dev TOML definitions. CLI uses the official SHA-256 manifest when available, with the official `devin` npm platform package and SHA-512 integrity as a fallback. An unfamiliar model field or a family with repeated effort variants can be discovered without a list of known codenames. Bare identifiers and their effort variants, including `max` and `none`, form one family, not multiple launches. Configuration, JavaScript/TypeScript and Go fields are inspected statically; JSON, TOML and YAML use structured parsers.

- Baselines, never-forget identifiers, build hashes, complete extracted registries and excerpts live under `data/intelligence/`. Registry snapshots use lossless gzip JSON to keep publishing practical. Evidence is written before a baseline advances or an alert is allowed. The original archive URL, build, member path/hash, observation time and first-present build timestamp are retained.
- Event labels are **New identifier**, **New variant**, **Registry update**, **Multiple sightings**, and **Released**. Metadata-only changes are registry updates. Registry presence is not release evidence. Cross-source sightings exclude identical member hashes and shared-upstream pipelines: models.dev API/source and Devin CLI/Desktop are not independent corroboration of each other. Routing providers and application publishers are not assumed to own models; absent or conflicting explicit metadata remains **Unattributed**.
- Initial scans seed historical cards silently. Previously unseen artifacts older than 48 hours never trigger "new today" alerts. New intelligence events notify Discord after their scanner succeeds, independently of slower announcement scanners. Failed deliveries remain retryable. Ordinary stories still merge the family and its evidence.
- Static inspection only: no downloaded binary, installer, JavaScript or packaged script is run. HTTPS hosts and redirects are allowlisted. CLI downloads are limited to 256 MiB with 768 MiB cumulative expansion; Desktop has a separate 512 MiB download and 1536 MiB expansion budget. Individual members stay capped at 256 MiB and archives at 30,000 members. Paths are checked; links are never followed. Only checksum-verified archives are cached, and hashes are checked again before reuse. Desktop artifacts without published checksums are explicitly marked as such, not "upstream verified".
- Unavailable pages, malformed registries, checksum failures and extraction failures leave baselines unchanged. Persistent source health includes last attempt/success, consecutive failures, duration and staleness; the feed exposes `intelligence_status` and `source_health`. Aggregate health for older scanners describes the outer scan, not every credential-dependent subsource. Unknown CDN hosts fail closed until reviewed and added to the allowlist. Existing `GITHUB_TOKEN` credentials are used only for GitHub API requests and stripped from redirects to artifact hosts.

### Identity and verification

`data/intelligence/identities.json` retains source-qualified identifiers, family, first/last evidence, provider metadata and declared alias edges. models.dev `canonical_model_id`, `base_model`, and explicit aliases are evidence-backed relationships; name similarity alone never merges identities. For example, differing Kimi highspeed spellings remain separate without a declared mapping. This graph is retained as metadata; existing dashboard story grouping is not replaced by a canonical identity resolver.

Each intelligence event separately reports existence, attribution, availability and novelty confidence. "Existence" means an identifier was observed in static evidence, not that a callable model exists. Attribution from a community-maintained catalog is qualified metadata, not independently confirmed lab ownership. Availability remains unknown without separate inference/launch verification. Test/example/deprecated-only records and community leads go to `candidate_queue.json`, retain `review: pending`, and do not generate confirmed alerts. Reviewed outcomes can be recorded as `confirmed` or `false_positive`; queue handling does not add new Reddit/X collectors or automate review.

Discord includes exact artifact evidence, timestamp basis, confidence dimensions and a manual X draft. Intelligence drafts describe observed registry IDs rather than claiming a launch. X posting is never automated.

### Operations and metrics

Lightweight full-catalog checks run every 120 seconds, LiteLLM every 180, CLI manifests every 300, models.dev source every 600 and Desktop releases every 900. Artifact downloads happen only for previously uninspected builds. Daily reconciliation replays retained snapshots into identity state without network downloads or alerts; it is not a complete daily remote-history backfill. Normal commit checks inspect the latest two commits, so transient entries between polls can still require manual backfill.

The feed's `intelligence_metrics` reports detection lag, explicit regression misses, reviewed false positives, evidence completeness and source health. Missing benchmarks/reviews produce unknown values, not invented zero rates. Lag is observation minus first-inspected build time, not exact model introduction time; date-only releases and observation-only catalogs cannot establish precise lead time.

Run the one-time historical comparison (no Discord alerts):

```bash
python -m tracker.intelligence --backfill --since 2026-10-01 --until 2026-12-01
python -m tracker.intelligence --report-only --since 2026-10-01 --until 2026-12-01
python -m tracker.intelligence --compact-evidence
python -m tracker.intelligence --reconcile
python -m unittest discover -s tests -p test_intelligence.py -v
```

The report is `data/intelligence/backfill_report.json`. First presence is bounded by the builds actually inspected; it is not a claimed exact introduction date. Missing releases are unverified. CLI history is limited to published Linux npm builds; LiteLLM backfill currently covers the latest 100 registry commits. Desktop parsing reads dated Linux archive links from the official page, including its embedded Mintlify JSON/MDX literals without executing them. A blocked release page is a failed source, not an empty successful scan.

GitHub Actions already has `workflow_dispatch`; enable its `intelligence_backfill` input for the historical run, or leave it off for an urgent normal scan. Evidence is committed with the existing data publishing step and historical runs also upload an evidence artifact. The existing two-minute worker loop and hourly watchdog are preserved. GitHub schedules and dispatches remain best-effort; this is not a near-real-time SLA.

The optional raw-artifact regression test requires the retained official CLI archives in `.cache/intelligence/` and their source state. Set `MODEL_TRACKER_REPLAY=1` before running the test suite. It verifies archive hashes, extracts all identifiers generically, then compares chronological discoveries against test-only expectations. Results are retained in `data/intelligence/regression_results.json`. Six inspected CLI builds reproduce Hyperion, Cactus, Kraken, Mythos and Cyber Blue. Frantic Ferret has synthetic coverage but no retained historical OpenCode/models.dev artifact here; Kimi highspeed spelling/alias behavior is covered synthetically. Neither is claimed as a completed historic artifact replay.

### Coverage boundaries

Existing collectors already cover several coding-agent packages, public cloud docs/catalogs, Arena, Hugging Face and public GitHub configuration leads. This upgrade does not implement every proposed additional agent/cloud/community source, models.dev pull-request monitoring, authenticated inference probes, account/region-specific cloud catalog completeness, or a universal launch-verification service. Those remain phased follow-up work. Public registry declarations, anonymous screenshots and hosted routes are never enough on their own to claim creator attribution or availability.

## 🧹 Novelty filter & codename hints (`tracker/novelty.py`)

Every card passes a central filter before it is published or alerted:

- **Already-released models are removed.** The reference is the [models.dev](https://models.dev) catalog (~9k models with release dates). A model is dropped when it was public more than 7 days before the card was detected, matched by normalized name (`GPT-5.4 mini (High)` = `gpt-5-4-mini`), by family prefix (`ERNIE-5.0-Preview` after `ernie-5.0-thinking-preview`), or by being two major generations behind the family frontier. Engine-PR references to Hugging Face repos created over 30 days earlier are dropped too. Cards left with no models disappear.
- **Codename hints are flagged.** Any token that appears in no public catalog (models.dev, LiteLLM, Arena, OpenRouter, gateways), such as `carbon` in `gemini-4-carbon` or `barium` in `barium-b-final-visibles-v7-tf`, gets a yellow `CODENAME` badge in the UI and a `[CODENAME: …]` prefix in Discord. Words listed in `data/hints.json` (fable, mythos, …) are flagged as long as they are unreleased. Flags are sticky, so they stay after the model ships.

---

## 🚀 Quick Start

Requires **Python 3.10+**. YAML inspection uses PyYAML; Python 3.10 also needs tomli for TOML inspection (3.11+ uses standard-library tomllib). GitHub Actions installs these automatically. The older binary/JSON collectors remain standard-library based.

```bash
python -m pip install PyYAML 'tomli; python_version < "3.11"'

# 1. Run a full live scan across all sources
python server.py --scan

# 2. Diff two specific Antigravity builds
python server.py --diff 2.22.0 2.23.0

# 3. Launch the live dark-mode web dashboard locally
python server.py --serve --port 8787
```

---

<p align="center">
  <b>Developed by <a href="https://x.com/StatsWire">@StatsWire</a> (<a href="https://github.com/siddiquiamir">Amir Siddiqui</a>)</b>
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0F172A,50:10B981,100:2563EB&height=100&section=footer" width="100%" />
</p>
