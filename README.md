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

**ModelPulse** is an automated, zero-dependency AI model & binary build diff tracker created by **Amir Siddiqui ([@StatsWire](https://x.com/StatsWire))**. It continuously scans compiled desktop binaries, CLI/SDK tarballs, cloud provider documentation, and canonical model registries every ~2 minutes to detect unannounced and newly deployed frontier AI models before official announcements.

---

## 🛰️ Authoritative Intelligence Sources

| Scanner Module | Target Sources | What It Detects |
| :--- | :--- | :--- |
| **`AntigravityDesktopScanner`** | Official Google Antigravity Linux x64 **Stable** (`/releases`) & **Nightly Insiders** (`insiders/latest-x64-linux.yml`) | Uses **ELF64 `.rodata` HTTP Range Slicing** (`Range: bytes=start-end`) on `language_server-linux-x64` to extract newly compiled model strings (e.g. `gemini-4-argon`, `claude-opus-5-5`, `claude-sonnet-5-5`) without downloading full 190 MB archives. |
| **`NpmCliAndSdkScanner`** | `@anthropic-ai/claude-code`, `@openai/codex`, `@google/genai`, `openai`, `@anthropic-ai/sdk` | Diffs official npm tarballs, JS bundles, and TypeScript `.d.ts` union definitions across releases. |
| **`AntigravityAcpScanner`** | Antigravity ACP npm package versions (probed ahead of publication) | Diffs the embedded discovery doc between every consecutive ACP version. |
| **`KimiCodeAndRouterScanner`** | Kimi Code CDN (`migration.json`), vLLM model registry (`main`), OpenRouter (`/api/v1/models`) | Diff-based: only IDs/architectures not seen before become cards (first sight seeds silently). |
| **`DocsAndGlobalRegistryScanner`** | Cursor, Anthropic, Gemini API, **Vertex AI**, **Bedrock**, xAI docs, `models.dev`, `LiteLLM`, `gemini-cli` `models.ts`, Claude Code `CHANGELOG.md` | Whitelist-free text extraction so unknown codenames are caught, diffed against a per-source baseline. |
| **`HuggingFaceOpenSourceScanner`** | Official lab orgs (`deepseek-ai`, `Qwen`, `meta-llama`, `mistralai`, `google`, `nvidia`, `microsoft`, `MiniMaxAI`, `moonshotai`, `THUDM`, ...) | New repos (`sort=createdAt` + `lastModified`), including ones created private and flipped public later. |
| **`LmArenaScanner`** | LMArena leaderboard | New arena entries and stealth codenames. |

## ⏱️ How it runs

GitHub throttles `*/5` cron schedules to one run every few hours, so the workflow does not rely on cron. Each run loops `python server.py --scan` every ~2 minutes for ~5.6 hours, sends Discord alerts immediately, publishes the feed when there are new cards (or every 30 minutes), then re-dispatches itself. An hourly cron acts only as a watchdog. A `concurrency` group guarantees a single loop, and a push that changes `tracker/`, `server.py` or `.github/` ends the current loop so the next one runs the new code.

Each scanner is isolated: a failure in one source is logged and its previous cards are kept. Baselines live in `data/source_baselines.json` (atomic writes); Discord alerts are only sent for cards detected within the last 48 h and are retried if the webhook fails.

## 🧹 Novelty filter & codename hints (`tracker/novelty.py`)

Every card passes a central filter before it is published or alerted:

- **Already-released models are removed.** The reference is the [models.dev](https://models.dev) catalog (~9k models with release dates). A model is dropped when it was public more than 7 days before the card was detected, matched by normalized name (`GPT-5.4 mini (High)` = `gpt-5-4-mini`), by family prefix (`ERNIE-5.0-Preview` after `ernie-5.0-thinking-preview`), or by being two major generations behind the family frontier. Engine-PR references to Hugging Face repos created over 30 days earlier are dropped too. Cards left with no models disappear.
- **Codename hints are flagged.** Any token that appears in no public catalog (models.dev, LiteLLM, Arena, OpenRouter, gateways), such as `carbon` in `gemini-4-carbon` or `barium` in `barium-b-final-visibles-v7-tf`, gets a yellow `CODENAME` badge in the UI and a `[CODENAME: …]` prefix in Discord. Words listed in `data/hints.json` (fable, mythos, …) are flagged as long as they are unreleased. Flags are sticky, so they stay after the model ships.

---

## 🚀 Quick Start (Zero Dependencies)

Requires **Python 3.10+** (standard library only).

```bash
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
