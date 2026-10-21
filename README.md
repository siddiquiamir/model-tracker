# ⚡ ModelPulse — First-to-Report AI Model & Build Diff Tracker

Real-time binary build differ, CLI/SDK tarball inspector, and open-source model radar designed to spot unreleased and newly shipped AI models before official announcements.

Built for **[@siddiquiamir](https://github.com/siddiquiamir)**.

---

## 🔍 How It Catches Models First

1. **Desktop Binary `.rodata` Diffing (`AntigravityDesktopScanner`)**
   - Polls Google Antigravity's official release manifest (`/releases`) and Nightly **Insiders** channel (`insiders/latest-x64-linux.yml`).
   - Uses **ELF64 `.rodata` HTTP Range Slicing** (`Range: bytes=start-end`) on `unsigned/language_server-linux-x64` to fetch only the 2.5 MB Go string literal table instead of downloading 190 MB archives.
   - De-concatenates Go's length-sorted `.rodata` string table to extract exact model identifiers (e.g. `gemini-4-argon`, `gemini-4-argon-high`, `claude-opus-5-5-max`, `gemini-robotics-er-1.6-preview`).

2. **CLI & SDK Package Tarball Diffing (`NpmCliAndSdkScanner`)**
   - Monitors `@anthropic-ai/claude-code`, `@openai/codex`, and `@google/genai` on the public npm registry.
   - Diffs JS bundles and `.d.ts` union types across versions to detect newly added model identifiers.

3. **Open-Source Hub & Engine Radar (`HuggingFaceOpenSourceScanner` & `GitHubArchitectureRadarScanner`)**
   - Tracks 10+ frontier open-source organizations on Hugging Face (`Qwen`, `deepseek-ai`, `meta-llama`, `mistralai`, `google`, `nvidia`, `microsoft`, `MiniMaxAI`, `moonshotai`, `THUDM`).
   - Monitors upstream commits in `huggingface/transformers` and `vllm-project/vllm` for new model architecture additions that precede weight drops.

---

## 🚀 Quick Start (Zero Dependencies)

Requires only **Python 3.10+** (uses standard library only).

### 1. Run a Full Live Scan
```bash
python server.py --scan
```

### 2. Diff Two Specific Antigravity Builds
```bash
python server.py --diff 2.22.0 2.23.0
python server.py --diff 2.23.0 2.25.0
```

### 3. Launch the Live Dark-Mode Web Dashboard
```bash
python server.py --serve --port 8787
```
Then open **http://localhost:8787** in your browser.

---

## 🔔 Discord Rich Embed Alerts & GitHub Actions

1. Create a Discord Webhook in your server channel.
2. **Locally**: Copy `.env.example` to `.env` and set `DISCORD_WEBHOOK_URL=...`.
3. **On GitHub**:
   - Push this repo to `https://github.com/siddiquiamir/model-tracker`.
   - Go to **Settings → Secrets and variables → Actions** and add `DISCORD_WEBHOOK_URL`.
   - Enable **GitHub Pages** from the `main` branch `/docs` folder to publish your live dashboard at `https://siddiquiamir.github.io/model-tracker/`.
