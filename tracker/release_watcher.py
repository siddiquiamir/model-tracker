"""24/7 Release Notes & Alpha Radar Watcher for AI Coding Agents and Protocols.

Tracks 100% verbatim release notes (zero truncation) across:
  - Google Antigravity (App, CLI, IDE Extensions, SDK, IDE)
  - OpenAI Codex CLI (Stable + Alpha PR Radar compare)
  - Anthropic Claude Code (CHANGELOG.md + npm dist-tags)
  - Google Gemini CLI (google-gemini/gemini-cli)
  - OpenCode (anomalyco/opencode)
  - Cursor (cursor.com/changelog)
  - Model Context Protocol Spec (modelcontextprotocol/modelcontextprotocol)

For every new release:
  1. Extracts Buried Gems (new CLI flags, slash commands, env vars, hook events,
     config keys, and model/alias deprecations) + Cross-Agent Convergence tags.
  2. Archives 100% verbatim Markdown to ``releases/<product>/<version>.md``.
  3. Exports searchable ``docs/data/releases.json`` + ``releases/INDEX.md``.
  4. Renders a 16:9 ``@StatsWire`` Release Card PNG (when Pillow is available)
     and posts a Discord webhook embed with BOTH the PNG card inline AND the
     complete verbatim ``.md`` file attached.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
import pathlib
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.request
import uuid

from tracker.notifiers import PROVIDER_LOGOS, _post_discord_request

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_STATE_FILE = ROOT_DIR / "data" / "release_state.json"
DEFAULT_RELEASES_DIR = ROOT_DIR / "releases"
DEFAULT_DOCS_JSON_FILE = ROOT_DIR / "docs" / "data" / "releases.json"

ANTIGRAVITY_CHANGELOG_URL = "https://antigravity.google/docs/changelog.md"
CODEX_RELEASES_API_URL = "https://api.github.com/repos/openai/codex/releases?per_page=25"
CODEX_COMPARE_API_TEMPLATE = "https://api.github.com/repos/openai/codex/compare/{base}...{head}"
CLAUDE_CODE_CHANGELOG_URL = "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md"
CLAUDE_CODE_NPM_TAGS_URL = "https://registry.npmjs.org/-/package/@anthropic-ai/claude-code/dist-tags"
GEMINI_CLI_RELEASES_API_URL = "https://api.github.com/repos/google-gemini/gemini-cli/releases?per_page=15"
OPENCODE_RELEASES_API_URL = "https://api.github.com/repos/anomalyco/opencode/releases?per_page=15"
CURSOR_CHANGELOG_URL = "https://cursor.com/changelog"
MCP_SPEC_RELEASES_API_URL = "https://api.github.com/repos/modelcontextprotocol/modelcontextprotocol/releases?per_page=10"

DEFAULT_USER_AGENT = "ModelPulse-ReleaseWatcher/2.0"

PRODUCT_META: Dict[str, Dict[str, Any]] = {
    "antigravity": {
        "provider_slug": "google",
        "color": 0x4285F4,
        "org": "Google",
        "badge": "NEW RELEASE",
    },
    "codex": {
        "provider_slug": "openai",
        "color": 0x10A37F,
        "org": "OpenAI",
        "badge": "NEW RELEASE",
    },
    "codex-alpha": {
        "provider_slug": "openai",
        "color": 0xF59E0B,
        "org": "OpenAI",
        "badge": "ALPHA RADAR",
    },
    "claude-code": {
        "provider_slug": "anthropic",
        "color": 0xD97757,
        "org": "Anthropic",
        "badge": "NEW RELEASE",
    },
    "gemini-cli": {
        "provider_slug": "google",
        "color": 0x60A5FA,
        "org": "Google",
        "badge": "NEW RELEASE",
    },
    "opencode": {
        "provider_slug": "opencode",
        "color": 0xA855F7,
        "org": "OpenCode",
        "badge": "NEW RELEASE",
    },
    "cursor": {
        "provider_slug": "cursor",
        "color": 0x94A3B8,
        "org": "Cursor",
        "badge": "NEW RELEASE",
    },
    "mcp-spec": {
        "provider_slug": "mcp",
        "color": 0x14B8A6,
        "org": "MCP",
        "badge": "SPEC UPDATE",
    },
}

CONVERGENCE_RULES: List[Tuple[str, str, re.Pattern[str]]] = [
    ("skills", "Skills & ~/.agents/skills", re.compile(r"(?:~/\.agents/skills|\bskills?\b|server:skill|SKILL\.md)", re.I)),
    ("mcp", "MCP & MCP Apps", re.compile(r"(?:\bMCP\b|Model Context Protocol|stdio MCP|SSE MCP|MCP Apps?)", re.I)),
    ("voice", "Voice & Dictation", re.compile(r"(?:\bvoice\b|\bdictation\b|\bmicrophone\b|speech|realtime call)", re.I)),
    ("auto-mode", "Auto Mode & Permissions", re.compile(r"(?:\bauto mode\b|permission prompt|approval reviewer|sandbox|allowlist)", re.I)),
    ("hooks", "Hooks & Security", re.compile(r"(?:\bPre[A-Z]\w+|Post[A-Z]\w+|\bhook(?:s)?\b|Guardian|OAuth|keychain)", re.I)),
    ("code-mode", "Code Mode & Sandboxes", re.compile(r"(?:\bCode Mode\b|sandboxed|Seatbelt|MXC sandbox|gRPC)", re.I)),
    ("swarms", "Swarms & Subagents", re.compile(r"(?:\bswarm\b|\bsub-?agents?\b|orchestrator|nested agents?|command center)", re.I)),
    ("remote", "Remote / SSH / Cloud", re.compile(r"(?:\bSSH\b|Remote Control|remote agents?|cloud scheduled|self-hosted runner)", re.I)),
    ("worktrees", "Worktrees & Git", re.compile(r"(?:\bworktrees?\b|EnterWorktree|\bgit\b|diff view|Jujutsu|Mercurial)", re.I)),
    ("compaction", "Compaction & Context", re.compile(r"(?:\bcompaction\b|/compact|/context|context window|token limit)", re.I)),
    ("ide", "IDE & VS Code", re.compile(r"(?:\[VSCode\]|\bVS Code\b|\bIDE\b|side panel|floating composer)", re.I)),
    ("models", "Models & Providers", re.compile(r"(?:\bGemini\s*\d|\bGPT-\d|\bSonnet\b|\bOpus\b|\bHaiku\b|Bedrock|Foundry|Vertex|model alias)", re.I)),
]

_COMMON_NON_ENV_CAPS = {
    "HTTPS", "HTTP", "JSON", "YAML", "HTML", "UTF-8", "ASCII", "POSIX", "LINUX", "MACOS",
    "WINDOWS", "GITHUB", "GOOGLE", "OPENAI", "CLAUDE", "README", "CHANGELOG", "TOKEN",
    "OAUTH", "STDIN", "STDOUT", "STDERR", "TOTAL", "ITEMS", "FIXED", "ADDED", "ALPHA",
    "STABLE", "LATEST", "DRAFT", "ERROR", "WARNING", "ENTER", "SHIFT", "CTRL", "ESCAPE",
    "MOUSE", "AUDIO", "VIDEO", "IMAGE", "MODEL", "AGENT", "CLOUD", "LOCAL", "REMOTE",
    "DESKTOP", "SERVER", "CLIENT", "PROMPT", "SLASH", "SHELL", "FILES", "DIFFS", "PATCH",
    "BUILD", "TESTS", "CACHE", "INDEX", "LIMIT", "SCOPE", "RULES", "HOOKS", "SKILLS",
    "PLUGINS", "VOICE", "TASKS", "SWARM", "STATE", "STATS", "USAGE", "QUOTA", "PROXY",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
}

_COMMON_NON_SLASH_PATHS = {
    "/releases", "/download", "/docs", "/blog", "/changelog", "/issues", "/pull", "/blob",
    "/tree", "/compare", "/repos", "/api", "/usr", "/etc", "/tmp", "/var", "/bin", "/home",
    "/dev", "/opt", "/path", "/file", "/dir", "/folder", "/name", "/id", "/v1", "/v2",
}


@dataclass
class ReleaseEntry:
    """One complete, verbatim release for a tracked product/surface."""

    track_key: str  # e.g. "antigravity:app", "codex:cli", "claude-code:cli"
    product_family: str  # matches PRODUCT_META keys
    display_name: str  # e.g. "Google Antigravity App", "OpenAI Codex CLI"
    folder_slug: str  # e.g. "antigravity-app", "codex-cli", "claude-code"
    version: str  # e.g. "v2.36.0", "rust-v0.172.0", "v2.1.332"
    published_at: str  # ISO date or human date string from source
    url: str  # authoritative link for this release
    title: str  # headline/summary title if available
    body_markdown: str  # 100% verbatim release notes — NEVER truncated
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def bullet_items(self) -> List[str]:
        return extract_markdown_bullets(self.body_markdown)

    @property
    def safe_filename(self) -> str:
        clean_ver = re.sub(r"[^A-Za-z0-9._-]+", "-", self.version).strip("-")
        return f"{clean_ver or 'release'}.md"


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "unknown"


def _http_get_text(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> str:
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        encoding = resp.headers.get_content_charset() or "utf-8"
        return raw.decode(encoding, errors="replace")


def _http_get_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> Any:
    return json.loads(_http_get_text(url, headers=headers, timeout=timeout))


def extract_markdown_bullets(markdown: str) -> List[str]:
    """Return every bullet item from a Markdown changelog body."""
    items: List[str] = []
    for raw_line in markdown.splitlines():
        m = re.match(r"^\s*[-*]\s+(.+?)\s*$", raw_line)
        if m:
            items.append(m.group(1).strip())
    return items


def _strip_md_inline(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _truncate_word(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 1:
        return text[:max_len]
    cut = text[: max_len - 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
    if not cut:
        cut = text[: max_len - 1]
    return cut + "…"


# ---------------------------------------------------------------------------
# Buried Gems & Cross-Agent Convergence Extractors
# ---------------------------------------------------------------------------


def extract_buried_gems(entry: ReleaseEntry) -> Dict[str, List[str]]:
    """Scan 100% of a release body to extract high-signal power-user details."""
    text = entry.body_markdown or ""

    def _dedupe(seq: Sequence[str], limit: int = 12) -> List[str]:
        seen: set[str] = set()
        out: List[str] = []
        for item in seq:
            key = item.lower()
            if key not in seen:
                seen.add(key)
                out.append(item)
                if len(out) >= limit:
                    break
        return out

    # CLI flags like `--resume`, `--effort`, `--configure-git`
    flags = _dedupe(re.findall(r"(?<![A-Za-z0-9-])--[a-z][a-z0-9-]{2,}", text))

    # Slash commands like `/btw`, `/rewind`, `/autocompact` (inside backticks or standalone)
    raw_slashes = re.findall(r"(?:(?<=`)|(?<=[\s(]))(/[a-z][a-z0-9-]{1,24})(?=[`\s,.;:)\]]|$)", text)
    slash_cmds = _dedupe([s for s in raw_slashes if s.lower() not in _COMMON_NON_SLASH_PATHS])

    # Environment variables like `VERTEX_REGION_CLAUDE_5_5_SONNET`, `AGY_CLI_AUTO_COMPACT_OVERRIDE`
    raw_envs = re.findall(r"\b([A-Z][A-Z0-9]{1,}(?:_[A-Z0-9]+)+)\b", text)
    env_vars = _dedupe([e for e in raw_envs if e not in _COMMON_NON_ENV_CAPS and len(e) >= 6])

    # Hook events & notable config/setting keys
    hooks_and_keys = _dedupe(
        re.findall(r"`((?:Pre|Post)[A-Z][A-Za-z0-9]+|PromptHint|turn\.step|[a-z][a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)`", text)
    )

    # Model / alias / deprecation / breaking-change lines
    model_shifts: List[str] = []
    for line in entry.bullet_items:
        low = line.lower()
        if any(tok in low for tok in ("deprecated", "retired", "model alias", "default model", "replaces ", "steps down")):
            model_shifts.append(_truncate_word(_strip_md_inline(line), 160))
            if len(model_shifts) >= 6:
                break

    return {
        "cli_flags": flags,
        "slash_commands": slash_cmds,
        "env_vars": env_vars,
        "hooks_and_keys": hooks_and_keys,
        "model_and_breaking": model_shifts,
    }


def flatten_gem_chips(gems: Dict[str, List[str]], limit: int = 5) -> List[str]:
    """Return top short chips (hooks, slash commands, flags, env vars) for cards & UI."""
    chips: List[str] = []
    for bucket in ("hooks_and_keys", "slash_commands", "cli_flags", "env_vars"):
        for val in gems.get(bucket) or []:
            if val not in chips:
                chips.append(val)
            if len(chips) >= limit:
                return chips
    return chips


def extract_convergence_tags(entry: ReleaseEntry) -> List[str]:
    """Return normalized cross-agent capability tag IDs matched by this release."""
    haystack = f"{entry.title}\n{entry.body_markdown}"
    matched: List[str] = []
    for tag_id, _label, pattern in CONVERGENCE_RULES:
        if pattern.search(haystack):
            matched.append(tag_id)
    return matched


# ---------------------------------------------------------------------------
# Parsers (100% verbatim extraction — nothing dropped)
# ---------------------------------------------------------------------------


def parse_antigravity_changelog(markdown: str) -> Dict[str, List[ReleaseEntry]]:
    """Parse ``https://antigravity.google/docs/changelog.md`` across all surfaces."""
    results: Dict[str, List[ReleaseEntry]] = {}
    lines = markdown.splitlines()

    section_indices: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        m = re.match(r"^##\s+(.+?)\s*$", line)
        if m:
            section_indices.append((idx, m.group(1).strip()))

    for s_pos, (start_idx, section_name) in enumerate(section_indices):
        end_idx = section_indices[s_pos + 1][0] if s_pos + 1 < len(section_indices) else len(lines)
        section_lines = lines[start_idx + 1 : end_idx]

        surface_slug = slugify(section_name)
        short_surface = surface_slug.removeprefix("antigravity-")
        track_key = f"antigravity:{short_surface}"
        folder_slug = surface_slug if surface_slug.startswith("antigravity-") else f"antigravity-{surface_slug}"
        display_name = (
            f"Google {section_name}"
            if section_name.lower().startswith("antigravity")
            else f"Google Antigravity {section_name}"
        )

        rel_starts: List[Tuple[int, str, str]] = []
        for r_idx, r_line in enumerate(section_lines):
            vm = re.match(r"^###\s+\[(v?[\d][^\]]*)\]\(([^\s\)]+)", r_line)
            if vm:
                ver = vm.group(1).strip()
                href = vm.group(2).strip()
                if href.startswith("/"):
                    href = f"https://antigravity.google{href}"
                rel_starts.append((r_idx, ver, href))

        entries: List[ReleaseEntry] = []
        for idx_in_list, (r_start, ver, href) in enumerate(rel_starts):
            r_end = rel_starts[idx_in_list + 1][0] if idx_in_list + 1 < len(rel_starts) else len(section_lines)
            chunk = section_lines[r_start + 1 : r_end]

            trimmed: List[str] = []
            for cl in chunk:
                if re.match(r"^Model launch[·\s]", cl):
                    break
                trimmed.append(cl)

            while trimmed and trimmed[-1].strip() in ("", "---"):
                trimmed.pop()
            while trimmed and trimmed[0].strip() == "":
                trimmed.pop(0)

            published_at = ""
            title = ""
            for cl in trimmed[:12]:
                s = cl.strip()
                if not s or s.lower() == "latest":
                    continue
                if not published_at and re.match(
                    r"^(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}$",
                    s,
                ):
                    published_at = s
                    continue
                if not title and s.startswith("### "):
                    title = s[4:].strip()
                    break

            body_md = "\n".join(trimmed).strip()
            entries.append(
                ReleaseEntry(
                    track_key=track_key,
                    product_family="antigravity",
                    display_name=display_name,
                    folder_slug=folder_slug,
                    version=ver,
                    published_at=published_at,
                    url=href,
                    title=title or f"{display_name} {ver}",
                    body_markdown=body_md,
                    extra={"surface": section_name},
                )
            )
        if entries:
            results[track_key] = entries

    return results


def parse_github_releases(
    releases_json: Sequence[Dict[str, Any]],
    *,
    track_key: str,
    product_family: str,
    display_name: str,
    folder_slug: str,
    repo_slug: str,
    include_prereleases: bool = False,
) -> Dict[str, List[ReleaseEntry]]:
    """Generic verbatim parser for standard GitHub Releases JSON arrays."""
    entries: List[ReleaseEntry] = []
    for rel in releases_json:
        if rel.get("draft"):
            continue
        is_pre = bool(rel.get("prerelease"))
        if is_pre and not include_prereleases:
            continue
        tag = str(rel.get("tag_name") or "").strip()
        if not tag:
            continue
        body = str(rel.get("body") or "").replace("\r\n", "\n").strip()
        published_at = str(rel.get("published_at") or rel.get("created_at") or "").strip()
        html_url = str(rel.get("html_url") or f"https://github.com/{repo_slug}/releases/tag/{tag}")
        rel_name = str(rel.get("name") or tag).strip()

        entries.append(
            ReleaseEntry(
                track_key=track_key,
                product_family=product_family,
                display_name=display_name,
                folder_slug=folder_slug,
                version=tag,
                published_at=published_at,
                url=html_url,
                title=rel_name if rel_name != tag else f"{display_name} {tag}",
                body_markdown=body,
                extra={"prerelease": is_pre, "name": rel_name, "repo": repo_slug},
            )
        )
    return {track_key: entries} if entries else {}


def parse_codex_releases(
    releases_json: Sequence[Dict[str, Any]],
    include_prereleases: bool = False,
) -> Dict[str, List[ReleaseEntry]]:
    """Parse GitHub Releases JSON for ``openai/codex`` (stable, plus optional raw alphas)."""
    out = parse_github_releases(
        releases_json,
        track_key="codex:cli",
        product_family="codex",
        display_name="OpenAI Codex CLI",
        folder_slug="codex-cli",
        repo_slug="openai/codex",
        include_prereleases=False,
    )
    if include_prereleases:
        alphas = [r for r in releases_json if not r.get("draft") and r.get("prerelease")]
        alpha_parsed = parse_github_releases(
            alphas,
            track_key="codex:cli-alpha",
            product_family="codex-alpha",
            display_name="OpenAI Codex CLI (Alpha)",
            folder_slug="codex-cli-alpha",
            repo_slug="openai/codex",
            include_prereleases=True,
        )
        out.update(alpha_parsed)
    return out


def build_codex_alpha_radar_entry(
    stable_tag: str,
    alpha_tag: str,
    alpha_published_at: str,
    compare_json: Dict[str, Any],
) -> Optional[ReleaseEntry]:
    """Turn GitHub compare JSON (``stable...alpha``) into a verbatim PR Radar release entry."""
    commits = list(compare_json.get("commits") or [])
    ahead_by = int(compare_json.get("ahead_by") or len(commits))
    if not commits:
        return None

    # Reverse so newest commits/PRs appear at the top; skip automated version bump noise
    pr_lines: List[str] = []
    for c in reversed(commits):
        msg = str((c.get("commit") or {}).get("message") or "").splitlines()[0].strip()
        if not msg:
            continue
        if re.match(r"^(?:Release|Bump version|Merge branch|chore\(release\))", msg, re.I):
            continue
        sha = str(c.get("sha") or "")[:7]
        author = str(((c.get("author") or {}).get("login")) or "")
        suffix = f" (`{sha}`" + (f", @{author}" if author else "") + ")"
        pr_lines.append(f"- {msg}{suffix}")

    if not pr_lines:
        return None

    compare_url = str(
        compare_json.get("html_url")
        or f"https://github.com/openai/codex/compare/{stable_tag}...{alpha_tag}"
    )
    body_lines = [
        f"Upcoming commits & PRs in **`{alpha_tag}`** ahead of latest stable **`{stable_tag}`** "
        f"({ahead_by} total commits ahead; {len(pr_lines)} shown from GitHub compare).",
        "",
        f"Full diff: {compare_url}",
        "",
        "## Upcoming Changes (Newest First)",
        "",
        *pr_lines,
    ]
    return ReleaseEntry(
        track_key="codex:alpha-radar",
        product_family="codex-alpha",
        display_name="OpenAI Codex Alpha Radar",
        folder_slug="codex-alpha-radar",
        version=alpha_tag,
        published_at=alpha_published_at,
        url=compare_url,
        title=f"{ahead_by} upcoming commits ahead of {stable_tag}",
        body_markdown="\n".join(body_lines),
        extra={"base_stable": stable_tag, "ahead_by": ahead_by, "prerelease": True},
    )


def parse_claude_code_changelog(
    markdown: str,
    dist_tags: Optional[Dict[str, str]] = None,
) -> Dict[str, List[ReleaseEntry]]:
    """Parse ``anthropics/claude-code/CHANGELOG.md`` (newest-first, 100% verbatim)."""
    lines = markdown.replace("\r\n", "\n").splitlines()
    headers: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines):
        m = re.match(r"^##\s+(v?\d+\.\d+\.\d+[^\s]*)\s*$", line)
        if m:
            headers.append((idx, m.group(1).strip()))

    entries: List[ReleaseEntry] = []
    tags_map = dist_tags or {}
    for pos, (h_idx, raw_ver) in enumerate(headers):
        end_idx = headers[pos + 1][0] if pos + 1 < len(headers) else len(lines)
        body_lines = lines[h_idx + 1 : end_idx]
        while body_lines and body_lines[0].strip() == "":
            body_lines.pop(0)
        while body_lines and body_lines[-1].strip() == "":
            body_lines.pop()

        ver_num = raw_ver.lstrip("v")
        ver_label = f"v{ver_num}"
        matched_tags = [k for k, v in tags_map.items() if v == ver_num]
        anchor = ver_num.replace(".", "")
        url = f"https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md#{anchor}"

        entries.append(
            ReleaseEntry(
                track_key="claude-code:cli",
                product_family="claude-code",
                display_name="Anthropic Claude Code",
                folder_slug="claude-code",
                version=ver_label,
                published_at=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                url=url,
                title=f"Claude Code {ver_label}",
                body_markdown="\n".join(body_lines).strip(),
                extra={"npm_dist_tags": matched_tags, "raw_version": ver_num},
            )
        )

    return {"claude-code:cli": entries} if entries else {}


class _ProseHTMLToMarkdown(HTMLParser):
    """Minimal pure-stdlib HTML -> clean Markdown converter for Cursor changelog prose."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: List[str] = []
        self._skip_depth = 0
        self._in_code = False
        self._in_li = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = dict(attrs)
        if tag in ("script", "style", "svg", "video", "source"):
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "a" and "anchor-link" in (attr_map.get("class") or ""):
            self._skip_depth += 1
            return
        if tag in ("h2", "h3", "h4"):
            lvl = "#" * int(tag[1])
            self.chunks.append(f"\n\n{lvl} ")
        elif tag == "p":
            if not self._in_li:
                self.chunks.append("\n\n")
        elif tag == "li":
            self._in_li = True
            self.chunks.append("\n- ")
        elif tag == "br":
            self.chunks.append("\n")
        elif tag == "code":
            self._in_code = True
            self.chunks.append("`")
        elif tag in ("strong", "b"):
            self.chunks.append("**")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "svg", "video", "source"):
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            if tag == "a":
                self._skip_depth -= 1
            return
        if tag == "code" and self._in_code:
            self._in_code = False
            self.chunks.append("`")
        elif tag in ("strong", "b"):
            self.chunks.append("**")
        elif tag == "li":
            self._in_li = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_code:
            self.chunks.append(data)
        else:
            collapsed = re.sub(r"\s+", " ", data)
            self.chunks.append(collapsed)

    def get_markdown(self) -> str:
        raw = "".join(self.chunks)
        raw = re.sub(r"[ \t]+\n", "\n", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def parse_cursor_changelog_html(html: str) -> Dict[str, List[ReleaseEntry]]:
    """Parse ``https://cursor.com/changelog`` ``<article>`` blocks into verbatim Markdown."""
    articles = re.findall(r"<article\b[^>]*>(.*?)</article>", html, flags=re.S | re.I)
    entries: List[ReleaseEntry] = []

    for art in articles:
        href_m = re.search(r'href="(/changelog/[^"#?]+)"', art)
        slug_path = href_m.group(1).strip() if href_m else ""
        slug_id = slug_path.rsplit("/", 1)[-1] if slug_path else ""

        time_m = re.search(r'<time[^>]*dateTime="([^"]+)"[^>]*>([^<]*)</time>', art, flags=re.I)
        published_at = (time_m.group(1) if time_m else "").strip()
        if published_at and "T" in published_at:
            published_at = published_at.split("T", 1)[0]

        h1_m = re.search(r"<h1\b[^>]*>(.*?)</h1>", art, flags=re.S | re.I)
        title = re.sub(r"<[^>]+>", "", h1_m.group(1)).strip() if h1_m else slug_id
        title = re.sub(r"\s+", " ", title)

        # Look for an explicit version pill (e.g., 2.4 or 1.7) or fall back to date+slug
        ver_pill = re.search(r">\s*(v?\d+\.\d+(?:\.\d+)?)\s*<", art[:1200])
        if ver_pill:
            ver = ver_pill.group(1).strip()
            if not ver.startswith("v"):
                ver = f"v{ver}"
        elif slug_id:
            ver = slug_id
        elif published_at:
            ver = published_at
        else:
            continue

        prose_m = re.search(r'<div[^>]*class="[^"]*prose[^"]*"[^>]*>(.*)</div>\s*</div>\s*</div>\s*$', art, flags=re.S | re.I)
        prose_html = prose_m.group(1) if prose_m else art
        conv = _ProseHTMLToMarkdown()
        conv.feed(prose_html)
        body_md = conv.get_markdown()
        if not body_md:
            continue

        # Ensure bullet items exist if prose only had headings/paragraphs
        full_url = f"https://cursor.com{slug_path}" if slug_path else CURSOR_CHANGELOG_URL
        entries.append(
            ReleaseEntry(
                track_key="cursor:changelog",
                product_family="cursor",
                display_name="Cursor",
                folder_slug="cursor",
                version=ver,
                published_at=published_at,
                url=full_url,
                title=title or f"Cursor {ver}",
                body_markdown=body_md,
                extra={"slug": slug_id},
            )
        )

    return {"cursor:changelog": entries} if entries else {}


# ---------------------------------------------------------------------------
# Tweet & Markdown rendering
# ---------------------------------------------------------------------------


def _select_highlight_bullets(entry: ReleaseEntry, max_items: int = 5) -> List[str]:
    """Pick the highest-signal bullets (features/improvements first) for cards & tweets."""
    bullets = entry.bullet_items
    if not bullets:
        # Fallback for prose-only changelogs (e.g. Cursor articles without <ul>)
        paras = [
            _strip_md_inline(p)
            for p in re.split(r"\n{2,}", entry.body_markdown)
            if p.strip() and not p.strip().startswith("#")
        ]
        return paras[:max_items]

    def score(b: str) -> Tuple[int, int]:
        low = b.lower()
        if low.startswith("[vscode]"):
            return (3, len(b))
        if low.startswith(("added ", "new ", "introduces ", "you can now ", "expanded ", "enabled ")):
            return (0, len(b))
        if low.startswith(("improved ", "updated ", "changed ", "carried ", "follow ", "press ", "jump ", "optional ", "set ", "app-server ")):
            return (1, len(b))
        if low.startswith("fixed "):
            return (2, len(b))
        return (1, len(b))

    indexed = list(enumerate(bullets))
    indexed.sort(key=lambda pair: (score(pair[1])[0], pair[0]))
    return [_strip_md_inline(b) for _, b in indexed[:max_items]]


def build_release_tweet(entry: ReleaseEntry) -> str:
    """Build a punchy, 100%-grounded X/Twitter draft strictly <= 280 characters."""
    total = len(entry.bullet_items)
    count_tag = f" ({total} changes)" if total >= 15 else ""
    header = f"{entry.display_name} {entry.version} is out{count_tag} 🚀"

    # If the release has a crisp non-generic headline (e.g. Antigravity or Cursor), lead with it!
    generic_titles = {
        f"{entry.display_name} {entry.version}".lower(),
        f"codex cli {entry.version}".lower(),
        f"claude code {entry.version}".lower(),
        entry.version.lower(),
    }
    clean_title = _strip_md_inline(entry.title or "")
    has_rich_title = bool(clean_title and clean_title.lower() not in generic_titles and len(clean_title) <= 110)

    highlights = _select_highlight_bullets(entry, max_items=5)
    if not highlights and clean_title:
        return f"{header}\n\n{_truncate_word(clean_title, 275 - len(header) - 2)}"[:280]

    prefix = f"{header}\n\n{clean_title}\n" if has_rich_title else f"{header}\n\nHighlights:\n"
    remaining = 280 - len(prefix)
    chosen: List[str] = []

    for raw in highlights:
        short = re.split(r"(?:;\s+|\s+—\s+)", raw, maxsplit=1)[0]
        candidate_len = min(64, remaining - 3)
        if candidate_len < 20:
            break
        line = f"• {_truncate_word(short, candidate_len)}"
        needed = len(line) + (1 if chosen else 0)
        if needed <= remaining:
            chosen.append(line)
            remaining -= needed
        if len(chosen) >= (3 if has_rich_title else 4):
            break

    if not chosen:
        fallback_line = clean_title if has_rich_title else (highlights[0] if highlights else entry.version)
        return f"{header}\n\n• {_truncate_word(fallback_line, 270 - len(header))}"[:280]

    return (prefix + "\n".join(chosen))[:280]


def render_verbatim_release_markdown(
    entry: ReleaseEntry,
    tweet: str,
    gems: Optional[Dict[str, List[str]]] = None,
    convergence_tags: Optional[List[str]] = None,
) -> str:
    """Render the complete, zero-truncation archive Markdown file for a release."""
    gems = gems if gems is not None else extract_buried_gems(entry)
    convergence_tags = convergence_tags if convergence_tags is not None else extract_convergence_tags(entry)
    total_bullets = len(entry.bullet_items)
    captured_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    meta_lines = [
        f"# {entry.display_name} — {entry.version}",
        "",
        f"- **Track:** `{entry.track_key}`",
        f"- **Version:** `{entry.version}`",
        f"- **Published:** {entry.published_at or 'unknown'}",
        f"- **Captured (UTC):** {captured_at}",
        f"- **Total bullet items:** {total_bullets}",
        f"- **Source:** {entry.url}",
    ]
    if entry.extra.get("npm_dist_tags"):
        meta_lines.append(f"- **npm dist-tags:** {', '.join(entry.extra['npm_dist_tags'])}")
    if convergence_tags:
        meta_lines.append(f"- **Capability tags:** {', '.join(f'`{t}`' for t in convergence_tags)}")

    gem_section: List[str] = []
    if any(gems.values()):
        gem_section.extend(["", "## Buried Gems & Power-User Signals", ""])
        if gems.get("hooks_and_keys"):
            gem_section.append("- **Hooks & Config Keys:** " + ", ".join(f"`{x}`" for x in gems["hooks_and_keys"]))
        if gems.get("slash_commands"):
            gem_section.append("- **Slash Commands:** " + ", ".join(f"`{x}`" for x in gems["slash_commands"]))
        if gems.get("cli_flags"):
            gem_section.append("- **CLI Flags:** " + ", ".join(f"`{x}`" for x in gems["cli_flags"]))
        if gems.get("env_vars"):
            gem_section.append("- **Env Vars:** " + ", ".join(f"`{x}`" for x in gems["env_vars"]))
        if gems.get("model_and_breaking"):
            gem_section.append("- **Model / Deprecation Shifts:**")
            for shift in gems["model_and_breaking"]:
                gem_section.append(f"  - {shift}")

    lines = [
        *meta_lines,
        "",
        "## Ready-to-Post Tweet",
        "",
        "```text",
        tweet,
        "```",
        *gem_section,
        "",
        "## Complete Verbatim Release Notes (Nothing Omitted)",
        "",
        entry.body_markdown or "_No release body provided upstream._",
        "",
    ]
    return "\n".join(lines)


def write_release_archive(
    entry: ReleaseEntry,
    tweet: str,
    releases_dir: pathlib.Path = DEFAULT_RELEASES_DIR,
    gems: Optional[Dict[str, List[str]]] = None,
    convergence_tags: Optional[List[str]] = None,
) -> Tuple[pathlib.Path, str]:
    """Save the 100% verbatim release markdown file and return ``(path, content)``."""
    target_dir = releases_dir / entry.folder_slug
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / entry.safe_filename
    content = render_verbatim_release_markdown(entry, tweet, gems=gems, convergence_tags=convergence_tags)
    target_file.write_text(content, encoding="utf-8")
    return target_file, content


def update_releases_index(
    state: Dict[str, Any],
    releases_dir: pathlib.Path = DEFAULT_RELEASES_DIR,
) -> pathlib.Path:
    """Write ``releases/INDEX.md`` summarizing every captured release."""
    releases_dir.mkdir(parents=True, exist_ok=True)
    history: List[Dict[str, Any]] = list(state.get("history") or [])
    lines = [
        "# Tracked Releases Index",
        "",
        "Automated 24/7 archive of 100% verbatim release notes for **Google Antigravity**, **OpenAI Codex CLI (+ Alpha Radar)**, **Anthropic Claude Code**, **Gemini CLI**, **OpenCode**, **Cursor**, and **MCP Spec**.",
        "",
        "| Captured (UTC) | Product | Version | Items | Signals | Full Notes | Upstream |",
        "| :--- | :--- | :--- | ---: | :--- | :--- | :--- |",
    ]
    for item in reversed(history[-250:]):
        rel_path = item.get("archive_relpath", "")
        rel_link = f"[Full notes]({rel_path})" if rel_path else "—"
        src_url = item.get("url", "")
        src_link = f"[Source]({src_url})" if src_url else "—"
        tags = item.get("convergence_tags") or []
        tags_str = ", ".join(f"`{t}`" for t in tags[:4]) if tags else "—"
        lines.append(
            f"| {item.get('captured_at', '')[:16].replace('T', ' ')} | "
            f"{item.get('display_name', '')} | "
            f"`{item.get('version', '')}` | "
            f"{item.get('bullet_count', 0)} | "
            f"{tags_str} | "
            f"{rel_link} | {src_link} |"
        )
    lines.append("")
    index_path = releases_dir / "INDEX.md"
    index_path.write_text("\n".join(lines), encoding="utf-8")
    return index_path


def export_docs_releases_json(
    state: Dict[str, Any],
    releases_dir: pathlib.Path = DEFAULT_RELEASES_DIR,
    docs_json_file: pathlib.Path = DEFAULT_DOCS_JSON_FILE,
) -> pathlib.Path:
    """Build ``docs/data/releases.json`` powering the searchable GitHub Pages Release Radar."""
    docs_json_file.parent.mkdir(parents=True, exist_ok=True)
    history: List[Dict[str, Any]] = list(state.get("history") or [])
    enriched: List[Dict[str, Any]] = []

    # Build convergence matrix: tag_id -> {label, products: {product_family: latest_version}}
    matrix: Dict[str, Dict[str, Any]] = {
        tag_id: {"id": tag_id, "label": label, "releases": []}
        for tag_id, label, _ in CONVERGENCE_RULES
    }

    for rec in reversed(history[-120:]):
        archive_relpath = str(rec.get("archive_relpath") or "")
        body_md = ""
        if archive_relpath:
            full_path = releases_dir / archive_relpath
            if full_path.exists():
                raw = full_path.read_text(encoding="utf-8", errors="replace")
                marker = "## Complete Verbatim Release Notes (Nothing Omitted)"
                body_md = raw.split(marker, 1)[1].strip() if marker in raw else raw

        item = dict(rec)
        item["body_markdown"] = body_md
        enriched.append(item)

        for tag_id in item.get("convergence_tags") or []:
            if tag_id in matrix:
                matrix[tag_id]["releases"].append(
                    {
                        "track_key": item.get("track_key"),
                        "product_family": item.get("product_family"),
                        "display_name": item.get("display_name"),
                        "version": item.get("version"),
                        "published_at": item.get("published_at"),
                        "captured_at": item.get("captured_at"),
                    }
                )

    payload = {
        "generated_at": state.get("last_checked_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tracks": state.get("tracks") or {},
        "convergence_axes": list(matrix.values()),
        "releases": enriched,
    }
    docs_json_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return docs_json_file


# ---------------------------------------------------------------------------
# Discord notification (embed + PNG Release Card + full verbatim .md file)
# ---------------------------------------------------------------------------


def build_release_discord_embed(
    entry: ReleaseEntry,
    tweet: str,
    gems: Optional[Dict[str, List[str]]] = None,
    convergence_tags: Optional[List[str]] = None,
    repo_slug: str = "",
    archive_relpath: str = "",
    card_png_filename: str = "",
) -> Dict[str, Any]:
    meta = PRODUCT_META.get(entry.product_family, PRODUCT_META["antigravity"])
    gems = gems if gems is not None else extract_buried_gems(entry)
    convergence_tags = convergence_tags if convergence_tags is not None else extract_convergence_tags(entry)
    total = len(entry.bullet_items)
    highlights = _select_highlight_bullets(entry, max_items=8)

    desc_lines: List[str] = []
    if entry.title and entry.title.lower() != f"{entry.display_name} {entry.version}".lower():
        desc_lines.append(f"**{_strip_md_inline(entry.title)}**")
        desc_lines.append("")

    if highlights:
        desc_lines.append(f"**Highlights ({total} total items — complete verbatim list attached as `.md`):**")
        for b in highlights:
            desc_lines.append(f"• {_truncate_word(b, 200)}")
        if total > len(highlights):
            desc_lines.append(f"*…+{total - len(highlights)} more items in the attached `.md` file (nothing omitted).*")
    else:
        desc_lines.append(_truncate_word(_strip_md_inline(entry.body_markdown), 1200))

    chips = flatten_gem_chips(gems, limit=8)
    if chips:
        desc_lines.extend(["", "**Buried Gems / Signals:** " + " · ".join(f"`{c}`" for c in chips)])
    if convergence_tags:
        desc_lines.append("**Convergence Tags:** " + " ".join(f"`#{t}`" for t in convergence_tags[:6]))

    links: List[str] = []
    if entry.url:
        links.append(f"[Official Notes]({entry.url})")
    if repo_slug and archive_relpath:
        gh_url = f"https://github.com/{repo_slug}/blob/main/releases/{archive_relpath}"
        links.append(f"[Full Verbatim Archive]({gh_url})")
    if repo_slug:
        owner = repo_slug.split("/", 1)[0]
        repo_name = repo_slug.split("/", 1)[-1]
        links.append(f"[Release Radar](https://{owner}.github.io/{repo_name}/releases.html)")
    if links:
        desc_lines.extend(["", " · ".join(links)])

    embed: Dict[str, Any] = {
        "author": {"name": f"{meta['badge']} · {meta['org'].upper()}"},
        "title": f"{entry.display_name} {entry.version}"[:256],
        "description": "\n".join(desc_lines)[:4000],
        "color": meta["color"],
        "thumbnail": {"url": PROVIDER_LOGOS.get(meta["provider_slug"], PROVIDER_LOGOS["google"])},
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fields": [
            {
                "name": f"Ready X Post Copy ({len(tweet)} chars)",
                "value": f"```text\n{tweet}\n```"[:1024],
            }
        ],
    }
    if entry.url:
        embed["url"] = entry.url
    if card_png_filename:
        embed["image"] = {"url": f"attachment://{card_png_filename}"}
    return embed


def build_multipart_files_webhook_body(
    payload: Dict[str, Any],
    files: Sequence[Tuple[str, bytes, str]],
) -> Tuple[bytes, str]:
    """Build a pure-stdlib multipart/form-data Discord body supporting multiple attachments.

    ``files`` is a sequence of ``(filename, raw_bytes, content_type)``.
    """
    boundary = f"----ReleaseWatcherBoundary{uuid.uuid4().hex}"
    parts: List[bytes] = [
        f"--{boundary}\r\n".encode("utf-8"),
        b'Content-Disposition: form-data; name="payload_json"\r\n',
        b"Content-Type: application/json\r\n\r\n",
        json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        b"\r\n",
    ]
    for idx, (filename, raw_bytes, mime_type) in enumerate(files):
        parts.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                f'Content-Disposition: form-data; name="files[{idx}]"; filename="{filename}"\r\n'.encode("utf-8"),
                f"Content-Type: {mime_type}\r\n\r\n".encode("utf-8"),
                raw_bytes,
                b"\r\n",
            ]
        )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _try_render_release_png(
    entry: ReleaseEntry,
    gems: Dict[str, List[str]],
) -> Optional[bytes]:
    try:
        from tracker.card_renderer import render_release_card_png
    except Exception:
        return None
    meta = PRODUCT_META.get(entry.product_family, PRODUCT_META["antigravity"])
    subtitle = (
        _strip_md_inline(entry.title)
        if entry.title and entry.title.lower() != f"{entry.display_name} {entry.version}".lower()
        else f"Published {entry.published_at}" if entry.published_at else "Official upstream release"
    )
    return render_release_card_png(
        display_name=entry.display_name,
        version=entry.version,
        provider_slug=meta["provider_slug"],
        org_label=meta["org"],
        badge_text=meta["badge"],
        item_count=len(entry.bullet_items),
        subtitle=subtitle,
        highlights=_select_highlight_bullets(entry, max_items=4),
        gem_chips=flatten_gem_chips(gems, limit=5),
        timestamp_iso=entry.published_at,
    )


def send_release_discord_notification(
    entry: ReleaseEntry,
    tweet: str,
    archive_content: str,
    gems: Optional[Dict[str, List[str]]] = None,
    convergence_tags: Optional[List[str]] = None,
    webhook_url: Optional[str] = None,
    repo_slug: str = "",
    archive_relpath: str = "",
    attach_png: bool = True,
    poster: Callable[[str, bytes, str], bool] = _post_discord_request,
) -> bool:
    """Post a Discord embed with the @StatsWire PNG card AND full verbatim `.md` attached."""
    url = (
        webhook_url
        or os.environ.get("RELEASE_DISCORD_WEBHOOK_URL")
        or os.environ.get("DISCORD_WEBHOOK_URL")
        or ""
    ).strip()
    if not url:
        return False

    gems = gems if gems is not None else extract_buried_gems(entry)
    convergence_tags = convergence_tags if convergence_tags is not None else extract_convergence_tags(entry)

    files: List[Tuple[str, bytes, str]] = []
    attachments_meta: List[Dict[str, Any]] = []
    png_name = ""

    if attach_png:
        png_bytes = _try_render_release_png(entry, gems)
        if png_bytes:
            png_name = f"statswire-{entry.folder_slug}-{entry.safe_filename.removesuffix('.md')}.png"
            attachments_meta.append({"id": len(files), "filename": png_name})
            files.append((png_name, png_bytes, "image/png"))

    md_name = f"{entry.folder_slug}-{entry.safe_filename}"
    attachments_meta.append({"id": len(files), "filename": md_name})
    files.append((md_name, archive_content.encode("utf-8"), "text/markdown; charset=utf-8"))

    embed = build_release_discord_embed(
        entry,
        tweet=tweet,
        gems=gems,
        convergence_tags=convergence_tags,
        repo_slug=repo_slug,
        archive_relpath=archive_relpath,
        card_png_filename=png_name,
    )
    payload = {
        "username": "ReleasePulse Watcher",
        "embeds": [embed],
        "attachments": attachments_meta,
    }
    body, content_type = build_multipart_files_webhook_body(payload, files)
    return poster(url, body, content_type)


# ---------------------------------------------------------------------------
# Diff detection & runner
# ---------------------------------------------------------------------------


def detect_new_releases(
    fetched_tracks: Dict[str, List[ReleaseEntry]],
    state: Dict[str, Any],
    max_catchup_per_track: int = 5,
) -> Tuple[List[ReleaseEntry], bool]:
    """Compare newest-first fetched tracks against persisted state.

    Returns ``(new_releases_chronological, was_initial_seed)``.
    Newly introduced tracks in an existing state file are seeded cleanly (1 latest
    entry each) without spamming historical releases; ``was_initial_seed`` is
    True only when the entire state file started empty.
    """
    seen_tracks: Dict[str, Any] = dict(state.get("tracks") or {})
    if not seen_tracks:
        seeded = [entries[0] for entries in fetched_tracks.values() if entries]
        return seeded, True

    new_entries: List[ReleaseEntry] = []
    for track_key, entries in fetched_tracks.items():
        if not entries:
            continue
        prev_info = seen_tracks.get(track_key)
        if not prev_info:
            # Brand-new track added to watcher config -> capture its latest baseline
            new_entries.append(entries[0])
            continue

        last_version = str(prev_info.get("latest_version") or "")
        seen_versions = set(prev_info.get("seen_versions") or [])
        if last_version:
            seen_versions.add(last_version)

        unseen_for_track: List[ReleaseEntry] = []
        for entry in entries:
            if entry.version in seen_versions:
                break
            unseen_for_track.append(entry)
            if len(unseen_for_track) >= max_catchup_per_track:
                break

        new_entries.extend(reversed(unseen_for_track))

    return new_entries, False


def fetch_all_tracks(
    include_codex_alphas: bool = True,
    github_token: Optional[str] = None,
) -> Tuple[Dict[str, List[ReleaseEntry]], List[str]]:
    """Fetch all upstream sources. Returns ``(tracks, errors)``."""
    tracks: Dict[str, List[ReleaseEntry]] = {}
    errors: List[str] = []

    gh_headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
    token = (github_token or os.environ.get("GITHUB_TOKEN") or "").strip()
    if token:
        gh_headers["Authorization"] = f"Bearer {token}"

    # 1. Google Antigravity (App, CLI, IDE Extensions, SDK, IDE)
    try:
        ag_md = _http_get_text(ANTIGRAVITY_CHANGELOG_URL)
        tracks.update(parse_antigravity_changelog(ag_md))
    except Exception as exc:
        errors.append(f"antigravity: {exc}")

    # 2. OpenAI Codex CLI (stable + Alpha PR Radar)
    try:
        codex_rels = _http_get_json(CODEX_RELEASES_API_URL, headers=gh_headers)
        tracks.update(parse_codex_releases(codex_rels, include_prereleases=False))
        if include_codex_alphas:
            stable_rel = next((r for r in codex_rels if not r.get("draft") and not r.get("prerelease")), None)
            alpha_rel = next((r for r in codex_rels if not r.get("draft") and r.get("prerelease")), None)
            if stable_rel and alpha_rel:
                stable_tag = str(stable_rel.get("tag_name") or "")
                alpha_tag = str(alpha_rel.get("tag_name") or "")
                if stable_tag and alpha_tag and stable_tag != alpha_tag:
                    cmp_url = CODEX_COMPARE_API_TEMPLATE.format(base=stable_tag, head=alpha_tag)
                    cmp_json = _http_get_json(cmp_url, headers=gh_headers)
                    radar = build_codex_alpha_radar_entry(
                        stable_tag=stable_tag,
                        alpha_tag=alpha_tag,
                        alpha_published_at=str(alpha_rel.get("published_at") or ""),
                        compare_json=cmp_json,
                    )
                    if radar:
                        tracks[radar.track_key] = [radar]
    except Exception as exc:
        errors.append(f"codex: {exc}")

    # 3. Anthropic Claude Code
    try:
        cc_md = _http_get_text(CLAUDE_CODE_CHANGELOG_URL)
        dist_tags: Dict[str, str] = {}
        try:
            dist_tags = _http_get_json(CLAUDE_CODE_NPM_TAGS_URL)
        except Exception:
            dist_tags = {}
        tracks.update(parse_claude_code_changelog(cc_md, dist_tags=dist_tags))
    except Exception as exc:
        errors.append(f"claude-code: {exc}")

    # 4. Google Gemini CLI
    try:
        gcli_rels = _http_get_json(GEMINI_CLI_RELEASES_API_URL, headers=gh_headers)
        tracks.update(
            parse_github_releases(
                gcli_rels,
                track_key="gemini-cli:cli",
                product_family="gemini-cli",
                display_name="Google Gemini CLI",
                folder_slug="gemini-cli",
                repo_slug="google-gemini/gemini-cli",
                include_prereleases=False,
            )
        )
    except Exception as exc:
        errors.append(f"gemini-cli: {exc}")

    # 5. OpenCode
    try:
        oc_rels = _http_get_json(OPENCODE_RELEASES_API_URL, headers=gh_headers)
        tracks.update(
            parse_github_releases(
                oc_rels,
                track_key="opencode:cli",
                product_family="opencode",
                display_name="OpenCode",
                folder_slug="opencode",
                repo_slug="anomalyco/opencode",
                include_prereleases=False,
            )
        )
    except Exception as exc:
        errors.append(f"opencode: {exc}")

    # 6. Cursor Changelog
    try:
        cursor_html = _http_get_text(CURSOR_CHANGELOG_URL)
        tracks.update(parse_cursor_changelog_html(cursor_html))
    except Exception as exc:
        errors.append(f"cursor: {exc}")

    # 7. Model Context Protocol Specification
    try:
        mcp_rels = _http_get_json(MCP_SPEC_RELEASES_API_URL, headers=gh_headers)
        tracks.update(
            parse_github_releases(
                mcp_rels,
                track_key="mcp:spec",
                product_family="mcp-spec",
                display_name="MCP Specification",
                folder_slug="mcp-spec",
                repo_slug="modelcontextprotocol/modelcontextprotocol",
                include_prereleases=False,
            )
        )
    except Exception as exc:
        errors.append(f"mcp-spec: {exc}")

    return tracks, errors


def load_state(state_file: pathlib.Path = DEFAULT_STATE_FILE) -> Dict[str, Any]:
    if not state_file.exists():
        return {"tracks": {}, "history": []}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except Exception:
        return {"tracks": {}, "history": []}


def save_state(state: Dict[str, Any], state_file: pathlib.Path = DEFAULT_STATE_FILE) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _backfill_existing_history_metadata(
    state: Dict[str, Any],
    releases_dir: pathlib.Path,
) -> None:
    """Ensure older state history entries have product_family, gems, and convergence_tags."""
    for rec in state.get("history") or []:
        if rec.get("product_family") and "buried_gems" in rec and "convergence_tags" in rec:
            continue
        tk = str(rec.get("track_key") or "")
        if not rec.get("product_family"):
            if tk.startswith("antigravity:"):
                rec["product_family"] = "antigravity"
            elif tk == "codex:alpha-radar":
                rec["product_family"] = "codex-alpha"
            elif tk.startswith("codex:"):
                rec["product_family"] = "codex"
            elif tk.startswith("claude-code:"):
                rec["product_family"] = "claude-code"
            elif tk.startswith("gemini-cli:"):
                rec["product_family"] = "gemini-cli"
            elif tk.startswith("opencode:"):
                rec["product_family"] = "opencode"
            elif tk.startswith("cursor:"):
                rec["product_family"] = "cursor"
            elif tk.startswith("mcp:"):
                rec["product_family"] = "mcp-spec"
            else:
                rec["product_family"] = "antigravity"
        rel_path = str(rec.get("archive_relpath") or "")
        body_md = ""
        if rel_path and (releases_dir / rel_path).exists():
            raw = (releases_dir / rel_path).read_text(encoding="utf-8", errors="replace")
            marker = "## Complete Verbatim Release Notes (Nothing Omitted)"
            body_md = raw.split(marker, 1)[1].strip() if marker in raw else raw
        dummy = ReleaseEntry(
            track_key=tk,
            product_family=rec["product_family"],
            display_name=str(rec.get("display_name") or ""),
            folder_slug=rel_path.split("/", 1)[0] if "/" in rel_path else "misc",
            version=str(rec.get("version") or ""),
            published_at=str(rec.get("published_at") or ""),
            url=str(rec.get("url") or ""),
            title=str(rec.get("display_name") or ""),
            body_markdown=body_md,
        )
        rec.setdefault("buried_gems", extract_buried_gems(dummy))
        rec.setdefault("convergence_tags", extract_convergence_tags(dummy))


def run_check(
    state_file: pathlib.Path = DEFAULT_STATE_FILE,
    releases_dir: pathlib.Path = DEFAULT_RELEASES_DIR,
    docs_json_file: Optional[pathlib.Path] = DEFAULT_DOCS_JSON_FILE,
    notify_discord: bool = True,
    notify_on_seed: bool = False,
    force_notify_latest: bool = False,
    include_codex_alphas: bool = True,
    dry_run: bool = False,
    repo_slug: str = "",
    fetcher: Callable[..., Tuple[Dict[str, List[ReleaseEntry]], List[str]]] = fetch_all_tracks,
) -> Dict[str, Any]:
    """Execute one full check cycle across all tracked agent & protocol sources."""
    state = load_state(state_file)
    prior_track_keys = set((state.get("tracks") or {}).keys())
    fetched_tracks, errors = fetcher(include_codex_alphas=include_codex_alphas)
    new_releases, was_seed = detect_new_releases(fetched_tracks, state)

    if force_notify_latest and not new_releases:
        new_releases = [entries[0] for entries in fetched_tracks.values() if entries]

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tracks_state: Dict[str, Any] = dict(state.get("tracks") or {})
    history: List[Dict[str, Any]] = list(state.get("history") or [])
    processed: List[Dict[str, Any]] = []

    for idx, entry in enumerate(new_releases):
        tweet = build_release_tweet(entry)
        gems = extract_buried_gems(entry)
        conv_tags = extract_convergence_tags(entry)
        archive_relpath = f"{entry.folder_slug}/{entry.safe_filename}"

        if not dry_run:
            _, archive_content = write_release_archive(
                entry,
                tweet,
                releases_dir=releases_dir,
                gems=gems,
                convergence_tags=conv_tags,
            )
        else:
            archive_content = render_verbatim_release_markdown(
                entry,
                tweet,
                gems=gems,
                convergence_tags=conv_tags,
            )

        is_brand_new_track = entry.track_key not in prior_track_keys
        should_notify = (
            notify_discord
            and not dry_run
            and ((not was_seed and not is_brand_new_track) or notify_on_seed or force_notify_latest)
        )
        notified = False
        if should_notify:
            try:
                notified = send_release_discord_notification(
                    entry,
                    tweet=tweet,
                    archive_content=archive_content,
                    gems=gems,
                    convergence_tags=conv_tags,
                    repo_slug=repo_slug,
                    archive_relpath=archive_relpath,
                )
            except Exception as exc:
                errors.append(f"discord({entry.track_key} {entry.version}): {exc}")
            if idx + 1 < len(new_releases):
                time.sleep(0.5)

        prev_seen = list((tracks_state.get(entry.track_key) or {}).get("seen_versions") or [])
        if entry.version not in prev_seen:
            prev_seen.append(entry.version)
        tracks_state[entry.track_key] = {
            "display_name": entry.display_name,
            "product_family": entry.product_family,
            "latest_version": entry.version,
            "published_at": entry.published_at,
            "url": entry.url,
            "bullet_count": len(entry.bullet_items),
            "archive_relpath": archive_relpath,
            "convergence_tags": conv_tags,
            "updated_at": now_iso,
            "seen_versions": prev_seen[-50:],
        }

        record = {
            "track_key": entry.track_key,
            "product_family": entry.product_family,
            "display_name": entry.display_name,
            "version": entry.version,
            "title": entry.title,
            "published_at": entry.published_at,
            "captured_at": now_iso,
            "bullet_count": len(entry.bullet_items),
            "archive_relpath": archive_relpath,
            "url": entry.url,
            "tweet": tweet,
            "buried_gems": gems,
            "convergence_tags": conv_tags,
            "notified": notified,
        }
        existing_idx = next(
            (
                i
                for i, h in enumerate(history)
                if h.get("track_key") == entry.track_key and h.get("version") == entry.version
            ),
            None,
        )
        if existing_idx is None:
            history.append(record)
        else:
            history[existing_idx] = record
        processed.append(record)

    state["tracks"] = tracks_state
    state["history"] = history[-500:]
    state["last_checked_at"] = now_iso

    if not dry_run:
        _backfill_existing_history_metadata(state, releases_dir=releases_dir)
        save_state(state, state_file=state_file)
        update_releases_index(state, releases_dir=releases_dir)
        if docs_json_file is not None:
            export_docs_releases_json(state, releases_dir=releases_dir, docs_json_file=docs_json_file)

    return {
        "checked_at": now_iso,
        "was_initial_seed": was_seed,
        "tracks_found": len(fetched_tracks),
        "new_count": len(processed),
        "processed": processed,
        "errors": errors,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="24/7 Release Notes & Alpha Radar Watcher for AI Coding Agents and MCP."
    )
    parser.add_argument("--state-file", type=pathlib.Path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--releases-dir", type=pathlib.Path, default=DEFAULT_RELEASES_DIR)
    parser.add_argument("--docs-json", type=pathlib.Path, default=DEFAULT_DOCS_JSON_FILE)
    parser.add_argument("--no-discord", action="store_true", help="Do not send Discord notifications.")
    parser.add_argument("--notify-on-seed", action="store_true", help="Also notify Discord on initial seed run.")
    parser.add_argument(
        "--force-notify-latest",
        action="store_true",
        help="Re-send the latest release for every track (useful for testing Discord delivery).",
    )
    parser.add_argument(
        "--no-codex-alphas",
        action="store_true",
        help="Disable OpenAI Codex Alpha PR Radar compare track.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Fetch and print without writing files or notifying.")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repo slug (owner/name) for archive & Radar links in Discord embeds.",
    )
    args = parser.parse_args(argv)

    include_alphas = not args.no_codex_alphas and os.environ.get("TRACK_CODEX_ALPHAS", "true").lower() not in (
        "0",
        "false",
        "no",
    )

    summary = run_check(
        state_file=args.state_file,
        releases_dir=args.releases_dir,
        docs_json_file=args.docs_json,
        notify_discord=not args.no_discord,
        notify_on_seed=args.notify_on_seed,
        force_notify_latest=args.force_notify_latest,
        include_codex_alphas=include_alphas,
        dry_run=args.dry_run,
        repo_slug=args.repo,
    )

    print(
        f"[ReleaseWatcher] Checked {summary['tracks_found']} tracks at {summary['checked_at']} "
        f"(seed={summary['was_initial_seed']}, processed={summary['new_count']}, errors={len(summary['errors'])})"
    )
    for item in summary["processed"]:
        print(
            f"  - {item['display_name']} {item['version']} "
            f"({item['bullet_count']} items, tags={len(item.get('convergence_tags') or [])}) "
            f"-> releases/{item['archive_relpath']} [discord={item['notified']}]"
        )
        print(f"    Tweet ({len(item['tweet'])} chars): {item['tweet'].splitlines()[0]}")
    for err in summary["errors"]:
        print(f"  [WARN] {err}", file=sys.stderr)

    return 1 if summary["tracks_found"] == 0 and summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
