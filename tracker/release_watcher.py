"""24/7 Release Notes Watcher for Google Antigravity, OpenAI Codex CLI, and Anthropic Claude Code.

Pure Python stdlib (zero external dependencies). Captures 100% verbatim release
notes with zero truncation, archives each release to ``releases/<product>/<version>.md``,
maintains ``data/release_state.json`` and ``releases/INDEX.md``, generates a
ready-to-post X/Twitter draft (<= 280 chars), and sends a Discord webhook embed
with the full verbatim Markdown file attached.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

ANTIGRAVITY_CHANGELOG_URL = "https://antigravity.google/docs/changelog.md"
CODEX_RELEASES_API_URL = "https://api.github.com/repos/openai/codex/releases?per_page=25"
CLAUDE_CODE_CHANGELOG_URL = "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md"
CLAUDE_CODE_NPM_TAGS_URL = "https://registry.npmjs.org/-/package/@anthropic-ai/claude-code/dist-tags"

DEFAULT_USER_AGENT = "ModelPulse-ReleaseWatcher/1.0"

PRODUCT_META: Dict[str, Dict[str, Any]] = {
    "antigravity": {
        "provider_slug": "google",
        "color": 0x4285F4,
        "org": "Google",
    },
    "codex": {
        "provider_slug": "openai",
        "color": 0x10A37F,
        "org": "OpenAI",
    },
    "claude-code": {
        "provider_slug": "anthropic",
        "color": 0xD97757,
        "org": "Anthropic",
    },
}


@dataclass
class ReleaseEntry:
    """One complete, verbatim release for a tracked product/surface."""

    track_key: str  # e.g. "antigravity:app", "codex:cli", "claude-code:cli"
    product_family: str  # "antigravity" | "codex" | "claude-code"
    display_name: str  # e.g. "Google Antigravity App", "OpenAI Codex CLI", "Claude Code"
    folder_slug: str  # e.g. "antigravity-app", "codex-cli", "claude-code"
    version: str  # e.g. "v2.35.2", "rust-v0.172.0", "v2.1.332"
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
    """Return every top-level bullet item from a Markdown changelog body."""
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
# Parsers (100% verbatim extraction — nothing dropped)
# ---------------------------------------------------------------------------


def parse_antigravity_changelog(markdown: str) -> Dict[str, List[ReleaseEntry]]:
    """Parse ``https://antigravity.google/docs/changelog.md``.

    Returns a mapping of ``track_key -> [ReleaseEntry, ...]`` ordered newest-first,
    covering every ``## <Surface>`` section (App, CLI, IDE Extensions, SDK, IDE).
    """
    results: Dict[str, List[ReleaseEntry]] = {}
    lines = markdown.splitlines()

    # Locate all `## <Product>` sections
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

        # Find every version header `### [vX.Y.Z](url ...)` inside this section
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

            # Stop before a model-launch interlude block (`Model launch·...`) if present
            trimmed: List[str] = []
            for cl in chunk:
                if re.match(r"^Model launch[·\s]", cl):
                    break
                trimmed.append(cl)

            # Strip trailing horizontal rules / blank lines
            while trimmed and trimmed[-1].strip() in ("", "---"):
                trimmed.pop()
            while trimmed and trimmed[0].strip() == "":
                trimmed.pop(0)

            # Extract date & subtitle while keeping the complete body verbatim
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


def parse_codex_releases(
    releases_json: Sequence[Dict[str, Any]],
    include_prereleases: bool = False,
) -> Dict[str, List[ReleaseEntry]]:
    """Parse GitHub Releases JSON for ``openai/codex`` (newest-first)."""
    stable_entries: List[ReleaseEntry] = []
    alpha_entries: List[ReleaseEntry] = []

    for rel in releases_json:
        if rel.get("draft"):
            continue
        is_pre = bool(rel.get("prerelease"))
        tag = str(rel.get("tag_name") or "").strip()
        if not tag:
            continue
        body = str(rel.get("body") or "").replace("\r\n", "\n").strip()
        published_at = str(rel.get("published_at") or rel.get("created_at") or "").strip()
        html_url = str(rel.get("html_url") or f"https://github.com/openai/codex/releases/tag/{tag}")
        rel_name = str(rel.get("name") or tag).strip()

        entry = ReleaseEntry(
            track_key="codex:cli-alpha" if is_pre else "codex:cli",
            product_family="codex",
            display_name="OpenAI Codex CLI (Alpha)" if is_pre else "OpenAI Codex CLI",
            folder_slug="codex-cli-alpha" if is_pre else "codex-cli",
            version=tag,
            published_at=published_at,
            url=html_url,
            title=f"Codex CLI {rel_name}",
            body_markdown=body,
            extra={"prerelease": is_pre, "name": rel_name},
        )
        if is_pre:
            alpha_entries.append(entry)
        else:
            stable_entries.append(entry)

    out: Dict[str, List[ReleaseEntry]] = {}
    if stable_entries:
        out["codex:cli"] = stable_entries
    if include_prereleases and alpha_entries:
        out["codex:cli-alpha"] = alpha_entries
    return out


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


# ---------------------------------------------------------------------------
# Tweet & Markdown rendering
# ---------------------------------------------------------------------------


def _select_highlight_bullets(entry: ReleaseEntry, max_items: int = 5) -> List[str]:
    """Pick the highest-signal bullets (features/improvements first) for summaries & tweets."""
    bullets = entry.bullet_items
    if not bullets:
        return []

    def score(b: str) -> Tuple[int, int]:
        low = b.lower()
        if low.startswith("[vscode]"):
            return (3, len(b))
        if low.startswith(("added ", "new ", "introduces ", "you can now ")):
            return (0, len(b))
        if low.startswith(("improved ", "updated ", "changed ", "follow ", "press ", "jump ", "optional ", "set ", "app-server ")):
            return (1, len(b))
        if low.startswith("fixed "):
            return (2, len(b))
        return (1, len(b))

    # Preserve original order within each priority tier
    indexed = list(enumerate(bullets))
    indexed.sort(key=lambda pair: (score(pair[1])[0], pair[0]))
    return [_strip_md_inline(b) for _, b in indexed[:max_items]]


def build_release_tweet(entry: ReleaseEntry) -> str:
    """Build a punchy, 100%-grounded X/Twitter draft strictly <= 280 characters."""
    total = len(entry.bullet_items)
    count_tag = f" ({total} changes)" if total >= 15 else ""
    header = f"{entry.display_name} {entry.version} is out{count_tag} 🚀"

    highlights = _select_highlight_bullets(entry, max_items=5)
    if not highlights and entry.title:
        body = f"{header}\n\n{_truncate_word(_strip_md_inline(entry.title), 275 - len(header) - 2)}"
        return body[:280]

    # Pack as many clean, readable bullets as fit comfortably inside 280 chars
    chosen: List[str] = []
    prefix = f"{header}\n\nHighlights:\n"
    remaining = 280 - len(prefix)

    for raw in highlights:
        # Take the first clause (before colon/semicolon if very long) for crisp tweet readability
        short = re.split(r"(?:;\s+|\s+—\s+)", raw, maxsplit=1)[0]
        short = re.sub(r"^(?:Added|Improved|Changed|Updated|Fixed)\s+", "", short)
        short = short[0].upper() + short[1:] if short else raw
        candidate_len = min(56, remaining - 3)
        if candidate_len < 18:
            break
        line = f"• {_truncate_word(short, candidate_len)}"
        needed = len(line) + (1 if chosen else 0)
        if needed <= remaining:
            chosen.append(line)
            remaining -= needed
        if len(chosen) >= 4:
            break

    if not chosen:
        fallback = f"{header}\n\n• {_truncate_word(highlights[0], 270 - len(header))}"
        return fallback[:280]

    tweet = prefix + "\n".join(chosen)
    return tweet[:280]


def render_verbatim_release_markdown(entry: ReleaseEntry, tweet: str) -> str:
    """Render the complete, zero-truncation archive Markdown file for a release."""
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

    lines = [
        *meta_lines,
        "",
        "## Ready-to-Post Tweet",
        "",
        "```text",
        tweet,
        "```",
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
) -> pathlib.Path:
    """Save the 100% verbatim release markdown file under ``releases/<folder>/<version>.md``."""
    target_dir = releases_dir / entry.folder_slug
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / entry.safe_filename
    content = render_verbatim_release_markdown(entry, tweet)
    target_file.write_text(content, encoding="utf-8")
    return target_file


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
        "Automated 24/7 archive of 100% verbatim release notes for **Google Antigravity**, **OpenAI Codex CLI**, and **Anthropic Claude Code**.",
        "",
        "| Captured (UTC) | Product | Version | Items | Full Notes | Upstream |",
        "| :--- | :--- | :--- | ---: | :--- | :--- |",
    ]
    for item in reversed(history[-200:]):
        rel_path = item.get("archive_relpath", "")
        rel_link = f"[Full notes]({rel_path})" if rel_path else "—"
        src_url = item.get("url", "")
        src_link = f"[Source]({src_url})" if src_url else "—"
        lines.append(
            f"| {item.get('captured_at', '')[:16].replace('T', ' ')} | "
            f"{item.get('display_name', '')} | "
            f"`{item.get('version', '')}` | "
            f"{item.get('bullet_count', 0)} | "
            f"{rel_link} | {src_link} |"
        )
    lines.append("")
    index_path = releases_dir / "INDEX.md"
    index_path.write_text("\n".join(lines), encoding="utf-8")
    return index_path


# ---------------------------------------------------------------------------
# Discord notification (embed + full .md file attachment — zero truncation)
# ---------------------------------------------------------------------------


def build_release_discord_embed(
    entry: ReleaseEntry,
    tweet: str,
    repo_slug: str = "",
    archive_relpath: str = "",
) -> Dict[str, Any]:
    meta = PRODUCT_META.get(entry.product_family, PRODUCT_META["antigravity"])
    total = len(entry.bullet_items)
    highlights = _select_highlight_bullets(entry, max_items=10)

    desc_lines: List[str] = []
    if entry.title and entry.title.lower() != f"{entry.display_name} {entry.version}".lower():
        desc_lines.append(f"**{_strip_md_inline(entry.title)}**")
        desc_lines.append("")

    if highlights:
        desc_lines.append(f"**Highlights ({total} total items — full list attached as `.md`):**")
        for b in highlights:
            desc_lines.append(f"• {_truncate_word(b, 220)}")
        if total > len(highlights):
            desc_lines.append(f"*…+{total - len(highlights)} more items in the attached `.md` file (nothing omitted).*")
    else:
        desc_lines.append(_truncate_word(_strip_md_inline(entry.body_markdown), 1500))

    links: List[str] = []
    if entry.url:
        links.append(f"[Official Release Notes]({entry.url})")
    if repo_slug and archive_relpath:
        gh_url = f"https://github.com/{repo_slug}/blob/main/releases/{archive_relpath}"
        links.append(f"[Full Verbatim Archive on GitHub]({gh_url})")
    if links:
        desc_lines.extend(["", " · ".join(links)])

    embed: Dict[str, Any] = {
        "author": {"name": f"NEW RELEASE · {meta['org'].upper()}"},
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
    return embed


def build_multipart_markdown_webhook_body(
    payload: Dict[str, Any],
    filename: str,
    markdown_bytes: bytes,
) -> Tuple[bytes, str]:
    """Build a pure-stdlib multipart/form-data Discord webhook body with a Markdown file."""
    boundary = f"----ReleaseWatcherBoundary{uuid.uuid4().hex}"
    parts: List[bytes] = [
        f"--{boundary}\r\n".encode("utf-8"),
        b'Content-Disposition: form-data; name="payload_json"\r\n',
        b"Content-Type: application/json\r\n\r\n",
        json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        b"\r\n",
        f"--{boundary}\r\n".encode("utf-8"),
        f'Content-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'.encode("utf-8"),
        b"Content-Type: text/markdown; charset=utf-8\r\n\r\n",
        markdown_bytes,
        b"\r\n",
        f"--{boundary}--\r\n".encode("utf-8"),
    ]
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def send_release_discord_notification(
    entry: ReleaseEntry,
    tweet: str,
    archive_content: str,
    webhook_url: Optional[str] = None,
    repo_slug: str = "",
    archive_relpath: str = "",
    poster: Callable[[str, bytes, str], bool] = _post_discord_request,
) -> bool:
    """Post a Discord embed + attach the complete verbatim `.md` release notes."""
    url = (
        webhook_url
        or os.environ.get("RELEASE_DISCORD_WEBHOOK_URL")
        or os.environ.get("DISCORD_WEBHOOK_URL")
        or ""
    ).strip()
    if not url:
        return False

    embed = build_release_discord_embed(
        entry,
        tweet=tweet,
        repo_slug=repo_slug,
        archive_relpath=archive_relpath,
    )
    attachment_name = f"{entry.folder_slug}-{entry.safe_filename}"
    payload = {
        "username": "ReleasePulse Watcher",
        "embeds": [embed],
        "attachments": [{"id": 0, "filename": attachment_name}],
    }
    body, content_type = build_multipart_markdown_webhook_body(
        payload,
        filename=attachment_name,
        markdown_bytes=archive_content.encode("utf-8"),
    )
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
    When ``state`` has no ``tracks`` yet (first run), returns only the latest
    release per track with ``was_initial_seed=True`` so callers can archive the
    baseline cleanly without spamming historical releases.
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
            # Newly discovered surface (e.g. a brand-new Antigravity product section)
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

        # Emit oldest -> newest so Discord & git history read in chronological order
        new_entries.extend(reversed(unseen_for_track))

    return new_entries, False


def fetch_all_tracks(
    include_codex_alphas: bool = False,
    github_token: Optional[str] = None,
) -> Tuple[Dict[str, List[ReleaseEntry]], List[str]]:
    """Fetch all 3 upstream sources. Returns ``(tracks, errors)``."""
    tracks: Dict[str, List[ReleaseEntry]] = {}
    errors: List[str] = []

    # 1. Google Antigravity
    try:
        ag_md = _http_get_text(ANTIGRAVITY_CHANGELOG_URL)
        tracks.update(parse_antigravity_changelog(ag_md))
    except Exception as exc:
        errors.append(f"antigravity: {exc}")

    # 2. OpenAI Codex CLI
    try:
        gh_headers: Dict[str, str] = {"Accept": "application/vnd.github+json"}
        token = (github_token or os.environ.get("GITHUB_TOKEN") or "").strip()
        if token:
            gh_headers["Authorization"] = f"Bearer {token}"
        codex_rels = _http_get_json(CODEX_RELEASES_API_URL, headers=gh_headers)
        tracks.update(parse_codex_releases(codex_rels, include_prereleases=include_codex_alphas))
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


def run_check(
    state_file: pathlib.Path = DEFAULT_STATE_FILE,
    releases_dir: pathlib.Path = DEFAULT_RELEASES_DIR,
    notify_discord: bool = True,
    notify_on_seed: bool = False,
    force_notify_latest: bool = False,
    include_codex_alphas: bool = False,
    dry_run: bool = False,
    repo_slug: str = "",
    fetcher: Callable[..., Tuple[Dict[str, List[ReleaseEntry]], List[str]]] = fetch_all_tracks,
) -> Dict[str, Any]:
    """Execute one full check cycle across Antigravity, Codex CLI, and Claude Code."""
    state = load_state(state_file)
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
        archive_content = render_verbatim_release_markdown(entry, tweet)
        archive_relpath = f"{entry.folder_slug}/{entry.safe_filename}"

        if not dry_run:
            write_release_archive(entry, tweet, releases_dir=releases_dir)

        should_notify = (
            notify_discord
            and not dry_run
            and (not was_seed or notify_on_seed or force_notify_latest)
        )
        notified = False
        if should_notify:
            try:
                notified = send_release_discord_notification(
                    entry,
                    tweet=tweet,
                    archive_content=archive_content,
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
            "latest_version": entry.version,
            "published_at": entry.published_at,
            "url": entry.url,
            "bullet_count": len(entry.bullet_items),
            "archive_relpath": archive_relpath,
            "updated_at": now_iso,
            "seen_versions": prev_seen[-50:],
        }

        record = {
            "track_key": entry.track_key,
            "display_name": entry.display_name,
            "version": entry.version,
            "published_at": entry.published_at,
            "captured_at": now_iso,
            "bullet_count": len(entry.bullet_items),
            "archive_relpath": archive_relpath,
            "url": entry.url,
            "tweet": tweet,
            "notified": notified,
        }
        if not any(
            h.get("track_key") == entry.track_key and h.get("version") == entry.version
            for h in history
        ):
            history.append(record)
        processed.append(record)

    state["tracks"] = tracks_state
    state["history"] = history[-500:]
    state["last_checked_at"] = now_iso

    if not dry_run:
        save_state(state, state_file=state_file)
        update_releases_index(state, releases_dir=releases_dir)

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
        description="24/7 Release Notes Watcher for Antigravity, Codex CLI, and Claude Code."
    )
    parser.add_argument("--state-file", type=pathlib.Path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--releases-dir", type=pathlib.Path, default=DEFAULT_RELEASES_DIR)
    parser.add_argument("--no-discord", action="store_true", help="Do not send Discord notifications.")
    parser.add_argument("--notify-on-seed", action="store_true", help="Also notify Discord on initial seed run.")
    parser.add_argument(
        "--force-notify-latest",
        action="store_true",
        help="Re-send the latest release for every track (useful for testing Discord delivery).",
    )
    parser.add_argument(
        "--include-codex-alphas",
        action="store_true",
        default=os.environ.get("TRACK_CODEX_ALPHAS", "").lower() in ("1", "true", "yes"),
        help="Also track OpenAI Codex CLI alpha prereleases.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Fetch and print without writing files or notifying.")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repo slug (owner/name) for archive links in Discord embeds.",
    )
    args = parser.parse_args(argv)

    summary = run_check(
        state_file=args.state_file,
        releases_dir=args.releases_dir,
        notify_discord=not args.no_discord,
        notify_on_seed=args.notify_on_seed,
        force_notify_latest=args.force_notify_latest,
        include_codex_alphas=args.include_codex_alphas,
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
            f"({item['bullet_count']} items) -> releases/{item['archive_relpath']} "
            f"[discord={item['notified']}]"
        )
        print(f"    Tweet ({len(item['tweet'])} chars): {item['tweet'].splitlines()[0]}")
    for err in summary["errors"]:
        print(f"  [WARN] {err}", file=sys.stderr)

    # Fail only if every single track fetch failed
    return 1 if summary["tracks_found"] == 0 and summary["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
