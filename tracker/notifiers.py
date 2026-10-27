"""Notification & social post generators (Discord Rich Embeds, Telegram, X/Twitter copy text)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import urllib.request
from typing import Any, Callable, Dict, List, Optional


PROVIDER_LOGOS: Dict[str, str] = {
    "google": "https://www.gstatic.com/images/branding/product/2x/googleg_96dp.png",
    "anthropic": "https://avatars.githubusercontent.com/u/76263028?s=200&v=4",
    "openai": "https://avatars.githubusercontent.com/u/14957082?s=200&v=4",
    "qwen": "https://avatars.githubusercontent.com/u/141221163?s=200&v=4",
    "deepseek": "https://avatars.githubusercontent.com/u/148330874?s=200&v=4",
    "meta": "https://avatars.githubusercontent.com/u/69631?s=200&v=4",
    "mistral": "https://avatars.githubusercontent.com/u/132372032?s=200&v=4",
    "xai": "https://avatars.githubusercontent.com/u/139835814?s=200&v=4",
    "opensource": "https://huggingface.co/front/assets/huggingface_logo-noborder.svg",
}


def hex_to_discord_color(hex_str: str) -> int:
    """Convert '#38bdf8' to integer color for Discord embeds."""
    clean = hex_str.lstrip("#")
    try:
        return int(clean, 16)
    except ValueError:
        return 0x38BDF8


def build_discord_embed(card: Dict[str, Any], github_user: str = "siddiquiamir") -> Dict[str, Any]:
    """
    Build a Discord webhook embed matching the exact LuminaBench-style diff card layout.
    """
    models_lines = []
    for item in card.get("models", [])[:15]:
        label = item.get("name", item["id"])
        mid = item["id"]
        models_lines.append(f"• **{label}** — `{mid}`")

    extra_count = len(card.get("models", [])) - 15
    if extra_count > 0:
        models_lines.append(f"*...and {extra_count} more identifiers*")

    links_row = []
    for lnk in card.get("links", []):
        if lnk.get("label") and lnk.get("url"):
            links_row.append(f"[{lnk['label']}]({lnk['url']})")
    links_md = " · ".join(links_row)

    desc_parts = [
        f"**{card.get('subtitle', 'Verified build comparison')}**",
        "",
        f"**{card.get('build_label', 'Build')}:** `{card.get('build_transition', 'latest')}`",
        "",
        "\n".join(models_lines),
        "",
        f"**Evidence:** `{card.get('evidence', 'binary/strings')}`",
        f"**Source:** {card.get('source_text', 'official public release archive.')}",
        "",
        card.get(
            "disclaimer_1",
            "Verified differences between existing builds; this is not a newly published release announcement.",
        ),
        "",
        card.get(
            "disclaimer_2",
            "Compiled-in names and identifiers. This does not confirm model rollout or account access.",
        ),
    ]
    if links_md:
        desc_parts.extend(["", links_md])

    desc_parts.extend(
        [
            "",
            "Developed by [@StatsWire](https://x.com/StatsWire) on X",
        ]
    )

    provider_slug = card.get("provider_slug", "google")
    thumb_url = PROVIDER_LOGOS.get(provider_slug, PROVIDER_LOGOS["google"])

    embed: Dict[str, Any] = {
        "author": {
            "name": card.get("header", "DESKTOP DIFF · GOOGLE"),
        },
        "title": (
            f"[CODENAME: {', '.join(card['codenames'])}] {card.get('title', 'New Model Detected')}"
            if card.get("codenames")
            else card.get("title", "New Model Detected")
        )[:256],
        "description": "\n".join(desc_parts),
        "color": hex_to_discord_color(card.get("accent_color", "#38bdf8")),
        "thumbnail": {"url": thumb_url},
        "timestamp": card.get("detected_at"),
    }
    if card.get("links"):
        embed["url"] = card["links"][0]["url"]

    return embed


def build_x_post_text(card: Dict[str, Any]) -> str:
    """
    Generate a punchy, ready-to-post X / Twitter breaking-news draft for a diff card.
    """
    header = card.get("header", "MODEL DIFF")
    title = card.get("title", "New Model")
    transition = card.get("build_transition", "")
    evidence = card.get("evidence", "")
    models = card.get("models", [])

    if card.get("category") == "subdomain-ct":
        bullets = [f"• {m['id']} ({m.get('name', 'Subdomain')})" for m in models[:6]]
        if len(models) > 6:
            bullets.append(f"• +{len(models) - 6} more endpoints")
        headline = (
            f"🚨 {title}"
            if card.get("scanner") == "cert-transparency"
            else f"🌐 {title} — {transition}"
        )
        return "\n".join(
            [
                headline,
                "",
                *bullets,
                "",
                f"Evidence: {evidence}",
                "",
                "Tracked by @StatsWire",
            ]
        )

    bullets = []
    for m in models[:6]:
        bullets.append(f"• {m.get('name', m['id'])} ({m['id']})")
    if len(models) > 6:
        bullets.append(f"• +{len(models) - 6} more variants")

    lines = [
        f"🚨 {header}",
        f"{title} spotted in {card.get('build_label', 'Build')} {transition}!",
        "",
        *bullets,
        "",
        f"Evidence: {evidence}",
        f"Source: {card.get('source_text', 'Official public release feed')}",
        "",
        "Tracked by @StatsWire",
    ]
    return "\n".join(lines)


def build_story_embed(story: Dict[str, Any], github_user: str = "siddiquiamir") -> Dict[str, Any]:
    """One Discord embed per model story: amber for leaks, green for releases."""
    lines = [f"**First spotted:** <t:{_epoch(story['detected_at'])}:f> in {story.get('first_source', '')}"]
    if story.get("lead"):
        lines.append(f"**Lead time:** {story['lead']}")
    if story.get("codenames"):
        lines.append(f"**Codename:** {', '.join(story['codenames'])}")
    ids = [f"`{v['id']}`" for v in story.get("models", [])[:10]]
    if ids:
        lines.append(f"**Identifiers:** {' '.join(ids)}")
    srcs = []
    for s in story.get("sources", [])[:8]:
        label = f"[{s['label']}]({s['url']})" if s.get("url") else s["label"]
        srcs.append(f"• <t:{_epoch(s['detected_at'])}:t> {label}")
    if srcs:
        lines += ["", "**Sources**", *srcs]
    lines += ["", f"[Live tracker](https://{github_user}.github.io/model-tracker/) · [@StatsWire](https://x.com/StatsWire)"]
    embed: Dict[str, Any] = {
        "author": {"name": story.get("header", "")},
        "title": story.get("title", "New model")[:256],
        "description": "\n".join(lines)[:4000],
        "color": 0xF59E0B if story.get("kind") == "leak" else 0x22C55E,
        "thumbnail": {"url": PROVIDER_LOGOS.get(story.get("provider_slug", ""), PROVIDER_LOGOS["opensource"])},
        "timestamp": story.get("detected_at"),
    }
    first_url = next((s["url"] for s in story.get("sources", []) if s.get("url")), "")
    if first_url:
        embed["url"] = first_url
    return embed


def _epoch(iso: str) -> int:
    try:
        dt = datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
        return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())
    except Exception:
        return 0


def send_discord_webhook(
    cards: List[Dict[str, Any]],
    webhook_url: Optional[str] = None,
    github_user: str = "siddiquiamir",
    embed_builder: Callable[..., Dict[str, Any]] = build_discord_embed,
) -> bool:
    """
    Send 1 or more diff cards to a Discord Webhook URL.
    Reads DISCORD_WEBHOOK_URL from environment if not passed explicitly.
    Never logs or exposes the webhook URL.
    """
    url = (webhook_url or os.environ.get("DISCORD_WEBHOOK_URL") or "").strip()
    if not url or not cards:
        return False

    # Discord allows up to 10 embeds per message
    for i in range(0, len(cards), 10):
        batch = cards[i : i + 10]
        payload = {
            "username": "ModelPulse Tracker",
            "embeds": [embed_builder(c, github_user=github_user) for c in batch],
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ModelPulse-Tracker/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status not in (200, 204):
                return False
    return True
