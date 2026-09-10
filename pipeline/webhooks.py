"""Slack / Teams / Discord webhook helpers.

Not imported by app.py. Host allowlist only; unused in the local project console.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx


class WebhookError(RuntimeError):
    pass


def _host_ok(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    allowed = (
        "hooks.slack.com",
        "outlook.office.com",
        "outlook.office365.com",
        "webhook.office.com",
        "discord.com",
        "discordapp.com",
    )
    return any(host == item or host.endswith("." + item) for item in allowed)


def _card_text(record: dict[str, Any], match: dict[str, Any]) -> str:
    cve = record.get("cve") or "unassigned"
    cvss = record.get("cvss") or "—"
    title = record.get("title") or "Advisory"
    reason = (match or {}).get("reason") or ""
    summary = (record.get("summary") or "")[:400]
    return (
        f"*{title}*\n"
        f"CVE {cve} · CVSS {cvss}\n"
        f"{reason}\n\n"
        f"{summary}"
    )


def _slack_payload(record: dict[str, Any], match: dict[str, Any]) -> dict[str, Any]:
    return {
        "text": "CVE2Detect high-severity match",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "CVE2Detect · estate match"},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": _card_text(record, match)}},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Rule imported as *testing/disabled*. Run the atomic test on staging, then enable.",
                    }
                ],
            },
        ],
    }


def _teams_payload(record: dict[str, Any], match: dict[str, Any]) -> dict[str, Any]:
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": record.get("title") or "CVE2Detect",
        "themeColor": "C45C26",
        "title": "CVE2Detect · estate match",
        "text": _card_text(record, match).replace("*", "**"),
    }


def _discord_payload(record: dict[str, Any], match: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": "CVE2Detect",
        "embeds": [
            {
                "title": record.get("title") or "Advisory",
                "description": _card_text(record, match).replace("*", ""),
                "color": 12854726,
            }
        ],
    }


def post_webhooks(
    urls: dict[str, str],
    record: dict[str, Any],
    match: dict[str, Any],
) -> list[dict[str, str]]:
    """POST to Slack/Teams/Discord if the URL host is on the allowlist."""
    results: list[dict[str, str]] = []
    mapping = {
        "slack": (_slack_payload, urls.get("slack") or ""),
        "teams": (_teams_payload, urls.get("teams") or ""),
        "discord": (_discord_payload, urls.get("discord") or ""),
    }
    with httpx.Client(timeout=20.0) as client:
        for name, (builder, url) in mapping.items():
            url = url.strip()
            if not url:
                continue
            if not url.startswith("https://") or not _host_ok(url):
                results.append({"channel": name, "status": "rejected", "detail": "URL host is not an allowed webhook."})
                continue
            try:
                response = client.post(url, json=builder(record, match))
                if response.status_code >= 300:
                    results.append(
                        {
                            "channel": name,
                            "status": "error",
                            "detail": f"HTTP {response.status_code}",
                        }
                    )
                else:
                    results.append({"channel": name, "status": "sent", "detail": "ok"})
            except httpx.HTTPError as exc:
                results.append({"channel": name, "status": "error", "detail": str(exc)})
    return results


def should_notify(
    *,
    cvss: float | None,
    matched: bool,
    profile_configured: bool,
    min_cvss: float = 8.0,
    only_matches: bool = True,
) -> bool:
    """True when CVSS is high enough and (optionally) the stack matched."""
    if cvss is None or cvss < min_cvss:
        return False
    if only_matches:
        return bool(profile_configured and matched)
    return True
