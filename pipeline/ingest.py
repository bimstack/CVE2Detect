"""Stage 1 — TinyFish search discovery and stealth fetch to clean Markdown."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

SEARCH_URL = "https://api.search.tinyfish.ai"
FETCH_URL = "https://api.fetch.tinyfish.ai"
AGENT_RUN_URL = "https://agent.tinyfish.ai/v1/automation/run"

DEFAULT_QUERIES = [
    "CVE vulnerability write-up exploit analysis",
    "zero-day disclosure technical advisory",
    "vulnerability disclosure proof of concept detection",
    "incident report exploitation command line Sysmon",
]

EXCLUDE_DOMAINS = ",".join(
    [
        "facebook.com",
        "instagram.com",
        "tiktok.com",
        "pinterest.com",
        "youtube.com",
        "reddit.com",
        "x.com",
        "twitter.com",
        "linkedin.com",
    ]
)

FETCH_EXCLUDE_SELECTORS = [
    "#onetrust-banner-sdk",
    "#cookie-banner",
    ".cookie-banner",
    ".cookie-consent",
    ".cc-window",
    "nav",
    "footer",
    ".sidebar",
    ".related-posts",
    ".comments",
    "#comments",
    ".newsletter",
    ".advertisement",
    ".ads",
]

FETCH_INCLUDE_SELECTORS = [
    "article",
    "main",
    ".post-content",
    ".entry-content",
    ".article-body",
    ".blog-post",
]

STEALTH_GOAL = (
    "Dismiss cookie banners and overlays if they appear. Extract the full technical "
    "article, CVE advisory, or incident write-up as clean Markdown. Preserve headings, "
    "code blocks, command lines, file paths, hashes, MITRE ATT&CK mappings, and tables. "
    "Exclude navigation, ads, cookie notices, related posts, and comment threads."
)

ProgressFn = Callable[[str, str], None]


class IngestError(RuntimeError):
    pass


@dataclass
class SearchHit:
    url: str
    title: str
    snippet: str
    site_name: str
    query: str
    date: str = ""
    position: int = 0


@dataclass
class FetchedAdvisory:
    url: str
    final_url: str
    title: str
    markdown: str
    method: str
    site_name: str = ""
    published_date: str = ""
    latency_ms: int | None = None
    errors: list[str] = field(default_factory=list)


def _api_key() -> str:
    load_dotenv(ROOT / ".env", override=True)
    key = os.environ.get("TINYFISH_API_KEY", "").strip()
    if not key:
        raise IngestError(
            "TINYFISH_API_KEY is not set. Add it to .env (https://agent.tinyfish.ai/api-keys)."
        )
    return key


def _headers() -> dict[str, str]:
    return {"X-API-Key": _api_key(), "Content-Type": "application/json"}


def _site_name(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host.removeprefix("www.")


def normalize_advisory_url(raw: str) -> str:
    """Accept a pasted URL, markdown link, or wrapped URL and return a clean http(s) URL."""
    text = (raw or "").strip()
    if not text:
        raise IngestError("URL is empty")

    md = re.search(r"\]\(\s*(https?://[^\s)]+)", text, re.I)
    if md:
        candidate = md.group(1)
    else:
        found = re.findall(r"https?://[^\s<>\"']+", text, re.I)
        candidate = found[0] if found else text

    if "](" in candidate:
        candidate = candidate.split("](", 1)[0]
    candidate = candidate.strip().strip("<>").rstrip(").,;]>\"'")
    if not candidate.startswith(("http://", "https://")):
        raise IngestError("URL must start with http:// or https://")
    parsed = urlparse(candidate)
    if not parsed.netloc or "." not in parsed.netloc:
        raise IngestError("URL is missing a valid host")
    return candidate


def discover(
    queries: list[str] | None = None,
    recency_minutes: int | None = None,
    progress: ProgressFn | None = None,
) -> list[SearchHit]:
    """Run TinyFish Search queries and return deduplicated hits."""
    queries = queries or DEFAULT_QUERIES
    recency = recency_minutes
    if recency is None:
        recency = int(os.environ.get("CVE2DETECT_SEARCH_RECENCY_MINUTES", "1440"))

    hits: dict[str, SearchHit] = {}
    with httpx.Client(timeout=45.0) as client:
        for query in queries:
            if progress:
                progress("ingest", f"Searching TinyFish: {query}")
            params: dict[str, Any] = {
                "query": query,
                "location": "US",
                "language": "en",
                "exclude_domains": EXCLUDE_DOMAINS,
                "recency_minutes": recency,
                "purpose": (
                    "Find newly published CVE write-ups, vulnerability disclosures, "
                    "and technical incident reports for detection engineering."
                ),
            }
            response = client.get(SEARCH_URL, params=params, headers=_headers())
            if response.status_code == 401:
                raise IngestError("TinyFish rejected the API key (401).")
            if response.status_code == 429:
                raise IngestError("TinyFish Search rate limit exceeded (429). Retry shortly.")
            response.raise_for_status()
            payload = response.json()
            for item in payload.get("results") or []:
                url = (item.get("url") or "").strip()
                if not url or url in hits:
                    continue
                hits[url] = SearchHit(
                    url=url,
                    title=item.get("title") or url,
                    snippet=item.get("snippet") or "",
                    site_name=item.get("site_name") or _site_name(url),
                    query=query,
                    date=item.get("date") or "",
                    position=int(item.get("position") or 0),
                )
    return list(hits.values())


def _markdown_from_fetch_result(page: dict[str, Any]) -> str:
    text = page.get("text") or ""
    if isinstance(text, dict):
        return str(text)
    return str(text)


def _fetch_once(
    client: httpx.Client,
    url: str,
    *,
    include_selectors: list[str] | None,
    ttl: int = 0,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    body: dict[str, Any] = {
        "urls": [url],
        "format": "markdown",
        "ttl": ttl,
        "per_url_timeout_ms": 90000,
        "exclude_selectors": FETCH_EXCLUDE_SELECTORS,
        "purpose": (
            "Extract the core technical advisory so a detection engineer can map "
            "exploitation behavior to Sigma telemetry."
        ),
    }
    if include_selectors:
        body["include_selectors"] = include_selectors
    response = client.post(FETCH_URL, headers=_headers(), json=body)
    if response.status_code == 401:
        raise IngestError("TinyFish rejected the API key (401).")
    if response.status_code == 429:
        raise IngestError("TinyFish Fetch rate limit exceeded (429). Retry shortly.")
    response.raise_for_status()
    payload = response.json()
    results = payload.get("results") or []
    errors = payload.get("errors") or []
    page = results[0] if results else None
    err = errors[0] if errors else None
    return page, err


def _agent_stealth_fetch(url: str, progress: ProgressFn | None) -> FetchedAdvisory:
    if progress:
        progress(
            "ingest",
            "Fetch hit anti-bot. Escalating to TinyFish Agent stealth browser.",
        )
    body = {
        "url": url,
        "goal": STEALTH_GOAL,
        "browser_profile": "stealth",
        "proxy_config": {"enabled": True, "type": "tetra", "country_code": "US"},
        "output_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "markdown": {"type": "string"},
            },
            "required": ["title", "markdown"],
        },
        "agent_config": {"max_duration_seconds": 180},
    }
    with httpx.Client(timeout=200.0) as client:
        response = client.post(AGENT_RUN_URL, headers=_headers(), json=body)
        if response.status_code in (401, 403):
            raise IngestError(
                "Stealth Agent run was rejected. Fetch was bot-blocked and Agent "
                "access/credits are required for Cloudflare/PerimeterX targets."
            )
        if response.status_code == 402:
            raise IngestError(
                "TinyFish Agent requires wallet credits. Fetch was blocked by anti-bot; "
                "add Agent credits or paste a less-protected URL."
            )
        response.raise_for_status()
        payload = response.json()

    if (payload.get("status") or "").upper() != "COMPLETED":
        err = payload.get("error") or {}
        message = err.get("message") if isinstance(err, dict) else str(err)
        raise IngestError(f"Stealth Agent failed: {message or payload.get('status')}")

    result = payload.get("result") or {}
    if isinstance(result, str):
        markdown = result
        title = ""
    else:
        markdown = (
            result.get("markdown")
            or result.get("text")
            or result.get("result")
            or ""
        )
        if isinstance(markdown, dict):
            markdown = markdown.get("markdown") or markdown.get("text") or str(markdown)
        title = result.get("title") or ""
    markdown = str(markdown or "").strip()
    if not markdown:
        raise IngestError("Stealth Agent completed but returned empty article text.")
    return FetchedAdvisory(
        url=url,
        final_url=url,
        title=title or url,
        markdown=markdown,
        method="stealth_agent",
        site_name=_site_name(url),
    )


def fetch_advisory(url: str, progress: ProgressFn | None = None) -> FetchedAdvisory:
    """Render a URL through TinyFish Fetch; escalate to stealth Agent on bot_blocked."""
    url = normalize_advisory_url(url)

    notes: list[str] = []
    if progress:
        progress("ingest", "Routing URL through TinyFish Fetch (JS render → Markdown).")

    with httpx.Client(timeout=160.0) as client:
        page, err = _fetch_once(client, url, include_selectors=FETCH_INCLUDE_SELECTORS)
        if err and err.get("error") == "selector_not_matched":
            notes.append("article selectors missed; retrying full-page extraction")
            if progress:
                progress("ingest", "Selectors missed. Retrying full-page TinyFish Fetch.")
            page, err = _fetch_once(client, url, include_selectors=None)

        if err and err.get("error") == "bot_blocked":
            stealth = _agent_stealth_fetch(url, progress)
            stealth.errors = notes + ["fetch_bot_blocked"]
            return stealth

        if err and not page:
            code = err.get("error") or "fetch_failed"
            status = err.get("status")
            detail = f"{code}" + (f" (HTTP {status})" if status else "")
            raise IngestError(f"TinyFish could not extract {url}: {detail}")

        if not page:
            raise IngestError(f"TinyFish returned no content for {url}")

        markdown = _markdown_from_fetch_result(page).strip()
        if not markdown:
            raise IngestError("TinyFish Fetch returned empty Markdown.")

        latency = page.get("latency_ms")
        return FetchedAdvisory(
            url=url,
            final_url=page.get("final_url") or url,
            title=page.get("title") or url,
            markdown=markdown,
            method="fetch",
            site_name=_site_name(page.get("final_url") or url),
            published_date=page.get("published_date") or "",
            latency_ms=int(latency) if latency is not None else None,
            errors=notes,
        )


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
