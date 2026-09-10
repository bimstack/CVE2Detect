"""Stage 1 — turn an advisory URL into clean Markdown.

Providers:
  * `http` — GET the page with httpx (no JS render, no API key).
  * `tinyfish` (or any API with the same Search/Fetch/Agent contract) — JS
    render plus 24h discovery. Hosts can be overridden with FETCH_*_URL.

Pasted Markdown and the bundled sample skip this module's network calls.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from pipeline.settings import fetch_api_key, fetch_provider, search_ready

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
    """One discovery-feed article (title + URL)."""
    url: str
    title: str
    snippet: str
    site_name: str
    query: str
    date: str = ""
    position: int = 0


@dataclass
class FetchedAdvisory:
    """Markdown plus fetch metadata after ingest."""
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
    key = fetch_api_key()
    if not key:
        raise IngestError(
            "FETCH_API_KEY is not set. Add it to .env, or set "
            "CVE2DETECT_FETCH_PROVIDER=http to GET the URL directly."
        )
    return key


def _headers() -> dict[str, str]:
    return {"X-API-Key": _api_key(), "Content-Type": "application/json"}


def _search_url() -> str:
    return os.environ.get("FETCH_SEARCH_URL", SEARCH_URL).strip() or SEARCH_URL


def _fetch_url() -> str:
    return os.environ.get("FETCH_URL", FETCH_URL).strip() or FETCH_URL


def _agent_url() -> str:
    return os.environ.get("FETCH_AGENT_URL", AGENT_RUN_URL).strip() or AGENT_RUN_URL


def _site_name(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host.removeprefix("www.")


def normalize_advisory_url(raw: str) -> str:
    """Accept a pasted URL, markdown link, or wrapped URL and return a clean http(s) URL.

    People often paste `[title](https://…)` from a write-up; we keep the first https URL.
    """
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
    """Run search queries and return deduplicated hits. Requires a search-capable fetch provider."""
    if not search_ready():
        raise IngestError(
            "Scan 24h needs a search-capable fetch provider and FETCH_API_KEY. "
            "Set CVE2DETECT_FETCH_PROVIDER=tinyfish, or paste an advisory URL / Markdown instead."
        )
    queries = queries or DEFAULT_QUERIES
    recency = recency_minutes
    if recency is None:
        recency = int(os.environ.get("CVE2DETECT_SEARCH_RECENCY_MINUTES", "1440"))

    hits: dict[str, SearchHit] = {}
    with httpx.Client(timeout=45.0) as client:
        for query in queries:
            if progress:
                progress("ingest", f"Searching: {query}")
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
            response = client.get(_search_url(), params=params, headers=_headers())
            if response.status_code == 401:
                raise IngestError("Fetch API rejected the key (401).")
            if response.status_code == 429:
                raise IngestError("Search rate limit exceeded (429). Retry shortly.")
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
    response = client.post(_fetch_url(), headers=_headers(), json=body)
    if response.status_code == 401:
        raise IngestError("Fetch API rejected the key (401).")
    if response.status_code == 429:
        raise IngestError("Fetch rate limit exceeded (429). Retry shortly.")
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
            "Fetch hit anti-bot. Escalating to stealth browser.",
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
        response = client.post(_agent_url(), headers=_headers(), json=body)
        if response.status_code in (401, 403):
            raise IngestError(
                "Stealth fetch was rejected. The page is bot-blocked; add stealth "
                "credits for this fetch provider, use HTTP on a static URL, or paste Markdown."
            )
        if response.status_code == 402:
            raise IngestError(
                "Stealth fetch requires credits. The page is bot-blocked; "
                "add credits, switch CVE2DETECT_FETCH_PROVIDER=http, or paste Markdown."
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


_SCRIPT_RE = re.compile(r"(?is)<(script|style|nav|footer|noscript|svg)[^>]*>.*?</\1>")
_BR_RE = re.compile(r"(?is)<br\s*/?>")
_BLOCK_RE = re.compile(r"(?is)</(p|div|h[1-6]|li|tr|section|article)>")
_HEADING_RE = re.compile(r"(?is)<h([1-6])[^>]*>")
_TAG_RE = re.compile(r"(?is)<[^>]+>")
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_WS_RE = re.compile(r"\n{3,}")


def html_to_markdown(html: str) -> str:
    """Strip chrome (nav/script/style) and keep headings/paragraphs as Markdown-ish text."""
    text = _SCRIPT_RE.sub(" ", html or "")
    text = _BR_RE.sub("\n", text)
    text = _HEADING_RE.sub(lambda m: "\n" + ("#" * int(m.group(1))) + " ", text)
    text = _BLOCK_RE.sub("\n\n", text)
    text = _TAG_RE.sub(" ", text)
    text = unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = _WS_RE.sub("\n\n", text)
    return text.strip()


def _http_fetch(url: str, progress: ProgressFn | None) -> FetchedAdvisory:
    if progress:
        progress("ingest", "Fetching URL over HTTP (no JavaScript render).")
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; CVE2Detect/1.0; +https://github.com/bimstack/CVE2Detect)"
        ),
        "Accept": "text/html,application/xhtml+xml,text/markdown,text/plain;q=0.9,*/*;q=0.8",
    }
    try:
        with httpx.Client(timeout=45.0, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise IngestError(f"HTTP fetch failed: {exc}") from exc
    if response.status_code >= 400:
        raise IngestError(f"HTTP fetch returned {response.status_code} for {url}")
    ctype = (response.headers.get("content-type") or "").lower()
    raw = response.text[:2_000_000]
    title = url
    if "html" in ctype or "<html" in raw[:400].lower():
        found = _TITLE_RE.search(raw)
        if found:
            title = unescape(_TAG_RE.sub("", found.group(1))).strip() or url
        markdown = html_to_markdown(raw)
    else:
        markdown = raw.strip()
    if not markdown:
        raise IngestError(
            "HTTP fetch returned empty text. Use a JS-capable fetch provider "
            "or paste the advisory Markdown."
        )
    return FetchedAdvisory(
        url=url,
        final_url=str(response.url) or url,
        title=title,
        markdown=markdown,
        method="http",
        site_name=_site_name(str(response.url) or url),
    )


def fetch_advisory(url: str, progress: ProgressFn | None = None) -> FetchedAdvisory:
    """Fetch a URL to Markdown via `http` or the configured search/render API."""
    url = normalize_advisory_url(url)
    if fetch_provider() == "http":
        return _http_fetch(url, progress)

    notes: list[str] = []
    if progress:
        progress("ingest", "Routing URL through the fetch API (JS render → Markdown).")

    with httpx.Client(timeout=160.0) as client:
        page, err = _fetch_once(client, url, include_selectors=FETCH_INCLUDE_SELECTORS)
        if err and err.get("error") == "selector_not_matched":
            notes.append("article selectors missed; retrying full-page extraction")
            if progress:
                progress("ingest", "Selectors missed. Retrying full-page fetch.")
            page, err = _fetch_once(client, url, include_selectors=None)

        if err and err.get("error") == "bot_blocked":
            stealth = _agent_stealth_fetch(url, progress)
            stealth.errors = notes + ["fetch_bot_blocked"]
            return stealth

        if err and not page:
            code = err.get("error") or "fetch_failed"
            status = err.get("status")
            detail = f"{code}" + (f" (HTTP {status})" if status else "")
            raise IngestError(f"Fetch API could not extract {url}: {detail}")

        if not page:
            raise IngestError(f"Fetch API returned no content for {url}")

        markdown = _markdown_from_fetch_result(page).strip()
        if not markdown:
            raise IngestError("Fetch API returned empty Markdown.")

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
