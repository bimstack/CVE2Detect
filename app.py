"""CVE2Detect — local threat-intel-to-Sigma project."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from queue import Queue
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

from pipeline.ingest import DEFAULT_QUERIES, discover  # noqa: E402
from pipeline.orchestrate import run_pipeline  # noqa: E402
from pipeline.profile import ASSET_CATALOG  # noqa: E402
from pipeline.settings import (  # noqa: E402
    llm_model,
    llm_models,
    provider_status,
    search_ready,
)
from pipeline.store import init_db, list_feed, upsert_feed  # noqa: E402

UI_DIR = ROOT / "ui"
init_db()

app = FastAPI(title="CVE2Detect", version="0.1.0")

# IP → timestamps for a simple sliding window (no extra dependency).
_rate: dict[str, deque[float]] = defaultdict(deque)


class DiscoverRequest(BaseModel):
    queries: list[str] = Field(default_factory=list)
    recency_minutes: int | None = None


class PipelineRequest(BaseModel):
    url: str = Field(default="", max_length=2048)
    use_sample: bool = False
    markdown: str = Field(default="", max_length=120_000)
    title: str = Field(default="", max_length=300)
    assets: list[str] = Field(default_factory=list)
    hunt_days: int = 90


def _client_ip(request: Request) -> str:
    # Only honor X-Forwarded-For when a reverse proxy is trusted. Otherwise
    # clients could spoof the header and bypass the sliding-window limit.
    if os.environ.get("CVE2DETECT_TRUST_PROXY", "0") == "1":
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


def _public_feed_item(item: dict[str, Any]) -> dict[str, Any]:
    """Discovery hits only — never expose per-user processed flags."""
    return {
        "url": item.get("url") or "",
        "title": item.get("title") or "",
        "snippet": item.get("snippet") or "",
        "site_name": item.get("site_name") or "",
        "query": item.get("query") or "",
        "discovered_at": item.get("discovered_at") or "",
    }


def _rate_limit(request: Request, bucket: str, max_n: int, window_s: float) -> None:
    now = time.time()
    key = f"{_client_ip(request)}:{bucket}"
    q = _rate[key]
    while q and now - q[0] > window_s:
        q.popleft()
    if len(q) >= max_n:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Wait a few minutes and try again.",
        )
    q.append(now)


def _keys() -> dict[str, bool]:
    status = provider_status()
    return {
        "fetch": bool(status["fetch_ready"]),
        "llm": bool(status["llm_ready"]),
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    load_dotenv(ROOT / ".env", override=True)
    status = provider_status()
    return {
        "ok": True,
        "project": "cve2detect",
        "mode": "project",
        "keys": _keys(),
        "providers": {
            "fetch": status["fetch"],
            "llm": status["llm"],
        },
        "model": llm_model(),
        "models": llm_models(),
        "daily_search": os.environ.get("CVE2DETECT_DAILY_SEARCH", "0") == "1",
        "persist_jobs": False,
    }


@app.get("/api/feed")
def feed(limit: int = Query(80, ge=1, le=200)) -> dict[str, Any]:
    return {"items": [_public_feed_item(item) for item in list_feed(limit)]}


@app.post("/api/discover")
def api_discover(request: Request, body: DiscoverRequest) -> dict[str, Any]:
    _rate_limit(request, "discover", max_n=6, window_s=600)
    if not search_ready():
        raise HTTPException(
            status_code=400,
            detail=(
                "Scan 24h needs a search-capable fetch provider and FETCH_API_KEY. "
                "Set CVE2DETECT_FETCH_PROVIDER=tinyfish, or paste a URL / Markdown instead."
            ),
        )
    queries = body.queries or DEFAULT_QUERIES
    try:
        hits = discover(queries=queries, recency_minutes=body.recency_minutes)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    upsert_feed(hits)
    return {"count": len(hits), "items": [_public_feed_item(item) for item in list_feed()]}


@app.post("/api/pipeline")
def api_pipeline(request: Request, body: PipelineRequest, stream: bool = True) -> Any:
    _rate_limit(request, "pipeline", max_n=8, window_s=600)
    if not body.use_sample and not body.url.strip() and not body.markdown.strip():
        raise HTTPException(
            status_code=400,
            detail="Provide a URL, pasted Markdown, or use_sample=true.",
        )
    allowed = {a["id"] for a in ASSET_CATALOG}
    assets = [a for a in body.assets if a in allowed][:40]
    hunt_days = body.hunt_days if body.hunt_days in (30, 60, 90) else 90
    kwargs = {
        "url": body.url,
        "use_sample": body.use_sample,
        "markdown": body.markdown,
        "title": body.title,
        "assets": assets,
        "hunt_days": hunt_days,
    }
    if not stream:
        final: dict[str, Any] | None = None
        for event in run_pipeline(**kwargs):
            final = event
        if not final:
            raise HTTPException(status_code=500, detail="Pipeline produced no events")
        if final.get("event") == "error":
            raise HTTPException(status_code=502, detail=final.get("message"))
        return final

    queue: Queue[dict[str, Any] | None] = Queue()

    def worker() -> None:
        try:
            for event in run_pipeline(**kwargs):
                queue.put(event)
        finally:
            queue.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def generate():
        while True:
            item = queue.get()
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/api/estate/catalog")
def api_catalog() -> dict[str, Any]:
    return {"assets": [{"id": a["id"], "label": a["label"]} for a in ASSET_CATALOG]}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(UI_DIR / "index.html")


app.mount("/static", StaticFiles(directory=UI_DIR), name="static")


def _start_scheduler() -> None:
    if os.environ.get("CVE2DETECT_DAILY_SEARCH", "0") != "1":
        return
    if not search_ready():
        return
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except Exception:
        return

    def job() -> None:
        try:
            hits = discover()
            upsert_feed(hits)
        except Exception:
            pass

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(job, "interval", hours=24, id="daily-tinyfish-search")
    scheduler.start()


_start_scheduler()


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("CVE2DETECT_HOST", "127.0.0.1")
    port = int(os.environ.get("CVE2DETECT_PORT", "8787"))
    uvicorn.run("app:app", host=host, port=port, reload=True)
