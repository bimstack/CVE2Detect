"""Stage 2 — Gemini extraction of telemetry and Sigma draft fields."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

import httpx
from dotenv import load_dotenv

from pipeline.schema import ANALYST_SYSTEM_PROMPT, IntelExtraction, make_strict_schema

ProgressFn = Callable[[str, str], None]
ROOT = Path(__file__).resolve().parent.parent
SAMPLE_EXTRACTION = ROOT / "samples" / "extraction.json"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

MAX_MARKDOWN_CHARS = 80_000


class ExtractError(RuntimeError):
    pass


def _reload_env() -> None:
    load_dotenv(ROOT / ".env", override=True)


def _api_key() -> str:
    _reload_env()
    return os.environ.get("GEMINI_API_KEY", "").strip()


def _model() -> str:
    _reload_env()
    return os.environ.get("GEMINI_MODEL", "gemini-3.8-flash").strip() or "gemini-3.8-flash"


def load_sample_extraction() -> IntelExtraction:
    raw = json.loads(SAMPLE_EXTRACTION.read_text(encoding="utf-8"))
    return IntelExtraction.model_validate(raw)


def _response_text(payload: dict[str, Any]) -> str:
    prompt_feedback = payload.get("promptFeedback") or {}
    block = prompt_feedback.get("blockReason")
    if block:
        raise ExtractError(f"Gemini blocked the prompt ({block}).")
    candidates = payload.get("candidates") or []
    if not candidates:
        raise ExtractError("Gemini returned no candidates.")
    finish = (candidates[0].get("finishReason") or "").upper()
    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    text = "".join(str(p.get("text") or "") for p in parts).strip()
    if not text:
        raise ExtractError(f"Gemini returned empty content (finishReason={finish or 'unknown'}).")
    return text


def extract_intel(
    markdown: str,
    *,
    source_url: str = "",
    title: str = "",
    use_sample_fallback: bool = False,
    progress: ProgressFn | None = None,
) -> IntelExtraction:
    text = (markdown or "").strip()
    if not text:
        raise ExtractError("No advisory Markdown to analyze.")

    if use_sample_fallback and SAMPLE_EXTRACTION.exists():
        if progress:
            progress("extract", "Using bundled sample extraction.")
        return load_sample_extraction()

    key = _api_key()
    if not key:
        raise ExtractError(
            "GEMINI_API_KEY is not set. Add it to .env (https://aistudio.google.com/apikey)."
        )

    if len(text) > MAX_MARKDOWN_CHARS:
        text = text[:MAX_MARKDOWN_CHARS] + "\n\n[truncated for context window]"

    model = _model()
    if progress:
        progress("extract", f"Gemini ({model}) acting as Senior Threat Analyst / Detection Engineer.")

    schema = make_strict_schema(IntelExtraction)
    schema.pop("$schema", None)
    user_block = (
        f"Source URL: {source_url or 'n/a'}\n"
        f"Page title: {title or 'n/a'}\n\n"
        f"--- ADVISORY MARKDOWN ---\n{text}"
    )
    body = {
        "systemInstruction": {"parts": [{"text": ANALYST_SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_block}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
            "responseJsonSchema": schema,
        },
    }
    url = GEMINI_ENDPOINT.format(model=model)
    try:
        with httpx.Client(timeout=180.0) as client:
            response = client.post(
                url,
                headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                json=body,
            )
    except httpx.HTTPError as exc:
        raise ExtractError(f"Gemini request failed: {exc}") from exc

    if response.status_code == 400:
        # Some models only accept OpenAPI-style responseSchema, not JSON Schema.
        fallback_body = json.loads(json.dumps(body))
        fallback_body["generationConfig"].pop("responseJsonSchema", None)
        fallback_body["generationConfig"]["responseSchema"] = schema
        with httpx.Client(timeout=180.0) as client:
            response = client.post(
                url,
                headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                json=fallback_body,
            )

    if response.status_code in (401, 403):
        raise ExtractError(
            "Gemini rejected the API key. Check GEMINI_API_KEY at https://aistudio.google.com/apikey."
        )
    if response.status_code == 404:
        raise ExtractError(
            f"Gemini model '{model}' was not found. Set GEMINI_MODEL in .env (try gemini-3.8-flash)."
        )
    if response.status_code >= 400:
        detail = response.text[:500]
        raise ExtractError(f"Gemini HTTP {response.status_code}: {detail}")

    content = _response_text(response.json())
    try:
        payload: dict[str, Any] = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ExtractError(f"Gemini did not return JSON: {exc}") from exc
    return IntelExtraction.model_validate(payload)
