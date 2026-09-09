"""Stage 2 — LLM extraction of telemetry and Sigma draft fields."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import httpx

from pipeline.schema import ANALYST_SYSTEM_PROMPT, IntelExtraction, make_strict_schema
from pipeline.settings import llm_api_base, llm_api_key, llm_model, llm_provider

ProgressFn = Callable[[str, str], None]
ROOT = Path(__file__).resolve().parent.parent
SAMPLE_EXTRACTION = ROOT / "samples" / "extraction.json"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

MAX_MARKDOWN_CHARS = 80_000
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I | re.M)


class ExtractError(RuntimeError):
    pass


def load_sample_extraction() -> IntelExtraction:
    raw = json.loads(SAMPLE_EXTRACTION.read_text(encoding="utf-8"))
    return IntelExtraction.model_validate(raw)


def _json_schema() -> dict[str, Any]:
    schema = make_strict_schema(IntelExtraction)
    schema.pop("$schema", None)
    return schema


def _user_block(markdown: str, source_url: str, title: str) -> str:
    return (
        f"Source URL: {source_url or 'n/a'}\n"
        f"Page title: {title or 'n/a'}\n\n"
        f"--- ADVISORY MARKDOWN ---\n{markdown}"
    )


def _parse_json_content(content: str) -> dict[str, Any]:
    text = _FENCE_RE.sub("", (content or "").strip()).strip()
    try:
        payload: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ExtractError(f"LLM did not return JSON: {exc}") from exc
    return payload


def _gemini_response_text(payload: dict[str, Any]) -> str:
    prompt_feedback = payload.get("promptFeedback") or {}
    block = prompt_feedback.get("blockReason")
    if block:
        raise ExtractError(f"LLM blocked the prompt ({block}).")
    candidates = payload.get("candidates") or []
    if not candidates:
        raise ExtractError("LLM returned no candidates.")
    finish = (candidates[0].get("finishReason") or "").upper()
    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    text = "".join(str(p.get("text") or "") for p in parts).strip()
    if not text:
        raise ExtractError(f"LLM returned empty content (finishReason={finish or 'unknown'}).")
    return text


def _extract_gemini(markdown: str, source_url: str, title: str, key: str, model: str) -> IntelExtraction:
    schema = _json_schema()
    body = {
        "systemInstruction": {"parts": [{"text": ANALYST_SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": _user_block(markdown, source_url, title)}]}],
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
        raise ExtractError(f"LLM request failed: {exc}") from exc

    if response.status_code == 400:
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
        raise ExtractError("LLM rejected the API key. Check LLM_API_KEY.")
    if response.status_code == 404:
        raise ExtractError(
            f"LLM model '{model}' was not found. Set LLM_MODEL in .env."
        )
    if response.status_code >= 400:
        raise ExtractError(f"LLM HTTP {response.status_code}: {response.text[:500]}")

    return IntelExtraction.model_validate(_parse_json_content(_gemini_response_text(response.json())))


def _extract_openai(markdown: str, source_url: str, title: str, key: str, model: str, base: str) -> IntelExtraction:
    if not base:
        raise ExtractError(
            "LLM_API_BASE is required for OpenAI-compatible providers "
            "(example: https://api.openai.com/v1)."
        )
    schema = _json_schema()
    endpoint = base.rstrip("/") + "/chat/completions"
    messages = [
        {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
        {"role": "user", "content": _user_block(markdown, source_url, title)},
    ]
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    strict_body: dict[str, Any] = {
        "model": model,
        "temperature": 0.1,
        "messages": messages,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "intel_extraction",
                "strict": True,
                "schema": schema,
            },
        },
    }
    loose_body: dict[str, Any] = {
        "model": model,
        "temperature": 0.1,
        "messages": messages
        + [
            {
                "role": "user",
                "content": "Respond with a single JSON object that matches the extraction schema. No markdown.",
            }
        ],
        "response_format": {"type": "json_object"},
    }

    def _post(body: dict[str, Any]) -> httpx.Response:
        with httpx.Client(timeout=180.0) as client:
            return client.post(endpoint, headers=headers, json=body)

    try:
        response = _post(strict_body)
    except httpx.HTTPError as exc:
        raise ExtractError(f"LLM request failed: {exc}") from exc

    if response.status_code == 400:
        try:
            response = _post(loose_body)
        except httpx.HTTPError as exc:
            raise ExtractError(f"LLM request failed: {exc}") from exc

    if response.status_code in (401, 403):
        raise ExtractError("LLM rejected the API key. Check LLM_API_KEY.")
    if response.status_code == 404:
        raise ExtractError(
            f"LLM model '{model}' was not found at {base}. Set LLM_MODEL / LLM_API_BASE."
        )
    if response.status_code >= 400:
        raise ExtractError(f"LLM HTTP {response.status_code}: {response.text[:500]}")

    payload = response.json()
    choices = payload.get("choices") or []
    if not choices:
        raise ExtractError("LLM returned no choices.")
    content = ((choices[0].get("message") or {}).get("content")) or ""
    return IntelExtraction.model_validate(_parse_json_content(str(content)))


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

    key = llm_api_key()
    if not key:
        raise ExtractError(
            "LLM_API_KEY is not set. Add your LLM key to .env "
            "(LLM_API_KEY, or a vendor alias such as GEMINI_API_KEY / OPENAI_API_KEY)."
        )

    if len(text) > MAX_MARKDOWN_CHARS:
        text = text[:MAX_MARKDOWN_CHARS] + "\n\n[truncated for context window]"

    provider = llm_provider()
    model = llm_model()
    if progress:
        progress("extract", f"LLM ({provider} / {model}) acting as Senior Threat Analyst.")

    if provider == "gemini":
        return _extract_gemini(text, source_url, title, key, model)
    return _extract_openai(text, source_url, title, key, model, llm_api_base())
