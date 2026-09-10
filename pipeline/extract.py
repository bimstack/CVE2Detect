"""Stage 2 — LLM extraction of telemetry and Sigma draft fields."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Callable

import httpx

from pipeline.schema import ANALYST_SYSTEM_PROMPT, IntelExtraction, make_strict_schema
from pipeline.settings import llm_api_base, llm_api_key, llm_models, llm_provider

ProgressFn = Callable[[str, str], None]
ROOT = Path(__file__).resolve().parent.parent
SAMPLE_EXTRACTION = ROOT / "samples" / "extraction.json"
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

MAX_MARKDOWN_CHARS = 80_000
ATTEMPTS_PER_MODEL = 2
BACKOFF_S = (2.0, 4.0)
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.I | re.M)


class ExtractError(RuntimeError):
    pass


class LlmHttpError(ExtractError):
    """Typed LLM HTTP failure so the caller can retry or skip a model."""

    def __init__(self, message: str, *, status: int, retryable: bool, skip_model: bool) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.skip_model = skip_model


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def _raise_http(status: int, body: str, model: str) -> None:
    snippet = (body or "")[:400]
    if status in (401, 403):
        raise LlmHttpError(
            "LLM rejected the API key. Check LLM_API_KEY.",
            status=status,
            retryable=False,
            skip_model=False,
        )
    if status == 404:
        raise LlmHttpError(
            f"LLM model '{model}' was not found.",
            status=status,
            retryable=False,
            skip_model=True,
        )
    if status in (408, 429, 500, 502, 503, 504):
        raise LlmHttpError(
            f"LLM HTTP {status} for {model}: {snippet}",
            status=status,
            retryable=True,
            skip_model=False,
        )
    raise LlmHttpError(
        f"LLM HTTP {status} for {model}: {snippet}",
        status=status,
        retryable=False,
        skip_model=False,
    )


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
    except httpx.TimeoutException as exc:
        raise LlmHttpError(
            f"LLM timed out for {model}: {exc}",
            status=408,
            retryable=True,
            skip_model=False,
        ) from exc
    except httpx.HTTPError as exc:
        raise LlmHttpError(
            f"LLM request failed for {model}: {exc}",
            status=503,
            retryable=True,
            skip_model=False,
        ) from exc

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

    if response.status_code >= 400:
        _raise_http(response.status_code, response.text, model)

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
    except httpx.TimeoutException as exc:
        raise LlmHttpError(
            f"LLM timed out for {model}: {exc}",
            status=408,
            retryable=True,
            skip_model=False,
        ) from exc
    except httpx.HTTPError as exc:
        raise LlmHttpError(
            f"LLM request failed for {model}: {exc}",
            status=503,
            retryable=True,
            skip_model=False,
        ) from exc

    if response.status_code == 400:
        try:
            response = _post(loose_body)
        except httpx.TimeoutException as exc:
            raise LlmHttpError(
                f"LLM timed out for {model}: {exc}",
                status=408,
                retryable=True,
                skip_model=False,
            ) from exc
        except httpx.HTTPError as exc:
            raise LlmHttpError(
                f"LLM request failed for {model}: {exc}",
                status=503,
                retryable=True,
                skip_model=False,
            ) from exc

    if response.status_code >= 400:
        _raise_http(response.status_code, response.text, model)

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
    models = llm_models()
    last_err: Exception | None = None
    for index, model in enumerate(models):
        for attempt in range(1, ATTEMPTS_PER_MODEL + 1):
            label = f"LLM ({provider} / {model})"
            if index > 0:
                label = f"Fallback {label}"
            if attempt > 1:
                label = f"{label} retry {attempt}/{ATTEMPTS_PER_MODEL}"
            if progress:
                progress("extract", f"{label} acting as Senior Threat Analyst.")
            try:
                if provider == "gemini":
                    return _extract_gemini(text, source_url, title, key, model)
                return _extract_openai(text, source_url, title, key, model, llm_api_base())
            except LlmHttpError as exc:
                last_err = exc
                if not exc.retryable and not exc.skip_model:
                    raise
                if exc.skip_model:
                    if progress:
                        progress("extract", f"{model} was not found. Trying the next model.")
                    break
                more_attempts = attempt < ATTEMPTS_PER_MODEL
                if more_attempts:
                    delay = BACKOFF_S[min(attempt - 1, len(BACKOFF_S) - 1)]
                    if progress:
                        progress(
                            "extract",
                            f"{model} is busy (HTTP {exc.status}). Retrying in {int(delay)}s.",
                        )
                    _sleep(delay)
                    continue
                if index < len(models) - 1 and progress:
                    progress("extract", f"{model} still unavailable. Trying the next model.")
                break
    tried = ", ".join(models)
    detail = str(last_err) if last_err else "no response"
    raise ExtractError(
        "LLM is unavailable (high demand or outage). "
        f"Tried: {tried}. Wait a minute and retry, or add more ids to LLM_MODELS. "
        f"Last error: {detail}"
    )
