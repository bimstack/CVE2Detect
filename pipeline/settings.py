"""Resolve fetch and LLM providers from the environment.

Prefer generic names (`FETCH_*`, `LLM_*`). Vendor aliases (`TINYFISH_*`,
`GEMINI_*`, `OPENAI_*`, `XAI_*`) still work so an existing `.env` needs no edit.
Dotenv is re-read on each call so saving `.env` takes effect without a restart.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent

_LLM_ALIASES = {
    "google": "gemini",
    "google-ai": "gemini",
    "gemini": "gemini",
    "openai": "openai",
    "openai-compatible": "openai_compatible",
    "openai_compatible": "openai_compatible",
    "compatible": "openai_compatible",
    "xai": "openai_compatible",
    "grok": "openai_compatible",
    "groq": "openai_compatible",
    "together": "openai_compatible",
    "ollama": "openai_compatible",
    "vllm": "openai_compatible",
    "azure": "openai_compatible",
}

_FETCH_ALIASES = {
    "tinyfish": "tinyfish",
    "search": "tinyfish",
    "http": "http",
    "direct": "http",
    "html": "http",
    "none": "http",
}


def reload_env() -> None:
    load_dotenv(ROOT / ".env", override=True)


def fetch_provider() -> str:
    """`http` or `tinyfish`. Auto: tinyfish when a fetch key exists, else http."""
    reload_env()
    raw = (
        os.environ.get("CVE2DETECT_FETCH_PROVIDER")
        or os.environ.get("FETCH_PROVIDER")
        or ""
    ).strip().lower()
    mapped = _FETCH_ALIASES.get(raw)
    if mapped:
        return mapped
    if fetch_api_key():
        return "tinyfish"
    return "http"


def fetch_api_key() -> str:
    reload_env()
    return (
        os.environ.get("FETCH_API_KEY")
        or os.environ.get("TINYFISH_API_KEY")
        or ""
    ).strip()


def fetch_ready() -> bool:
    if fetch_provider() == "http":
        return True
    return bool(fetch_api_key())


def search_ready() -> bool:
    return fetch_provider() == "tinyfish" and bool(fetch_api_key())


def llm_provider() -> str:
    """`gemini`, `openai`, or `openai_compatible`, from env or inferred from keys."""
    reload_env()
    raw = (
        os.environ.get("CVE2DETECT_LLM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or ""
    ).strip().lower()
    mapped = _LLM_ALIASES.get(raw)
    if mapped:
        return mapped
    base = (
        os.environ.get("LLM_API_BASE")
        or os.environ.get("OPENAI_BASE_URL")
        or ""
    ).strip()
    if base and "generativelanguage.googleapis.com" not in base:
        return "openai_compatible"
    if os.environ.get("XAI_API_KEY", "").strip():
        return "openai_compatible"
    if os.environ.get("OPENAI_API_KEY", "").strip():
        return "openai"
    if os.environ.get("GEMINI_API_KEY", "").strip():
        return "gemini"
    if os.environ.get("LLM_API_KEY", "").strip() and base:
        return "openai_compatible"
    return "gemini"


def llm_api_key() -> str:
    reload_env()
    provider = llm_provider()
    if provider == "gemini":
        return (
            os.environ.get("LLM_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
            or ""
        ).strip()
    if provider == "openai":
        return (
            os.environ.get("LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        ).strip()
    return (
        os.environ.get("LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("XAI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or ""
    ).strip()


def llm_ready() -> bool:
    return bool(llm_api_key())


def llm_api_base() -> str:
    reload_env()
    explicit = (
        os.environ.get("LLM_API_BASE")
        or os.environ.get("OPENAI_BASE_URL")
        or ""
    ).strip().rstrip("/")
    if explicit:
        return explicit
    raw = (
        os.environ.get("CVE2DETECT_LLM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or ""
    ).strip().lower()
    if llm_provider() == "openai":
        return "https://api.openai.com/v1"
    if raw in {"xai", "grok"} or os.environ.get("XAI_API_KEY", "").strip():
        return "https://api.x.ai/v1"
    if raw == "groq":
        return "https://api.groq.com/openai/v1"
    if raw == "ollama":
        return "http://127.0.0.1:11434/v1"
    if llm_provider() == "openai_compatible":
        return "https://api.openai.com/v1"
    return ""


def llm_model() -> str:
    reload_env()
    explicit = (
        os.environ.get("LLM_MODEL")
        or os.environ.get("GEMINI_MODEL")
        or os.environ.get("OPENAI_MODEL")
        or ""
    ).strip()
    if explicit:
        return explicit
    raw = (
        os.environ.get("CVE2DETECT_LLM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or ""
    ).strip().lower()
    if llm_provider() == "gemini":
        return "gemini-3.8-flash"
    if raw in {"xai", "grok"}:
        return "grok-4"
    return "gpt-4o-mini"


_GEMINI_DEFAULT_FALLBACKS = ("gemini-2.5-flash", "gemini-2.0-flash")


def llm_models() -> list[str]:
    """Primary model first, then extras from LLM_MODELS (comma-separated).

    When the provider is Gemini and LLM_MODELS is empty, a short same-vendor
    fallback list is used so a 503 on one SKU can try another.
    Set LLM_MODELS=none to disable those defaults.
    """
    reload_env()
    primary = llm_model()
    extra = (os.environ.get("LLM_MODELS") or os.environ.get("GEMINI_MODELS") or "").strip()
    if extra.lower() in {"none", "off", "-"}:
        extra = ""
    elif not extra and llm_provider() == "gemini":
        extra = ",".join(_GEMINI_DEFAULT_FALLBACKS)
    ordered: list[str] = []
    for item in [primary, *[part.strip() for part in extra.split(",")]]:
        if item and item not in ordered:
            ordered.append(item)
    return ordered


def provider_status() -> dict[str, str | bool | list[str]]:
    return {
        "fetch": fetch_provider(),
        "llm": llm_provider(),
        "model": llm_model(),
        "models": llm_models(),
        "fetch_ready": fetch_ready(),
        "llm_ready": llm_ready(),
        "search_ready": search_ready(),
    }
