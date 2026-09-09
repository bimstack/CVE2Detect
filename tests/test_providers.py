from __future__ import annotations

from pipeline.ingest import html_to_markdown
from pipeline import settings


def _isolate_env(monkeypatch) -> None:
    monkeypatch.setattr(settings, "load_dotenv", lambda *a, **k: None)
    for key in (
        "CVE2DETECT_FETCH_PROVIDER",
        "FETCH_PROVIDER",
        "FETCH_API_KEY",
        "TINYFISH_API_KEY",
        "CVE2DETECT_LLM_PROVIDER",
        "LLM_PROVIDER",
        "LLM_API_KEY",
        "LLM_MODEL",
        "LLM_API_BASE",
        "OPENAI_BASE_URL",
        "GEMINI_API_KEY",
        "GEMINI_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "XAI_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


def test_fetch_defaults_to_http_without_key(monkeypatch):
    _isolate_env(monkeypatch)
    assert settings.fetch_provider() == "http"
    assert settings.fetch_ready() is True
    assert settings.search_ready() is False


def test_fetch_tinyfish_when_key_present(monkeypatch):
    _isolate_env(monkeypatch)
    monkeypatch.setenv("FETCH_API_KEY", "test-fetch-key")
    assert settings.fetch_provider() == "tinyfish"
    assert settings.search_ready() is True


def test_llm_openai_compatible_from_base(monkeypatch):
    _isolate_env(monkeypatch)
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_API_BASE", "https://example-llm.test/v1")
    monkeypatch.setenv("LLM_MODEL", "local-model")
    assert settings.llm_provider() == "openai_compatible"
    assert settings.llm_api_base() == "https://example-llm.test/v1"
    assert settings.llm_model() == "local-model"
    assert settings.llm_ready() is True


def test_llm_gemini_alias(monkeypatch):
    _isolate_env(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test")
    assert settings.llm_provider() == "gemini"
    assert settings.llm_api_key() == "gemini-test"


def test_html_to_markdown_strips_chrome():
    html = """
    <html><head><title>CVE-2026-1</title><style>nav{}</style></head>
    <body>
      <nav>ignore</nav>
      <h1>Advisory</h1>
      <p>w3wp.exe spawned cmd.exe</p>
      <script>void 0</script>
    </body></html>
    """
    text = html_to_markdown(html)
    assert "Advisory" in text
    assert "w3wp.exe" in text
    assert "ignore" not in text
    assert "void 0" not in text
