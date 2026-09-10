from __future__ import annotations

from pipeline.extract import ExtractError, LlmHttpError, extract_intel, load_sample_extraction


def test_retries_then_falls_back_to_next_model(monkeypatch):
    calls: list[str] = []

    def fake_gemini(markdown, source_url, title, key, model):
        calls.append(model)
        if model == "primary-model":
            raise LlmHttpError("busy", status=503, retryable=True, skip_model=False)
        return load_sample_extraction()

    monkeypatch.setattr("pipeline.extract.llm_api_key", lambda: "test-key")
    monkeypatch.setattr("pipeline.extract.llm_provider", lambda: "gemini")
    monkeypatch.setattr("pipeline.extract.llm_models", lambda: ["primary-model", "backup-model"])
    monkeypatch.setattr("pipeline.extract._extract_gemini", fake_gemini)
    monkeypatch.setattr("pipeline.extract._sleep", lambda _s: None)

    intel = extract_intel("# advisory", source_url="https://example.test")
    assert intel.cve == "CVE-2026-44011"
    assert calls == ["primary-model", "primary-model", "backup-model"]


def test_auth_error_does_not_failover(monkeypatch):
    def fake_gemini(markdown, source_url, title, key, model):
        raise LlmHttpError("bad key", status=401, retryable=False, skip_model=False)

    monkeypatch.setattr("pipeline.extract.llm_api_key", lambda: "bad")
    monkeypatch.setattr("pipeline.extract.llm_provider", lambda: "gemini")
    monkeypatch.setattr("pipeline.extract.llm_models", lambda: ["a", "b"])
    monkeypatch.setattr("pipeline.extract._extract_gemini", fake_gemini)

    try:
        extract_intel("# advisory")
        raise AssertionError("expected ExtractError")
    except LlmHttpError as exc:
        assert exc.status == 401


def test_all_models_busy_raises(monkeypatch):
    def busy(*_a, **_k):
        raise LlmHttpError("busy", status=503, retryable=True, skip_model=False)

    monkeypatch.setattr("pipeline.extract.llm_api_key", lambda: "test-key")
    monkeypatch.setattr("pipeline.extract.llm_provider", lambda: "gemini")
    monkeypatch.setattr("pipeline.extract.llm_models", lambda: ["a"])
    monkeypatch.setattr("pipeline.extract._extract_gemini", busy)
    monkeypatch.setattr("pipeline.extract._sleep", lambda _s: None)

    try:
        extract_intel("# advisory")
        raise AssertionError("expected ExtractError")
    except ExtractError as exc:
        assert "unavailable" in str(exc).lower()
