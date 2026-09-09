"""Stage 3 — YAML + pySigma validation and SIEM transpilation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

import yaml

ProgressFn = Callable[[str, str], None]


@dataclass
class ValidationResult:
    yaml_ok: bool
    sigma_ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parsed: Any | None = None
    splunk_spl: str = ""
    elastic_dsl: str = ""
    sentinel_kql: str = ""

    @property
    def ok(self) -> bool:
        return self.yaml_ok and self.sigma_ok


REQUIRED_KEYS = ("title", "logsource", "detection")


def _as_query(converted: Any) -> str:
    if converted is None:
        return ""
    if isinstance(converted, str):
        return converted.strip()
    if isinstance(converted, list):
        parts = [_as_query(item) for item in converted]
        return "\n\n".join(p for p in parts if p)
    if isinstance(converted, dict):
        return yaml.dump(converted, sort_keys=False, allow_unicode=True).strip()
    return str(converted).strip()


def _try_convert(rule: Any, factory: Callable[[], Any], fmt: str | None = None) -> str:
    backend = factory()
    if fmt:
        converted = backend.convert_rule(rule, output_format=fmt)
    else:
        converted = backend.convert_rule(rule)
    return _as_query(converted)


def validate_and_transpile(
    sigma_yaml: str,
    progress: ProgressFn | None = None,
) -> ValidationResult:
    result = ValidationResult(yaml_ok=False, sigma_ok=False)
    try:
        loaded = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as exc:
        result.errors.append(f"YAML parse error: {exc}")
        return result

    if not isinstance(loaded, dict):
        result.errors.append("YAML root must be a mapping.")
        return result

    missing = [key for key in REQUIRED_KEYS if key not in loaded]
    if missing:
        result.errors.append(f"Missing required Sigma fields: {', '.join(missing)}")
        return result

    detection = loaded.get("detection") or {}
    if not isinstance(detection, dict) or "condition" not in detection:
        result.errors.append("detection.condition is required.")
        return result
    if len(detection) < 2:
        result.errors.append("detection needs at least one selection plus condition.")
        return result

    result.yaml_ok = True
    if progress:
        progress("validate", "YAML structure OK. Parsing with pySigma.")

    try:
        from sigma.rule import SigmaRule
    except Exception as exc:  # pragma: no cover
        result.errors.append(f"pySigma is not available: {exc}")
        return result

    try:
        rule = SigmaRule.from_yaml(sigma_yaml)
        result.parsed = rule
        result.sigma_ok = True
    except Exception as exc:
        result.errors.append(f"pySigma rejected the rule: {exc}")
        return result

    if progress:
        progress("validate", "Transpiling to Splunk SPL, Elastic DSL, Sentinel KQL.")

    try:
        from sigma.backends.splunk import SplunkBackend

        try:
            from sigma.pipelines.splunk import splunk_windows_pipeline

            result.splunk_spl = _try_convert(
                rule, lambda: SplunkBackend(processing_pipeline=splunk_windows_pipeline())
            )
        except Exception:
            result.splunk_spl = _try_convert(rule, SplunkBackend)
    except Exception as exc:
        result.warnings.append(f"Splunk transpile skipped: {exc}")

    try:
        try:
            from sigma.backends.elasticsearch.elasticsearch import LuceneBackend
        except ImportError:
            from sigma.backends.elasticsearch import LuceneBackend

        try:
            result.elastic_dsl = _try_convert(
                rule, LuceneBackend, fmt="dsl_lucene"
            )
        except Exception:
            result.elastic_dsl = _try_convert(rule, LuceneBackend)
    except Exception as exc:
        result.warnings.append(f"Elastic transpile skipped: {exc}")

    try:
        from sigma.backends.kusto import KustoBackend

        pipeline = None
        try:
            from sigma.pipelines.sentinelasim import sentinel_asim_pipeline

            pipeline = sentinel_asim_pipeline()
        except Exception:
            try:
                from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

                pipeline = microsoft_xdr_pipeline()
            except Exception:
                pipeline = None
        if pipeline is not None:
            result.sentinel_kql = _try_convert(
                rule, lambda: KustoBackend(processing_pipeline=pipeline)
            )
        else:
            result.sentinel_kql = _try_convert(rule, KustoBackend)
    except Exception as exc:
        result.warnings.append(f"Sentinel KQL transpile skipped: {exc}")

    return result
