"""Run the four-stage pipeline and emit progress events."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from pipeline.atomic import generate_atomic_tests
from pipeline.extract import extract_intel
from pipeline.hunt import build_retro_hunts
from pipeline.ingest import FetchedAdvisory, IngestError, fetch_advisory, utcnow
from pipeline.ossiem import build_limacharlie_yaml, build_wazuh_xml
from pipeline.profile import match_stack, parse_cvss
from pipeline.schema import IntelExtraction
from pipeline.sigma_build import build_sigma_yaml
from pipeline.validate import validate_and_transpile

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_MD = ROOT / "samples" / "advisory.md"
SAMPLE_URL = "https://cve2detect.local/samples/iis-rce-cobalt-thread"


def _event(stage: str, message: str, **extra: Any) -> dict[str, Any]:
    payload = {"event": "progress", "stage": stage, "message": message}
    payload.update(extra)
    return payload


def _record_from_parts(
    advisory: FetchedAdvisory,
    intel: IntelExtraction,
    sigma_yaml: str,
    validation: Any,
) -> dict[str, Any]:
    return {
        "url": advisory.final_url or advisory.url,
        "title": intel.sigma.title or advisory.title,
        "site_name": advisory.site_name,
        "fetch_method": advisory.method,
        "markdown": advisory.markdown,
        "summary": intel.summary,
        "cve": intel.cve,
        "cvss": intel.cvss,
        "vulnerability_type": intel.vulnerability_type,
        "threat_actor": intel.threat_actor,
        "campaign": intel.campaign,
        "affected_json": json.dumps([a.model_dump() for a in intel.affected]),
        "techniques_json": json.dumps([t.model_dump() for t in intel.techniques]),
        "telemetry_json": json.dumps([t.model_dump() for t in intel.telemetry]),
        "process_anomalies_json": json.dumps(
            [p.model_dump() for p in intel.process_anomalies]
        ),
        "command_lines_json": json.dumps(intel.command_lines),
        "paths_json": json.dumps(intel.paths),
        "indicators_json": json.dumps([i.model_dump() for i in intel.indicators]),
        "confidence": intel.confidence,
        "is_actionable": 1 if intel.is_actionable else 0,
        "caveats": intel.caveats,
        "sigma_yaml": sigma_yaml,
        "sigma_valid": 1 if validation.ok else 0,
        "validation_errors_json": json.dumps(validation.errors + validation.warnings),
        "splunk_spl": validation.splunk_spl,
        "elastic_dsl": validation.elastic_dsl,
        "sentinel_kql": validation.sentinel_kql,
        "logsource_product": intel.sigma.logsource_product,
        "logsource_category": intel.sigma.logsource_category,
        "created_at": utcnow(),
        "wazuh_xml": "",
        "limacharlie_yaml": "",
        "atomic_tests_json": "[]",
        "retrohunt_json": "{}",
        "stack_match": 0,
        "stack_configured": 0,
        "stack_hits_json": "[]",
        "stack_reason": "",
        "cvss_numeric": None,
        "webhook_sent": 0,
    }


def _client_record(payload: dict[str, Any]) -> dict[str, Any]:
    """Shape a pipeline payload for the browser without writing a shared database."""
    payload = dict(payload)
    payload["id"] = payload.get("id") or uuid.uuid4().hex[:12]
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if key.endswith("_json"):
            name = key[: -len("_json")]
            empty: Any = {} if name == "retrohunt" else []
            try:
                out[name] = json.loads(value) if value else empty
            except json.JSONDecodeError:
                out[name] = empty
        else:
            out[key] = value
    return out


def load_sample_advisory() -> FetchedAdvisory:
    markdown = SAMPLE_MD.read_text(encoding="utf-8")
    return FetchedAdvisory(
        url=SAMPLE_URL,
        final_url=SAMPLE_URL,
        title="IIS worker RCE — Project Cobalt Thread (sample advisory)",
        markdown=markdown,
        method="sample",
        site_name="cve2detect.local",
    )


def run_pipeline(
    *,
    url: str = "",
    use_sample: bool = False,
    markdown: str = "",
    title: str = "",
    assets: list[str] | None = None,
    hunt_days: int = 90,
) -> Iterator[dict[str, Any]]:
    """Yield SSE-friendly events, then a final `complete` or `error` event."""
    try:
        yield _event("ingest", "Stage 1 — Ingestion & stealth retrieval.")
        if use_sample:
            advisory = load_sample_advisory()
            yield _event("ingest", "Loaded bundled sample advisory (no live fetch).")
        elif markdown.strip():
            advisory = FetchedAdvisory(
                url=url or "pasted://advisory",
                final_url=url or "pasted://advisory",
                title=title or "Pasted advisory",
                markdown=markdown,
                method="paste",
                site_name="",
            )
            yield _event("ingest", "Using pasted Markdown.")
        elif url.strip():
            notes: list[dict[str, Any]] = []

            def _ingest_progress(stage: str, message: str) -> None:
                notes.append(_event(stage, message))

            advisory = fetch_advisory(url.strip(), progress=_ingest_progress)
            for note in notes:
                yield note
            yield _event(
                "ingest",
                f"Retrieved {len(advisory.markdown)} chars via {advisory.method}.",
                title=advisory.title,
                method=advisory.method,
                latency_ms=advisory.latency_ms,
            )
        else:
            raise IngestError("Provide a URL, pasted Markdown, or use the sample advisory.")

        yield _event("extract", "Stage 2 — Intelligence & behavioral telemetry extraction.")
        intel = extract_intel(
            advisory.markdown,
            source_url=advisory.final_url,
            title=advisory.title,
            use_sample_fallback=use_sample,
        )
        yield _event(
            "extract",
            f"Extracted {intel.cve or 'unassigned'} · {len(intel.telemetry)} telemetry points · "
            f"confidence {intel.confidence}.",
        )

        yield _event("validate", "Stage 3 — Sigma YAML synthesis, parse, transpile.")
        sigma_yaml = build_sigma_yaml(intel, [advisory.final_url] if advisory.final_url else [])
        validation = validate_and_transpile(sigma_yaml)
        if validation.ok:
            yield _event("validate", "pySigma accepted the rule. SIEM queries compiled.")
        else:
            yield _event(
                "validate",
                "Validation issues: " + "; ".join(validation.errors[:3]),
            )

        extra_text = " ".join(
            [
                intel.summary,
                intel.campaign,
                intel.sigma.logsource_product,
                intel.sigma.description,
            ]
        )
        stack = match_stack(intel.affected, assets or [], extra_text)
        cvss_n = parse_cvss(intel.cvss)
        detection = {}
        try:
            loaded = yaml.safe_load(sigma_yaml) or {}
            detection = loaded.get("detection") or {}
        except Exception:
            detection = {}
        wazuh_xml = build_wazuh_xml(
            title=intel.sigma.title,
            description=intel.sigma.description or intel.summary,
            detection=detection,
            techniques=intel.techniques,
            seed=advisory.final_url or intel.sigma.title,
            level=intel.sigma.level,
        )
        lc_yaml = build_limacharlie_yaml(
            title=intel.sigma.title,
            detection=detection,
            seed=advisory.final_url or intel.cve or "rule",
        )
        atomic = generate_atomic_tests(
            techniques=intel.techniques,
            command_lines=intel.command_lines,
            process_anomalies=intel.process_anomalies,
            logsource_product=intel.sigma.logsource_product,
        )
        hunts = build_retro_hunts(
            splunk_spl=validation.splunk_spl,
            elastic_dsl=validation.elastic_dsl,
            sentinel_kql=validation.sentinel_kql,
            windows=int(hunt_days or 90),
        )
        payload = _record_from_parts(advisory, intel, sigma_yaml, validation)
        payload.update(
            {
                "wazuh_xml": wazuh_xml,
                "limacharlie_yaml": lc_yaml,
                "atomic_tests_json": json.dumps(atomic),
                "retrohunt_json": json.dumps(hunts),
                "stack_match": 1 if stack["matched"] else 0,
                "stack_configured": 1 if stack["configured"] else 0,
                "stack_hits_json": json.dumps(stack["hits"]),
                "stack_reason": stack["reason"],
                "cvss_numeric": cvss_n,
            }
        )

        yield _event("store", "Stage 4 — Output ready. Copy queries; this run is not stored on the server.")
        if stack["configured"]:
            yield _event(
                "store",
                ("Stack match — " if stack["matched"] else "Out of scope — ") + stack["reason"],
            )
        record = _client_record(payload)
        yield {
            "event": "complete",
            "stage": "store",
            "message": "Pipeline complete.",
            "record": record,
        }
    except Exception as exc:
        yield {
            "event": "error",
            "stage": "error",
            "message": str(exc),
        }
