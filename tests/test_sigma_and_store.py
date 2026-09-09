from __future__ import annotations

import json
from pathlib import Path

from pipeline.extract import load_sample_extraction
from pipeline.ingest import normalize_advisory_url
from pipeline.schema import IntelExtraction, make_strict_schema
from pipeline.sigma_build import build_sigma_yaml
from pipeline.store import get_record, save_record, search_records
from pipeline.validate import validate_and_transpile

ROOT = Path(__file__).resolve().parent.parent


def test_normalize_markdown_and_garbled_urls():
    clean = "https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2025-0282-cve-2025-0283/"
    garbled = (
        "https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2025-0282-cve-2025-0283/]"
        "(https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2025-0282-cve-2025-0283/"
    )
    md = f"[Unit 42 brief]({clean})"
    assert normalize_advisory_url(garbled) == clean
    assert normalize_advisory_url(md) == clean
    assert normalize_advisory_url(f"<{clean}>") == clean
    assert normalize_advisory_url(clean) == clean


def test_sample_extraction_matches_schema():
    intel = load_sample_extraction()
    assert intel.cve == "CVE-2026-44011"
    assert intel.is_actionable
    assert any(t.event_id == "1" for t in intel.telemetry)
    assert intel.sigma.condition


def test_strict_schema_requires_all_properties():
    schema = make_strict_schema(IntelExtraction)
    assert schema["additionalProperties"] is False
    assert "cve" in schema["required"]
    assert "sigma" in schema["properties"]


def test_sigma_yaml_is_pysigma_valid():
    intel = load_sample_extraction()
    yaml_text = build_sigma_yaml(intel, ["https://cve2detect.local/sample"])
    assert "title:" in yaml_text
    assert "status: experimental" in yaml_text
    assert "logsource:" in yaml_text
    assert "detection:" in yaml_text
    assert "ParentImage|endswith" in yaml_text
    result = validate_and_transpile(yaml_text)
    assert result.yaml_ok, result.errors
    assert result.sigma_ok, result.errors
    assert result.ok
    assert "w3wp" in result.splunk_spl.lower() or "ParentImage" in result.splunk_spl or result.splunk_spl


def test_invalid_yaml_fails():
    result = validate_and_transpile("not: valid: sigma: [")
    assert not result.yaml_ok
    assert result.errors


def test_store_and_search(tmp_db):
    intel = load_sample_extraction()
    yaml_text = build_sigma_yaml(intel, ["https://example.test/a"])
    validation = validate_and_transpile(yaml_text)
    record = save_record(
        {
            "url": "https://example.test/a",
            "title": intel.sigma.title,
            "site_name": "example.test",
            "fetch_method": "sample",
            "markdown": "# hi",
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
            "is_actionable": 1,
            "caveats": intel.caveats,
            "sigma_yaml": yaml_text,
            "sigma_valid": 1 if validation.ok else 0,
            "validation_errors_json": json.dumps(validation.errors),
            "splunk_spl": validation.splunk_spl,
            "elastic_dsl": validation.elastic_dsl,
            "sentinel_kql": validation.sentinel_kql,
            "logsource_product": "windows",
            "logsource_category": "process_creation",
            "created_at": "2026-08-22T00:00:00+00:00",
        }
    )
    assert record["cve"] == "CVE-2026-44011"
    loaded = get_record(record["id"])
    assert loaded is not None
    hits = search_records("T1059.001")
    assert any(h["id"] == record["id"] for h in hits)
    hits2 = search_records("process_creation")
    assert any(h["id"] == record["id"] for h in hits2)
