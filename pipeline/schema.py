"""Structured extraction schema and event types for the four pipeline stages."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AttackTechnique(StrictModel):
    id: str = Field(description="MITRE ATT&CK technique ID such as T1059.001")
    name: str = Field(description="Technique name")
    tactic: str = Field(description="ATT&CK tactic such as Execution")


class AffectedProduct(StrictModel):
    vendor: str
    product: str
    versions: str = Field(description="Affected versions, or unknown")


class TelemetryEvent(StrictModel):
    os: str = Field(description="windows, linux, or macos")
    source: str = Field(
        description="Log source, e.g. sysmon, windows_security, auditd, syslog"
    )
    event_id: str = Field(
        description="Event identifier such as 1, 11, 13, 4688, or syscall name"
    )
    name: str = Field(description="Human-readable event name such as Process Creation")
    description: str = Field(
        description="What this event captures during exploitation, grounded in the write-up"
    )


class ProcessAnomaly(StrictModel):
    parent_image: str
    child_image: str
    command_line: str
    notes: str


class Indicator(StrictModel):
    type: str = Field(description="hash, ip, domain, url, path, mutex, registry, email")
    value: str
    context: str


class FieldMatch(StrictModel):
    field: str = Field(
        description="Sigma field name, e.g. Image, CommandLine, ParentImage, TargetFilename, TargetObject"
    )
    modifier: str = Field(
        description="Sigma modifier or empty: contains, endswith, startswith, re, windash, all"
    )
    values: list[str] = Field(description="One or more match values")


class SelectionBlock(StrictModel):
    name: str = Field(description="Detection selection identifier, e.g. selection_process")
    is_filter: bool = Field(
        description="True when this block is a false-positive filter (NOT in the condition)"
    )
    fields: list[FieldMatch]


class SigmaDraft(StrictModel):
    title: str
    status: str = Field(description="experimental, test, or stable")
    description: str
    logsource_category: str = Field(
        description="Sigma logsource category such as process_creation, file_event, registry_set"
    )
    logsource_product: str = Field(description="windows, linux, macos, or empty")
    logsource_service: str = Field(
        description="Optional service such as sysmon, security, auditd"
    )
    selections: list[SelectionBlock]
    condition: str = Field(
        description="Sigma condition referencing selection names, e.g. selection_process and not filter_admin"
    )
    falsepositives: list[str]
    level: str = Field(description="informational, low, medium, high, or critical")


class IntelExtraction(StrictModel):
    summary: str = Field(description="2-4 sentence analyst summary of the write-up")
    cve: str = Field(description="Primary CVE identifier or empty if none")
    cvss: str = Field(description="CVSS score as text, e.g. 9.8, or empty")
    vulnerability_type: str = Field(
        description="e.g. RCE, LPE, auth bypass, deserialization, SSRF"
    )
    threat_actor: str = Field(description="Named actor or empty if not stated")
    campaign: str = Field(description="Campaign or malware family, or empty")
    affected: list[AffectedProduct]
    techniques: list[AttackTechnique]
    telemetry: list[TelemetryEvent]
    process_anomalies: list[ProcessAnomaly]
    command_lines: list[str]
    paths: list[str]
    indicators: list[Indicator]
    sigma: SigmaDraft
    confidence: str = Field(description="high, medium, or low")
    is_actionable: bool = Field(
        description="True if the write-up contains enough behavioral telemetry to justify a detection rule"
    )
    caveats: str = Field(
        description="Gaps, assumptions, or invented-looking details that should be reviewed"
    )


def make_strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Force additionalProperties:false and required=all properties for xAI structured output."""
    schema = model.model_json_schema()

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if "properties" in node:
            node["type"] = "object"
            node["additionalProperties"] = False
            node["required"] = list(node["properties"].keys())
            for child in node["properties"].values():
                walk(child)
        if "items" in node:
            walk(node["items"])
        for key in ("anyOf", "oneOf", "allOf"):
            for item in node.get(key, []):
                walk(item)
        if "$defs" in node:
            for item in node["$defs"].values():
                walk(item)

    walk(schema)
    return schema


ANALYST_SYSTEM_PROMPT = """You are a Senior Threat Analyst and Detection Engineer.

Your job is to convert an unstructured vulnerability write-up into structured behavioral telemetry and a Sigma detection draft.

Rules:
- Ground every field in the source text. Do not invent hashes, IPs, file paths, CVE IDs, or event IDs that are not supported by the advisory.
- Prefer operating-system events over generic file hashes. Map exploitation to concrete telemetry:
  Windows: Event ID 4688 / Sysmon 1 (process create), Sysmon 11 (file create), Sysmon 13 (registry), Sysmon 3 (network), Sysmon 10 (process access), Sysmon 7 (image load).
  Linux: auditd syscalls (execve, connect, openat, ptrace), syslog, auth logs.
- Capture parent-child process anomalies (e.g. w3wp.exe spawning cmd.exe or powershell.exe) and exact command-line flags when present.
- Use official Sigma field names for the target log source (Image, CommandLine, ParentImage, TargetFilename, TargetObject, DestinationIp, exe, comm, SYSCALL).
- Selection names must be valid identifiers: letters, digits, underscore. Condition must reference those names with and/or/not.
- If the article is not a technical exploit write-up, set is_actionable=false, keep sigma minimal, and explain why in caveats.
- confidence=high only when event IDs or process chains are explicit in the text. Otherwise medium or low.
- Empty string / empty list when unknown. Never pad with placeholders like N/A or TODO.
"""


StageName = Literal["ingest", "extract", "validate", "store"]
