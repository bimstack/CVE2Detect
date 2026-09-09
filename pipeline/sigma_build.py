"""Assemble Sigma YAML from structured extraction fields."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml

from pipeline.schema import IntelExtraction, SelectionBlock, SigmaDraft

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class LiteralStr(str):
    pass


def _literal_representer(dumper: yaml.Dumper, data: LiteralStr) -> yaml.Node:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


yaml.add_representer(LiteralStr, _literal_representer)


def _ident(name: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", (name or "").strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"s_{cleaned}"
    return cleaned


def _unique(name: str, used: set[str]) -> str:
    base = name
    i = 2
    while name in used:
        name = f"{base}_{i}"
        i += 1
    used.add(name)
    return name


def _field_key(field: str, modifier: str) -> str:
    field = (field or "CommandLine").strip()
    modifier = (modifier or "").strip().lower()
    if modifier in {"", "eq", "equals"}:
        return field
    return f"{field}|{modifier}"


def _selection_map(block: SelectionBlock) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for match in block.fields:
        if not match.values:
            continue
        key = _field_key(match.field, match.modifier)
        values = [v for v in match.values if str(v).strip()]
        if not values:
            continue
        out[key] = values[0] if len(values) == 1 else values
    return out


def _tag_list(intel: IntelExtraction) -> list[str]:
    tags: list[str] = []
    for tech in intel.techniques:
        tid = (tech.id or "").strip().upper()
        if tid.startswith("T"):
            slug = tid.lower().replace(".", ".")
            tags.append(f"attack.{slug.lower()}")
    cve = (intel.cve or "").strip().upper()
    if cve.startswith("CVE-"):
        tags.append("cve." + cve[4:].replace("-", ".").lower())
    # de-dupe, preserve order
    seen: set[str] = set()
    ordered = []
    for tag in tags:
        if tag not in seen:
            seen.add(tag)
            ordered.append(tag)
    return ordered


def build_sigma_document(intel: IntelExtraction, references: list[str]) -> dict[str, Any]:
    draft: SigmaDraft = intel.sigma
    used: set[str] = {"condition"}
    detection: dict[str, Any] = {}
    name_map: dict[str, str] = {}

    selections = draft.selections or []
    if not selections:
        selections = [
            SelectionBlock(
                name="selection",
                is_filter=False,
                fields=[],
            )
        ]

    for i, block in enumerate(selections):
        fallback = "filter" if block.is_filter else f"selection_{i+1}"
        name = _unique(_ident(block.name, fallback), used)
        name_map[block.name] = name
        mapped = _selection_map(block)
        if not mapped:
            continue
        detection[name] = mapped

    if not detection:
        detection["selection"] = {"Image|endswith": "\\cmd.exe"}
        condition = "selection"
    else:
        condition = (draft.condition or "").strip()
        for old, new in name_map.items():
            if old and old != new:
                condition = re.sub(rf"\b{re.escape(old)}\b", new, condition)
        known = set(detection.keys())
        if not condition or not any(n in condition for n in known):
            names = list(detection.keys())
            filters = [n for n in names if n.startswith("filter")]
            selects = [n for n in names if n not in filters]
            if selects and filters:
                condition = " and ".join(selects) + " and not (" + " or ".join(filters) + ")"
            else:
                condition = " and ".join(names)
        detection["condition"] = condition

    logsource: dict[str, str] = {}
    if draft.logsource_category:
        logsource["category"] = draft.logsource_category.strip()
    if draft.logsource_product:
        logsource["product"] = draft.logsource_product.strip()
    if draft.logsource_service:
        logsource["service"] = draft.logsource_service.strip()
    if not logsource:
        logsource = {"category": "process_creation", "product": "windows"}

    # Public v1 always emits draft rules. Analysts promote status after hunting.
    status = "experimental"
    level = (draft.level or "medium").strip().lower()
    if level not in {"informational", "low", "medium", "high", "critical"}:
        level = "medium"

    title = (draft.title or intel.summary or "Suspicious behavior from advisory").strip()
    title = re.sub(r"\s+", " ", title)[:120]

    description = (draft.description or intel.summary or "").strip()
    refs = [r for r in references if r]
    fps = [fp for fp in (draft.falsepositives or []) if fp.strip()]
    if not fps:
        fps = ["Unknown"]

    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    doc: dict[str, Any] = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": status,
        "description": LiteralStr(description) if description else description,
        "references": refs,
        "author": "CVE2Detect",
        "date": today,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": fps,
        "level": level,
    }
    tags = _tag_list(intel)
    if tags:
        doc["tags"] = tags
    if not refs:
        doc.pop("references")
    return doc


def dump_sigma_yaml(doc: dict[str, Any]) -> str:
    dumped = yaml.dump(
        doc,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=1000,
    )
    return dumped.strip() + "\n"


def build_sigma_yaml(intel: IntelExtraction, references: list[str]) -> str:
    return dump_sigma_yaml(build_sigma_document(intel, references))
