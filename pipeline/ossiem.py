"""Open-source SIEM transpilers: Wazuh XML and LimaCharlie D&R YAML."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from xml.sax.saxutils import escape

import yaml


def _rule_id(seed: str) -> int:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    return 100000 + (int(digest[:6], 16) % 90000)


def _selections(detection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        name: block
        for name, block in (detection or {}).items()
        if name != "condition" and isinstance(block, dict)
    }


def _field_values(block: dict[str, Any]) -> list[tuple[str, str, list[str]]]:
    out: list[tuple[str, str, list[str]]] = []
    for key, raw in block.items():
        field, _, modifier = str(key).partition("|")
        values = raw if isinstance(raw, list) else [raw]
        cleaned = [str(v) for v in values if str(v).strip()]
        if cleaned:
            out.append((field, modifier.lower(), cleaned))
    return out


def _wazuh_field(sigma_field: str) -> str:
    mapping = {
        "Image": "win.eventdata.image",
        "ParentImage": "win.eventdata.parentImage",
        "CommandLine": "win.eventdata.commandLine",
        "OriginalFileName": "win.eventdata.originalFileName",
        "TargetFilename": "win.eventdata.targetFilename",
        "TargetObject": "win.eventdata.targetObject",
        "DestinationIp": "win.eventdata.destinationIp",
        "DestinationPort": "win.eventdata.destinationPort",
        "User": "win.eventdata.user",
        "exe": "full_log",
        "comm": "full_log",
    }
    return mapping.get(sigma_field, "win.eventdata." + sigma_field[:1].lower() + sigma_field[1:])


def _wazuh_match(modifier: str, value: str) -> str:
    escaped = re.escape(value)
    if modifier == "endswith":
        pattern = f".*{escaped}$"
    elif modifier == "startswith":
        pattern = f"^{escaped}.*"
    elif modifier == "re":
        pattern = value
    else:
        pattern = f".*{escaped}.*"
    return escape(pattern)


def build_wazuh_xml(
    *,
    title: str,
    description: str,
    detection: dict[str, Any],
    techniques: list[Any],
    seed: str,
    level: str = "high",
) -> str:
    wazuh_level = {"informational": 3, "low": 5, "medium": 7, "high": 10, "critical": 12}.get(
        (level or "high").lower(), 10
    )
    rid = _rule_id(seed or title)
    mitre_ids: list[str] = []
    for tech in techniques or []:
        tid = tech.get("id") if isinstance(tech, dict) else getattr(tech, "id", "")
        if tid:
            mitre_ids.append(escape(str(tid)))
    groups = ["cve2detect", "experimental"]
    field_xml: list[str] = []
    for block in _selections(detection).values():
        for field, modifier, values in _field_values(block):
            wazuh_name = _wazuh_field(field)
            joined = "|".join(_wazuh_match(modifier, v) for v in values)
            field_xml.append(
                f'    <field name="{escape(wazuh_name)}" type="pcre2">{joined}</field>'
            )
    if not field_xml:
        field_xml.append('    <match>cve2detect-placeholder</match>')
    mitre = ""
    if mitre_ids:
        inner = "\n".join(f"      <id>{i}</id>" for i in mitre_ids[:8])
        mitre = f"    <mitre>\n{inner}\n    </mitre>\n"
    desc = escape((description or title or "CVE2Detect rule")[:512])
    return (
        f'<group name="{",".join(groups)},">\n'
        f'  <rule id="{rid}" level="{wazuh_level}">\n'
        f"    <info>{escape(title or 'CVE2Detect detection')}</info>\n"
        f"    <description>{desc}</description>\n"
        + "\n".join(field_xml)
        + "\n"
        + mitre
        + "  </rule>\n"
        "</group>\n"
    )


def _lc_op(modifier: str) -> str:
    if modifier == "endswith":
        return "ends with"
    if modifier == "startswith":
        return "starts with"
    if modifier == "re":
        return "matches"
    return "contains"


def _lc_path(field: str) -> str:
    mapping = {
        "Image": "event/FILE_PATH",
        "ParentImage": "event/PARENT/FILE_PATH",
        "CommandLine": "event/COMMAND_LINE",
        "TargetFilename": "event/FILE_PATH",
        "DestinationIp": "event/NETWORK_CONNECTIONS/IP_ADDRESS",
        "User": "event/USER_NAME",
    }
    return mapping.get(field, "event/COMMAND_LINE")


def build_limacharlie_yaml(
    *,
    title: str,
    detection: dict[str, Any],
    seed: str,
) -> str:
    rules: list[dict[str, Any]] = []
    for block in _selections(detection).values():
        for field, modifier, values in _field_values(block):
            path = _lc_path(field)
            op = _lc_op(modifier)
            if len(values) == 1:
                rules.append(
                    {
                        "op": op,
                        "path": path,
                        "value": values[0],
                        "case sensitive": False,
                    }
                )
            else:
                rules.append(
                    {
                        "op": "or",
                        "rules": [
                            {
                                "op": op,
                                "path": path,
                                "value": v,
                                "case sensitive": False,
                            }
                            for v in values
                        ],
                    }
                )
    detect: dict[str, Any] = {
        "event": "NEW_PROCESS",
        "op": "and",
        "rules": rules
        or [{"op": "contains", "path": "event/COMMAND_LINE", "value": "cve2detect"}],
    }
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "cve2detect").lower()).strip("-")[:48]
    doc = {
        "detect": detect,
        "respond": [{"action": "report", "name": f"cve2detect-{slug or seed[:8]}"}],
        "metadata": {
            "author": "CVE2Detect",
            "enabled": False,
            "note": "Imported as a testing rule. Enable only after a staging atomic test.",
        },
    }
    return yaml.dump(doc, sort_keys=False, allow_unicode=True)
