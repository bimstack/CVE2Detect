"""Historical retro-hunt wrappers (30 / 90 day lookback)."""

from __future__ import annotations

import json
from typing import Any


def _elastic_with_range(query: str, days: int) -> str:
    text = (query or "").strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parsed.setdefault("query", {})
            original = parsed["query"]
            parsed["query"] = {
                "bool": {
                    "must": [original],
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{days}d/d",
                                    "lte": "now",
                                }
                            }
                        }
                    ],
                }
            }
            return json.dumps(parsed, indent=2)
    except json.JSONDecodeError:
        pass
    return f"{text} AND @timestamp:[now-{days}d TO now]"


def build_retro_hunts(
    *,
    splunk_spl: str = "",
    elastic_dsl: str = "",
    sentinel_kql: str = "",
    windows: int = 90,
) -> dict[str, str]:
    days = 90 if windows not in (30, 60, 90) else windows
    hunts: dict[str, str] = {}
    if splunk_spl.strip():
        hunts["splunk"] = (
            f"earliest=-{days}d latest=now\n"
            f"{splunk_spl.strip()}\n"
            "| stats count by host, user, ParentImage, Image, CommandLine"
        )
    if elastic_dsl.strip():
        hunts["elastic"] = _elastic_with_range(elastic_dsl, days)
    if sentinel_kql.strip():
        kql = sentinel_kql.strip()
        if "TimeGenerated" in kql:
            hunts["sentinel"] = kql
        else:
            hunts["sentinel"] = (
                f"{kql}\n| where TimeGenerated > ago({days}d)\n"
                "| summarize hits=count() by bin(TimeGenerated, 1d), Computer, InitiatingProcessFileName, FileName"
            )
    hunts["note"] = (
        f"Look back {days} days for the same command lines, parent-child pairs, "
        "and destinations extracted from the advisory — before the public write-up."
    )
    return hunts
