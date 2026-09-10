"""Environment profile catalog and affected-software matching."""

from __future__ import annotations

import re
from typing import Any

ASSET_CATALOG: list[dict[str, Any]] = [
    {
        "id": "windows-server-2022",
        "label": "Windows Server 2022",
        "aliases": ["windows server 2022", "windows server", "win2022", "server 2022"],
    },
    {
        "id": "windows-server-2019",
        "label": "Windows Server 2019",
        "aliases": ["windows server 2019", "win2019", "server 2019"],
    },
    {
        "id": "windows-10",
        "label": "Windows 10",
        "aliases": ["windows 10", "win10"],
    },
    {
        "id": "windows-11",
        "label": "Windows 11",
        "aliases": ["windows 11", "win11"],
    },
    {
        "id": "iis",
        "label": "Microsoft IIS",
        "aliases": [
            "iis",
            "internet information services",
            "w3wp",
            "nativelib",
        ],
    },
    {
        "id": "m365",
        "label": "Microsoft 365 / Entra",
        "aliases": [
            "microsoft 365",
            "office 365",
            "m365",
            "entra",
            "azure ad",
            "azure active directory",
            "exchange online",
            "sharepoint online",
        ],
    },
    {
        "id": "exchange",
        "label": "Exchange Server",
        "aliases": ["exchange server", "microsoft exchange", "owa"],
    },
    {
        "id": "sharepoint",
        "label": "SharePoint Server",
        "aliases": ["sharepoint"],
    },
    {
        "id": "sql-server",
        "label": "Microsoft SQL Server",
        "aliases": ["sql server", "mssql"],
    },
    {
        "id": "nginx",
        "label": "Nginx",
        "aliases": ["nginx"],
    },
    {
        "id": "apache",
        "label": "Apache httpd",
        "aliases": ["apache", "httpd"],
    },
    {
        "id": "fortinet-vpn",
        "label": "Fortinet VPN / FortiGate",
        "aliases": ["fortinet", "fortigate", "forticlient", "ssl-vpn"],
    },
    {
        "id": "palo-alto",
        "label": "Palo Alto Networks",
        "aliases": ["palo alto", "pan-os", "globalprotect"],
    },
    {
        "id": "cisco-asa",
        "label": "Cisco ASA / IOS",
        "aliases": ["cisco asa", "cisco ios", "cisco", "anyconnect"],
    },
    {
        "id": "ivanti",
        "label": "Ivanti / Pulse Connect Secure",
        "aliases": [
            "ivanti",
            "pulse connect",
            "pulse secure",
            "connect secure",
            "policy secure",
        ],
    },
    {
        "id": "citrix",
        "label": "Citrix / NetScaler",
        "aliases": ["citrix", "netscaler", "adc"],
    },
    {
        "id": "aws",
        "label": "Amazon Web Services",
        "aliases": ["amazon web services", "aws", "ec2", "s3", "iam"],
    },
    {
        "id": "azure",
        "label": "Microsoft Azure",
        "aliases": ["microsoft azure", "azure"],
    },
    {
        "id": "gcp",
        "label": "Google Cloud",
        "aliases": ["google cloud", "gcp", "gce"],
    },
    {
        "id": "linux-ubuntu",
        "label": "Ubuntu Linux",
        "aliases": ["ubuntu", "debian"],
    },
    {
        "id": "rhel",
        "label": "RHEL / CentOS",
        "aliases": ["red hat", "rhel", "centos", "rocky"],
    },
    {
        "id": "macos",
        "label": "macOS",
        "aliases": ["macos", "os x", "darwin"],
    },
    {
        "id": "vmware",
        "label": "VMware",
        "aliases": ["vmware", "esxi", "vcenter", "vsphere"],
    },
    {
        "id": "sap",
        "label": "SAP",
        "aliases": ["sap ", "netweaver"],
    },
]


def catalog_by_id() -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in ASSET_CATALOG}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def _haystack(affected: list[Any], extra: str = "") -> str:
    parts = [extra]
    for item in affected or []:
        if isinstance(item, dict):
            parts.extend([item.get("vendor") or "", item.get("product") or "", item.get("versions") or ""])
        else:
            parts.extend(
                [
                    getattr(item, "vendor", ""),
                    getattr(item, "product", ""),
                    getattr(item, "versions", ""),
                ]
            )
    return _norm(" ".join(str(p) for p in parts if p))


def match_stack(
    affected: list[Any],
    asset_ids: list[str],
    extra_text: str = "",
) -> dict[str, Any]:
    """Return whether extracted products overlap the configured estate."""
    selected = [i for i in asset_ids if i in catalog_by_id()]
    if not selected:
        return {
            "configured": False,
            "matched": False,
            "hits": [],
            "reason": "No environment profile configured — every advisory is shown.",
        }
    blob = _haystack(affected, extra_text)
    hits: list[dict[str, str]] = []
    index = catalog_by_id()
    for asset_id in selected:
        item = index[asset_id]
        for alias in item["aliases"]:
            if _norm(alias) and _norm(alias) in blob:
                hits.append({"id": asset_id, "label": item["label"], "alias": alias})
                break
    if hits:
        labels = ", ".join(sorted({h["label"] for h in hits}))
        reason = f"Matches your estate: {labels}."
    else:
        reason = "Does not match the technologies in your environment profile."
    return {
        "configured": True,
        "matched": bool(hits),
        "hits": hits,
        "reason": reason,
    }


def parse_cvss(value: str) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if not match:
        return None
    try:
        score = float(match.group(1))
    except ValueError:
        return None
    if 0.0 <= score <= 10.0:
        return score
    return None
