"""Push a generated rule to a SIEM as disabled / testing."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv

ROOT_ENV = Path(__file__).resolve().parent.parent / ".env"


class DeployError(RuntimeError):
    pass


def _env() -> None:
    load_dotenv(ROOT_ENV, override=True)


def _public_https(url: str) -> str:
    url = (url or "").rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DeployError("SIEM URL must be https:// with a hostname.")
    host = parsed.hostname.lower()
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        raise DeployError("Refusing to post to a loopback or .local SIEM URL from this helper.")
    return url


def deploy_rule(target: str, record: dict[str, Any], settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create the rule in a disabled/testing state. Never enables it."""
    _env()
    settings = settings or {}
    target = (target or settings.get("siem_target") or "").lower().strip()
    if target == "wazuh":
        return _deploy_wazuh(record, settings)
    if target == "elastic":
        return _deploy_elastic(record, settings)
    if target == "sentinel":
        return _deploy_sentinel(record, settings)
    if target == "limacharlie":
        return _deploy_limacharlie(record, settings)
    raise DeployError(
        "Unknown SIEM target. Choose wazuh, elastic, sentinel, or limacharlie."
    )


def _deploy_wazuh(record: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    base = _public_https(settings.get("wazuh_url") or os.environ.get("WAZUH_URL", ""))
    user = settings.get("wazuh_user") or os.environ.get("WAZUH_USER", "")
    password = settings.get("wazuh_password") or os.environ.get("WAZUH_PASSWORD", "")
    xml = record.get("wazuh_xml") or ""
    if not xml.strip():
        raise DeployError("No Wazuh XML on this record.")
    if not user or not password:
        raise DeployError("Set Wazuh URL, user, and password in Estate settings or .env.")
    auth = (user, password)
    path = "etc/rules/cve2detect_rules.xml"
    with httpx.Client(timeout=30.0, verify=True) as client:
        token_res = client.post(f"{base}/security/user/authenticate?raw=true", auth=auth)
        if token_res.status_code >= 300:
            raise DeployError(f"Wazuh auth failed: HTTP {token_res.status_code}")
        token = token_res.text.strip()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}
        put = client.put(
            f"{base}/manager/files",
            params={"path": path, "overwrite": "true"},
            headers=headers,
            content=xml.encode("utf-8"),
        )
        if put.status_code >= 300:
            raise DeployError(f"Wazuh upload failed: HTTP {put.status_code} {put.text[:200]}")
    return {
        "ok": True,
        "target": "wazuh",
        "remote_id": path,
        "enabled": False,
        "message": "Wrote cve2detect_rules.xml on the Wazuh manager. Reload rules, leave disabled until the atomic test passes.",
    }


def _deploy_elastic(record: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    base = _public_https(settings.get("elastic_url") or os.environ.get("ELASTIC_KIBANA_URL", ""))
    api_key = settings.get("elastic_api_key") or os.environ.get("ELASTIC_API_KEY", "")
    query = record.get("elastic_dsl") or ""
    if not query.strip():
        raise DeployError("No Elastic query on this record.")
    if not api_key:
        raise DeployError("Set ELASTIC_KIBANA_URL and ELASTIC_API_KEY.")
    body = {
        "name": record.get("title") or "CVE2Detect rule",
        "description": (record.get("summary") or "")[:500],
        "enabled": False,
        "query": query if not query.lstrip().startswith("{") else "*",
        "language": "lucene" if not query.lstrip().startswith("{") else "kuery",
        "type": "query",
        "from": "now-6m",
        "interval": "5m",
        "risk_score": 73,
        "severity": "high",
        "tags": ["cve2detect", "testing"],
        "author": ["CVE2Detect"],
        "false_positives": ["Unverified AI-assisted import — keep disabled until staging test"],
    }
    if query.lstrip().startswith("{"):
        body["query"] = record.get("splunk_spl") or "*"
        body["note"] = "Elastic DSL stored on the record; imported as a disabled query rule."
    headers = {
        "Authorization": f"ApiKey {api_key}",
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=30.0) as client:
        res = client.post(f"{base}/api/detection_engine/rules", headers=headers, json=body)
        if res.status_code >= 300:
            raise DeployError(f"Elastic import failed: HTTP {res.status_code} {res.text[:240]}")
        payload = res.json() if res.content else {}
    return {
        "ok": True,
        "target": "elastic",
        "remote_id": payload.get("id") or payload.get("rule_id") or "",
        "enabled": False,
        "message": "Created a Kibana detection rule with enabled=false.",
    }


def _deploy_sentinel(record: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    tenant = settings.get("sentinel_tenant") or os.environ.get("SENTINEL_TENANT_ID", "")
    client_id = settings.get("sentinel_client_id") or os.environ.get("SENTINEL_CLIENT_ID", "")
    secret = settings.get("sentinel_client_secret") or os.environ.get("SENTINEL_CLIENT_SECRET", "")
    sub = settings.get("sentinel_subscription") or os.environ.get("SENTINEL_SUBSCRIPTION_ID", "")
    rg = settings.get("sentinel_rg") or os.environ.get("SENTINEL_RESOURCE_GROUP", "")
    workspace = settings.get("sentinel_workspace") or os.environ.get("SENTINEL_WORKSPACE_NAME", "")
    kql = record.get("sentinel_kql") or ""
    if not kql.strip():
        raise DeployError("No Sentinel KQL on this record.")
    if not all([tenant, client_id, secret, sub, rg, workspace]):
        raise DeployError(
            "Set Sentinel tenant, app registration, subscription, resource group, and workspace."
        )
    with httpx.Client(timeout=30.0) as client:
        token_res = client.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "client_secret": secret,
                "grant_type": "client_credentials",
                "scope": "https://management.azure.com/.default",
            },
        )
        if token_res.status_code >= 300:
            raise DeployError(f"Sentinel token failed: HTTP {token_res.status_code}")
        token = token_res.json().get("access_token")
        rule_name = (record.get("id") or "cve2detect")[:64]
        url = (
            f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_name}"
            "?api-version=2023-02-01"
        )
        body = {
            "kind": "Scheduled",
            "properties": {
                "displayName": record.get("title") or "CVE2Detect",
                "enabled": False,
                "severity": "High",
                "query": kql,
                "queryFrequency": "PT1H",
                "queryPeriod": "PT1H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "PT1H",
                "suppressionEnabled": False,
            },
        }
        put = client.put(url, headers={"Authorization": f"Bearer {token}"}, json=body)
        if put.status_code >= 300:
            raise DeployError(f"Sentinel PUT failed: HTTP {put.status_code} {put.text[:240]}")
    return {
        "ok": True,
        "target": "sentinel",
        "remote_id": rule_name,
        "enabled": False,
        "message": "Created a Sentinel scheduled rule with enabled=false.",
    }


def _deploy_limacharlie(record: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    oid = settings.get("lc_oid") or os.environ.get("LIMACHARLIE_OID", "")
    key = settings.get("lc_key") or os.environ.get("LIMACHARLIE_API_KEY", "")
    yaml_text = record.get("limacharlie_yaml") or ""
    if not yaml_text.strip():
        raise DeployError("No LimaCharlie D&R YAML on this record.")
    if not oid or not key:
        raise DeployError("Set LIMACHARLIE_OID and LIMACHARLIE_API_KEY.")
    import yaml

    data = yaml.safe_load(yaml_text)
    detect = data.get("detect") if isinstance(data, dict) else None
    respond = data.get("respond") if isinstance(data, dict) else None
    if not detect:
        raise DeployError("LimaCharlie YAML missing detect block.")
    name = f"cve2detect-{(record.get('id') or 'rule')[:20]}"
    token = base64.b64encode(f"{oid}:{key}".encode()).decode()
    with httpx.Client(timeout=30.0) as client:
        res = client.post(
            f"https://api.limacharlie.io/v1/orgs/{oid}/hive/dr-general/{name}",
            headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
            json={"data": {"detect": detect, "respond": respond or []}, "enabled": False},
        )
        if res.status_code >= 300:
            raise DeployError(f"LimaCharlie hive failed: HTTP {res.status_code} {res.text[:240]}")
    return {
        "ok": True,
        "target": "limacharlie",
        "remote_id": name,
        "enabled": False,
        "message": "Wrote a disabled D&R rule to the LimaCharlie hive.",
    }
