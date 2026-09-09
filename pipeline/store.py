"""SQLite persistence.

Public v1 uses this module for the shared TinyFish discovery feed only.
Job records, estate profiles, and SIEM credentials are not written by the
HTTP layer; `save_record` / `save_profile` remain for tests and local forks.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "cve2detect.db"
_LEGACY_DB = DATA_DIR / "autozday.db"

_local = threading.local()


def db_path() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_PATH.exists() and _LEGACY_DB.exists():
        _LEGACY_DB.rename(DB_PATH)
        for suffix in ("-wal", "-shm"):
            old = Path(str(_LEGACY_DB) + suffix)
            if old.exists():
                old.rename(Path(str(DB_PATH) + suffix))
    return DB_PATH


def set_db_path(path: Path) -> None:
    global DB_PATH
    DB_PATH = Path(path)
    conn = getattr(_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
        _local.conn = None
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(db_path(), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _local.conn = conn
    return conn


def init_db() -> None:
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS feed (
            url TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            snippet TEXT NOT NULL DEFAULT '',
            site_name TEXT NOT NULL DEFAULT '',
            query TEXT NOT NULL DEFAULT '',
            discovered_at TEXT NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS records (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            site_name TEXT NOT NULL DEFAULT '',
            fetch_method TEXT NOT NULL,
            markdown TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            cve TEXT NOT NULL DEFAULT '',
            cvss TEXT NOT NULL DEFAULT '',
            vulnerability_type TEXT NOT NULL DEFAULT '',
            threat_actor TEXT NOT NULL DEFAULT '',
            campaign TEXT NOT NULL DEFAULT '',
            affected_json TEXT NOT NULL DEFAULT '[]',
            techniques_json TEXT NOT NULL DEFAULT '[]',
            telemetry_json TEXT NOT NULL DEFAULT '[]',
            process_anomalies_json TEXT NOT NULL DEFAULT '[]',
            command_lines_json TEXT NOT NULL DEFAULT '[]',
            paths_json TEXT NOT NULL DEFAULT '[]',
            indicators_json TEXT NOT NULL DEFAULT '[]',
            confidence TEXT NOT NULL DEFAULT '',
            is_actionable INTEGER NOT NULL DEFAULT 0,
            caveats TEXT NOT NULL DEFAULT '',
            sigma_yaml TEXT NOT NULL DEFAULT '',
            sigma_valid INTEGER NOT NULL DEFAULT 0,
            validation_errors_json TEXT NOT NULL DEFAULT '[]',
            splunk_spl TEXT NOT NULL DEFAULT '',
            elastic_dsl TEXT NOT NULL DEFAULT '',
            sentinel_kql TEXT NOT NULL DEFAULT '',
            logsource_product TEXT NOT NULL DEFAULT '',
            logsource_category TEXT NOT NULL DEFAULT '',
            wazuh_xml TEXT NOT NULL DEFAULT '',
            limacharlie_yaml TEXT NOT NULL DEFAULT '',
            atomic_tests_json TEXT NOT NULL DEFAULT '[]',
            retrohunt_json TEXT NOT NULL DEFAULT '{}',
            stack_match INTEGER NOT NULL DEFAULT 0,
            stack_configured INTEGER NOT NULL DEFAULT 0,
            stack_hits_json TEXT NOT NULL DEFAULT '[]',
            stack_reason TEXT NOT NULL DEFAULT '',
            cvss_numeric REAL,
            webhook_sent INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
            id UNINDEXED,
            title,
            cve,
            threat_actor,
            vulnerability_type,
            techniques,
            logsource,
            yaml,
            summary
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    extra = {
        "wazuh_xml": "TEXT NOT NULL DEFAULT ''",
        "limacharlie_yaml": "TEXT NOT NULL DEFAULT ''",
        "atomic_tests_json": "TEXT NOT NULL DEFAULT '[]'",
        "retrohunt_json": "TEXT NOT NULL DEFAULT '{}'",
        "stack_match": "INTEGER NOT NULL DEFAULT 0",
        "stack_configured": "INTEGER NOT NULL DEFAULT 0",
        "stack_hits_json": "TEXT NOT NULL DEFAULT '[]'",
        "stack_reason": "TEXT NOT NULL DEFAULT ''",
        "cvss_numeric": "REAL",
        "webhook_sent": "INTEGER NOT NULL DEFAULT 0",
    }
    existing = {row[1] for row in conn.execute("PRAGMA table_info(records)").fetchall()}
    for name, decl in extra.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE records ADD COLUMN {name} {decl}")
    conn.commit()


def upsert_feed(hits: list[Any]) -> int:
    conn = connect()
    inserted = 0
    for hit in hits:
        cur = conn.execute(
            """
            INSERT INTO feed (url, title, snippet, site_name, query, discovered_at, processed)
            VALUES (?, ?, ?, ?, ?, datetime('now'), 0)
            ON CONFLICT(url) DO UPDATE SET
                title=excluded.title,
                snippet=excluded.snippet,
                site_name=excluded.site_name,
                query=excluded.query
            """,
            (hit.url, hit.title, hit.snippet, hit.site_name, hit.query),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


def list_feed(limit: int = 80) -> list[dict[str, Any]]:
    conn = connect()
    rows = conn.execute(
        "SELECT * FROM feed ORDER BY discovered_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_feed_processed(url: str) -> None:
    conn = connect()
    conn.execute("UPDATE feed SET processed = 1 WHERE url = ?", (url,))
    conn.commit()


def _fts_blob(record: dict[str, Any]) -> tuple[str, str]:
    techniques = []
    for item in json.loads(record.get("techniques_json") or "[]"):
        techniques.append(item.get("id", ""))
        techniques.append(item.get("name", ""))
        techniques.append(item.get("tactic", ""))
    tech = " ".join(t for t in techniques if t)
    logsource = " ".join(
        [
            record.get("logsource_product") or "",
            record.get("logsource_category") or "",
        ]
    )
    return tech, logsource


def save_record(payload: dict[str, Any]) -> dict[str, Any]:
    conn = connect()
    record_id = payload.get("id") or uuid.uuid4().hex[:12]
    payload["id"] = record_id
    existing = conn.execute(
        "SELECT id FROM records WHERE url = ?", (payload["url"],)
    ).fetchone()
    if existing:
        record_id = existing["id"]
        payload["id"] = record_id
        conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        conn.execute("DELETE FROM records_fts WHERE id = ?", (record_id,))

    columns = [
        "id",
        "url",
        "title",
        "site_name",
        "fetch_method",
        "markdown",
        "summary",
        "cve",
        "cvss",
        "vulnerability_type",
        "threat_actor",
        "campaign",
        "affected_json",
        "techniques_json",
        "telemetry_json",
        "process_anomalies_json",
        "command_lines_json",
        "paths_json",
        "indicators_json",
        "confidence",
        "is_actionable",
        "caveats",
        "sigma_yaml",
        "sigma_valid",
        "validation_errors_json",
        "splunk_spl",
        "elastic_dsl",
        "sentinel_kql",
        "logsource_product",
        "logsource_category",
        "wazuh_xml",
        "limacharlie_yaml",
        "atomic_tests_json",
        "retrohunt_json",
        "stack_match",
        "stack_configured",
        "stack_hits_json",
        "stack_reason",
        "cvss_numeric",
        "webhook_sent",
        "created_at",
    ]

    def _value(col: str) -> Any:
        if col in payload and payload[col] is not None:
            return payload[col]
        if col in {
            "stack_match",
            "stack_configured",
            "webhook_sent",
            "is_actionable",
            "sigma_valid",
        }:
            return 0
        if col == "cvss_numeric":
            return None
        if col == "retrohunt_json":
            return "{}"
        if col.endswith("_json"):
            return "[]"
        return payload.get(col) or ""

    values = [_value(c) for c in columns]
    placeholders = ", ".join("?" for _ in columns)
    conn.execute(
        f"INSERT INTO records ({', '.join(columns)}) VALUES ({placeholders})",
        values,
    )
    tech, logsource = _fts_blob(payload)
    conn.execute(
        """
        INSERT INTO records_fts (id, title, cve, threat_actor, vulnerability_type, techniques, logsource, yaml, summary)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record_id,
            payload.get("title") or "",
            payload.get("cve") or "",
            payload.get("threat_actor") or "",
            payload.get("vulnerability_type") or "",
            tech,
            logsource,
            payload.get("sigma_yaml") or "",
            payload.get("summary") or "",
        ),
    )
    conn.commit()
    mark_feed_processed(payload["url"])
    return get_record(record_id) or payload


def get_record(record_id: str) -> dict[str, Any] | None:
    conn = connect()
    row = conn.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()
    return _hydrate(row) if row else None


def get_record_by_url(url: str) -> dict[str, Any] | None:
    conn = connect()
    row = conn.execute("SELECT * FROM records WHERE url = ?", (url,)).fetchone()
    return _hydrate(row) if row else None


def list_records(limit: int = 100) -> list[dict[str, Any]]:
    conn = connect()
    rows = conn.execute(
        """
        SELECT id, url, title, site_name, cve, cvss, threat_actor, vulnerability_type,
               confidence, sigma_valid, logsource_product, logsource_category,
               techniques_json, stack_match, stack_configured, stack_reason, created_at
        FROM records ORDER BY created_at DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [_hydrate(r, compact=True) for r in rows]


def search_records(query: str, limit: int = 50) -> list[dict[str, Any]]:
    q = (query or "").strip()
    if not q:
        return list_records(limit)
    conn = connect()
    like = f"%{q}%"
    try:
        rows = conn.execute(
            """
            SELECT r.id, r.url, r.title, r.site_name, r.cve, r.cvss, r.threat_actor,
                   r.vulnerability_type, r.confidence, r.sigma_valid, r.logsource_product,
                   r.logsource_category, r.techniques_json, r.stack_match,
                   r.stack_configured, r.stack_reason, r.created_at
            FROM records_fts f
            JOIN records r ON r.id = f.id
            WHERE records_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (q, limit),
        ).fetchall()
        if rows:
            return [_hydrate(r, compact=True) for r in rows]
    except sqlite3.OperationalError:
        pass
    rows = conn.execute(
        """
        SELECT id, url, title, site_name, cve, cvss, threat_actor, vulnerability_type,
               confidence, sigma_valid, logsource_product, logsource_category,
               techniques_json, stack_match, stack_configured, stack_reason, created_at
        FROM records
        WHERE title LIKE ? OR cve LIKE ? OR threat_actor LIKE ?
           OR vulnerability_type LIKE ? OR logsource_product LIKE ?
           OR logsource_category LIKE ? OR techniques_json LIKE ?
           OR sigma_yaml LIKE ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (like, like, like, like, like, like, like, like, limit),
    ).fetchall()
    return [_hydrate(r, compact=True) for r in rows]


def stats() -> dict[str, int]:
    conn = connect()
    feed = conn.execute("SELECT COUNT(*) AS n FROM feed").fetchone()["n"]
    records = conn.execute("SELECT COUNT(*) AS n FROM records").fetchone()["n"]
    valid = conn.execute(
        "SELECT COUNT(*) AS n FROM records WHERE sigma_valid = 1"
    ).fetchone()["n"]
    return {"feed": feed, "records": records, "validated_rules": valid}


def _hydrate(row: sqlite3.Row, compact: bool = False) -> dict[str, Any]:
    data = dict(row)
    json_fields = [
        "affected_json",
        "techniques_json",
        "telemetry_json",
        "process_anomalies_json",
        "command_lines_json",
        "paths_json",
        "indicators_json",
        "validation_errors_json",
        "atomic_tests_json",
        "retrohunt_json",
        "stack_hits_json",
    ]
    out: dict[str, Any] = {}
    for key, value in data.items():
        if key.endswith("_json"):
            name = key[: -len("_json")]
            empty: Any = {} if name == "retrohunt" else []
            try:
                out[name] = json.loads(value) if value else empty
            except json.JSONDecodeError:
                out[name] = empty
        else:
            out[key] = value
    if compact:
        out.pop("markdown", None)
        out.pop("sigma_yaml", None)
        out.pop("splunk_spl", None)
        out.pop("elastic_dsl", None)
        out.pop("sentinel_kql", None)
        out.pop("wazuh_xml", None)
        out.pop("limacharlie_yaml", None)
        out.pop("atomic_tests", None)
        out.pop("retrohunt", None)
    return out


DEFAULT_PROFILE = {
    "name": "Primary estate",
    "assets": [],
    "notify_min_cvss": 8.0,
    "notify_only_matches": True,
    "hunt_days": 90,
    "webhooks": {"slack": "", "teams": "", "discord": ""},
    "siem": {
        "target": "",
        "wazuh_url": "",
        "wazuh_user": "",
        "wazuh_password": "",
        "elastic_url": "",
        "elastic_api_key": "",
        "sentinel_tenant": "",
        "sentinel_client_id": "",
        "sentinel_client_secret": "",
        "sentinel_subscription": "",
        "sentinel_rg": "",
        "sentinel_workspace": "",
        "lc_oid": "",
        "lc_key": "",
    },
}


def get_profile() -> dict[str, Any]:
    conn = connect()
    row = conn.execute("SELECT value FROM settings WHERE key = 'profile'").fetchone()
    if not row:
        return json.loads(json.dumps(DEFAULT_PROFILE))
    try:
        data = json.loads(row["value"])
    except json.JSONDecodeError:
        return json.loads(json.dumps(DEFAULT_PROFILE))
    merged = json.loads(json.dumps(DEFAULT_PROFILE))
    merged.update({k: v for k, v in data.items() if k != "siem" and k != "webhooks"})
    merged["webhooks"].update(data.get("webhooks") or {})
    merged["siem"].update(data.get("siem") or {})
    if isinstance(data.get("assets"), list):
        merged["assets"] = data["assets"]
    return merged


def save_profile(profile: dict[str, Any]) -> dict[str, Any]:
    current = get_profile()
    if "assets" in profile:
        current["assets"] = [str(a) for a in profile["assets"]]
    if "name" in profile:
        current["name"] = str(profile["name"])[:80]
    if "notify_min_cvss" in profile:
        current["notify_min_cvss"] = float(profile["notify_min_cvss"])
    if "notify_only_matches" in profile:
        current["notify_only_matches"] = bool(profile["notify_only_matches"])
    if "hunt_days" in profile:
        days = int(profile["hunt_days"])
        current["hunt_days"] = days if days in (30, 60, 90) else 90
    if "webhooks" in profile and isinstance(profile["webhooks"], dict):
        current["webhooks"].update({k: str(v).strip() for k, v in profile["webhooks"].items()})
    if "siem" in profile and isinstance(profile["siem"], dict):
        current["siem"].update({k: str(v).strip() if v is not None else "" for k, v in profile["siem"].items()})
    conn = connect()
    conn.execute(
        "INSERT INTO settings(key, value) VALUES('profile', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (json.dumps(current),),
    )
    conn.commit()
    return get_profile()


def mark_webhook_sent(record_id: str) -> None:
    conn = connect()
    conn.execute("UPDATE records SET webhook_sent = 1 WHERE id = ?", (record_id,))
    conn.commit()
