from __future__ import annotations

from fastapi.testclient import TestClient

from app import app


def test_health_and_pages():
    client = TestClient(app)
    health = client.get("/api/health")
    assert health.status_code == 200
    body = health.json()
    assert body["ok"] is True
    assert body["mode"] == "public"
    assert body["persist_jobs"] is False
    assert "keys" in body
    assert "fetch" in body["keys"]
    assert "llm" in body["keys"]
    assert "providers" in body
    assert "fetch" in body["providers"]
    assert "llm" in body["providers"]
    home = client.get("/")
    assert home.status_code == 200
    assert b"CVE2Detect" in home.content
    assert b"does not connect to your SIEM" in home.content
    css = client.get("/static/styles.css")
    assert css.status_code == 200
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert b"/api/records" not in js.content
    assert b"cve2detect.session.records" in js.content


def test_sample_pipeline_json():
    client = TestClient(app)
    res = client.post("/api/pipeline?stream=false", json={"use_sample": True})
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["event"] == "complete"
    record = payload["record"]
    assert record["cve"] == "CVE-2026-44011"
    assert record["sigma_valid"] == 1
    assert "w3wp" in record["sigma_yaml"]
    assert "title:" in record["sigma_yaml"]
    assert "status: experimental" in record["sigma_yaml"]
    assert record.get("wazuh_xml")
    assert record.get("limacharlie_yaml")
    assert record.get("atomic_tests")
    assert record.get("retrohunt")
    listed = client.get("/api/records?q=T1059")
    assert listed.status_code == 404


def test_public_surface_has_no_siem_or_shared_archive():
    client = TestClient(app)
    assert client.get("/api/records").status_code == 404
    assert client.get("/api/records/abc").status_code == 404
    assert client.get("/api/estate").status_code == 404
    assert client.put("/api/estate", json={"assets": ["iis"]}).status_code == 404
    assert client.post("/api/deploy", json={"target": "wazuh"}).status_code == 404
    assert client.post("/api/webhooks", json={}).status_code == 404
    cat = client.get("/api/estate/catalog")
    assert cat.status_code == 200
    assets = cat.json()["assets"]
    assert any(a["id"] == "iis" for a in assets)
    feed = client.get("/api/feed")
    assert feed.status_code == 200
    for item in feed.json()["items"]:
        assert "processed" not in item
