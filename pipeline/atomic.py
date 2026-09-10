"""Safe Atomic Red Team-style snippets for a staging host.

Live C2 IPs/URLs/hashes from the advisory are rewritten to example.com and
TEST-NET-3 so the text is not a working implant. Run only in isolation.
"""

from __future__ import annotations

import re
from typing import Any

TEST_HOST = "example.com"
TEST_IP = "203.0.113.10"
TEST_PATH_WIN = r"C:\Temp\cve2detect-atomic.txt"
TEST_PATH_NIX = "/tmp/cve2detect-atomic.txt"
TEST_URL = f"https://{TEST_HOST}/cve2detect-atomic.txt"

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL = re.compile(r"https?://[^\s'\"<>]+", re.I)
_WIN_PATH = re.compile(r"[A-Za-z]:\\[^\s'\"<>]+")
_HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _sanitize(command: str, windows: bool) -> str:
    """Replace IPs, URLs, hashes, and Windows paths with documentation stand-ins."""
    text = command
    text = _URL.sub(TEST_URL, text)
    text = _IP.sub(TEST_IP, text)
    text = _HASH.sub("0" * 64, text)
    replacement = TEST_PATH_WIN if windows else TEST_PATH_NIX
    text = _WIN_PATH.sub(lambda _m: replacement, text)
    return text


def _windows(intel_os: str, logsource: str) -> bool:
    blob = f"{intel_os} {logsource}".lower()
    return "linux" not in blob and "macos" not in blob


def generate_atomic_tests(
    *,
    techniques: list[Any],
    command_lines: list[str],
    process_anomalies: list[Any],
    logsource_product: str = "",
) -> list[dict[str, str]]:
    """Build Invoke-AtomicTest plus sanitized command replay (max 6 items)."""
    windows = _windows(logsource_product, logsource_product)
    tests: list[dict[str, str]] = []

    for tech in techniques or []:
        tid = tech.get("id") if isinstance(tech, dict) else getattr(tech, "id", "")
        name = tech.get("name") if isinstance(tech, dict) else getattr(tech, "name", "")
        if not tid:
            continue
        if windows:
            cmd = f'Invoke-AtomicTest {tid} -TestNumbers 1 -ShowDetailsBrief'
            note = (
                "Requires Atomic Red Team on a staging Windows host. "
                "Review -ShowDetailsBrief before running the live test number."
            )
        else:
            cmd = f"invoke-atomicredteam {tid} --test-numbers 1"
            note = "Requires Atomic Red Team on a staging Linux host. Inspect the test before execution."
        tests.append(
            {
                "title": f"Atomic Red Team {tid}",
                "platform": "windows" if windows else "linux",
                "command": cmd,
                "note": note + (f" ({name})" if name else ""),
            }
        )

    seen: set[str] = set()
    raw_commands = list(command_lines or [])
    for anomaly in process_anomalies or []:
        if isinstance(anomaly, dict):
            raw_commands.append(anomaly.get("command_line") or "")
        else:
            raw_commands.append(getattr(anomaly, "command_line", "") or "")

    for raw in raw_commands:
        raw = (raw or "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        safe = _sanitize(raw, windows)
        if windows:
            command = (
                f'New-Item -ItemType Directory -Force -Path "C:\\Temp" | Out-Null; '
                f"Write-Output 'CVE2Detect staging probe' | "
                f"Set-Content -Path '{TEST_PATH_WIN}'; {safe}"
            )
        else:
            command = f"mkdir -p /tmp && echo 'CVE2Detect staging probe' > {TEST_PATH_NIX} && {safe}"
        tests.append(
            {
                "title": "Sanitized command-line replay",
                "platform": "windows" if windows else "linux",
                "command": command,
                "note": (
                    "C2 IPs, URLs, and hashes replaced with example.com / TEST-NET-3. "
                    "Run only on an isolated staging endpoint with the new SIEM rule in test mode."
                ),
            }
        )
        if len(tests) >= 6:
            break

    if not tests:
        if windows:
            tests.append(
                {
                    "title": "Benign process-create canary",
                    "platform": "windows",
                    "command": r'cmd.exe /c echo CVE2Detect-canary > C:\Temp\cve2detect-atomic.txt',
                    "note": "Generates a process-create event without network activity. Confirm the rule does not fire on this canary.",
                }
            )
        else:
            tests.append(
                {
                    "title": "Benign process-create canary",
                    "platform": "linux",
                    "command": "echo CVE2Detect-canary > /tmp/cve2detect-atomic.txt",
                    "note": "Generates a process-create event without network activity.",
                }
            )
    return tests
