# CVE2Detect User Guide

A detection engineering tool for SOC analysts and detection teams. You do not need to write Sigma by hand, but you should know CVE, ATT&CK, and how your SIEM searches logs.

CVE2Detect is an open-source project designed around a **generate-and-copy** workflow. You provide an advisory (via URL, pasted Markdown, or discovery search), extract structured threat intel, and generate portable detection rules ready to copy directly into your security tools. The application operates statelessly for runs: it does not require SIEM write credentials, connect directly to production SIEMs, or persist pipeline runs to a server-side database.

## What It Does

CVE2Detect turns a public vulnerability write-up into:

- Structured intel (CVE, CVSS, actor, ATT&CK, host telemetry, IoCs)
- A generic **Sigma** rule (`status: experimental`)
- Vendor queries (Splunk SPL, Elastic Query DSL, Sentinel KQL, Wazuh XML, LimaCharlie D&R)
- A **retro-hunt** query (30 / 60 / 90 days)
- An **atomic test** for a staging host (C2 replaced with `example.com` / TEST-NET-3)

The tool is a detection assistant: it does not automatically deploy rules or replace manual rule review. Always hunt and tune false positives first.

## Installation & Setup

1. Open a terminal (PowerShell, bash, or zsh) in the `CVE2Detect` project directory.
2. Set up a virtual environment and install dependencies:

   **Windows (PowerShell):**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   copy .env.example .env
   ```

   **macOS / Linux:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. Configure your keys in `.env` (copied from `.env.example`):
   - **Fetch** — `CVE2DETECT_FETCH_PROVIDER=http` (no key required for plain HTTP) or configure a search/render API via `FETCH_API_KEY`.
   - **LLM** — `LLM_API_KEY`, `LLM_MODEL`, and optionally `LLM_API_BASE` for any OpenAI-compatible endpoint (or Gemini).
4. Run the application:
   ```bash
   python app.py
   ```
5. Open [http://127.0.0.1:8787](http://127.0.0.1:8787) in your browser.

Header indicators display **Fetch** and **LLM** status. An inactive pill indicates that the corresponding provider is unconfigured in `.env`.

The application binds to localhost (`127.0.0.1`) by default. To expose it on a local network interface or behind a reverse proxy, set `CVE2DETECT_HOST` in `.env`.

## Application Views

| View | Purpose |
|---|---|
| **Pipeline** | Ingest an advisory and generate structured threat intel + detections |
| **Archive** | View runs from the current browser session (`sessionStorage`) |
| **Environment** | Define monitored assets and default retro-hunt windows (`localStorage`) |

### Environment (Recommended First Step)

Select the technologies you monitor (Windows Server, IIS, M365, Fortinet, Ivanti, AWS, etc.) and save your profile.

- The profile is stored locally in your browser's `localStorage`.
- Asset IDs are sent to the server only when executing **Run pipeline** to perform stack matching.
- Subsequent runs tag the intel pane with:
  - **stack match** — affected product is in your environment profile.
  - **out of scope** — affected product is not in your profile.
  - **no profile** — no assets have been selected.
- The Archive can be filtered by **Stack matches only**.

Because CVE2Detect uses a generate-and-copy model, there are no SIEM credentials or webhook configurations required on this screen.

### Pipeline

1. Ingest an advisory using one of four methods:
   - **Scan 24h** — populate the discovery feed and select an article (requires a search-capable fetch provider).
   - **Advisory URL** — paste a direct link to an advisory or write-up.
   - **Advisory Markdown** — paste raw Markdown directly (skips external fetch).
   - **Load sample** — load an offline IIS RCE fixture without calling external APIs.
2. Click **Run pipeline** — executes through four stages: Ingest → Extract → Validate → Output.

**Left Pane — Threat Intelligence**

Displays extracted CVE, CVSS, vulnerability type, threat actor, campaign, affected software, ATT&CK mappings, host telemetry (Sysmon / Windows Event ID 4688), process tree anomalies, IoCs, and analyst notes.

**Right Pane — Detection Output**

| Tab | Contents |
|---|---|
| Sigma | Portable YAML rule (`status: experimental`) |
| Splunk / Elastic / Sentinel | Transpiled vendor queries |
| Wazuh / LimaCharlie | Open-source detection formats (LimaCharlie defaults to `enabled: false`) |
| Retro-hunt | Query tailored for 30 / 60 / 90 day look-backs |
| Atomic test | Staging validation command with C2 rewritten to `example.com` |

- **validated** indicates the YAML successfully parsed and validated as a Sigma rule. It is a syntactically verified rule draft, not a pre-tuned production alert. Always hunt and test against your telemetry before enabling.
- **Copy** copies the active tab contents to your clipboard.
- **Download .yml** downloads the generated Sigma rule file.

*Note on Rate Limits:* The built-in in-process rate limiter (default: 8 pipeline runs and 6 discovery scans per client IP per 10 minutes) protects against runaway API calls and accidental token consumption.

### Archive

The Archive provides a local session history:
- Completed runs are kept client-side in `sessionStorage` (up to 40 records).
- Runs are tied to the active browser tab and clear when the tab closes.
- The backend server does not maintain a database of generated rules.
- Filter records using the search bar or the **Stack matches only** toggle.

## Data Handling & Architecture

- **Article Fetching:** When using a URL, article text is retrieved using your configured fetch provider (or direct `http` GET).
- **LLM Extraction:** The retrieved Markdown is submitted to your configured LLM API. Do not analyze confidential or classified advisories unless your chosen provider and endpoint meet your organization's data compliance requirements.
- **Backend Storage:** The local SQLite database (`data/cve2detect.db`) is used exclusively to cache the **discovery feed** (public article titles and URLs from 24h scans). It does not store pipeline runs, extracted intelligence, or generated Sigma rules.
- **Client Storage:** Monitored asset profiles reside in browser `localStorage`; run history resides in browser `sessionStorage`.

## Frequently Asked Questions

**What is the difference between Load sample and live URL runs?**  
The bundled sample runs completely offline without requiring any API keys. Live URLs require a configured LLM provider plus a fetch provider (`http`, a dedicated fetch API, or pasted Markdown). The **Scan 24h** feature requires a search-capable fetch provider.

**Why did fetch return a 404 error?**  
Ensure you paste the clean URL from your browser address bar rather than an incomplete Markdown link or relative URL.

**Why is there no direct SIEM deploy option?**  
CVE2Detect deliberately adopts a generate-and-copy architecture. By not managing direct SIEM API connections or credentials, the application minimizes security risks and operational complexity. Copy the generated Splunk, Elastic, Sentinel, Wazuh, or LimaCharlie queries into your production consoles after testing.

**Why did my Archive clear?**  
Archive records are held in the browser's `sessionStorage` and persist only for the life of the current browser tab. Use **Download .yml** or copy rules you wish to retain permanently.

**Does the server store my generated detection rules?**  
No. All pipeline executions are processed statelessly in memory and streamed directly to the browser client; they are not saved to the SQLite database.
