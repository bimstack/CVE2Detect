# CVE2Detect user guide

For SOC analysts and small detection teams. You do not need to write Sigma by hand, but you should know CVE, ATT&CK, and how your SIEM searches logs.

This is the **public generate-and-copy** product. You paste or pick an advisory, get detections, and copy them into your own tools. CVE2Detect never logs into a SIEM and never stores your runs for other users.

## What it is

CVE2Detect turns a public vulnerability write-up into:

- Structured intel (CVE, CVSS, actor, ATT&CK, host telemetry, IoCs)
- A generic **Sigma** rule (`status: experimental`)
- Vendor queries (Splunk SPL, Elastic, Sentinel KQL, Wazuh XML, LimaCharlie D&R)
- A **retro-hunt** (30 / 60 / 90 days)
- An **atomic test** for a staging host (C2 replaced with example.com / TEST-NET-3)

It does not enable alerts, does not deploy rules, and does not replace rule review. Hunt first.

## Setup (self-host)

1. Open PowerShell in the `CVE2Detect` folder.
2. First time:

   ```
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   copy .env.example .env
   ```

3. Put **your** keys in `.env` (copy from `.env.example`):
   - **Fetch** — `CVE2DETECT_FETCH_PROVIDER=http` (no key) or a search/render API via `FETCH_API_KEY`
   - **LLM** — `LLM_API_KEY`, `LLM_MODEL`, and if needed `LLM_API_BASE` for any OpenAI-compatible endpoint
4. `python app.py`
5. Open [http://127.0.0.1:8787](http://127.0.0.1:8787)

Header pills: **Fetch live** / **LLM live**. Missing means that slot is empty — save `.env` and refresh.

The process binds to this machine only (`127.0.0.1`) unless you change `CVE2DETECT_HOST` for hosting behind a reverse proxy.

## Screens

| Nav | Use |
|---|---|
| **Pipeline** | Ingest an advisory and copy intel + detections |
| **Archive** | Runs from **this browser tab** (cleared when the tab closes) |
| **Environment** | Products you monitor + retro-hunt window (saved in this browser) |

### Environment (optional, do this first)

Select products you monitor (Windows Server, IIS, M365, Fortinet, Ivanti, AWS, …). Save profile. The list stays in `localStorage` on this machine. It is sent to the server only as asset IDs on the next **Run pipeline**, so matching can run.

Later runs stamp the intel pane:

- **stack match** — in scope
- **out of scope** — not in the profile
- **no profile** — nothing selected yet

Archive can filter **Stack matches only**.

There are no webhook URLs and no SIEM credentials on this screen. Copy the query from the detection tabs into your own console.

### Pipeline

1. **Scan 24h** — fill the shared discovery feed, click an item (needs a search-capable fetch provider)  
   **or** paste an **Advisory URL**  
   **or** paste **advisory Markdown** (skips live fetch)  
   **or** **Load sample** (offline IIS RCE fixture)
2. **Run pipeline** — stages: Ingest → Extract → Validate → Output

**Left — Threat intelligence**

CVE, CVSS, type, actor, campaign, affected software, ATT&CK, host telemetry (Sysmon / 4688, etc.), process tree, IoCs, analyst notes.

**Right — Detection output**

| Tab | Contents |
|---|---|
| Sigma | Portable YAML (`status: experimental`) |
| Splunk / Elastic / Sentinel | Transpiled queries |
| Wazuh / LimaCharlie | Open-source rule formats (LimaCharlie `enabled: false`) |
| Retro-hunt | Same logic, last 30–90 days |
| Atomic test | Staging command; C2 replaced with example.com |

**validated** = YAML parsed as Sigma. It is not a production-ready correlation. Hunt first, then promote the rule in your SIEM.

**Copy** puts the current tab on the clipboard. **Download .yml** saves the Sigma rule.

Rate limits (per client IP, 10-minute window): 8 pipeline runs, 6 discovery scans. Wait and retry if you see HTTP 429.

### Archive

This is not a shared knowledge base. Each completed run is kept in `sessionStorage` in this tab (up to 40). Other users, other browsers, and a closed tab cannot see it. Search and **Stack matches only** filter that local list.

## Privacy

Article text is sent to **your configured fetch API** (or only to the target site if fetch is `http`) and Markdown is sent to **your configured LLM**. Do not process classified or internal advisories unless those providers are allowed to see the content.

The server stores:

- The **shared discovery feed** (public article titles/URLs from Scan 24h)
- Nothing else from your pipeline: no Sigma YAML, no pasted Markdown after the request finishes, no SIEM credentials

Your stack profile lives in this browser. Your run history lives in this tab.

## FAQ

**Load sample vs live URL**  
Sample needs neither API. Live URLs need an LLM key plus fetch (`http`, a fetch API, or pasted Markdown). Scan 24h needs a search-capable fetch provider.

**404 on fetch**  
Paste the browser address bar URL, not a Markdown link.

**Where is Deploy?**  
Public v1 is generate-and-copy only. Paste the Splunk / Elastic / Sentinel / Wazuh / LimaCharlie tab into the product you already operate.

**Why did my Archive empty?**  
It is this tab only. Copy or download anything you need to keep.

**Can other users see my rules?**  
No. Jobs are not written to the shared database.
