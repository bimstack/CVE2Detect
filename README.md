# CVE2Detect

**Threat intelligence in. Detection queries out.**

CVE2Detect turns a public vulnerability write-up into a portable [Sigma](https://github.com/SigmaHQ/sigma) rule plus ready-to-copy queries for Splunk, Elastic, Microsoft Sentinel, Wazuh, and LimaCharlie.

Paste an advisory URL (or scan the last 24 hours). The pipeline fetches the page, extracts host telemetry and ATT&CK, validates the rule with pySigma, and hands you copy/download output. You paste those queries into tools you already run.

This is a **generate-and-copy** console, not a SIEM. It does not log into your environment, deploy rules, or keep a shared archive of other users' jobs.

[User guide](docs/USER_GUIDE.md) · [Technical documentation](docs/TECHNICAL.md)

---

## What you get

| Output | Notes |
|---|---|
| Structured intel | CVE, CVSS, actor, campaign, affected products, ATT&CK, Sysmon / 4688-style telemetry, process trees, IoCs |
| Sigma YAML | Always `status: experimental` until you hunt and promote it |
| Vendor queries | Splunk SPL, Elastic DSL, Sentinel KQL |
| Open-source formats | Wazuh XML, LimaCharlie D&R (`enabled: false`) |
| Retro-hunt | Same logic over the last 30 / 60 / 90 days |
| Atomic test | Staging-only; live C2 is rewritten to `example.com` / TEST-NET-3 |

A **validated** stamp means the YAML parsed as Sigma. It is not a production-ready correlation. Hunt first.

## Pipeline

```
Advisory URL or 24h discovery hit
        │
        ▼
  1 Ingest     TinyFish Search / Fetch (stealth Agent fallback) → Markdown
        │
        ▼
  2 Extract    Gemini as a Senior Threat Analyst → structured JSON
        │
        ▼
  3 Validate   Assemble Sigma → pySigma parse → Splunk / Elastic / Sentinel
               + Wazuh, LimaCharlie, retro-hunt, atomic test
        │
        ▼
  4 Output     Copy or download in the browser
               Job is not stored on the server
```

**Pipeline** is the working view. **Environment** (optional) tags runs as in-scope vs out-of-scope from products you select in this browser. **Archive** keeps up to 40 runs in this tab (`sessionStorage`); closing the tab clears it.

## Requirements

- Python 3.11+
- A [TinyFish API key](https://agent.tinyfish.ai/api-keys) — Search and Fetch are free; stealth Agent uses wallet credits
- A [Google AI Studio (Gemini) API key](https://aistudio.google.com/apikey)

Load sample works without TinyFish. Live URLs need both keys.

## Quick start

**Windows (PowerShell)**

```powershell
git clone https://github.com/bimstack/CVE2Detect.git
cd CVE2Detect
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

**macOS / Linux**

```bash
git clone https://github.com/bimstack/CVE2Detect.git
cd CVE2Detect
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set:

```
TINYFISH_API_KEY=...
GEMINI_API_KEY=...
```

Then:

```bash
python app.py
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Header pills should read **TinyFish live** and **Gemini live**.

Default bind is loopback (`127.0.0.1:8787`). API keys stay on the server; the browser only sees whether they are present.

## Using the console

1. *(Optional)* Open **Environment**, tick the products you monitor, set the hunt window, Save profile. The list stays in this browser and is sent only as asset IDs on the next run.
2. On **Pipeline**, either:
   - **Scan 24h** and click a feed item, or
   - paste an **Advisory URL** (the address-bar URL, not a Markdown link), or
   - **Load sample** (bundled IIS RCE fixture, no live fetch).
3. **Run pipeline**. Watch Ingest → Extract → Validate → Output.
4. Copy the tab you need, or **Download .yml** for the Sigma rule.

Paste the query into your own Splunk / Kibana / Sentinel / Wazuh / LimaCharlie console. CVE2Detect never connects to those products.

Rate limits (per client IP, 10-minute window): **8** pipeline runs, **6** discovery scans.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TINYFISH_API_KEY` | — | Search, Fetch, stealth Agent |
| `GEMINI_API_KEY` | — | Stage 2 extraction |
| `GEMINI_MODEL` | `gemini-3.8-flash` | Gemini model id |
| `CVE2DETECT_HOST` | `127.0.0.1` | Bind address |
| `CVE2DETECT_PORT` | `8787` | Bind port |
| `CVE2DETECT_DAILY_SEARCH` | `0` | `1` refreshes the shared discovery feed every 24 hours |
| `CVE2DETECT_SEARCH_RECENCY_MINUTES` | `1440` | Discovery look-back |
| `CVE2DETECT_TRUST_PROXY` | `0` | `1` only behind a reverse proxy that **overwrites** `X-Forwarded-For` |

`.env` is gitignored. Never commit keys.

## Privacy and safety

- Live fetches send page text to TinyFish; extraction sends Markdown to Gemini. Do not run classified or internal advisories unless those vendors are allowed to see the content.
- The server stores the **shared discovery feed** (public article titles and URLs). It does **not** store pipeline jobs, Sigma YAML, or SIEM credentials.
- Your stack profile is `localStorage`. Your run history is this tab only.
- Generated Sigma is always `experimental`. Atomic tests are for a staging host.
- `pipeline/deploy.py` and `pipeline/webhooks.py` exist for private forks. Public v1 does not import or expose them.

## Project layout

```
app.py                 FastAPI app, SSE pipeline, rate limits
pipeline/ingest.py     URL normalize, TinyFish search / fetch
pipeline/extract.py    Gemini structured extraction
pipeline/sigma_build.py  Deterministic Sigma YAML
pipeline/validate.py   pySigma parse + vendor transpile
pipeline/ossiem.py     Wazuh XML, LimaCharlie D&R
pipeline/atomic.py     Sanitized atomic tests
pipeline/hunt.py       30 / 60 / 90 day retro-hunt wrappers
pipeline/profile.py    Asset catalog + stack matching
pipeline/store.py      SQLite for the discovery feed only
ui/                    Static console
samples/               Offline IIS RCE fixture
docs/                  User guide and technical documentation
tests/                 Schema, Sigma, HTTP surface
```

## HTTP API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | `{ mode: "public", persist_jobs: false, keys, model }` |
| `GET` | `/api/feed` | Shared discovery hits |
| `POST` | `/api/discover` | Refresh feed (needs TinyFish) |
| `POST` | `/api/pipeline` | Default **SSE**; `?stream=false` returns JSON |
| `GET` | `/api/estate/catalog` | Asset ids for Environment |

There is no `/api/records`, no server-side estate profile, and no deploy or webhook routes.

## Tests

```bash
pytest -q
```

Sample pipeline runs do not call TinyFish or Gemini.

## Docs

- [User guide](docs/USER_GUIDE.md) — SOC walkthrough of Pipeline, Archive, and Environment
- [Technical documentation](docs/TECHNICAL.md) — architecture, APIs, schema, hosting notes, limitations

## License

No license file is attached yet. All rights reserved unless the repository owner adds one.
