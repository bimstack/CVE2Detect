# CVE2Detect

**Threat intelligence in. Detection queries out.**

CVE2Detect turns a public vulnerability write-up into a portable [Sigma](https://github.com/SigmaHQ/sigma) rule plus ready-to-copy queries for Splunk, Elastic, Microsoft Sentinel, Wazuh, and LimaCharlie.

Paste an advisory URL or Markdown (or scan the last 24 hours if your fetch API supports search). The pipeline retrieves the page, extracts host telemetry and ATT&CK with **your** LLM, validates the rule with pySigma, and hands you copy/download output. You paste those queries into tools you already run.

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
Advisory URL, pasted Markdown, or 24h discovery hit
        │
        ▼
  1 Ingest     Your fetch API (or plain HTTP / pasted Markdown) → Markdown
        │
        ▼
  2 Extract    Your LLM as a Senior Threat Analyst → structured JSON
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

## Bring your own APIs

CVE2Detect is two slots you fill with keys you already have. It is not locked to one vendor.

| Slot | What it does | You can use |
|---|---|---|
| **Fetch** | Retrieve a write-up as Markdown | `http` (no key — GET the URL), or a JS-render / search API (`tinyfish` contract). Paste Markdown to skip fetch entirely. |
| **LLM** | Extract telemetry + Sigma draft | Google Gemini, OpenAI, or **any OpenAI-compatible** `/v1/chat/completions` host (xAI, Groq, Together, vLLM, Ollama, Azure-compatible gateways, …) |

Header pills read **Fetch** and **LLM**. Live means that slot is configured — not that a specific brand is required.

**Load sample** needs neither slot. Live URLs need Fetch (or pasted Markdown) plus LLM. **Scan 24h** needs a search-capable fetch provider.

## Requirements

- Python 3.11+
- An **LLM API key** for live extraction (`LLM_API_KEY`, or a vendor alias)
- Fetch is optional: plain `http`, a search/render API key, or pasted Markdown

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

Edit `.env` with **your** endpoints and keys. Minimal live extraction:

```
CVE2DETECT_FETCH_PROVIDER=http
CVE2DETECT_LLM_PROVIDER=openai_compatible
LLM_API_KEY=...
LLM_MODEL=...
LLM_API_BASE=https://api.openai.com/v1
```

Gemini-style native API:

```
CVE2DETECT_LLM_PROVIDER=gemini
LLM_API_KEY=...
LLM_MODEL=gemini-3.8-flash
```

Vendor aliases (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, `TINYFISH_API_KEY`) still work if that is what you already keep in `.env`.

Then:

```bash
python app.py
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Pills should read **Fetch live** and **LLM live**.

Default bind is loopback (`127.0.0.1:8787`). Keys stay on the server; the browser only sees whether each slot is present.

## Using the console

1. *(Optional)* Open **Environment**, tick the products you monitor, set the hunt window, Save profile. The list stays in this browser and is sent only as asset IDs on the next run.
2. On **Pipeline**, either:
   - **Scan 24h** and click a feed item (search-capable fetch provider), or
   - paste an **Advisory URL** (the address-bar URL, not a Markdown link), or
   - paste **advisory Markdown** (skips live fetch), or
   - **Load sample** (bundled IIS RCE fixture).
3. **Run pipeline**. Watch Ingest → Extract → Validate → Output.
4. Copy the tab you need, or **Download .yml** for the Sigma rule.

Paste the query into your own Splunk / Kibana / Sentinel / Wazuh / LimaCharlie console. CVE2Detect never connects to those products.

Rate limits (per client IP, 10-minute window): **8** pipeline runs, **6** discovery scans.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CVE2DETECT_FETCH_PROVIDER` | `http` if no fetch key, else `tinyfish` | `http` or `tinyfish` |
| `FETCH_API_KEY` | — | Key for a search/render fetch API |
| `FETCH_SEARCH_URL` / `FETCH_URL` / `FETCH_AGENT_URL` | TinyFish-shaped hosts | Override if your fetch API uses the same contract on different URLs |
| `CVE2DETECT_LLM_PROVIDER` | auto-detected from keys | `gemini`, `openai`, or `openai_compatible` |
| `LLM_API_KEY` | — | Key for the LLM slot |
| `LLM_MODEL` | provider default | Model id |
| `LLM_API_BASE` | provider default | OpenAI-compatible base, e.g. `https://api.openai.com/v1` |
| `CVE2DETECT_HOST` | `127.0.0.1` | Bind address |
| `CVE2DETECT_PORT` | `8787` | Bind port |
| `CVE2DETECT_DAILY_SEARCH` | `0` | `1` refreshes the shared discovery feed every 24 hours |
| `CVE2DETECT_SEARCH_RECENCY_MINUTES` | `1440` | Discovery look-back |
| `CVE2DETECT_TRUST_PROXY` | `0` | `1` only behind a reverse proxy that **overwrites** `X-Forwarded-For` |

`.env` is gitignored. Never commit keys.

## Privacy and safety

- Live fetches send page text to **your configured fetch API** (or only to the target site if `http`). Extraction sends Markdown to **your configured LLM**. Do not run classified or internal advisories unless those providers are allowed to see the content.
- The server stores the **shared discovery feed** (public article titles and URLs). It does **not** store pipeline jobs, Sigma YAML, or SIEM credentials.
- Your stack profile is `localStorage`. Your run history is this tab only.
- Generated Sigma is always `experimental`. Atomic tests are for a staging host.
- `pipeline/deploy.py` and `pipeline/webhooks.py` exist for private forks. Public v1 does not import or expose them.

## Project layout

```
app.py                   FastAPI app, SSE pipeline, rate limits
pipeline/settings.py     Fetch / LLM provider resolution
pipeline/ingest.py       URL normalize, pluggable fetch, HTTP fallback
pipeline/extract.py      Pluggable LLM structured extraction
pipeline/sigma_build.py  Deterministic Sigma YAML
pipeline/validate.py     pySigma parse + vendor transpile
pipeline/ossiem.py       Wazuh XML, LimaCharlie D&R
pipeline/atomic.py       Sanitized atomic tests
pipeline/hunt.py         30 / 60 / 90 day retro-hunt wrappers
pipeline/profile.py      Asset catalog + stack matching
pipeline/store.py        SQLite for the discovery feed only
ui/                      Static console
samples/                 Offline IIS RCE fixture
docs/                    User guide and technical documentation
tests/                   Schema, Sigma, HTTP surface, providers
```

## HTTP API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | `{ mode: "public", persist_jobs: false, keys.{fetch,llm}, providers, model }` |
| `GET` | `/api/feed` | Shared discovery hits |
| `POST` | `/api/discover` | Refresh feed (search-capable fetch provider) |
| `POST` | `/api/pipeline` | Default **SSE**; `?stream=false` returns JSON |
| `GET` | `/api/estate/catalog` | Asset ids for Environment |

There is no `/api/records`, no server-side estate profile, and no deploy or webhook routes.

## Tests

```bash
pytest -q
```

Sample pipeline runs do not call a fetch API or an LLM.

## Docs

- [User guide](docs/USER_GUIDE.md) — SOC walkthrough of Pipeline, Archive, and Environment
- [Technical documentation](docs/TECHNICAL.md) — architecture, APIs, schema, hosting notes, limitations

## License

No license file is attached yet. All rights reserved unless the repository owner adds one.
