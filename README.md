# CVE2Detect

Local project: turn a public vulnerability write-up into a [Sigma](https://github.com/SigmaHQ/sigma) rule and copy-ready queries for Splunk, Elastic, Microsoft Sentinel, Wazuh, and LimaCharlie.

Paste an advisory URL or Markdown (or scan the last 24 hours if your fetch API supports search). The pipeline fetches the page, extracts host telemetry and ATT&CK with **your** LLM, validates the rule with pySigma, and shows copy/download output. Paste those queries into tools you already run.

This is a **generate-and-copy** project, not a SIEM and not a hosted product. It does not log into an environment, deploy rules, or keep a shared job archive.

[User guide](docs/USER_GUIDE.md) · [Technical documentation](docs/TECHNICAL.md)

---

## What it produces

| Output | Notes |
|---|---|
| Structured intel | CVE, CVSS, actor, campaign, affected software, ATT&CK, Sysmon / 4688-style telemetry, process trees, IoCs |
| Sigma YAML | Always `status: experimental` until you hunt and promote it |
| Vendor queries | Splunk SPL, Elastic DSL, Sentinel KQL |
| Open-source formats | Wazuh XML, LimaCharlie D&R (`enabled: false`) |
| Retro-hunt | Same logic over the last 30 / 60 / 90 days |
| Atomic test | Staging-only; live C2 is rewritten to `example.com` / TEST-NET-3 |

A **validated** stamp means the YAML parsed as Sigma. Hunt before you enable anything.

## Pipeline

```
Advisory URL, pasted Markdown, or 24h discovery hit
        │
        ▼
  1 Ingest     Fetch API (or plain HTTP / pasted Markdown) → Markdown
        │
        ▼
  2 Extract    LLM as a Senior Threat Analyst → structured JSON
        │
        ▼
  3 Validate   Assemble Sigma → pySigma parse → Splunk / Elastic / Sentinel
               + Wazuh, LimaCharlie, retro-hunt, atomic test
        │
        ▼
  4 Output     Copy or download in the browser
               The run is not stored in SQLite
```

**Pipeline** is the working view. **Environment** (optional) tags runs as in-scope vs out-of-scope from technologies you select in this browser. **Archive** keeps up to 40 runs in this tab (`sessionStorage`); closing the tab clears it.

## APIs

Two slots, filled with keys you already have. Not locked to one vendor.

| Slot | What it does | You can use |
|---|---|---|
| **Fetch** | Retrieve a write-up as Markdown | `http` (no key — GET the URL), or a JS-render / search API. Paste Markdown to skip fetch. |
| **LLM** | Extract telemetry + Sigma draft | Gemini, OpenAI, or any OpenAI-compatible `/v1/chat/completions` host |

**Load sample** needs neither slot. Live URLs need Fetch (or pasted Markdown) plus LLM. **Scan 24h** needs a search-capable fetch provider.

If the primary model returns 429/503 (high demand), the extract stage retries twice with backoff, then tries the next id in `LLM_MODELS`. For Gemini, when `LLM_MODELS` is empty the project also tries `gemini-2.5-flash` then `gemini-2.0-flash`. Set `LLM_MODELS=none` to disable that list.

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

Edit `.env` with your endpoints and keys. Example Gemini:

```
CVE2DETECT_FETCH_PROVIDER=http
CVE2DETECT_LLM_PROVIDER=gemini
LLM_API_KEY=...
LLM_MODEL=gemini-3.8-flash
LLM_MODELS=gemini-2.5-flash,gemini-2.0-flash
```

OpenAI-compatible:

```
CVE2DETECT_LLM_PROVIDER=openai_compatible
LLM_API_KEY=...
LLM_MODEL=...
LLM_API_BASE=https://api.openai.com/v1
```

Vendor aliases (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`, `TINYFISH_API_KEY`) still work.

```bash
python app.py
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Pills should read **Fetch live** and **LLM live**. Default bind is loopback.

## Using the console

1. *(Optional)* **Environment** — tick technologies you monitor, set the hunt window, Save profile.
2. **Pipeline** — Scan 24h, paste a URL, paste Markdown, or Load sample.
3. **Run pipeline**. Copy the tab you need, or **Download .yml**.

Rate limits (per client IP, 10-minute window): **8** pipeline runs, **6** discovery scans.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CVE2DETECT_FETCH_PROVIDER` | `http` if no fetch key, else `tinyfish` | `http` or `tinyfish` |
| `FETCH_API_KEY` | — | Key for a search/render fetch API |
| `CVE2DETECT_LLM_PROVIDER` | auto-detected | `gemini`, `openai`, or `openai_compatible` |
| `LLM_API_KEY` | — | LLM key |
| `LLM_MODEL` | provider default | Primary model id |
| `LLM_MODELS` | Gemini: `gemini-2.5-flash,gemini-2.0-flash` | Comma-separated fallbacks after retries; `none` disables |
| `LLM_API_BASE` | provider default | OpenAI-compatible base URL |
| `CVE2DETECT_HOST` / `CVE2DETECT_PORT` | `127.0.0.1` / `8787` | Bind |
| `CVE2DETECT_DAILY_SEARCH` | `0` | `1` refreshes the discovery feed every 24 hours |
| `CVE2DETECT_SEARCH_RECENCY_MINUTES` | `1440` | Discovery look-back |
| `CVE2DETECT_TRUST_PROXY` | `0` | `1` only if a reverse proxy overwrites `X-Forwarded-For` |

`.env` is gitignored. Never commit keys.

## Data handling

- Live fetches send page text to the configured fetch API (or only to the target site if `http`). Extraction sends Markdown to the configured LLM.
- SQLite (`data/cve2detect.db`) caches the discovery feed only. Pipeline jobs are not stored there.
- Stack profile is `localStorage`. Run history is this tab (`sessionStorage`).
- `pipeline/deploy.py` and `pipeline/webhooks.py` are unused by `app.py`.

## Tests

```bash
pytest -q
```

Sample pipeline runs do not call a fetch API or an LLM.
