# CVE2Detect

Public **generate-and-copy** console: a vulnerability write-up in, Sigma plus vendor queries out. Four stages:

1. **Ingest** — TinyFish Search discovers recent CVE write-ups; TinyFish Fetch (stealth Agent fallback) returns Markdown.
2. **Extract** — Gemini, instructed as a Senior Threat Analyst, emits structured telemetry (event IDs, parent-child trees, command lines) plus Sigma field drafts.
3. **Validate** — In-memory YAML checks, pySigma parse, then transpile to Splunk SPL, Elastic DSL, and Microsoft Sentinel KQL. Wazuh XML and LimaCharlie D&R are generated in the same pass.
4. **Output** — Copy or download. Runs are **not** stored on the server. The Archive is this browser session only.

CVE2Detect does **not** connect to a SIEM, does **not** send Slack/Teams/Discord webhooks, and does **not** keep a shared archive of other users' jobs. Generated rules are `experimental` until you hunt and test them.

## Setup

```powershell
cd CVE2Detect
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Fill `.env`:

- `TINYFISH_API_KEY` — [agent.tinyfish.ai/api-keys](https://agent.tinyfish.ai/api-keys) (Search + Fetch are free; stealth Agent uses wallet credits)
- `GEMINI_API_KEY` — [aistudio.google.com/apikey](https://aistudio.google.com/apikey)

## Run

```powershell
python app.py
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Default bind is loopback.

Documentation:

- [User guide](docs/USER_GUIDE.md) — walkthrough of Pipeline, Archive, and Environment
- [Technical documentation](docs/TECHNICAL.md) — architecture, APIs, schema, hosting, and limitations

In the console:

- **Environment** — products you monitor (saved in this browser). Matching tags in-scope vs out-of-scope; the asset list is sent only with the next pipeline run.
- **Pipeline** — advisory URL, Scan 24h, or Load sample. Copy Sigma / Splunk / Elastic / Sentinel / Wazuh / LimaCharlie, plus retro-hunt and a sanitized atomic test.
- **Archive** — runs from this tab (sessionStorage, max 40). Closing the tab clears it.

Set `CVE2DETECT_DAILY_SEARCH=1` to refresh the shared discovery feed every 24 hours.

## Public hosting

Keep API keys on the server. Do not collect SIEM credentials.

| Variable | Public default |
|---|---|
| `CVE2DETECT_HOST` | `127.0.0.1` — set `0.0.0.0` only behind a reverse proxy |
| `CVE2DETECT_PORT` | `8787` |
| `CVE2DETECT_TRUST_PROXY` | `0` — set `1` only if the proxy overwrites `X-Forwarded-For` |
| Rate limits | Pipeline 8 / 10 min and discover 6 / 10 min per client IP |

The SQLite file holds the **shared discovery feed** only (`data/cve2detect.db`). Pipeline jobs stay in the caller's browser.

## Tests

```powershell
pytest -q
```
