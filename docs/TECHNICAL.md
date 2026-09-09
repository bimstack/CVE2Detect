# CVE2Detect technical documentation

## Role

CVE2Detect is a FastAPI application that turns a public vulnerability write-up into a **generic Sigma rule** plus vendor queries (Splunk SPL, Elastic Query DSL, Microsoft Sentinel KQL, Wazuh XML, LimaCharlie D&R).

Public v1 is a **generate-and-copy** service:

- The HTTP layer does not persist pipeline jobs.
- The UI archive is `sessionStorage` in the caller's tab (max 40 records).
- The environment profile is `localStorage` (`cve2detect.profile`). Asset IDs are sent only on `POST /api/pipeline`.
- There is no SIEM deploy API and no webhook API. Do not store SIEM credentials on a public host.
- SQLite holds the **shared TinyFish discovery feed** only.
- Generated Sigma always uses `status: experimental`.

It is a detection-engineering assistant, not a scanner, exploit framework, or production SIEM. Every live URL run sends page text to TinyFish and the extracted Markdown to Gemini.

## Four stages

```
URL or Search hit
        │
        ▼
[1 Ingest]  TinyFish Search → Fetch (markdown) → stealth Agent on bot_blocked
        │  clean Markdown
        ▼
[2 Extract] Gemini structured JSON (IntelExtraction schema)
        │  telemetry + Sigma field draft
        ▼
[3 Validate] assemble YAML → yaml.safe_load → SigmaRule.from_yaml → backends
        │  sigma_yaml + splunk_spl + elastic_dsl + sentinel_kql
        │  + wazuh_xml + limacharlie_yaml + atomic tests + retro-hunt
        ▼
[4 Output]  SSE `complete` with the record → browser copy/download
            (no INSERT into records; sessionStorage only)
```

| Stage | Module | External dependency |
|---|---|---|
| 1 Ingest | `pipeline/ingest.py` | TinyFish Search `GET https://api.search.tinyfish.ai`, Fetch `POST https://api.fetch.tinyfish.ai`, Agent `POST https://agent.tinyfish.ai/v1/automation/run` |
| 2 Extract | `pipeline/extract.py`, `pipeline/schema.py` | Gemini `generativelanguage.googleapis.com` (`gemini-3.8-flash` default) |
| 3 Validate | `pipeline/sigma_build.py`, `pipeline/validate.py`, `pipeline/ossiem.py`, `pipeline/atomic.py`, `pipeline/hunt.py` | pySigma + Splunk / Elastic / Kusto backends |
| 4 Output / UI | `pipeline/orchestrate.py`, `app.py`, `ui/` | Record shaped in memory; SQLite used only for `feed` |

Orchestration lives in `pipeline/orchestrate.py`. The HTTP layer streams progress as SSE.

## Layout

| Path | Role |
|---|---|
| `app.py` | FastAPI app, SSE pipeline, rate limits, optional 24h feed scheduler |
| `pipeline/ingest.py` | URL normalize, TinyFish search/fetch, stealth fallback |
| `pipeline/schema.py` | Pydantic `IntelExtraction` + strict JSON Schema helper |
| `pipeline/extract.py` | Gemini `generateContent` with JSON schema |
| `pipeline/sigma_build.py` | Deterministic YAML from structured fields (`status: experimental`) |
| `pipeline/validate.py` | YAML + pySigma parse + transpile |
| `pipeline/ossiem.py` | Wazuh XML and LimaCharlie D&R from Sigma selections |
| `pipeline/atomic.py` | Sanitized Atomic Red Team-style commands |
| `pipeline/hunt.py` | 30 / 60 / 90 day retro-hunt wrappers |
| `pipeline/profile.py` | Asset catalog + stack matching |
| `pipeline/store.py` | SQLite. Public v1 writes **feed** only. `save_record` / profile helpers remain for tests and private forks |
| `pipeline/orchestrate.py` | Stage runner / SSE events (`_client_record`, no `save_record`) |
| `pipeline/deploy.py` | Unused in public v1 (not imported by `app.py`) |
| `pipeline/webhooks.py` | Unused in public v1 (not imported by `app.py`) |
| `ui/` | Static console (`index.html`, `styles.css`, `app.js`) |
| `samples/advisory.md` | Bundled IIS RCE write-up |
| `samples/extraction.json` | Fixture extraction used when sample + no `GEMINI_API_KEY` |
| `data/cve2detect.db` | Shared discovery feed (gitignored) |
| `tests/` | Schema, YAML, pySigma, store unit tests, public HTTP surface |

## HTTP API

Base URL: `http://127.0.0.1:8787` (override with `CVE2DETECT_HOST` / `CVE2DETECT_PORT`).

| Method | Path | Notes |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/static/*` | UI assets |
| GET | `/api/health` | `{ ok, service, mode: "public", persist_jobs: false, keys.{tinyfish,gemini}, model, daily_search }` — re-reads `.env` |
| GET | `/api/feed` | TinyFish discovery hits (no `processed` flag) |
| POST | `/api/discover` | `{ queries?, recency_minutes? }` → upsert feed. Needs TinyFish key. **6 / 10 min / IP** |
| GET | `/api/estate/catalog` | Asset id/label list for the Environment checkboxes |
| POST | `/api/pipeline` | `{ url, use_sample, markdown, title, assets[], hunt_days }`. Default **SSE**. `?stream=false` returns the final event as JSON. **8 / 10 min / IP** |

Removed in public v1 (404):

- `GET /api/records`, `GET /api/records/{id}`
- `GET` / `PUT /api/estate` (no server-side profile, no SIEM secrets)
- deploy and webhook routes

`assets` must be catalog ids (max 40). `hunt_days` must be `30`, `60`, or `90` (else 90).

### Pipeline SSE

`Content-Type: text/event-stream`. Each frame is `data: <json>\n\n`.

Progress:

```json
{ "event": "progress", "stage": "ingest|extract|validate|store", "message": "..." }
```

The UI stage tile `store` is labeled **Output**. The event name is unchanged so existing clients keep working.

Success:

```json
{ "event": "complete", "stage": "store", "message": "Pipeline complete.", "record": { } }
```

Failure:

```json
{ "event": "error", "stage": "error", "message": "..." }
```

The worker thread is a daemon. The UI maps `stage` onto the four header tiles.

Deep links: `/?record=<id>` loads a record from **this tab's** sessionStorage; `/?view=archive` opens Archive; `/?view=estate` opens Environment.

Console views:

| View (`data-view`) | Screen label | Purpose |
|---|---|---|
| `pipeline` | Pipeline | Ingest → extract → validate → output |
| `archive` | Archive | This-tab sessionStorage, optional stack-match filter |
| `estate` | Environment | Asset checkboxes + hunt window in localStorage |

Detection tabs: `yaml`, `splunk`, `elastic`, `kql`, `wazuh`, `lc`, `hunt`, `atomic`. Copy / download only.

## Stage 1 — ingest

`normalize_advisory_url()` accepts a bare URL, `<url>`, `[title](url)`, or a garbled markdown paste (`url](url`). The first `https://` token is kept; junk after `](` is dropped.

Fetch request:

- `format: markdown`, `ttl: 0` (live), `per_url_timeout_ms: 90000`
- `exclude_selectors`: cookie banners, nav, footer, ads, comments
- `include_selectors`: `article`, `main`, `.post-content`, `.entry-content`, …
- `purpose` string for TinyFish ranking/extraction quality

If `selector_not_matched`, retry without include selectors. If `bot_blocked`, POST Agent with `browser_profile: stealth`, Tetra US proxy, and an output schema `{ title, markdown }`. Agent draws wallet credits; Search and Fetch do not.

Discovery queries (default, 1440 minute recency, social domains excluded):

- CVE vulnerability write-up exploit analysis
- zero-day disclosure technical advisory
- vulnerability disclosure proof of concept detection
- incident report exploitation command line Sysmon

Hits land in `feed` (deduped by URL). `CVE2DETECT_DAILY_SEARCH=1` starts APScheduler every 24 hours. Feed items returned to the browser omit `processed` so one user's run cannot mark a URL for everyone else.

## Stage 2 — extract

System prompt: Senior Threat Analyst / Detection Engineer. Grounding rules: no invented hashes/CVEs/event IDs; prefer OS telemetry over hashes; Sigma field names (`Image`, `CommandLine`, `ParentImage`, …).

Client: REST `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` with header `x-goog-api-key`. Default model `GEMINI_MODEL` or `gemini-3.8-flash`.

`make_strict_schema(IntelExtraction)` forces `additionalProperties: false` and `required = all properties`. The schema is sent as `generationConfig.responseJsonSchema` (falls back to `responseSchema` on HTTP 400).

Markdown is truncated at 80,000 characters.

If `use_sample=true`, `samples/extraction.json` is loaded instead of calling Gemini (so CI and Load sample stay deterministic).

Top-level extraction fields: `summary`, `cve`, `cvss`, `vulnerability_type`, `threat_actor`, `campaign`, `affected[]`, `techniques[]`, `telemetry[]`, `process_anomalies[]`, `command_lines[]`, `paths[]`, `indicators[]`, nested `sigma` draft, `confidence`, `is_actionable`, `caveats`.

## Stage 3 — validate / transpile

`build_sigma_yaml()` does **not** dump the model’s free-form YAML. It maps `SelectionBlock`s to Sigma detection keys, sanitizes identifiers, synthesizes a condition if the model’s condition does not reference known selections, and emits ordered YAML (`title`, `id` UUID, `status`, `description`, `references`, `author`, `date`, `logsource`, `detection`, `falsepositives`, `level`, `tags`).

Public v1 **forces** `status: experimental` regardless of the model draft.

Validation:

1. `yaml.safe_load`
2. Require `title`, `logsource`, `detection.condition`, at least one selection
3. `SigmaRule.from_yaml`
4. Convert:
   - Splunk: `SplunkBackend` + `splunk_windows_pipeline` when importable
   - Elastic: `LuceneBackend` `dsl_lucene`, else default Lucene
   - Sentinel: `KustoBackend` with `sentinel_asim_pipeline` or `microsoft_xdr_pipeline`

Backend failures are **warnings**; they do not fail `sigma_valid`. Only YAML/pySigma errors set `sigma_valid = 0`.

Wazuh XML and LimaCharlie D&R are built from the same detection map (`pipeline/ossiem.py`). LimaCharlie metadata keeps `enabled: false`. Atomic tests replace live C2 with TEST-NET-3 (`203.0.113.1`) and `example.com`. Retro-hunt wraps the vendor queries with a 30 / 60 / 90 day look-back from the request (or the browser profile).

Stack matching (`pipeline/profile.py`) compares `intel.affected` plus summary text against the request `assets` list. An empty list ⇒ `stack_configured = 0` (no filter).

## Stage 4 — output (not a shared store)

`run_pipeline` yields `_client_record(payload)`: JSON columns decoded, a fresh `id`, no `save_record`. The browser calls `rememberRecord()` into `sessionStorage` key `cve2detect.session.records`.

SQLite WAL, `check_same_thread=False`, thread-local connection. Public writes:

- `feed(url PK, title, snippet, site_name, query, discovered_at, processed)` — `processed` is unused by the API

The `records`, `records_fts`, and `settings` tables may still exist on disk from earlier local-tool builds. Public v1 does not read or write them from `app.py`.

## Rate limits and proxy

Sliding window in process memory (`deque` of timestamps), keyed by client IP + bucket.

| Bucket | Max | Window |
|---|---|---|
| `pipeline` | 8 | 600 s |
| `discover` | 6 | 600 s |

`X-Forwarded-For` is ignored unless `CVE2DETECT_TRUST_PROXY=1`. Enable that only when the reverse proxy **overwrites** the header; otherwise clients could spoof IPs and skip the limit.

## Environment

Loaded from `.env` at process start and **re-read** on health checks, TinyFish calls, and Gemini calls (`load_dotenv(..., override=True)`).

| Variable | Purpose |
|---|---|
| `TINYFISH_API_KEY` | Search, Fetch, stealth Agent |
| `GEMINI_API_KEY` | Stage 2 (Google AI Studio key from aistudio.google.com/apikey) |
| `GEMINI_MODEL` | Default `gemini-3.8-flash` |
| `CVE2DETECT_HOST` / `CVE2DETECT_PORT` | Bind, default `127.0.0.1:8787` |
| `CVE2DETECT_DAILY_SEARCH` | `1` enables 24h discovery job |
| `CVE2DETECT_SEARCH_RECENCY_MINUTES` | Default `1440` |
| `CVE2DETECT_TRUST_PROXY` | `1` to trust `X-Forwarded-For` behind a reverse proxy |

`.env` is gitignored. Keys never leave the server process; the browser only sees booleans from `/api/health`.

### Hosting a public instance

1. Keep the default loopback bind, or set `CVE2DETECT_HOST=0.0.0.0` **behind TLS termination** that you control.
2. Do not put SIEM URLs, API keys, or webhook secrets in `.env` or SQLite. Public v1 has no place for them.
3. Set `CVE2DETECT_TRUST_PROXY=1` only if the proxy sets `X-Forwarded-For`.
4. Treat `data/cve2detect.db` as a shared list of public article URLs, not as user data.

`pipeline/deploy.py` and `pipeline/webhooks.py` remain in the tree for private forks. They are not imported by `app.py` and must stay that way on a public host.

## Tests

```
pytest -q
```

Coverage: URL sanitizer, extraction schema, Sigma YAML + pySigma parse of the sample (`status: experimental`), store/FTS unit tests, public HTTP surface (`mode=public`, `persist_jobs=false`, sample pipeline, 404 on records/estate/deploy/webhooks).

Live TinyFish/Gemini calls are not in CI. Sample pipeline does not call Gemini.

## Limitations

- LLM extraction can omit or invent telemetry if the write-up is thin; `confidence` and `caveats` exist so an analyst can reject the rule.
- Sigma field names follow the generic Sysmon/Windows vocabulary. Pipelines remap some of them; unmapped fields yield empty or odd vendor queries.
- Stealth Agent is paid and still cannot solve CAPTCHAs.
- In-process rate limits reset on process restart and do not sync across workers. Use one worker or put a limiter in the proxy for multi-process hosting.
- A `validated` stamp means **syntactically valid Sigma**, not a tested detection. Tune false positives before enabling anything in a SIEM.
- Session archive is lost when the tab closes. Download YAML you need to keep.

## Safety invariants

- Default bind `127.0.0.1`
- API keys stay server-side
- No SIEM credentials collected or stored
- No shared job archive
- Fetch rejects the need for custom scrapers; TinyFish is the only HTTP client to third-party sites
- Sample path does not call TinyFish or Gemini
- Generated Sigma `status` is always `experimental`
- Atomic tests rewrite live C2 to documentation ranges
