# CVE2Detect Technical Documentation

## Overview

CVE2Detect is a FastAPI application that ingests public vulnerability write-ups and threat advisories and produces **generic Sigma rules** along with transpiled vendor queries (Splunk SPL, Elastic Query DSL, Microsoft Sentinel KQL, Wazuh XML, and LimaCharlie D&R).

This project is a detection-engineering assistant for rule authoring and hunting. It is not a scanner, exploit framework, SIEM, or hosted product.

## Architecture & Design Principles

CVE2Detect is built around a lightweight, **generate-and-copy** architecture:

- **Stateless Pipeline Execution:** The HTTP layer processes pipeline runs in memory and streams results to the client via Server-Sent Events (SSE). Completed runs are not persisted to a server-side database.
- **Client-Side Session State:** Run history is maintained in the user's browser tab using `sessionStorage` (capped at 40 records). Monitored asset profiles reside in browser `localStorage` (`cve2detect.profile`) and are transmitted to the backend only as asset IDs during pipeline runs.
- **Decoupled Security Model:** The project eliminates the need to store sensitive SIEM API credentials or webhook secrets on the server. Detections are generated, reviewed, and copied into the target security tools.
- **Scoped Database Storage:** The local SQLite database (`data/cve2detect.db`) is used exclusively to cache the discovery feed (`feed` table).
- **Conservative Rule Status:** Generated Sigma rules enforce `status: experimental` so a human reviews, hunts, and tunes them before enabling anything.

## Pipeline Architecture

```
Advisory URL, Search hit, or Markdown paste
        │
        ▼
[1 Ingest]   Fetch provider (HTTP GET, search/render API) or pasted Markdown
        │    Output: Clean Markdown
        ▼
[2 Extract]  Configured LLM with structured JSON schema (IntelExtraction)
        │    Retry on 429/503, then next id in LLM_MODELS
        │    Output: Telemetry, ATT&CK mappings, and Sigma detection fields
        ▼
[3 Validate] Assemble YAML → yaml.safe_load → pySigma parsing → backends
        │    Output: Sigma YAML + Splunk + Elastic + Sentinel
        │            + Wazuh + LimaCharlie + Atomic tests + Retro-hunt
        ▼
[4 Output]   SSE `complete` event streaming record to the browser
             Client stores run in sessionStorage for copy / export
```

| Stage | Module | External Dependencies & Protocols |
|---|---|---|
| 1 Ingest | `pipeline/ingest.py`, `pipeline/settings.py` | HTTP GET (`httpx`), or search/render API (`tinyfish` contract; host URLs overridable via `FETCH_*_URL`) |
| 2 Extract | `pipeline/extract.py`, `pipeline/schema.py`, `pipeline/settings.py` | Gemini (`generateContent`), or OpenAI-compatible endpoint (`POST {LLM_API_BASE}/chat/completions`) |
| 3 Validate | `pipeline/sigma_build.py`, `pipeline/validate.py`, `pipeline/ossiem.py`, `pipeline/atomic.py`, `pipeline/hunt.py` | `pySigma` core + Splunk, Elastic, and Kusto backends |
| 4 Output / UI | `pipeline/orchestrate.py`, `app.py`, `ui/` | In-memory record assembly; SQLite used only for discovery `feed` |

Pipeline orchestration is managed by `pipeline/orchestrate.py`, with real-time stage progress streamed over SSE.

## Project Structure

| Path | Purpose |
|---|---|
| `app.py` | FastAPI application, SSE streaming endpoints, rate limiting, and discovery feed scheduler |
| `pipeline/settings.py` | Provider and environment configuration resolution |
| `pipeline/ingest.py` | URL normalization, pluggable article fetch, HTML-to-Markdown conversion, and search discovery |
| `pipeline/schema.py` | Pydantic `IntelExtraction` data model and strict JSON schema generation helper |
| `pipeline/extract.py` | Pluggable LLM extraction client (Gemini or OpenAI-compatible) using structured outputs |
| `pipeline/sigma_build.py` | Deterministic Sigma YAML generation from structured fields (`status: experimental`) |
| `pipeline/validate.py` | YAML validation, pySigma rule parsing, and vendor query compilation |
| `pipeline/ossiem.py` | Wazuh XML and LimaCharlie D&R generation from Sigma detection selections |
| `pipeline/atomic.py` | Atomic Red Team-style staging validation commands (C2 rewritten to safe domains) |
| `pipeline/hunt.py` | 30 / 60 / 90 day retro-hunt query wrappers |
| `pipeline/profile.py` | Monitored technology catalog and stack matching logic |
| `pipeline/store.py` | SQLite operations for discovery `feed`. (Record persistence helpers remain available for tests and custom extensions) |
| `pipeline/orchestrate.py` | Pipeline stage coordinator and SSE event emitter |
| `pipeline/deploy.py` | Modular SIEM deployment extension (disabled in default configuration) |
| `pipeline/webhooks.py` | Modular webhook notification extension (disabled in default configuration) |
| `ui/` | Static front-end assets (`index.html`, `styles.css`, `app.js`) |
| `samples/advisory.md` | Bundled IIS RCE vulnerability write-up fixture |
| `samples/extraction.json` | Sample extraction fixture used when `use_sample=true` |
| `data/cve2detect.db` | Local SQLite discovery feed database (gitignored) |
| `tests/` | Test suite covering schemas, YAML building, pySigma transpilation, storage, and API surface |

## HTTP API

Base URL: `http://127.0.0.1:8787` (configured via `CVE2DETECT_HOST` and `CVE2DETECT_PORT`).

### Active Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | Web console interface |
| GET | `/static/*` | Static CSS and JavaScript assets |
| GET | `/api/health` | Health and provider status (`{ ok, project, mode: "project", persist_jobs, keys, providers, model, models, daily_search }`) |
| GET | `/api/feed` | Cached discovery search hits from the local database |
| POST | `/api/discover` | Trigger discovery search: `{ queries?, recency_minutes? }`. Requires a search-capable fetch provider (rate-limited: 6 requests / 10 min / IP) |
| GET | `/api/estate/catalog` | Catalog of monitored asset identifiers and labels for the Environment view |
| POST | `/api/pipeline` | Execute pipeline: `{ url, use_sample, markdown, title, assets[], hunt_days }`. Default response is SSE; `?stream=false` returns the final record as JSON (rate-limited: 8 requests / 10 min / IP) |

### Inactive / Modular Endpoints (Return 404)

- `GET /api/records`, `GET /api/records/{id}` (pipeline runs are kept in client `sessionStorage`)
- `GET` / `PUT /api/estate` (environment profile is maintained in client `localStorage`)
- Direct SIEM deploy and webhook push endpoints

Parameters:
- `assets`: Array of asset IDs from `/api/estate/catalog` (maximum 40).
- `hunt_days`: Integer look-back window (`30`, `60`, or `90`; defaults to `90`).

### Pipeline Server-Sent Events (SSE)

`Content-Type: text/event-stream`. Each message adheres to the SSE standard: `data: <json>\n\n`.

**Progress Event:**
```json
{ "event": "progress", "stage": "ingest|extract|validate|store", "message": "..." }
```
*(The UI displays the final `store` stage as **Output**).*

**Completion Event:**
```json
{ "event": "complete", "stage": "store", "message": "Pipeline complete.", "record": { ... } }
```

**Error Event:**
```json
{ "event": "error", "stage": "error", "message": "..." }
```

### Client Console Views

| View Identifier (`data-view`) | Interface Label | Purpose |
|---|---|---|
| `pipeline` | Pipeline | Ingest advisories, view extracted threat intel, and copy detections |
| `archive` | Archive | Current session history (`sessionStorage`), with stack-match filtering |
| `estate` | Environment | Monitored asset checkboxes and default retro-hunt duration (`localStorage`) |

Detection tabs: `yaml` (Sigma), `splunk`, `elastic`, `kql`, `wazuh`, `lc` (LimaCharlie), `hunt` (Retro-hunt), and `atomic` (Atomic test).

## Pipeline Stages in Detail

### Stage 1 — Ingest

- `normalize_advisory_url()` accepts standard URLs, Markdown links (`[title](url)`), angled URLs (`<url>`), or malformed clipboard pastes. It isolates the primary HTTP/HTTPS target.
- **HTTP Fetch:** When `CVE2DETECT_FETCH_PROVIDER=http` (or when no fetch API key is provided), the module issues an `httpx` GET request and converts the HTML DOM into Markdown. JavaScript-heavy single-page applications may produce incomplete content; in such cases, users can paste Markdown directly.
- **Advanced Render / Search Provider:** Using a provider adhering to the `tinyfish` API contract, the module submits:
  - `format: markdown`, `ttl: 0`, `per_url_timeout_ms: 90000`
  - `exclude_selectors`: Navigation bars, cookie consent banners, footers, advertisements, and comments.
  - `include_selectors`: `article`, `main`, `.post-content`, `.entry-content`, etc.
  - Automatically falls back to broader selectors if initial targets fail, or invokes an agent profile if bot detection is encountered.
- **Discovery Feeds:** Default discovery queries run against security research topics (exploits, zero-days, PoCs, and incident command lines). Results are saved to the `feed` table. When `CVE2DETECT_DAILY_SEARCH=1`, an APScheduler job triggers discovery every 24 hours.

### Stage 2 — Extract

- **Prompting & Grounding:** Uses a Senior Threat Analyst persona with strict instructions to ground detections strictly in the advisory text, prioritizing observable OS telemetry (process execution, command lines, parent processes) over transient indicators, and utilizing standard Sigma logsource naming.
- **Provider Routing:**
  - `gemini`: Uses the Google Generative Language API with strict schema validation (`responseJsonSchema`, falling back to `responseSchema` if needed).
  - `openai` / `openai_compatible`: Dispatches to `{LLM_API_BASE}/chat/completions` using `response_format.json_schema` (strict mode), falling back to `json_object` if strict mode is unsupported.
- `make_strict_schema(IntelExtraction)` enforces `additionalProperties: false` across all objects and marks all schema fields as required.
- Long write-ups are safely truncated at 80,000 characters before LLM submission.
- When `use_sample=true`, the pipeline bypasses external LLM calls and loads `samples/extraction.json` for deterministic offline testing.
- **Busy / high-demand handling:** Each model is tried up to twice with 2s then 4s backoff on HTTP 429, 503, 502, 504, 408, and transport timeouts. A 404 skips to the next model. 401/403 fail immediately (bad key). After the list is exhausted, extract raises `ExtractError` naming every model tried.
- **Model list:** `LLM_MODEL` (or `GEMINI_MODEL`) is primary. `LLM_MODELS` is a comma-separated fallback list. If the provider is Gemini and `LLM_MODELS` is empty, defaults are `gemini-2.5-flash` then `gemini-2.0-flash`. Set `LLM_MODELS=none` to disable defaults.

### Stage 3 — Validate & Transpile

- `build_sigma_yaml()` maps extracted detection blocks into formal Sigma structures, sanitizes identifiers, validates condition syntax, and generates ordered YAML.
- **Rule Status:** The builder enforces `status: experimental` on all generated Sigma rules.
- **Validation Steps:**
  1. `yaml.safe_load` verification.
  2. Structural check for required keys (`title`, `logsource`, `detection.condition`, and at least one selection block).
  3. Parsing via pySigma: `SigmaRule.from_yaml`.
  4. Backend transpilation:
     - **Splunk:** `SplunkBackend` with `splunk_windows_pipeline`.
     - **Elastic:** `LuceneBackend` (`dsl_lucene`).
     - **Sentinel:** `KustoBackend` with `sentinel_asim_pipeline` or `microsoft_xdr_pipeline`.
  5. Open-source query synthesis: Wazuh XML rules and LimaCharlie D&R rules (with `enabled: false`) are generated from the detection map.
  6. Atomic tests rewrite any live C2 endpoints to RFC-reserved documentation ranges (`example.com` and `203.0.113.1`).
  7. Retro-hunt queries wrap the transpiled vendor query with the selected time window (30, 60, or 90 days).
- Transpiler warnings are captured in `record.warnings` without failing the overall run; only YAML or core pySigma syntax errors mark `sigma_valid = 0`.
- Stack matching checks extracted `affected` technologies against the user's environment profile to indicate coverage relevance.

### Stage 4 — Output

- The pipeline constructs an in-memory client record (`_client_record(payload)`) and streams it over the SSE connection.
- No rule or extraction records are written to the database.
- The web UI receives the payload and adds it to `sessionStorage` (`cve2detect.session.records`).

## Storage & Database Model

The local SQLite database (`data/cve2detect.db`) is configured with write-ahead logging (WAL) and thread-local connections.

Active table:
- `feed(url TEXT PRIMARY KEY, title TEXT, snippet TEXT, site_name TEXT, query TEXT, discovered_at TEXT, processed INTEGER)`

*Note on Historical Tables:* Legacy tables (`records`, `records_fts`, `settings`) may exist in earlier database files, but the core application operates statelessly and does not read or write them.

## Rate Limiting

The application includes an in-process rate limiter utilizing sliding timestamp windows (`collections.deque`) keyed by client IP:

| Endpoint Bucket | Default Limit | Window |
|---|---|---|
| `pipeline` | 8 requests | 600 seconds (10 minutes) |
| `discover` | 6 requests | 600 seconds (10 minutes) |

When running behind a trusted reverse proxy, set `CVE2DETECT_TRUST_PROXY=1` to accurately identify client IPs from `X-Forwarded-For`.

## Configuration Reference

The application loads settings from `.env` on startup and refreshes them dynamically upon health check requests:

| Variable | Default | Purpose |
|---|---|---|
| `CVE2DETECT_FETCH_PROVIDER` | auto | `http` or `tinyfish` (defaults to `tinyfish` if `FETCH_API_KEY` is present, else `http`) |
| `FETCH_API_KEY` | None | API key for search and browser-render fetch APIs (alias: `TINYFISH_API_KEY`) |
| `FETCH_SEARCH_URL` / `FETCH_URL` / `FETCH_AGENT_URL` | None | Overrides for fetch provider API endpoints |
| `CVE2DETECT_LLM_PROVIDER` | auto | `gemini`, `openai`, or `openai_compatible` (detected from keys and base URL) |
| `LLM_API_KEY` | None | LLM API key (aliases: `GEMINI_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`) |
| `LLM_MODEL` | provider default | Primary model id (aliases: `GEMINI_MODEL`, `OPENAI_MODEL`) |
| `LLM_MODELS` | Gemini defaults `gemini-2.5-flash,gemini-2.0-flash` | Comma-separated fallbacks after retries; `none` disables defaults |
| `LLM_API_BASE` | provider default | Base URL for OpenAI-compatible gateways (alias: `OPENAI_BASE_URL`) |
| `CVE2DETECT_HOST` | `127.0.0.1` | Network interface to bind |
| `CVE2DETECT_PORT` | `8787` | Port to bind |
| `CVE2DETECT_DAILY_SEARCH` | `0` | Set to `1` to enable scheduled 24h discovery searches |
| `CVE2DETECT_SEARCH_RECENCY_MINUTES` | `1440` | Recency threshold for discovery searches (in minutes) |
| `CVE2DETECT_TRUST_PROXY` | `0` | Set to `1` to trust `X-Forwarded-For` from reverse proxies |

## Running locally

`python app.py` binds to `127.0.0.1:8787` unless `CVE2DETECT_HOST` / `CVE2DETECT_PORT` say otherwise. `.env` is gitignored. `/api/health` reports booleans such as `keys.llm`, never the tokens.

This project is meant to run on your machine. It is not a public website.

## Testing

Execute the test suite with pytest:

```bash
pytest -q
```

Test coverage includes:
- Advisory URL parsing and sanitization
- `IntelExtraction` Pydantic schema validation
- Sigma YAML assembly and pySigma compilation using sample fixtures
- SQLite store operations
- HTTP routes and health checks (stateless operation and sample pipeline)

## Operational Limitations

- **Extraction Quality:** LLM extraction accuracy depends on the detail present in the source advisory. The extracted `confidence` score and `caveats` section provide guidance on whether manual refinement is needed.
- **Field Mapping:** Sigma field naming adheres to standard Sysmon / Windows event conventions. Transpiler backends map standard fields to vendor targets; unmapped custom fields may require manual SIEM query adjustment.
- **In-Memory Rate Limiting:** Built-in rate limits are maintained in process memory and reset when the server restarts.
- **Session-Bound History:** Archive items are stored in client `sessionStorage` and clear when the browser tab is closed. Use the download button to save Sigma rules locally.

## Design & Security Invariants

- Binds to `127.0.0.1` unless reconfigured.
- Does not store or prompt for SIEM credentials.
- Advisories and generated rules are not persisted in SQLite.
- Atomic tests rewrite C2 to documentation ranges.
- Generated Sigma `status` is always `experimental`.
- LLM 429/503 retries, then `LLM_MODELS` fallbacks; 401/403 do not failover.
