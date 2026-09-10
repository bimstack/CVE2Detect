const state = {
  record: null,
  tab: "yaml",
  view: "pipeline",
  pane: "intel",
  running: false,
  feed: [],
  catalog: [],
  profile: null,
};

const TAB_HINTS = {
  yaml: "Generic Sigma YAML. Vendor queries are on the other tabs.",
  splunk: "Splunk SPL. Hunt first; do not enable as a live correlation until tested.",
  elastic: "Elastic query / DSL for Kibana.",
  kql: "Microsoft Sentinel / Defender KQL.",
  wazuh: "Wazuh XML for local_rules. Import disabled until the atomic test fires.",
  lc: "LimaCharlie D&R YAML. Created with enabled: false.",
  hunt: "Same logic, last 30–90 days. Use this for “were we already compromised?”",
  atomic: "Staging-only. C2 IPs and URLs are replaced with example.com / TEST-NET-3.",
};

const PROFILE_KEY = "cve2detect.profile";
const SESSION_KEY = "cve2detect.session.records";

const $ = (id) => document.getElementById(id);

function readProfile() {
  try {
    return JSON.parse(localStorage.getItem(PROFILE_KEY) || "{}");
  } catch {
    return {};
  }
}

function writeProfile(profile) {
  localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
}

function sessionRecords() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "[]");
  } catch {
    return [];
  }
}

function rememberRecord(record) {
  if (!record || !record.id) return;
  const list = sessionRecords().filter((r) => r.id !== record.id);
  list.unshift(record);
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(list.slice(0, 40)));
}

function clock() {
  if (!$("clock")) return;
  $("clock").textContent = new Date().toISOString().replace("T", " ").slice(0, 19) + "Z";
}

function pill(label, ok) {
  const el = document.createElement("span");
  el.className = "pill " + (ok ? "ok" : "missing");
  el.textContent = label + (ok ? " live" : " missing");
  return el;
}

async function loadHealth() {
  const res = await fetch("/api/health");
  const data = await res.json();
  const host = $("key-pills");
  host.innerHTML = "";
  const fetchOk = data.keys && (data.keys.fetch ?? data.keys.tinyfish);
  const llmOk = data.keys && (data.keys.llm ?? data.keys.gemini);
  host.append(pill("Fetch", !!fetchOk), pill("LLM", !!llmOk));
}

function setStatus(msg) {
  $("status-line").textContent = msg;
}

function setTabHint() {
  if ($("tab-hint")) $("tab-hint").textContent = TAB_HINTS[state.tab] || "";
}

function setStage(name, kind) {
  document.querySelectorAll(".stage").forEach((el) => {
    const stage = el.dataset.stage;
    el.classList.remove("active", "done", "error");
    if (kind === "error" && stage === name) el.classList.add("error");
    else if (stage === name) el.classList.add(kind || "active");
    else if (
      ["ingest", "extract", "validate", "store"].indexOf(stage) <
      ["ingest", "extract", "validate", "store"].indexOf(name)
    ) {
      el.classList.add("done");
    }
  });
}

function resetStages() {
  document.querySelectorAll(".stage").forEach((el) => {
    el.classList.remove("active", "done", "error");
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderFeed() {
  const host = $("feed");
  if (!state.feed.length) {
    host.innerHTML = '<div class="empty-inline">No results yet. Run Scan 24h or paste an advisory URL.</div>';
    return;
  }
  host.innerHTML = state.feed
    .map(
      (item) => `
      <article class="feed-item" data-url="${escapeHtml(item.url)}">
        <div class="site">${escapeHtml(item.site_name || "web")}</div>
        <h3>${escapeHtml(item.title)}</h3>
        <p>${escapeHtml(item.snippet || item.url)}</p>
      </article>`
    )
    .join("");
  host.querySelectorAll(".feed-item").forEach((el) => {
    el.addEventListener("click", () => {
      $("url").value = el.dataset.url;
      host.querySelectorAll(".feed-item").forEach((n) => n.classList.remove("active"));
      el.classList.add("active");
      switchView("pipeline");
      setPane("intel");
      closeRail();
    });
  });
}

async function loadFeed() {
  const res = await fetch("/api/feed");
  const data = await res.json();
  state.feed = data.items || [];
  renderFeed();
}

function chips(items, cls) {
  if (!items || !items.length) return '<span class="empty-inline">None extracted.</span>';
  return `<div class="chips">${items
    .map((t) => {
      if (typeof t === "string") return `<span class="chip ${cls}">${escapeHtml(t)}</span>`;
      const label = t.id ? `${t.id} ${t.name || ""}` : t.name || JSON.stringify(t);
      return `<span class="chip ${cls}">${escapeHtml(label)}</span>`;
    })
    .join("")}</div>`;
}

function renderIntel(record) {
  const stamp = $("confidence-stamp");
  const conf = (record.confidence || "").toLowerCase();
  stamp.textContent = conf ? `confidence ${conf}` : "";
  stamp.className = "stamp " + (conf || "");
  const match = $("match-stamp");
  if (!record.stack_configured) {
    match.textContent = "no profile";
    match.className = "stamp";
  } else if (record.stack_match) {
    match.textContent = "stack match";
    match.className = "stamp valid";
  } else {
    match.textContent = "out of scope";
    match.className = "stamp invalid";
  }

  const affected = (record.affected || [])
    .map((a) => `${a.vendor} ${a.product} (${a.versions})`)
    .join(" · ");
  const telemetry = (record.telemetry || [])
    .map(
      (t) => `<div class="tele-row"><span class="eid">${escapeHtml(t.source)}/${escapeHtml(t.event_id)}</span>
        <b>${escapeHtml(t.name)}</b> — ${escapeHtml(t.description)}</div>`
    )
    .join("");
  const procs = (record.process_anomalies || [])
    .map(
      (p) => `<div class="proc-row"><code>${escapeHtml(p.parent_image)}</code>
        → <code>${escapeHtml(p.child_image)}</code><br/>${escapeHtml(p.command_line)}
        <div class="empty-inline">${escapeHtml(p.notes)}</div></div>`
    )
    .join("");
  const iocs = (record.indicators || [])
    .map(
      (i) => `<div class="ioc-row"><b>${escapeHtml(i.type)}</b> <code>${escapeHtml(i.value)}</code>
        <div class="empty-inline">${escapeHtml(i.context)}</div></div>`
    )
    .join("");

  $("intel-body").innerHTML = `
    <div class="meta-grid">
      <div><span>CVE</span><b>${escapeHtml(record.cve || "unassigned")}</b></div>
      <div><span>CVSS</span><b class="cvss">${escapeHtml(record.cvss || "—")}</b></div>
      <div><span>Type</span><b>${escapeHtml(record.vulnerability_type || "—")}</b></div>
      <div><span>Threat actor</span><b>${escapeHtml(record.threat_actor || "unattributed")}</b></div>
      <div><span>Campaign</span><b>${escapeHtml(record.campaign || "—")}</b></div>
      <div><span>Source</span><b>${escapeHtml(record.site_name || record.fetch_method || "—")}</b></div>
    </div>
    <p class="summary">${escapeHtml(record.summary || "")}</p>
    <div class="block-title">Affected software</div>
    <p class="summary">${escapeHtml(affected || "Not specified")}</p>
    ${record.stack_reason ? `<p class="summary">${escapeHtml(record.stack_reason)}</p>` : ""}
    <div class="block-title">MITRE ATT&amp;CK</div>
    ${chips(record.techniques, "attack")}
    <div class="block-title">Host telemetry</div>
    ${telemetry || '<span class="empty-inline">No host events extracted.</span>'}
    <div class="block-title">Process tree / command lines</div>
    ${procs || '<span class="empty-inline">No process anomalies extracted.</span>'}
    <div class="block-title">IoCs</div>
    ${iocs || '<span class="empty-inline">No indicators extracted.</span>'}
    ${record.caveats ? `<div class="block-title">Analyst notes</div><p class="summary">${escapeHtml(record.caveats)}</p>` : ""}
  `;
}

function formatAtomic(record) {
  const tests = record.atomic_tests || [];
  if (!tests.length) return "// No atomic test generated.";
  return tests
    .map((t) => `# ${t.title} (${t.platform})\n# ${t.note}\n${t.command}`)
    .join("\n\n");
}

function formatHunt(record) {
  const hunt = record.retrohunt || {};
  const parts = [];
  if (hunt.note) parts.push(`# ${hunt.note}`);
  if (hunt.splunk) parts.push(`# Splunk\n${hunt.splunk}`);
  if (hunt.elastic) parts.push(`# Elastic\n${hunt.elastic}`);
  if (hunt.sentinel) parts.push(`# Sentinel KQL\n${hunt.sentinel}`);
  return parts.join("\n\n") || "// Retro-hunt unavailable until a SIEM query exists.";
}

function currentQuery(record) {
  if (!record) return "";
  if (state.tab === "splunk") return record.splunk_spl || "// Splunk query unavailable";
  if (state.tab === "elastic") return record.elastic_dsl || "// Elastic query unavailable";
  if (state.tab === "kql") return record.sentinel_kql || "// Sentinel KQL unavailable";
  if (state.tab === "wazuh") return record.wazuh_xml || "// Wazuh XML unavailable";
  if (state.tab === "lc") return record.limacharlie_yaml || "// LimaCharlie D&R unavailable";
  if (state.tab === "hunt") return formatHunt(record);
  if (state.tab === "atomic") return formatAtomic(record);
  return record.sigma_yaml || "// No Sigma YAML";
}

function renderRule(record) {
  const stamp = $("valid-stamp");
  if (record.sigma_valid) {
    stamp.textContent = "validated";
    stamp.className = "stamp valid";
  } else {
    stamp.textContent = "needs review";
    stamp.className = "stamp invalid";
  }
  setTabHint();
  $("code-view").querySelector("code").textContent = currentQuery(record);
}

function showRecord(record) {
  state.record = record;
  renderIntel(record);
  renderRule(record);
}

function normalizeUrl(raw) {
  const text = (raw || "").trim();
  const md = text.match(/\]\(\s*(https?:\/\/[^\s)]+)/i);
  let candidate = md ? md[1] : (text.match(/https?:\/\/[^\s<>"']+/i) || [text])[0];
  if (candidate.includes("](")) candidate = candidate.split("](")[0];
  return candidate.replace(/^<|>$/g, "").replace(/[).,;>\]]+$/g, "");
}

async function runPipeline({ url = "", useSample = false, markdown = "" } = {}) {
  if (state.running) return;
  state.running = true;
  $("btn-run").disabled = true;
  resetStages();
  setStage("ingest", "active");
  setStatus("Starting pipeline…");
  switchView("pipeline");
  try {
    const res = await fetch("/api/pipeline", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        use_sample: useSample,
        markdown,
        assets: readProfile().assets || [],
        hunt_days: Number(readProfile().hunt_days || 90),
      }),
    });
    if (!res.ok && !res.body) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Pipeline failed");
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const chunks = buf.split("\n\n");
      buf = chunks.pop() || "";
      for (const chunk of chunks) {
        const line = chunk.split("\n").find((l) => l.startsWith("data: "));
        if (!line) continue;
        const event = JSON.parse(line.slice(6));
        if (event.stage && event.stage !== "error") setStage(event.stage, "active");
        if (event.message) setStatus(event.message);
        if (event.event === "complete" && event.record) {
          setStage("store", "done");
          showRecord(event.record);
          rememberRecord(event.record);
          await loadFeed();
          loadArchive();
          if (isNarrow()) {
            setPane("output");
            if ($("sigma-col")) $("sigma-col").scrollIntoView({ behavior: "smooth", block: "start" });
          }
        }
        if (event.event === "error") {
          setStage(event.stage || "ingest", "error");
          setStatus(event.message);
        }
      }
    }
  } catch (err) {
    setStage("ingest", "error");
    setStatus(err.message || String(err));
  } finally {
    state.running = false;
    $("btn-run").disabled = false;
  }
}

function isNarrow() {
  return window.matchMedia("(max-width: 1100px)").matches;
}

function openRail() {
  document.body.classList.add("rail-open");
  if ($("btn-open-rail")) $("btn-open-rail").setAttribute("aria-expanded", "true");
  if ($("backdrop")) $("backdrop").hidden = false;
}

function closeRail() {
  document.body.classList.remove("rail-open");
  if ($("btn-open-rail")) $("btn-open-rail").setAttribute("aria-expanded", "false");
  if ($("backdrop")) $("backdrop").hidden = true;
}

function setPane(pane) {
  state.pane = pane === "output" ? "output" : "intel";
  if ($("split")) {
    $("split").classList.toggle("show-intel", state.pane === "intel");
    $("split").classList.toggle("show-output", state.pane === "output");
  }
  document.querySelectorAll("[data-pane]").forEach((btn) => {
    btn.classList.toggle("on", btn.dataset.pane === state.pane);
  });
}

function switchView(view) {
  state.view = view;
  document.querySelectorAll("[data-view]").forEach((btn) => {
    btn.classList.toggle("on", btn.dataset.view === view);
  });
  $("pipeline-view").classList.toggle("hidden", view !== "pipeline");
  $("split").classList.toggle("hidden", view !== "pipeline");
  if ($("pane-switch")) $("pane-switch").classList.toggle("hidden", view !== "pipeline");
  $("archive-view").classList.toggle("hidden", view !== "archive");
  $("estate-view").classList.toggle("hidden", view !== "estate");
  if (view !== "pipeline") closeRail();
}

function loadArchive(q = "") {
  const matchesOnly = $("matches-only") && $("matches-only").checked;
  const needle = (q || "").toLowerCase();
  let items = sessionRecords();
  if (matchesOnly) items = items.filter((i) => i.stack_match);
  if (needle) {
    items = items.filter((i) =>
      [i.title, i.cve, i.threat_actor, i.logsource_product, i.logsource_category]
        .join(" ")
        .toLowerCase()
        .includes(needle)
    );
  }
  const host = $("archive-list");
  if (!items.length) {
    host.innerHTML =
      '<div class="empty">No runs in this browser session. Pipeline results are not saved on the server.</div>';
    return;
  }
  host.innerHTML = items
    .map((item) => {
      let tag = item.sigma_valid ? "VALID" : "REVIEW";
      if (item.stack_match) tag = "MATCH · " + tag;
      else if (item.stack_configured) tag = "OOS · " + tag;
      return `
      <button type="button" class="archive-card" data-id="${escapeHtml(item.id)}">
        <div>
          <b>${escapeHtml(item.title)}</b><br/>
          <small>${escapeHtml(item.cve || "no CVE")} · ${escapeHtml(item.logsource_product || "")} ${escapeHtml(item.logsource_category || "")} · ${escapeHtml(item.threat_actor || "")}</small>
        </div>
        <small>${escapeHtml(tag)}</small>
      </button>`;
    })
    .join("");
  host.querySelectorAll(".archive-card").forEach((el) => {
    el.addEventListener("click", () => {
      const rec = sessionRecords().find((r) => r.id === el.dataset.id);
      if (!rec) return;
      showRecord(rec);
      switchView("pipeline");
      setPane("intel");
      setStatus("Loaded " + rec.title + " from this session.");
    });
  });
}

async function discover() {
  openRail();
  setStatus("Running 24h discovery…");
  $("btn-discover").disabled = true;
  try {
    const res = await fetch("/api/discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Discovery failed");
    state.feed = data.items || [];
    renderFeed();
    setStatus(`Discovery complete — ${data.count} unique articles.`);
  } catch (err) {
    setStatus(err.message || String(err));
  } finally {
    $("btn-discover").disabled = false;
  }
}

$("run-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const markdown = ($("markdown") && $("markdown").value) || "";
  const cleaned = normalizeUrl($("url").value);
  $("url").value = cleaned;
  runPipeline({ url: cleaned, markdown });
});
$("btn-sample").addEventListener("click", () => runPipeline({ useSample: true }));
$("btn-discover").addEventListener("click", discover);
$("url").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    const cleaned = normalizeUrl($("url").value);
    $("url").value = cleaned;
    runPipeline({ url: cleaned });
  }
});
document.querySelectorAll("[data-view]").forEach((btn) => {
  btn.addEventListener("click", () => {
    switchView(btn.dataset.view);
    if (btn.dataset.view === "archive") loadArchive($("archive-q").value);
    if (btn.dataset.view === "estate") loadEstate();
  });
});
document.querySelectorAll("[data-pane]").forEach((btn) => {
  btn.addEventListener("click", () => setPane(btn.dataset.pane));
});
if ($("btn-open-rail")) $("btn-open-rail").addEventListener("click", openRail);
if ($("btn-close-rail")) $("btn-close-rail").addEventListener("click", closeRail);
if ($("backdrop")) $("backdrop").addEventListener("click", closeRail);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") closeRail();
});
document.querySelectorAll("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.tab = btn.dataset.tab;
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("on", b === btn));
    if (state.record) renderRule(state.record);
    else setTabHint();
  });
});
$("btn-copy").addEventListener("click", async () => {
  if (!state.record) return;
  await navigator.clipboard.writeText(currentQuery(state.record));
  $("btn-copy").textContent = "Copied";
  setTimeout(() => ($("btn-copy").textContent = "Copy"), 1200);
});
$("btn-download").addEventListener("click", () => {
  if (!state.record) return;
  const blob = new Blob([state.record.sigma_yaml || currentQuery(state.record)], { type: "text/yaml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = (state.record.cve || "rule").replaceAll("/", "-") + ".yml";
  a.click();
});
$("archive-q").addEventListener("input", () => loadArchive($("archive-q").value));
$("matches-only").addEventListener("change", () => loadArchive($("archive-q").value));

async function loadEstate() {
  const cat = await fetch("/api/estate/catalog").then((r) => r.json());
  state.catalog = cat.assets || [];
  const prof = readProfile();
  state.profile = prof;
  const selected = new Set(prof.assets || []);
  $("asset-grid").innerHTML = state.catalog
    .map(
      (a) => `<label class="asset-chip"><input type="checkbox" value="${escapeHtml(a.id)}" ${
        selected.has(a.id) ? "checked" : ""
      }/> ${escapeHtml(a.label)}</label>`
    )
    .join("");
  if ($("hunt-days")) $("hunt-days").value = String(prof.hunt_days || 90);
}

$("btn-save-estate").addEventListener("click", () => {
  const assets = [...$("asset-grid").querySelectorAll("input:checked")].map((el) => el.value);
  writeProfile({
    assets,
    hunt_days: Number($("hunt-days") ? $("hunt-days").value : 90),
  });
  setStatus("Stack profile saved in this browser. New runs will tag matches. Nothing was sent to the server except the asset list on the next pipeline run.");
});

async function boot() {
  clock();
  setInterval(clock, 1000);
  await loadHealth();
  await loadFeed();
  loadArchive();
  setTabHint();
  const params = new URLSearchParams(location.search);
  if (params.get("view") === "archive") switchView("archive");
  if (params.get("view") === "estate") {
    switchView("estate");
    await loadEstate();
  }
  const recId = params.get("record");
  if (!recId) return;
  const rec = sessionRecords().find((r) => r.id === recId);
  if (rec) {
    showRecord(rec);
    setStatus("Loaded " + rec.title + " from this session.");
  }
}

boot();
