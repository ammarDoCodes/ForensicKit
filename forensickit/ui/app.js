/* Thin presentation layer: all evidence and derived objects come from the local API. */

const state = {
  caseId: null,
  overview: null,
  events: [],
  eventConfidence: {},
  timelineTotal: 0,
  timelineTruncated: false,
  threads: [],
  entities: [],
  investigation: { hypotheses: [], notes: [], decisions: [] },
  activeThread: null,
  graph: null,
  assistant: null,
  csrfToken: null,
  username: null,
  themePreference: "system",
};

const $ = (id) => document.getElementById(id);

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function jsonText(value) {
  try { return JSON.stringify(value, null, 2); } catch (_) { return "[unavailable]"; }
}

function empty(node, message) {
  clear(node);
  node.appendChild(element("div", "empty", message));
}

function setError(message) {
  const node = $("app-error");
  if (!message) { node.hidden = true; node.textContent = ""; return; }
  node.hidden = false;
  node.textContent = message;
}

function setConnectionStatus(label) {
  const node = $("connection-state");
  node.textContent = label;
  node.classList.toggle("is-pending", label === "Connecting");
  node.classList.toggle("is-unavailable", label === "Unavailable");
}

async function api(path, options = {}) {
  const headers = { "Accept": "application/json", ...(options.headers || {}) };
  if ((options.method || "GET").toUpperCase() === "POST" && state.csrfToken) headers["X-FK-CSRF"] = state.csrfToken;
  const response = await fetch(path, { ...options, credentials: "same-origin", headers });
  let body;
  try { body = await response.json(); } catch (_) { throw new Error("The local workbench returned an invalid response."); }
  if (!body || typeof body !== "object") throw new Error("The local workbench returned an invalid response.");
  if (response.status === 401 && body.error?.code === "AUTHENTICATION_REQUIRED") {
    state.csrfToken = null;
    showAuthScreen({ setup_required: false, authenticated: false }, "Your local session ended. Sign in again to continue.");
  }
  if (!response.ok) throw new Error(body.error?.message || "The local workbench request failed.");
  return body;
}

function setAuthMessage(message, kind = "error") {
  const node = $("auth-message");
  node.textContent = message || "";
  node.hidden = !message;
  node.classList.toggle("is-error", kind === "error");
  node.classList.toggle("is-success", kind === "success");
}

function showAuthScreen(authState, message = "") {
  $("workbench-shell").hidden = true;
  $("auth-screen").hidden = false;
  const setupRequired = Boolean(authState?.setup_required);
  $("setup-form").hidden = !setupRequired;
  $("login-form").hidden = setupRequired;
  $("auth-title").textContent = setupRequired ? "Secure your investigation workspace" : "Sign in to your investigation workspace";
  setAuthMessage(message);
}

async function authRequest(path, payload) {
  const response = await fetch(path, {
    method: "POST", credentials: "same-origin",
    headers: { "Accept": "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  let body;
  try { body = await response.json(); } catch (_) { throw new Error("The local sign-in service returned an invalid response."); }
  if (!body || typeof body !== "object") throw new Error("The local sign-in service returned an invalid response.");
  if (!response.ok) throw new Error(body.error?.message || "Local sign-in could not be completed.");
  return body;
}

function applyThemePreference(preference) {
  state.themePreference = ["system", "light", "dark"].includes(preference) ? preference : "system";
  const root = document.documentElement;
  if (state.themePreference === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", state.themePreference);
  document.querySelectorAll("[data-theme-choice]").forEach((button) => {
    const selected = button.dataset.themeChoice === state.themePreference;
    button.setAttribute("aria-pressed", String(selected));
    button.classList.toggle("is-selected", selected);
  });
}

async function loadUserSettings() {
  const response = await api("/api/settings");
  applyThemePreference(response.data?.theme);
}

async function completeAuthentication(response) {
  state.csrfToken = response.data?.csrf_token || null;
  state.username = response.data?.username || null;
  if (!state.csrfToken || !state.username) throw new Error("The local sign-in response was incomplete.");
  $("signed-in-as").textContent = `Analyst · ${state.username}`;
  $("auth-screen").hidden = true;
  $("workbench-shell").hidden = false;
  setAuthMessage("");
  try { await loadUserSettings(); } catch (_) { applyThemePreference("system"); }
  await loadWorkbench();
}

async function checkAuthentication() {
  try {
    const response = await fetch("/api/auth/state", { credentials: "same-origin", headers: { "Accept": "application/json" } });
    let body;
    try { body = await response.json(); } catch (_) { throw new Error("The local sign-in service returned an invalid response."); }
    if (!response.ok || !body?.data) throw new Error("The local sign-in service is unavailable.");
    const authState = body.data;
    if (authState.authenticated) {
      await completeAuthentication({ data: authState });
      return;
    }
    showAuthScreen(authState);
  } catch (error) {
    showAuthScreen({ setup_required: false }, error.message);
  }
}

function bindAuthentication() {
  $("setup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const password = values.get("password");
    if (password !== values.get("password_confirm")) return setAuthMessage("The passwords do not match.");
    const submit = form.querySelector("button[type=submit]"); submit.disabled = true; submit.textContent = "Creating local account…";
    try {
      const response = await authRequest("/api/auth/setup", { setup_code: values.get("setup_code"), username: values.get("username"), password });
      form.reset();
      await completeAuthentication(response);
    } catch (error) { setAuthMessage(error.message); }
    finally { submit.disabled = false; submit.textContent = "Create local account"; }
  });
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const submit = form.querySelector("button[type=submit]"); submit.disabled = true; submit.textContent = "Signing in…";
    try {
      const response = await authRequest("/api/auth/login", { username: values.get("username"), password: values.get("password") });
      form.reset();
      await completeAuthentication(response);
    } catch (error) { setAuthMessage(error.message); }
    finally { submit.disabled = false; submit.textContent = "Sign in to case"; }
  });
  $("logout-button").addEventListener("click", async () => {
    try { await post("/api/auth/logout", {}); } catch (_) { /* Session expiry already invalidates the cookie. */ }
    state.csrfToken = null; state.username = null;
    showAuthScreen({ setup_required: false }, "You have signed out.");
  });
  document.querySelectorAll("[data-theme-choice]").forEach((button) => button.addEventListener("click", async () => {
    const previous = state.themePreference;
    const next = button.dataset.themeChoice;
    if (!["system", "light", "dark"].includes(next) || next === previous) return;
    applyThemePreference(next);
    try { await post("/api/settings", { theme: next }); }
    catch (error) { applyThemePreference(previous); setError(error.message); }
  }));
  const media = window.matchMedia?.("(prefers-color-scheme: dark)");
  media?.addEventListener?.("change", () => { if (state.themePreference === "system") applyThemePreference("system"); });
}

function casePath(path) {
  return `/api/cases/${encodeURIComponent(state.caseId)}${path}`;
}

function formatTime(value) {
  return value || "Unknown time";
}

function badge(value) {
  return element("span", `badge ${String(value || "unknown")}`, value || "unknown");
}

function addPills(parent, values, onClick) {
  const wrap = element("div", "pills");
  (values || []).forEach((value) => {
    const node = onClick ? element("button", "pill pill-button", value) : element("span", "pill", value);
    if (onClick) node.addEventListener("click", () => onClick(value));
    wrap.appendChild(node);
  });
  parent.appendChild(wrap);
}

function appendDefinition(parent, label, value) {
  const dt = element("dt", null, label);
  const display = value === undefined || value === null ? "—" : (typeof value === "string" ? value : jsonText(value));
  const dd = element("dd", null, display);
  parent.appendChild(dt); parent.appendChild(dd);
}

function renderCounts() {
  const cards = $("count-cards"); clear(cards);
  const labels = { events: "Events", entities: "Entities", relationships: "Relationships", threads: "Threads", warnings: "Warnings", gaps: "Evidence gaps", contradictions: "Contradictions", hypotheses: "Hypotheses" };
  const viewByCount = { events: "timeline", entities: "pivot", relationships: "graph", threads: "threads", hypotheses: "investigation" };
  Object.entries(labels).forEach(([key, label]) => {
    const view = viewByCount[key];
    const card = element(view ? "button" : "div", `card${view ? " card-link" : ""}`);
    if (view) {
      card.type = "button";
      card.setAttribute("aria-label", `Open ${label.toLowerCase()} view`);
      card.addEventListener("click", () => switchView(view));
    }
    card.appendChild(element("strong", null, state.overview.counts?.[key] ?? 0));
    card.appendChild(element("span", null, label));
    cards.appendChild(card);
  });
}

function renderOverview() {
  renderCounts();
  const manifest = state.overview.manifest || {};
  $("case-id").textContent = manifest.case_id || state.caseId || "Unknown case";
  $("overview-version").textContent = `Schema ${state.overview.versions?.schema_version || "unknown"}`;
  const navCounts = {
    "nav-overview-count": state.overview.counts?.warnings || 0,
    "nav-timeline-count": state.overview.counts?.events || 0,
    "nav-threads-count": state.overview.counts?.threads || 0,
    "nav-graph-count": state.overview.counts?.relationships || 0,
    "nav-pivot-count": state.overview.counts?.entities || 0,
    "nav-investigation-count": (state.overview.counts?.hypotheses || 0) + (state.overview.counts?.notes || 0) + (state.overview.counts?.decisions || 0),
  };
  Object.entries(navCounts).forEach(([id, count]) => {
    const countNode = $(id);
    if (!countNode) return;
    countNode.textContent = String(count);
    const button = countNode.closest(".nav-button");
    if (button) button.setAttribute("aria-label", `${button.title} (${count})`);
  });
  const table = $("inputs-table"); clear(table);
  const inputs = manifest.inputs || [];
  if (!inputs.length) { empty(table, "No imported inputs were recorded."); }
  else {
    const tableNode = element("table");
    const head = element("tr"); ["File", "SHA-256", "Format", "Size"].forEach((label) => head.appendChild(element("th", null, label)));
    tableNode.appendChild(head);
    inputs.forEach((item) => {
      const row = element("tr");
      [item.relative_path || "Unknown", item.sha256 || "Unknown", item.detected_format || "Unknown", `${item.size_bytes ?? "?"} bytes`].forEach((value) => row.appendChild(element("td", "mono", value)));
      tableNode.appendChild(row);
    });
    table.appendChild(tableNode);
  }
  $("config-view").textContent = jsonText({ analysis_config: state.overview.analysis_config || {}, versions: state.overview.versions || {}, analysis_config_hash: manifest.analysis_config_hash || null });
  const warnings = state.overview.warnings || [];
  $("warning-count").textContent = String(warnings.length);
  const warningList = $("warnings-list"); clear(warningList);
  if (!warnings.length) empty(warningList, "No parser warnings were reported.");
  warnings.forEach((warning) => {
    const item = element("div", "warning");
    item.appendChild(element("strong", null, warning.code || "WARNING"));
    item.appendChild(element("span", null, warning.message || "No warning message supplied."));
    item.appendChild(element("div", "quiet mono", `${warning.source_file_id || "unknown source"} · ${warning.source_locator || "unknown location"}`));
    warningList.appendChild(item);
  });
}

function populateEventFilters() {
  const select = $("filter-event-type"); clear(select); select.appendChild(element("option", null, "All types")); select.firstChild.value = "";
  [...new Set(state.events.map((event) => event.event_type).filter(Boolean))].sort().forEach((type) => {
    const option = element("option", null, type); option.value = type; select.appendChild(option);
  });
}

function eventMatches(event) {
  const type = $("filter-event-type").value;
  const host = $("filter-host").value.trim().toLowerCase();
  const user = $("filter-user").value.trim().toLowerCase();
  const entity = $("filter-entity").value.trim().toLowerCase();
  const confidence = $("filter-confidence").value;
  const entities = (event.entities || []).map((item) => item.entity_id || "");
  if (type && event.event_type !== type) return false;
  if (host && !(event.host_id || "").toLowerCase().includes(host)) return false;
  if (user && !entities.some((item) => item.toLowerCase().includes(user))) return false;
  if (entity && !entities.some((item) => item.toLowerCase().includes(entity))) return false;
  if (confidence && state.eventConfidence[event.event_id] !== confidence) return false;
  return true;
}

function renderEvent(event, container, compact = false) {
  const card = element("article", compact ? "event compact" : "event");
  const time = element("div", "event-time");
  time.appendChild(element("strong", null, formatTime(event.observed_at?.utc)));
  time.appendChild(element("span", null, `Original: ${formatTime(event.observed_at?.original)}`));
  time.appendChild(element("span", null, `Time quality: ${event.observed_at?.quality || "unknown"}`));
  card.appendChild(time);
  const main = element("div", "event-main");
  main.appendChild(element("h3", null, event.event_type || "unknown event"));
  main.appendChild(element("p", null, `${event.event_id || "unknown event id"} · ${event.host_id || "host unknown"}`));
  addPills(main, (event.entities || []).map((item) => item.entity_id).filter(Boolean), (id) => pivotEntity(id));
  if (!compact && event.source_payload) main.appendChild(element("pre", "code-block", jsonText(event.source_payload)));
  card.appendChild(main);
  const side = element("div", "event-side");
  side.appendChild(badge(state.eventConfidence[event.event_id] || "unknown"));
  const source = element("button", "button secondary", "Provenance"); source.addEventListener("click", () => showProvenance(event, "Event provenance")); side.appendChild(source);
  card.appendChild(side);
  container.appendChild(card);
}

function renderTimeline() {
  const list = $("timeline-list"); clear(list);
  const filtered = state.events.filter(eventMatches);
  $("timeline-count").textContent = `${filtered.length} of ${state.timelineTotal || state.events.length} events`;
  if (state.timelineTruncated) {
    const bounded = element("div", "warning"); bounded.appendChild(element("strong", null, "BOUNDED VIEW")); bounded.appendChild(element("span", null, `Showing the first ${state.events.length} timeline events. Use the API limit/offset parameters or CLI exports for the complete case.`)); list.appendChild(bounded);
  }
  if (!filtered.length) return empty(list, "No events match the selected filters.");
  filtered.forEach((event) => renderEvent(event, list));
}

function renderThreads() {
  const list = $("thread-list"); clear(list);
  $("thread-count").textContent = `${state.threads.length} candidate thread${state.threads.length === 1 ? "" : "s"}`;
  if (!state.threads.length) return empty(list, "No candidate threads were generated.");
  state.threads.forEach((thread) => {
    const card = element("article", "thread-card");
    const heading = element("div", "panel-heading");
    const title = element("div"); title.appendChild(element("h3", null, thread.title || thread.thread_id)); title.appendChild(element("p", null, `${thread.thread_id} · ${thread.status || "candidate"}`));
    heading.appendChild(title); heading.appendChild(badge(thread.confidence)); card.appendChild(heading);
    const range = thread.time_range || {}; card.appendChild(element("p", null, `${formatTime(range.start_utc)} → ${formatTime(range.end_utc)}${range.uncertain ? " · time uncertain" : ""}`));
    addPills(card, thread.related_entities || thread.entity_ids, (id) => pivotEntity(id));
    card.appendChild(element("p", null, `${(thread.supporting_evidence_ids || []).length} supporting evidence · ${(thread.contradiction_ids || []).length} contradictions · ${(thread.gap_ids || []).length} gaps`));
    const open = element("button", "button primary", "Open replay"); open.addEventListener("click", () => openThread(thread.thread_id)); card.appendChild(open);
    list.appendChild(card);
  });
}

function appendReferenceSection(parent, title, values, emptyMessage) {
  const section = element("div", "detail-section"); section.appendChild(element("h4", null, title));
  if (!values || !values.length) section.appendChild(element("div", "empty", emptyMessage || "None recorded."));
  else values.forEach((value) => {
    const row = element("div", "object-card"); row.appendChild(element("div", null, value)); section.appendChild(row);
  });
  parent.appendChild(section);
}

function renderReplay(detail, replayData) {
  const replayBox = element("div", "detail-section");
  replayBox.appendChild(element("h4", null, "Incident replay"));
  replayBox.appendChild(element("p", null, `${replayData.confidence || "unknown"} confidence · ${replayData.time_uncertain ? "time uncertainty present" : "timestamps exact"}`));
  const boundedParts = Object.entries(replayData.result_bounds || {}).filter(([, bound]) => bound.truncated).map(([kind, bound]) => `${bound.returned} of ${bound.total} ${kind}`);
  if (boundedParts.length) replayBox.appendChild(element("div", "warning", `This replay is bounded: ${boundedParts.join(", ")}.`));
  const events = replayData.events || [];
  const relationships = replayData.relationships || [];
  const gaps = replayData.gaps || [];
  const contradictions = replayData.contradictions || [];
  const shown = new Set();
  if (!events.length) replayBox.appendChild(element("div", "empty", "The replay has no available events."));
  events.forEach((event) => {
    const step = element("div", "replay-step");
    step.appendChild(element("div", "eyebrow", "OBSERVED"));
    renderEvent(event, step, true);
    relationships.filter((relationship) => relationship.evidence_ids?.includes(event.event_id) && !shown.has(relationship.relationship_id)).forEach((relationship) => {
      shown.add(relationship.relationship_id);
      const derived = element("div", "object-card");
      derived.appendChild(element("div", "eyebrow", "DERIVED"));
      derived.appendChild(element("strong", null, `${relationship.type || "relationship"} · ${relationship.strength || "unknown"}`));
      derived.appendChild(element("p", null, relationship.explanation || "No relationship explanation supplied."));
      derived.appendChild(element("div", "quiet mono", `${relationship.rule_id || "rule"}@${relationship.rule_version || "unknown"} · ${relationship.relationship_id || "unknown"}`));
      const provenance = element("button", "button secondary", "Relationship provenance"); provenance.addEventListener("click", () => showProvenance(relationship, "Relationship provenance")); derived.appendChild(provenance);
      step.appendChild(derived);
    });
    gaps.filter((gap) => (gap.affected_event_ids || []).includes(event.event_id)).forEach((gap) => {
      const item = element("div", "warning"); item.appendChild(element("strong", null, "EVIDENCE GAP")); item.appendChild(element("span", null, gap.description || gap.reason || "Unresolved evidence gap.")); step.appendChild(item);
    });
    contradictions.filter((contradiction) => (contradiction.evidence_ids || []).includes(event.event_id)).forEach((contradiction) => {
      const item = element("div", "warning"); item.appendChild(element("strong", null, "CONTRADICTION")); item.appendChild(element("span", null, contradiction.description || contradiction.type || "Contradiction detected.")); step.appendChild(item);
    });
    replayBox.appendChild(step);
  });
  if (shown.size < relationships.length) appendReferenceSection(replayBox, "Other derived relationships", relationships.filter((item) => !shown.has(item.relationship_id)).map((item) => `${item.relationship_id}: ${item.explanation || item.type}`));
  detail.appendChild(replayBox);
}

async function openThread(threadId) {
  try {
    setError("");
    const response = await api(casePath(`/threads/${encodeURIComponent(threadId)}?replay=1`));
    state.activeThread = response.data;
    const detail = $("thread-detail"); clear(detail); detail.hidden = false;
    const thread = response.data.thread;
    const heading = element("div", "panel-heading"); heading.appendChild(element("h3", null, thread.title || thread.thread_id)); heading.appendChild(badge(thread.confidence)); detail.appendChild(heading);
    detail.appendChild(element("p", null, `${thread.status || "candidate"} · ${thread.thread_id}`));
    addPills(detail, thread.entity_ids, (id) => pivotEntity(id));
    appendReferenceSection(detail, "Supporting evidence", thread.supporting_evidence_ids, "No supporting evidence references.");
    appendReferenceSection(detail, "Contradictions", thread.contradiction_ids, "No contradictions recorded.");
    appendReferenceSection(detail, "Evidence gaps", thread.gap_ids, "No evidence gaps recorded.");
    renderReplay(detail, response.data.replay);
    detail.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) { setError(error.message); }
}

function renderEntitiesSelect() {
  const select = $("pivot-entity"); clear(select);
  state.entities.forEach((entity) => {
    const option = element("option", null, `${entity.type || "entity"}: ${entity.display_name || entity.entity_id}`); option.value = entity.entity_id; select.appendChild(option);
  });
}

function renderReportScopeOptions() {
  const scope = $("report-scope").value;
  const wrapper = $("report-scope-id-wrap");
  const select = $("report-scope-id");
  const downloadButton = $("report-download");
  const requiresId = scope === "thread" || scope === "hypothesis";
  wrapper.hidden = !requiresId;
  clear(select);
  if (!requiresId) { select.disabled = true; downloadButton.disabled = false; return; }
  const records = scope === "thread" ? state.threads : (state.investigation.hypotheses || []);
  const idField = scope === "thread" ? "thread_id" : "hypothesis_id";
  const ordered = [...records].sort((a, b) => {
    const left = String(a?.[idField] || ""); const right = String(b?.[idField] || "");
    return left < right ? -1 : left > right ? 1 : 0;
  });
  if (!ordered.length) {
    const option = element("option", null, scope === "thread" ? "No candidate threads available" : "No hypotheses available");
    option.value = ""; option.disabled = true; option.selected = true; select.appendChild(option); select.disabled = true; downloadButton.disabled = true; return;
  }
  ordered.forEach((record) => {
    const id = String(record?.[idField] || "");
    const label = scope === "thread" ? (record.title || id) : (record.statement || id);
    const option = element("option", null, `${label} · ${id}`); option.value = id; select.appendChild(option);
  });
  select.disabled = false; downloadButton.disabled = false;
}

async function downloadReport(event) {
  event.preventDefault();
  const button = $("report-download"); const formElement = event.currentTarget; const previousText = button.textContent;
  const scope = $("report-scope").value; const format = $("report-format").value;
  const redactions = [...formElement.querySelectorAll('input[name="redactions"]:checked')].map((input) => input.value);
  button.disabled = true; button.textContent = "Preparing report…"; formElement.setAttribute("aria-busy", "true");
  clear($("report-result")); $("report-result").hidden = true; setError("");
  try {
    const response = await post(casePath("/reports/export"), {
      format, scope,
      scope_id: ["thread", "hypothesis"].includes(scope) ? $("report-scope-id").value : null,
      redactions,
    });
    const data = response?.data;
    if (!data || typeof data.content !== "string" || !Number.isSafeInteger(data.byte_size) || data.byte_size < 0 || data.byte_size > 8 * 1024 * 1024) throw new Error("The report service returned an invalid or oversized result.");
    const extensions = { json: "json", html: "html", markdown: "md" };
    if (!extensions[data.format] || typeof data.filename !== "string" || !/^forensickit-[A-Za-z0-9_-]{1,80}-(case|investigation|thread|hypothesis)\.(json|html|md)$/.test(data.filename)) throw new Error("The report service returned an unsafe filename or format.");
    const contentTypes = { json: "application/json; charset=utf-8", html: "text/html; charset=utf-8", markdown: "text/markdown; charset=utf-8" };
    const actualSize = new TextEncoder().encode(data.content).byteLength;
    if (data.content_type !== contentTypes[data.format] || data.byte_size !== actualSize || actualSize > 8 * 1024 * 1024 || data.scope?.type !== scope) throw new Error("The report service returned an invalid or oversized result.");
    const blob = new Blob([data.content], { type: contentTypes[data.format] });
    const objectUrl = URL.createObjectURL(blob); const anchor = document.createElement("a");
    anchor.href = objectUrl; anchor.download = data.filename; anchor.hidden = true; anchor.rel = "noopener";
    document.body.appendChild(anchor); anchor.click(); anchor.remove(); window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    const result = $("report-result"); result.hidden = false;
    result.appendChild(element("h3", null, "Report download prepared"));
    result.appendChild(element("p", null, `${data.format.toUpperCase()} · ${data.byte_size.toLocaleString()} bytes · report schema ${data.report_schema_version || "unknown"}`));
    result.appendChild(element("p", "quiet", `Scope: ${data.scope?.type || scope}. Raw evidence payloads are omitted; source evidence was not modified.`));
    result.appendChild(element("p", "quiet mono", data.filename));
  } catch (error) { setError(error.message || "The report could not be prepared safely."); }
  finally { button.textContent = previousText; formElement.removeAttribute("aria-busy"); renderReportScopeOptions(); }
}

function renderPivotObjectList(parent, title, objects, formatter) {
  const section = element("div", "detail-section"); section.appendChild(element("h4", null, title));
  if (!objects.length) section.appendChild(element("div", "empty", "None recorded."));
  objects.forEach((object) => section.appendChild(element("div", "object-card", formatter(object))));
  parent.appendChild(section);
}

function renderPivot(result) {
  const root = $("pivot-result"); clear(root);
  const heading = element("article", "panel"); heading.appendChild(element("h3", null, `Pivot from ${result.entity_id}`)); heading.appendChild(element("p", null, `Depth ${result.depth} · ${result.expanded_entity_ids.length} expanded entities · ${result.event_ids.length} related events`)); addPills(heading, result.expanded_entity_ids, (id) => pivotEntity(id)); root.appendChild(heading);
  if (Object.values(result.result_bounds || {}).some((bound) => bound.truncated)) root.appendChild(element("div", "warning", "This pivot response is bounded. Expand the API limit or use canonical exports for omitted records."));
  renderPivotObjectList(root, "Related events", result.events, (event) => `${event.event_id} · ${event.event_type} · ${formatTime(event.observed_at?.utc)}`);
  renderPivotObjectList(root, "Relationships", result.relationships, (relationship) => `${relationship.type} · ${relationship.strength} · ${relationship.explanation || "No explanation"}`);
  renderPivotObjectList(root, "Candidate threads", result.threads, (thread) => `${thread.thread_id} · ${thread.title}`);
  renderPivotObjectList(root, "Hypotheses", result.hypotheses, (hypothesis) => `${hypothesis.status} · ${hypothesis.statement}`);
  renderPivotObjectList(root, "Evidence gaps", result.gaps, (gap) => `${gap.gap_id} · ${gap.description || gap.reason}`);
  renderPivotObjectList(root, "Contradictions", result.contradictions, (contradiction) => `${contradiction.contradiction_id} · ${contradiction.description || contradiction.type}`);
}

async function runPivot() {
  const entityId = $("pivot-entity").value;
  if (!entityId) return empty($("pivot-result"), "No entities are available for pivoting.");
  try {
    setError("");
    const response = await api(casePath(`/entities/${encodeURIComponent(entityId)}/pivot?depth=${encodeURIComponent($("pivot-depth").value)}`));
    renderPivot(response.data);
  } catch (error) { setError(error.message); }
}

function pivotEntity(entityId) {
  if (!state.entities.some((entity) => entity.entity_id === entityId)) return;
  $("pivot-entity").value = entityId;
  switchView("pivot");
  runPivot();
}

function renderInvestigation() {
  const hypotheses = $("hypotheses-list"); clear(hypotheses);
  const items = state.investigation.hypotheses || [];
  if (!items.length) empty(hypotheses, "No hypotheses have been created.");
  items.forEach((hypothesis) => {
    const card = element("div", "object-card"); card.appendChild(element("strong", null, hypothesis.statement)); card.appendChild(element("p", null, `${hypothesis.hypothesis_id} · ${hypothesis.analyst || "local"}`));
    const provenance = element("button", "button secondary", "Provenance"); provenance.addEventListener("click", () => showProvenance(hypothesis, "Hypothesis provenance")); card.appendChild(provenance);
    const row = element("div", "filters");
    const select = document.createElement("select"); ["open", "in_review", "supported", "weakened", "accepted", "rejected", "inconclusive"].forEach((status) => { const option = element("option", null, status); option.value = status; option.selected = status === hypothesis.status; select.appendChild(option); });
    const note = document.createElement("input"); note.placeholder = "Optional analyst update"; note.value = hypothesis.analyst_note || "";
    const update = element("button", "button secondary", "Update"); update.addEventListener("click", async () => { try { await post(casePath(`/hypotheses/${encodeURIComponent(hypothesis.hypothesis_id)}`), { status: select.value, analyst_note: note.value }); await refreshInvestigation(); } catch (error) { setError(error.message); } });
    row.appendChild(select); row.appendChild(note); row.appendChild(update); card.appendChild(row);
    appendReferenceSection(card, "Supporting evidence", hypothesis.supporting_evidence_ids, "None recorded.");
    appendReferenceSection(card, "Weakening evidence", hypothesis.weakening_evidence_ids, "None recorded.");
    appendReferenceSection(card, "Unresolved gaps", hypothesis.unresolved_gap_ids, "None recorded.");
    hypotheses.appendChild(card);
  });
  const notes = $("notes-list"); clear(notes); const noteItems = state.investigation.notes || [];
  notes.appendChild(element("h4", null, "Analyst notes"));
  if (!noteItems.length) notes.appendChild(element("div", "empty", "No analyst notes have been added."));
  noteItems.forEach((item) => {
    const card = element("div", "object-card"); card.appendChild(element("div", null, `${item.text}${item.target_id ? ` · ${item.target_type || "target"}: ${item.target_id}` : ""}`));
    const provenance = element("button", "button secondary", "Provenance"); provenance.addEventListener("click", () => showProvenance(item, "Note provenance")); card.appendChild(provenance); notes.appendChild(card);
  });
  const decisions = $("decisions-list"); clear(decisions); decisions.appendChild(element("h4", null, "Investigation decisions"));
  const decisionItems = state.investigation.decisions || [];
  if (!decisionItems.length) decisions.appendChild(element("div", "empty", "No investigation decisions have been recorded."));
  decisionItems.forEach((item) => {
    const card = element("div", "object-card"); card.appendChild(element("strong", null, item.statement)); card.appendChild(element("p", null, `${item.decision_id} · ${item.status}`)); if (item.rationale) card.appendChild(element("p", null, item.rationale));
    const row = element("div", "filters");
    const select = document.createElement("select"); ["open", "in_review", "closed"].forEach((status) => { const option = element("option", null, status); option.value = status; option.selected = status === item.status; select.appendChild(option); });
    const update = element("button", "button secondary", "Update status"); update.addEventListener("click", async () => { try { await post(casePath(`/decisions/${encodeURIComponent(item.decision_id)}`), { status: select.value }); await refreshInvestigation(); } catch (error) { setError(error.message); } });
    row.appendChild(select); row.appendChild(update); card.appendChild(row);
    const provenance = element("button", "button secondary", "Provenance"); provenance.addEventListener("click", () => showProvenance(item, "Decision provenance")); card.appendChild(provenance); decisions.appendChild(card);
  });
}

function splitRefs(value) { return value.split(",").map((item) => item.trim()).filter(Boolean); }

async function post(path, payload) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
}

async function refreshInvestigation() {
  const response = await api(casePath("/investigation")); state.investigation = response.data || state.investigation; renderInvestigation(); renderReportScopeOptions();
}

function renderAssistantSelectionOptions() {
  const type = $("assistant-selection-type").value;
  const id = $("assistant-selection-id");
  const needsId = ["thread", "replay", "hypothesis", "entity"].includes(type);
  id.disabled = !needsId;
  id.placeholder = needsId ? "select or enter an object ID" : "not required for this context";
  if (!needsId) { id.value = ""; return; }
  const values = type === "thread" || type === "replay"
    ? state.threads.map((item) => ({ id: item.thread_id, label: `${item.title || "thread"} · ${item.thread_id}` }))
    : type === "hypothesis"
      ? (state.investigation.hypotheses || []).map((item) => ({ id: item.hypothesis_id, label: `${item.status || "open"} · ${item.hypothesis_id}` }))
      : state.entities.map((item) => ({ id: item.entity_id, label: `${item.type || "entity"}: ${item.display_name || item.entity_id}` }));
  if (!values.length) return;
  let list = $("assistant-selection-options");
  if (!list) {
    list = element("datalist"); list.id = "assistant-selection-options"; document.body.appendChild(list); id.setAttribute("list", list.id);
  }
  clear(list); values.sort((left, right) => left.id.localeCompare(right.id)).forEach((item) => { const option = element("option", null, item.label); option.value = item.id; list.appendChild(option); });
}

function renderAssistantItems(parent, title, items, referenceKeys) {
  const section = element("div", "detail-section"); section.appendChild(element("h4", null, title));
  if (!items || !items.length) { section.appendChild(element("div", "empty", "None recorded.")); parent.appendChild(section); return; }
  items.forEach((item) => {
    const card = element("div", "object-card"); card.appendChild(element("p", null, item.text || item.description || "Unlabeled assistant item."));
    const refs = referenceKeys.flatMap((key) => Array.isArray(item[key]) ? item[key] : []);
    if (refs.length) appendReferenceSection(card, "Citations", refs, "None recorded.");
    if (item.confidence) card.appendChild(element("p", "quiet", `Confidence: ${item.confidence}`));
    section.appendChild(card);
  });
  parent.appendChild(section);
}

function renderAssistantResult(result) {
  const root = $("assistant-result"); clear(root); root.hidden = false;
  root.appendChild(element("div", "panel-heading", `Assistant result · ${result.provider || "disabled"} · ${result.status || "unknown"}`));
  const response = result.response || {};
  root.appendChild(element("p", null, response.answer || "No answer was returned."));
  const definition = element("dl");
  appendDefinition(definition, "Task", result.task);
  appendDefinition(definition, "Case", result.context_summary?.case_id);
  appendDefinition(definition, "Context digest", result.context_summary?.context_digest);
  appendDefinition(definition, "Context limits", result.context_summary?.limits);
  root.appendChild(definition);
  renderAssistantItems(root, "Observed facts", response.observed_facts, ["evidence_ids"]);
  renderAssistantItems(root, "Inferences", response.inferences, ["evidence_ids"]);
  renderAssistantItems(root, "Uncertainties", response.uncertainties, ["gap_ids", "contradiction_ids"]);
  const followups = element("div", "detail-section"); followups.appendChild(element("h4", null, "Suggested follow-up questions"));
  (response.follow_up_questions || []).forEach((item) => followups.appendChild(element("p", null, item)));
  if (!(response.follow_up_questions || []).length) followups.appendChild(element("div", "empty", "None recorded."));
  root.appendChild(followups);
}

async function runAssistant() {
  const selectionType = $("assistant-selection-type").value;
  const question = $("assistant-question").value;
  if (!question.trim()) return setError("Enter an assistant question first.");
  try {
    setError("");
    const offline = $("assistant-offline").checked;
    const response = await post(casePath("/assistant"), {
      task: $("assistant-task").value,
      question,
      provider: offline ? "fake" : "disabled",
      offline,
      selection_type: selectionType,
      selection_id: $("assistant-selection-id").value.trim() || null,
      compare_hypothesis_id: $("assistant-compare-hypothesis-id").value.trim() || null,
      report_section: $("assistant-report-section").value || null,
      redactions: splitRefs($("assistant-redactions").value || ""),
    });
    state.assistant = response.data; renderAssistantResult(response.data);
  } catch (error) { setError(error.message); }
}

function svgElement(tag) {
  return document.createElementNS("http://www.w3.org/2000/svg", tag);
}

function graphObjectsForType(type) {
  if (type === "event") return state.events.map((event) => ({ id: event.event_id, label: `${event.event_type || "event"} · ${event.event_id}` }));
  if (type === "thread") return state.threads.map((thread) => ({ id: thread.thread_id, label: `${thread.title || "thread"} · ${thread.thread_id}` }));
  return state.entities.filter((entity) => entity.type !== "source").map((entity) => ({ id: entity.entity_id, label: `${entity.type || "entity"}: ${entity.display_name || entity.entity_id}` }));
}

function renderGraphStarts() {
  const select = $("graph-start"); clear(select);
  const objects = graphObjectsForType($("graph-start-type").value);
  if (!objects.length) {
    select.appendChild(element("option", null, "No start objects available"));
    select.firstChild.value = "";
    return;
  }
  objects.sort((left, right) => left.id.localeCompare(right.id)).forEach((object) => {
    const option = element("option", null, object.label); option.value = object.id; select.appendChild(option);
  });
}

function renderGraphFilters(available) {
  const values = available || {};
  const confidence = $("graph-confidence");
  const confidenceValue = confidence.value; clear(confidence); confidence.appendChild(element("option", null, "All confidence")); confidence.firstChild.value = "";
  (values.confidence || ["high", "moderate", "weak", "unknown"]).forEach((item) => { const option = element("option", null, item); option.value = item; confidence.appendChild(option); });
  confidence.value = confidenceValue;
  const entityType = $("graph-entity-type");
  const entityTypeValue = entityType.value; clear(entityType); entityType.appendChild(element("option", null, "All entity types")); entityType.firstChild.value = "";
  (values.entity_types || []).forEach((item) => { const option = element("option", null, item); option.value = item; entityType.appendChild(option); });
  entityType.value = entityTypeValue;
  const thread = $("graph-thread");
  const threadValue = thread.value; clear(thread); thread.appendChild(element("option", null, "All threads")); thread.firstChild.value = "";
  (values.thread_ids || []).forEach((item) => { const option = element("option", null, item); option.value = item; thread.appendChild(option); });
  thread.value = threadValue;
}

function graphWarningText(warning) {
  return `${warning.code || "WARNING"}: ${warning.message || "The graph response contains a warning."}`;
}

function renderGraphWarnings(warnings, result) {
  const root = $("graph-warnings"); clear(root);
  const bounded = Object.entries(result?.result_bounds || {}).filter(([, bound]) => bound.truncated).map(([kind, bound]) => `${bound.returned} of ${bound.total} ${kind}`);
  const all = [...(warnings || [])];
  if (bounded.length && !all.some((warning) => warning.code === "GRAPH_RESULT_BOUNDED")) all.push({ code: "GRAPH_RESULT_BOUNDED", message: `This graph is bounded: ${bounded.join(", ")}.` });
  all.forEach((warning) => root.appendChild(element("div", "warning", graphWarningText(warning))));
}

function graphNodeClass(node) {
  let result = node.kind === "gap" ? "graph-node gap-node" : node.kind === "contradiction" ? "graph-node contradiction-node" : node.observed && !node.derived ? "graph-node observed-node" : "graph-node derived-node";
  if (node.uncertain_time) result += " uncertain-time";
  return result;
}

function graphEdgeClass(edge) {
  let result = edge.edge_type === "gap_affects_event" ? "graph-edge gap-edge" : edge.edge_type === "contradiction_evidence" ? "graph-edge contradiction-edge" : edge.observed && !edge.derived ? "graph-edge observed-edge" : "graph-edge derived-edge";
  if (edge.uncertain_time) result += " uncertain-time";
  return result;
}

function renderGraph(result) {
  const svg = $("graph-svg"); clear(svg);
  if (!result || !result.nodes?.length) {
    $("graph-count").textContent = "No graph loaded";
    const emptyText = svgElement("text"); emptyText.setAttribute("x", "550"); emptyText.setAttribute("y", "340"); emptyText.setAttribute("text-anchor", "middle"); emptyText.setAttribute("class", "graph-empty"); emptyText.textContent = "Select a start object and load a graph."; svg.appendChild(emptyText);
    return;
  }
  const nodes = [...result.nodes].sort((left, right) => (left.depth - right.depth) || left.node_id.localeCompare(right.node_id));
  const positions = new Map();
  const byDepth = new Map();
  nodes.forEach((node) => { if (!byDepth.has(node.depth)) byDepth.set(node.depth, []); byDepth.get(node.depth).push(node); });
  [...byDepth.keys()].sort((left, right) => left - right).forEach((depth) => {
    const group = byDepth.get(depth).sort((left, right) => left.node_id.localeCompare(right.node_id));
    const y = Math.min(610, 90 + depth * 170);
    group.forEach((node, index) => positions.set(node.node_id, { x: 90 + ((index + 1) * 920 / (group.length + 1)), y }));
  });
  const edgeLayer = svgElement("g"); edgeLayer.setAttribute("aria-label", "Graph relationships");
  [...(result.edges || [])].sort((left, right) => left.edge_id.localeCompare(right.edge_id)).forEach((edge) => {
    const from = positions.get(edge.from); const to = positions.get(edge.to); if (!from || !to) return;
    const line = svgElement("line"); line.setAttribute("x1", String(from.x)); line.setAttribute("y1", String(from.y)); line.setAttribute("x2", String(to.x)); line.setAttribute("y2", String(to.y)); line.setAttribute("class", graphEdgeClass(edge)); line.setAttribute("tabindex", "0"); line.setAttribute("aria-label", `${edge.label || edge.edge_type || "relationship"} ${edge.confidence || "unknown"}`);
    line.addEventListener("click", (event) => { event.stopPropagation(); renderGraphDetail("edge", edge); });
    line.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); renderGraphDetail("edge", edge); } });
    edgeLayer.appendChild(line);
    if (result.edges.length <= 80) {
      const label = svgElement("text"); label.setAttribute("x", String((from.x + to.x) / 2)); label.setAttribute("y", String((from.y + to.y) / 2 - 5)); label.setAttribute("class", "graph-edge-label"); label.setAttribute("text-anchor", "middle"); label.textContent = edge.label || edge.edge_type || "relationship"; edgeLayer.appendChild(label);
    }
  });
  svg.appendChild(edgeLayer);
  const nodeLayer = svgElement("g"); nodeLayer.setAttribute("aria-label", "Graph nodes");
  nodes.forEach((node) => {
    const point = positions.get(node.node_id); const group = svgElement("g"); group.setAttribute("class", graphNodeClass(node)); group.setAttribute("tabindex", "0"); group.setAttribute("role", "button"); group.setAttribute("aria-label", `${node.node_type || node.kind || "node"}: ${node.label || node.object_id || "unknown"}`); group.addEventListener("click", () => renderGraphDetail("node", node)); group.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); renderGraphDetail("node", node); } });
    const circle = svgElement("circle"); circle.setAttribute("cx", String(point.x)); circle.setAttribute("cy", String(point.y)); circle.setAttribute("r", node.node_id === result.start.node_id ? "27" : "22"); group.appendChild(circle);
    const title = svgElement("title"); title.textContent = `${node.label || node.object_id || "unknown"} · ${node.confidence || "unknown"}${node.uncertain_time ? " · time uncertain" : ""}`; group.appendChild(title);
    const label = svgElement("text"); label.setAttribute("x", String(point.x)); label.setAttribute("y", String(point.y + 42)); label.setAttribute("class", "graph-node-label"); label.setAttribute("text-anchor", "middle"); label.textContent = String(node.label || node.object_id || "unknown").slice(0, 42); group.appendChild(label);
    nodeLayer.appendChild(group);
  });
  svg.appendChild(nodeLayer);
  $("graph-count").textContent = `${result.nodes.length} nodes · ${result.edges.length} edges · depth ${result.depth}`;
}

function renderGraphDetail(kind, item) {
  const panel = $("graph-detail"); const content = $("graph-detail-content"); clear(content); panel.hidden = false;
  const title = item.label || item.display_name || item.object_id || item.edge_id || "Selected object";
  content.appendChild(element("h4", null, title));
  const definition = element("dl");
  appendDefinition(definition, "Object", item.object_id || item.edge_id || item.node_id);
  appendDefinition(definition, "Type", item.node_type || item.edge_type || item.kind);
  appendDefinition(definition, "Confidence", item.confidence || "unknown");
  appendDefinition(definition, "Observed", item.observed ? "yes" : "no");
  appendDefinition(definition, "Derived", item.derived ? "yes" : "no");
  appendDefinition(definition, "Time uncertainty", item.uncertain_time ? "present" : "not indicated");
  if (kind === "edge") {
    appendDefinition(definition, "From", item.from); appendDefinition(definition, "To", item.to); appendDefinition(definition, "Relationship", item.relationship_id || item.edge_type); appendDefinition(definition, "Explanation", item.explanation); appendDefinition(definition, "Derivation", item.derivation); appendDefinition(definition, "Direct evidence IDs", item.direct_evidence_ids || item.evidence_ids);
  } else {
    appendDefinition(definition, "Depth", item.depth); appendDefinition(definition, "Status", item.status); appendDefinition(definition, "Source provenance", item.provenance); appendDefinition(definition, "Direct evidence IDs", item.direct_evidence_ids || item.evidence_ids);
  }
  content.appendChild(definition);
  const provenanceObject = { ...item };
  if (kind === "node" && item.kind === "event") provenanceObject.event_id = item.object_id;
  if (kind === "edge" && item.relationship_id) provenanceObject.relationship_id = item.relationship_id;
  const provenance = element("button", "button secondary", "Open provenance panel"); provenance.addEventListener("click", () => showProvenance(provenanceObject, "Graph object provenance")); content.appendChild(provenance);
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function loadGraph() {
  const startType = $("graph-start-type").value; const startId = $("graph-start").value;
  if (!startId) return setError("Choose a graph start object first.");
  try {
    setError("");
    const query = new URLSearchParams({ start_type: startType, start_id: startId, depth: $("graph-depth").value, limit: "1000" });
    const relationshipType = $("graph-relationship-type").value.trim(); if (relationshipType) query.set("relationship_type", relationshipType);
    if ($("graph-confidence").value) query.set("confidence", $("graph-confidence").value);
    if ($("graph-entity-type").value) query.set("entity_type", $("graph-entity-type").value);
    if ($("graph-thread").value) query.set("thread_id", $("graph-thread").value);
    const response = await api(casePath(`/graph?${query.toString()}`)); state.graph = response.data; renderGraphFilters(response.data.available_filters); renderGraphWarnings(response.warnings, response.data); renderGraph(response.data);
  } catch (error) { setError(error.message); }
}

function resetGraph() {
  state.graph = null; $("graph-relationship-type").value = ""; $("graph-confidence").value = ""; $("graph-entity-type").value = ""; $("graph-thread").value = ""; $("graph-depth").value = "1"; $("graph-start-type").value = "entity"; renderGraphStarts(); clear($("graph-warnings")); clear($("graph-detail-content")); $("graph-detail").hidden = true; renderGraph(null);
}

function bindForms() {
  $("hypothesis-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement);
    try { await post(casePath("/hypotheses"), { statement: form.get("statement"), status: form.get("status"), supporting_evidence_ids: splitRefs(form.get("supporting_evidence_ids")), weakening_evidence_ids: splitRefs(form.get("weakening_evidence_ids")), unresolved_gap_ids: splitRefs(form.get("unresolved_gap_ids")) }); formElement.reset(); await refreshInvestigation(); } catch (error) { setError(error.message); }
  });
  $("note-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement);
    try { await post(casePath("/notes"), { text: form.get("text"), target_type: form.get("target_type") || null, target_id: form.get("target_id") || null }); formElement.reset(); await refreshInvestigation(); } catch (error) { setError(error.message); }
  });
  $("decision-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement);
    try { await post(casePath("/decisions"), { statement: form.get("statement"), status: form.get("status"), evidence_ids: splitRefs(form.get("evidence_ids")), rationale: form.get("rationale") }); formElement.reset(); await refreshInvestigation(); } catch (error) { setError(error.message); }
  });
  $("assistant-form").addEventListener("submit", async (event) => { event.preventDefault(); await runAssistant(); });
}

function showProvenance(object, title) {
  const panel = $("provenance-panel"); const content = $("provenance-content"); clear(content); panel.hidden = false;
  content.appendChild(element("h4", null, title));
  const definition = element("dl");
  if (object.event_id || object.kind === "event") {
    const eventId = object.event_id || object.object_id;
    appendDefinition(definition, "Event ID", eventId);
    appendDefinition(definition, "Source file", object.provenance?.source_file_id);
    appendDefinition(definition, "Source locator", object.provenance?.source_locator);
    appendDefinition(definition, "Parser", object.provenance?.parser);
    appendDefinition(definition, "Parser version", object.provenance?.parser_version);
    appendDefinition(definition, "Record fingerprint", object.provenance?.record_fingerprint);
    appendDefinition(definition, "Import batch", object.provenance?.import_batch_id);
    appendDefinition(definition, "Direct evidence IDs", object.direct_evidence_ids || [eventId]);
  } else {
    appendDefinition(definition, "Object ID", object.relationship_id || object.edge_id || object.object_id || object.node_id || object.hypothesis_id || object.note_id || object.decision_id);
    appendDefinition(definition, "Derivation rule", object.rule_id || object.derivation?.rule_id || object.provenance?.derivation?.algorithm);
    appendDefinition(definition, "Rule version", object.rule_version || object.derivation?.rule_version || object.provenance?.derivation?.version);
    appendDefinition(definition, "Direct evidence IDs", object.direct_evidence_ids || object.evidence_ids || object.provenance?.evidence_ids || []);
    appendDefinition(definition, "Explanation", object.explanation || object.statement || object.text);
  }
  content.appendChild(definition);
}

function switchView(name) {
  document.querySelectorAll(".view").forEach((view) => { view.hidden = view.id !== `${name}-view`; });
  document.querySelectorAll(".nav-button").forEach((button) => {
    const active = button.dataset.view === name;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function bindNavigation() {
  const collapseButton = $("nav-collapse");
  const setNavigationCollapsed = (collapsed) => {
    document.body.classList.toggle("nav-collapsed", collapsed);
    collapseButton.setAttribute("aria-expanded", String(!collapsed));
    collapseButton.setAttribute("aria-label", `${collapsed ? "Expand" : "Collapse"} navigation`);
    collapseButton.title = `${collapsed ? "Expand" : "Collapse"} navigation`;
    collapseButton.firstElementChild.textContent = collapsed ? "›" : "‹";
    try { localStorage.setItem("forensickit.nav-collapsed", collapsed ? "true" : "false"); } catch (_) { /* Navigation still works without browser storage. */ }
  };
  let startCollapsed = false;
  try { startCollapsed = localStorage.getItem("forensickit.nav-collapsed") === "true"; } catch (_) { /* Use the expanded default. */ }
  setNavigationCollapsed(startCollapsed);
  collapseButton.addEventListener("click", () => setNavigationCollapsed(!document.body.classList.contains("nav-collapsed")));
  document.querySelectorAll(".nav-button").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  document.querySelectorAll(".nav-jump").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented || /INPUT|TEXTAREA|SELECT/.test(event.target?.tagName || "")) return;
    const views = { "1": "overview", "2": "timeline", "3": "threads", "4": "graph", "5": "pivot", "6": "investigation", "7": "reports", "8": "assistant" };
    if (views[event.key]) { event.preventDefault(); switchView(views[event.key]); }
    if (event.key === "Escape") { $("provenance-panel").hidden = true; $("graph-detail").hidden = true; }
  });
  ["filter-event-type", "filter-confidence"].forEach((id) => $(id).addEventListener("change", renderTimeline));
  ["filter-host", "filter-user", "filter-entity"].forEach((id) => $(id).addEventListener("input", renderTimeline));
  $("clear-filters").addEventListener("click", () => { ["filter-host", "filter-user", "filter-entity"].forEach((id) => { $(id).value = ""; }); $("filter-event-type").value = ""; $("filter-confidence").value = ""; renderTimeline(); });
  $("run-pivot").addEventListener("click", runPivot);
  $("report-scope").addEventListener("change", renderReportScopeOptions);
  $("report-form").addEventListener("submit", downloadReport);
  $("assistant-selection-type").addEventListener("change", renderAssistantSelectionOptions);
  $("graph-start-type").addEventListener("change", renderGraphStarts);
  $("load-graph").addEventListener("click", loadGraph);
  $("reset-graph").addEventListener("click", resetGraph);
  $("close-provenance").addEventListener("click", () => { $("provenance-panel").hidden = true; });
}

async function loadWorkbench() {
  try {
    const summary = await api("/api/bootstrap").catch(() => null);
    if (!summary) throw new Error("The workbench could not discover the loaded case.");
    state.caseId = summary.case_id;
    state.overview = summary.data;
    const [events, threads, entities, investigation] = await Promise.all([
      api(casePath("/events")), api(casePath("/threads")), api(casePath("/entities")), api(casePath("/investigation")),
    ]);
    state.events = events.data.events || [];
    state.eventConfidence = events.data.event_confidence || {};
    state.timelineTotal = events.data.total || state.events.length;
    state.timelineTruncated = Boolean(events.data.truncated);
    state.threads = threads.data || [];
    state.entities = entities.data || [];
    state.investigation = investigation.data || state.investigation;
    renderOverview(); populateEventFilters(); renderTimeline(); renderThreads(); renderEntitiesSelect(); renderGraphStarts(); renderInvestigation(); renderReportScopeOptions(); renderAssistantSelectionOptions(); await loadGraph();
    setConnectionStatus("Local-only");
  } catch (error) {
    setConnectionStatus("Unavailable");
    setError(error.message);
  }
}

applyThemePreference("system");
bindNavigation(); bindForms(); bindAuthentication(); checkAuthentication();
