"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { csrf: "", user: null, posts: [], alerts: [], incidents: [], postLimit: 50 };
const routes = new Set(["overview", "posts", "enroll", "checks", "history", "evidence", "investigate", "actions", "incidents", "devices", "fleet"]);

async function request(path, options = {}) {
  const config = { ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) } };
  let response;
  try { response = await fetch(path, config); }
  catch { throw new Error("Watchpost could not be reached. Check the service and try again."); }
  let body = {};
  if (response.status !== 204) {
    try { body = await response.json(); } catch { body = {}; }
  }
  if (!response.ok) {
    if (response.status === 401) throw new Error("Your session has ended. Sign in again.");
    if (response.status === 403) throw new Error(body.error === "forbidden" ? "You do not have permission to perform this operation." : body.error || "Permission denied.");
    throw new Error(body.error || `Request failed (${response.status}).`);
  }
  return body;
}

function formJSON(form) { return Object.fromEntries(new FormData(form)); }
function escapeHTML(value) { return String(value ?? "").replace(/[&<>'"]/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]); }
function title(value) { return String(value || "unknown").replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase()); }
function setBusy(form, busy) { const button = $("button[type=submit]", form); if (button) { button.disabled = busy; button.dataset.label ||= button.textContent; button.textContent = busy ? "Working…" : button.dataset.label; } }
function showMessage(text, kind = "success") { const node = $("#global-message"); node.textContent = text; node.className = `toast ${kind === "error" ? "error" : ""}`; node.hidden = false; clearTimeout(showMessage.timer); showMessage.timer = setTimeout(() => { node.hidden = true; }, 6000); }
function stateBox(titleText, detail, kind = "empty") { return `<div class="state-box ${kind === "loading" ? "loading" : ""} ${kind === "permission" ? "permission-state" : ""}"><h2>${escapeHTML(titleText)}</h2><p>${escapeHTML(detail)}</p></div>`; }

async function bootstrap() {
  try {
    const boot = await request("/api/v1/bootstrap");
    if (boot.authenticated) return enterApp(boot);
    showAuth(boot.setup_required ? "setup" : "login");
  } catch (error) {
    $("#auth-shell").hidden = false;
    $("#auth-message").textContent = error.message;
  }
}

function showAuth(mode, email = "") {
  $("#app").hidden = true; $("#auth-shell").hidden = false;
  $("#setup-view").hidden = mode !== "setup"; $("#login-view").hidden = mode !== "login";
  $("#auth-message").textContent = "";
  if (mode === "setup") $("#setup-email").focus();
  else { $("#login-email").value = email; (email ? $("#login-password") : $("#login-email")).focus(); }
}

async function enterApp(session) {
  state.csrf = session.csrf_token; state.user = session.user;
  $("#auth-shell").hidden = true; $("#app").hidden = false;
  $("#account-name").textContent = session.user.email;
  await loadCore(); route();
}

async function loadCore() {
  $("#summary").innerHTML = stateBox("Loading workspace", "Collecting the latest operational state.", "loading");
  const results = await Promise.allSettled([request("/api/v1/posts"), request("/api/v1/alerts"), request("/api/v1/incidents")]);
  const failures = results.filter(result => result.status === "rejected");
  state.posts = results[0].status === "fulfilled" ? results[0].value.posts : [];
  state.alerts = results[1].status === "fulfilled" ? results[1].value.alerts : [];
  state.incidents = results[2].status === "fulfilled" ? results[2].value.incidents : [];
  updatePostSelects(); renderOverview(); renderPosts(); renderIncidents();
  if (failures.length) showMessage(`${failures.length} workspace section${failures.length === 1 ? "" : "s"} could not be loaded. Available data is still shown.`, "error");
}

function route() {
  const routeName = location.hash.replace(/^#\/?/, "").split("?")[0] || "overview";
  const current = routes.has(routeName) ? routeName : "overview";
  $$(".view").forEach(view => { view.hidden = view.dataset.view !== current; });
  $$("[data-route]").forEach(link => { const active = link.dataset.route === current; link.classList.toggle("active", active); if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); });
  $("#primary-nav").classList.remove("open"); $("#nav-toggle").setAttribute("aria-expanded", "false");
  const heading = $(`.view[data-view="${current}"] h1`); if (heading) { document.title = `${heading.textContent} · Watchpost`; $("#page").focus({ preventScroll: true }); }
}

function updatePostSelects() {
  const options = state.posts.length ? `<option value="">Choose a post</option>${state.posts.map(post => `<option value="${escapeHTML(post.id)}">${escapeHTML(post.name)} · ${escapeHTML(post.id)}</option>`).join("")}` : `<option value="">No posts enrolled</option>`;
  $$('[data-post-select]').forEach(select => { const selected = select.value; select.innerHTML = options; if (state.posts.some(post => post.id === selected)) select.value = selected; });
}

function renderOverview() {
  const firing = state.alerts.filter(alert => alert.state === "firing").length;
  const open = state.incidents.filter(incident => (incident.Status || incident.status) !== "resolved").length;
  $("#summary").innerHTML = [[state.posts.length, "Posts"], [firing, "Firing alerts"], [open, "Open incidents"], [state.posts.filter(post => post.maintenance).length, "In maintenance"]].map(([value, label]) => `<div class="summary-card"><strong>${value}</strong><span>${label}</span></div>`).join("");
  $("#overview-posts").innerHTML = state.posts.length ? state.posts.slice(0, 5).map(postRow).join("") : stateBox("No posts yet", "Enroll the first system, service, or device to begin monitoring.");
  const evidence = [...state.alerts.slice(0, 3).map(alert => `<div class="evidence-row"><div><h3>${escapeHTML(title(alert.severity))} alert</h3><p>${escapeHTML(alert.post_id)} · ${escapeHTML(alert.state)}</p></div><span class="badge ${alert.severity === "critical" ? "danger" : "warning"}">${escapeHTML(alert.state)}</span></div>`), ...state.incidents.slice(0, 3).map(incident => `<div class="incident-row"><div><h3>${escapeHTML(incident.Title || incident.title)}</h3><p>${escapeHTML(incident.Severity || incident.severity)}</p></div><span class="badge">${escapeHTML(incident.Status || incident.status)}</span></div>`)];
  $("#overview-evidence").innerHTML = evidence.length ? evidence.join("") : stateBox("Nothing active", "Alerts and incidents will appear here when evidence requires attention.");
}

function postRow(post) {
  const stale = post.archived ? "Archived" : post.maintenance ? "Maintenance" : "Active";
  return `<article class="post-row" data-post-id="${escapeHTML(post.id)}"><div><h3>${escapeHTML(post.name)}</h3><p>${escapeHTML(title(post.kind))} · <code>${escapeHTML(post.id)}</code> <span class="badge">${stale}</span></p></div><div class="row-actions"><button class="quiet-button" type="button" data-post-action="maintenance">${post.maintenance ? "End maintenance" : "Start maintenance"}</button><button class="quiet-button" type="button" data-post-action="archive">${post.archived ? "Restore" : "Archive"}</button></div></article>`;
}

function renderPosts() {
  const query = ($("#post-filter").value || "").trim().toLowerCase();
  const filtered = state.posts.filter(post => [post.id, post.name, post.kind].some(value => String(value).toLowerCase().includes(query)));
  const shown = filtered.slice(0, state.postLimit);
  $("#post-count").textContent = `${filtered.length} post${filtered.length === 1 ? "" : "s"}`;
  $("#posts").innerHTML = shown.length ? shown.map(postRow).join("") : stateBox(query ? "No matching posts" : "No posts enrolled", query ? "Try a different name, ID, or kind." : "Enroll a post to build the monitored inventory.");
  $("#more-posts").hidden = shown.length === filtered.length; $("#more-posts").textContent = `Show ${Math.min(50, filtered.length - shown.length)} more posts`;
}

async function updatePost(post, changes) {
  await request(`/api/v1/posts/${encodeURIComponent(post.id)}`, { method: "PUT", headers: { "X-Watchpost-CSRF": state.csrf, "If-Match": String(post.version) }, body: JSON.stringify({ ...post, ...changes }) });
  await loadCore();
}

function renderIncidents() {
  $("#incidents").innerHTML = state.incidents.length ? state.incidents.map(incident => `<article class="incident-row"><div><h3>${escapeHTML(incident.Title || incident.title)}</h3><p>${escapeHTML(incident.Severity || incident.severity)} · ${escapeHTML(incident.Status || incident.status)}</p></div></article>`).join("") : stateBox("No incidents", "Open an incident when related evidence needs durable coordination.");
}

function setupWizard(prefix, stepSelector, stepsSelector, backSelector, nextSelector, submitSelector, beforeFinal) {
  let step = 1; const panels = $$(stepSelector), indicators = $$(`${stepsSelector} li`), back = $(backSelector), next = $(nextSelector), submit = $(submitSelector);
  const draw = () => { panels.forEach(panel => { panel.hidden = Number(panel.dataset.step || panel.dataset.snmpStep) !== step; }); indicators.forEach((item, index) => item.classList.toggle("active", index + 1 === step)); back.hidden = step === 1; next.hidden = step === panels.length; submit.hidden = step !== panels.length; if (step === panels.length && beforeFinal) beforeFinal(); };
  next.addEventListener("click", () => { const visible = panels[step - 1]; const fields = $$('input,select,textarea', visible); if (!fields.every(field => field.reportValidity())) return; step = Math.min(panels.length, step + 1); draw(); });
  back.addEventListener("click", () => { step = Math.max(1, step - 1); draw(); });
  return { reset() { step = 1; draw(); } };
}

function installResizeHandles() {
  $$(".resize-handle").forEach(handle => { const textarea = handle.previousElementSibling; let startY = 0, startHeight = 0; const move = event => { textarea.style.height = `${Math.max(90, startHeight + event.clientY - startY)}px`; }; const stop = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", stop); };
    handle.addEventListener("pointerdown", event => { event.preventDefault(); startY = event.clientY; startHeight = textarea.offsetHeight; handle.setPointerCapture?.(event.pointerId); window.addEventListener("pointermove", move); window.addEventListener("pointerup", stop); });
    handle.addEventListener("keydown", event => { if (!["ArrowUp", "ArrowDown"].includes(event.key)) return; event.preventDefault(); textarea.style.height = `${Math.max(90, textarea.offsetHeight + (event.key === "ArrowDown" ? 12 : -12))}px`; });
  });
}

function addOID(values = { name: "uptime", oid: ".1.3.6.1.2.1.1.3.0", unit: "ticks" }) {
  const row = document.createElement("div"); row.className = "oid-row"; row.innerHTML = `<label>Name<input data-oid="name" value="${escapeHTML(values.name)}" required></label><label>OID<input data-oid="oid" value="${escapeHTML(values.oid)}" required></label><label>Unit<input data-oid="unit" value="${escapeHTML(values.unit)}"></label><button class="quiet-button" type="button" aria-label="Remove OID">Remove</button>`; $("button", row).onclick = () => row.remove(); $("#oid-rows").append(row);
}

async function searchEvidence(postID, query = "", focusID = "") {
  const target = $("#evidence-results"); target.innerHTML = stateBox("Searching evidence", "Reading the bounded log window.", "loading");
  const to = new Date(), from = new Date(to.getTime() - 24 * 60 * 60 * 1000), params = new URLSearchParams({ q: query, from: from.toISOString(), to: to.toISOString() });
  try { const data = await request(`/api/v1/posts/${encodeURIComponent(postID)}/logs?${params}`); target.innerHTML = data.logs.length ? data.logs.map(log => `<article id="evidence-log-${log.id}" class="evidence-row"><div><h3>${escapeHTML(log.source)} <span class="badge">${escapeHTML(log.severity)}</span></h3><p>${escapeHTML(log.message)}</p><p><code>log:${log.id}</code> · ${escapeHTML(new Date(log.observed_at).toLocaleString())}</p></div><div class="row-actions"><button type="button" class="quiet-button" data-cite-log="${log.id}" data-post="${escapeHTML(log.post_id)}">Use in investigation</button></div></article>`).join("") : stateBox("No evidence found", "Try a broader search or add a bounded log record."); if (focusID) { const node = $(`#evidence-log-${CSS.escape(String(focusID))}`); node?.scrollIntoView({ behavior: "smooth", block: "center" }); node?.classList.add("focused"); } }
  catch (error) { target.innerHTML = stateBox("Evidence unavailable", error.message, error.message.includes("permission") ? "permission" : "error"); }
}

$("#setup").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget; setBusy(form, true); try { const values = formJSON(form); await request("/api/v1/setup", { method: "POST", body: JSON.stringify(values) }); showAuth("login", values.email); $("#auth-message").textContent = "Administrator created. Sign in to continue."; } catch (error) { $("#auth-message").textContent = error.message; } finally { setBusy(form, false); } });
$("#login").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget; setBusy(form, true); try { await enterApp(await request("/api/v1/login", { method: "POST", body: JSON.stringify(formJSON(form)) })); } catch (error) { $("#auth-message").textContent = error.message; } finally { setBusy(form, false); } });
$("#logout").addEventListener("click", async () => { try { await request("/api/v1/logout", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf } }); } finally { state.csrf = ""; state.user = null; showAuth("login"); } });
$("#nav-toggle").addEventListener("click", event => { const open = $("#primary-nav").classList.toggle("open"); event.currentTarget.setAttribute("aria-expanded", String(open)); });
window.addEventListener("hashchange", route);

$("#post-filter").addEventListener("input", () => { state.postLimit = 50; renderPosts(); });
$("#more-posts").addEventListener("click", () => { state.postLimit += 50; renderPosts(); });
$("#posts").addEventListener("click", async event => { const button = event.target.closest("[data-post-action]"); if (!button) return; const post = state.posts.find(item => item.id === button.closest("[data-post-id]").dataset.postId); try { button.disabled = true; await updatePost(post, button.dataset.postAction === "maintenance" ? { maintenance: !post.maintenance } : { archived: !post.archived }); } catch (error) { showMessage(error.message, "error"); } });

const postWizard = setupWizard("post", "[data-step]", "#post-steps", "#post-back", "#post-next", "#post-submit", () => { const values = formJSON($("#create")); $("#post-review").innerHTML = `<dt>ID</dt><dd><code>${escapeHTML(values.id)}</code></dd><dt>Name</dt><dd>${escapeHTML(values.name)}</dd><dt>Kind</dt><dd>${escapeHTML(title(values.kind))}</dd>`; });
$("#create").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, post = { ...formJSON(form), labels: {} }; setBusy(form, true); try { await request("/api/v1/posts", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(post) }); form.reset(); postWizard.reset(); await loadCore(); location.hash = "#/posts"; showMessage(`${post.name} enrolled.`); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });

$("#check").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, output = $("#check-result"); setBusy(form, true); output.hidden = false; output.innerHTML = stateBox("Running check", "Waiting for the target to respond.", "loading"); try { const result = await request("/api/v1/checks", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(formJSON(form)) }); output.innerHTML = `<h2>${result.ok ? "Check healthy" : "Check failed"}</h2><dl class="review-list"><dt>Result</dt><dd>${result.ok ? "Target responded successfully" : escapeHTML(result.failure || "Unknown failure")}</dd><dt>Latency</dt><dd>${escapeHTML(result.latency || "Not available")}</dd></dl>`; output.classList.toggle("permission-state", !result.ok); } catch (error) { output.innerHTML = stateBox("Check unavailable", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

$("#history").addEventListener("submit", async event => { event.preventDefault(); const values = formJSON(event.currentTarget), to = new Date(), from = new Date(to.getTime() - 3600000), signals = values.signals.split(",").map(value => value.trim()).filter(Boolean).slice(0, 4), series = []; try { for (const signal of signals) { const params = new URLSearchParams({ signal, from: from.toISOString(), to: to.toISOString() }); series.push({ signal, points: (await request(`/api/v1/posts/${encodeURIComponent(values.post)}/history?${params}`)).points }); } const all = series.flatMap(item => item.points).filter(point => point.value !== null), svg = $("#chart"); svg.replaceChildren(); if (!all.length) { $("#history-empty").innerHTML = `<h2>No numeric history</h2><p>This post has no matching numeric samples in the last hour. Recent data may be stale or collection may not have started.</p>`; $("#history-empty").hidden = false; svg.hidden = true; return; } const numbers = all.map(point => point.value), min = Math.min(...numbers), max = Math.max(...numbers), span = max - min || 1, colors = ["#9fcb78", "#dbb66f", "#dd8078", "#b7bdb7"]; series.forEach((entry, index) => { const numeric = entry.points.filter(point => point.value !== null), line = document.createElementNS("http://www.w3.org/2000/svg", "polyline"); line.setAttribute("fill", "none"); line.setAttribute("stroke", colors[index]); line.setAttribute("stroke-width", "3"); line.setAttribute("points", numeric.map((point, i) => `${20 + 760 * i / Math.max(1, numeric.length - 1)},${230 - 200 * (point.value - min) / span}`).join(" ")); svg.append(line); }); $("#history-empty").hidden = true; svg.hidden = false; const params = new URLSearchParams({ signal: signals[0], from: from.toISOString(), to: to.toISOString(), format: "csv" }); $("#export").href = `/api/v1/posts/${encodeURIComponent(values.post)}/history?${params}`; $("#export").hidden = false; } catch (error) { showMessage(error.message, "error"); } });

$("#log").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, value = { ...formJSON(form), observed_at: new Date().toISOString(), fields: {} }; setBusy(form, true); try { const stored = await request("/api/v1/logs", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(value) }); showMessage(`Log evidence ${stored.id} stored.`); await searchEvidence(value.post_id, "", String(stored.id)); form.elements.message.value = ""; } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });
$("#log-search").addEventListener("submit", async event => { event.preventDefault(); const value = formJSON(event.currentTarget); await searchEvidence(value.post, value.query); });
$("#evidence-results").addEventListener("click", event => { const button = event.target.closest("[data-cite-log]"); if (!button) return; $("#agent-log-id").value = button.dataset.citeLog; const select = $('#agent [name="post"]'); select.value = button.dataset.post; location.hash = "#/investigate"; showMessage(`Log ${button.dataset.citeLog} attached to the investigation form.`); });

$("#agent").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, value = formJSON(form), output = $("#investigation-result"); setBusy(form, true); output.hidden = false; output.innerHTML = stateBox("Investigating", "Reading only the evidence you supplied.", "loading"); try { const conversation = await request("/api/v1/conversations", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ post_id: value.post }) }), evidence = value.log_id ? [{ kind: "log", id: value.log_id, summary: "Operator-selected log evidence" }] : [], response = await request(`/api/v1/conversations/${conversation.id}/investigate`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ question: value.question, evidence }) }); const citations = (response.citations || []).map(citation => `<span class="citation"><button type="button" class="quiet-button" data-investigation-citation="${escapeHTML(citation.id)}" data-kind="${escapeHTML(citation.kind)}" data-post="${escapeHTML(value.post)}">${escapeHTML(citation.kind)}:${escapeHTML(citation.id)}</button></span>`).join(""); output.innerHTML = `<h2>Investigation result</h2><p>${escapeHTML(response.answer)}</p><h3>Verified evidence</h3><p>${citations || "No evidence was cited."}</p><h3>Uncertainty</h3><p>${escapeHTML(response.uncertainty)}</p>`; } catch (error) { output.innerHTML = stateBox("Investigation unavailable", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });
$("#investigation-result").addEventListener("click", async event => { const button = event.target.closest("[data-investigation-citation]"); if (!button || button.dataset.kind !== "log") return; location.hash = "#/evidence"; $('#log-search [name="post"]').value = button.dataset.post; await searchEvidence(button.dataset.post, "", button.dataset.investigationCitation); });

$("#action [name=type]").addEventListener("change", event => { $("#route-field").hidden = event.target.value !== "silence_route"; });
$("#action").addEventListener("submit", event => { event.preventDefault(); const value = formJSON(event.currentTarget), needsApproval = value.type === "silence_route", output = $("#action-review"), effect = needsApproval ? `Disable notification route ${value.route_id || "(route required)"}` : `Schedule a fresh check for post ${value.post}`; if (needsApproval && !value.route_id) { showMessage("Route ID is required.", "error"); return; } output.hidden = false; output.innerHTML = `<h2>Review typed action</h2><dl class="review-list"><dt>Before</dt><dd>${needsApproval ? "Notification route is enabled or unchanged" : "Existing check evidence remains unchanged"}</dd><dt>Proposed change</dt><dd>${escapeHTML(effect)}</dd><dt>Approval</dt><dd>${needsApproval ? "Required from a different administrator" : "Not required for this bounded action"}</dd><dt>Verification</dt><dd>${needsApproval ? "Execution result must confirm the route was disabled" : "Execution result must confirm the check was scheduled"}</dd></dl><button id="confirm-action" type="button">Confirm request</button>`; $("#confirm-action").onclick = () => requestAction(value, output); });
async function requestAction(value, output) { output.innerHTML = stateBox("Requesting action", "Writing an auditable typed request.", "loading"); const needsApproval = value.type === "silence_route", parameters = needsApproval ? { route_id: value.route_id } : { check: "manual" }; try { const response = await request("/api/v1/actions", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ Type: value.type, PostID: value.post, IdempotencyKey: crypto.randomUUID(), Parameters: parameters }) }); output.innerHTML = `<h2>Action ${response.id} requested</h2><dl class="review-list"><dt>State</dt><dd>${needsApproval ? "Pending independent approval" : "Approved and ready"}</dd><dt>Expected result</dt><dd>${needsApproval ? "Route reports disabled: true" : "Scheduler reports scheduled: true"}</dd></dl>${needsApproval ? `<p class="callout">A different administrator must approve action ${response.id} through the approval API before execution. The requester cannot approve their own action.</p>` : `<button id="execute-action" type="button">Execute and verify</button>`}`; if (!needsApproval) $("#execute-action").onclick = () => executeAction(response.id, output); } catch (error) { output.innerHTML = stateBox("Action request failed", error.message, error.message.includes("permission") ? "permission" : "error"); } }
async function executeAction(id, output) { output.innerHTML = stateBox("Executing action", "The idempotent execution claim is being verified.", "loading"); try { const result = await request(`/api/v1/actions/${id}/execute`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf } }); output.innerHTML = `<h2>Action completed</h2><dl class="review-list"><dt>Final state</dt><dd>Completed</dd><dt>Verification result</dt><dd><code>${escapeHTML(JSON.stringify(result))}</code></dd></dl>`; } catch (error) { output.innerHTML = stateBox("Action did not complete", error.message, "error"); } }

$("#incident").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, value = { ...formJSON(form), alert_ids: [] }; setBusy(form, true); try { await request("/api/v1/incidents", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(value) }); form.reset(); await loadCore(); showMessage("Incident opened."); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });

addOID(); $("#add-oid").addEventListener("click", () => addOID({ name: "", oid: "", unit: "" }));
const snmpWizard = setupWizard("snmp", "[data-snmp-step]", "#snmp-steps", "#snmp-back", "#snmp-next", "#snmp-test", () => { const values = formJSON($("#snmp")), count = $$(".oid-row").length; $("#snmp-review").innerHTML = `<dt>Target</dt><dd>${escapeHTML(values.address)}:${escapeHTML(values.port)}</dd><dt>Security</dt><dd>SNMPv3 authPriv · SHA-256 · AES</dd><dt>Profile</dt><dd>${escapeHTML(values.profile_id)} (${escapeHTML(title(values.device_kind))})</dd><dt>OIDs</dt><dd>${count}</dd>`; });
$("#snmp").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), output = $("#snmp-result"), OIDs = $$(".oid-row").map(row => ({ Name: $('[data-oid="name"]', row).value, OID: $('[data-oid="oid"]', row).value, Unit: $('[data-oid="unit"]', row).value })); output.hidden = false; output.innerHTML = stateBox("Testing SNMP connection", "Authenticating and polling the bounded OID profile.", "loading"); setBusy(form, true); try { const result = await request("/api/v1/devices/snmp/poll", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ config: { Address: values.address, Port: Number(values.port), Username: values.username, AuthPassword: values.auth_password, PrivacyPassword: values.privacy_password, Timeout: 5_000_000_000 }, profile: { ID: values.profile_id, Kind: values.device_kind, OIDs } }) }); output.innerHTML = `<h2>Connection successful</h2><p>${result.readings.length} reading${result.readings.length === 1 ? "" : "s"} returned.</p><dl class="review-list">${result.readings.map(reading => `<dt>${escapeHTML(reading.Name)}</dt><dd>${escapeHTML(reading.Value)} ${escapeHTML(reading.Unit)} · ${escapeHTML(reading.Quality)}</dd>`).join("")}</dl>`; } catch (error) { output.innerHTML = stateBox("Connection test failed", `${error.message} Check reachability, authPriv credentials, allowed source addresses, and OIDs.`, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

$("#fleet").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), output = $("#fleet-result"); output.hidden = false; output.innerHTML = stateBox("Creating pairing secret", "Enrolling the peer with a one-time credential.", "loading"); setBusy(form, true); try { const result = await request("/api/v1/peers", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(values) }); output.innerHTML = `<h2>Pairing ready</h2><ol><li>Copy the secret now; it will not be shown again.</li><li>On <strong>${escapeHTML(result.id)}</strong>, configure this Watchpost as its peer.</li><li>Send one signed test envelope and verify it is accepted before enabling event sharing.</li></ol><code class="secret">${escapeHTML(result.secret)}</code><button id="copy-secret" class="quiet-button" type="button">Copy secret</button><p class="callout">Each Watchpost remains independently useful. Pairing enables selective coordination, not continuous upstream dependence.</p>`; $("#copy-secret").onclick = async () => { await navigator.clipboard.writeText(result.secret); showMessage("Pairing secret copied."); }; form.reset(); } catch (error) { output.innerHTML = stateBox("Pairing failed", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

installResizeHandles(); bootstrap();
