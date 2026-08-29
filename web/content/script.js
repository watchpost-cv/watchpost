"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { csrf: "", user: null, posts: [], collectors: [], agentConnections: [], rules: [], checkSchedules: [], deviceProfiles: [], deviceAdapters: [], devicePresets: [], alerts: [], incidents: [], agentRequests: [], storage: null, postTotal: 0, postLimit: 100 };
const routes = new Set(["overview", "survey", "posts", "edit-post", "enroll", "checks", "history", "rules", "evidence", "investigate", "actions", "incidents", "devices", "fleet", "audit", "users", "account"]);

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
    showAuth(boot.setup_required ? "setup" : "login", "", Boolean(boot.setup_token_required));
  } catch (error) {
    $("#auth-shell").hidden = false;
    $("#auth-message").textContent = error.message;
  }
}

function showAuth(mode, email = "", tokenRequired = false) {
  $("#app").hidden = true; $("#auth-shell").hidden = false;
  $("#setup-view").hidden = mode !== "setup"; $("#login-view").hidden = mode !== "login";
  $("#auth-message").textContent = "";
  if (mode === "setup") {
    const field = $("#setup-token-field");
    if (field) {
      field.hidden = !tokenRequired;
      const input = $("input", field);
      if (input) input.required = tokenRequired;
    }
    $("#setup-email").focus();
  } else { $("#login-email").value = email; (email ? $("#login-password") : $("#login-email")).focus(); }
}

async function enterApp(session) {
  state.csrf = session.csrf_token; state.user = session.user;
  $("#auth-shell").hidden = true; $("#app").hidden = false;
  $("#account-name").textContent = session.user.email;
  await loadCore(); route();
}

async function loadCore() {
  $("#summary").innerHTML = stateBox("Loading workspace", "Collecting the latest operational state.", "loading");
  const results = await Promise.allSettled([request("/api/v1/posts"), request("/api/v1/alerts"), request("/api/v1/incidents"), request("/api/v1/collectors"), request("/api/v1/agent-pairing-requests"), request("/api/v1/agent-connections"), request("/api/v1/rules"), request("/api/v1/check-schedules"), request("/api/v1/device-profiles"), request("/api/v1/device-adapters"), request("/api/v1/device-presets"), request("/api/v1/storage")]);
  const failures = results.filter(result => result.status === "rejected");
  state.posts = results[0].status === "fulfilled" ? results[0].value.posts : [];
  state.postTotal = results[0].status === "fulfilled" ? results[0].value.total || 0 : 0;
  state.alerts = results[1].status === "fulfilled" ? results[1].value.alerts : [];
  state.incidents = results[2].status === "fulfilled" ? results[2].value.incidents : [];
  state.collectors = results[3].status === "fulfilled" ? results[3].value.collectors : [];
  state.agentRequests = results[4].status === "fulfilled" ? results[4].value : [];
  state.agentConnections = results[5].status === "fulfilled" ? results[5].value.connections : [];
  state.rules = results[6].status === "fulfilled" ? results[6].value.rules : [];
  state.checkSchedules = results[7].status === "fulfilled" ? results[7].value.schedules : [];
  state.deviceProfiles = results[8].status === "fulfilled" ? results[8].value.profiles : [];
  state.deviceAdapters = results[9].status === "fulfilled" ? results[9].value.adapters : [];
  state.devicePresets = results[10].status === "fulfilled" ? results[10].value.presets : [];
  state.storage = results[11].status === "fulfilled" ? results[11].value : null;
  updatePostSelects(); renderOverview(); renderPosts(); renderIncidents(); renderAgentRequests(); renderRuleInventory(); renderCheckSchedules(); renderDeviceProfiles(); renderStorageWarning();
  if (failures.length) showMessage(`${failures.length} workspace section${failures.length === 1 ? "" : "s"} could not be loaded. Available data is still shown.`, "error");
}

function renderStorageWarning() {
  const node = $("#storage-warning");
  if (!node) return;
  if (!state.storage || state.storage.full === undefined) { node.hidden = true; return; }
  if (state.storage.full) {
    node.hidden = false;
    node.textContent = `Storage at capacity: ${state.storage.reason || "database footprint at capacity"}. Telemetry is paused until retention reclaims space; agents retry within their bounded queues.`;
    node.className = "storage-warning critical";
  } else if (state.storage.cap_bytes > 0 && state.storage.total_bytes >= 0.9 * state.storage.cap_bytes) {
    node.hidden = false;
    node.textContent = `Storage approaching capacity: ${Math.round(state.storage.total_bytes / 1048576)} MiB of ${Math.round(state.storage.cap_bytes / 1048576)} MiB.`;
    node.className = "storage-warning warning";
  } else {
    node.hidden = true;
  }
}

function renderAgentRequests() {
  const enrollment = $('[data-view="enroll"]'); let panel = $("#agent-requests");
  if (!panel) { panel = document.createElement("section"); panel.id = "agent-requests"; panel.className = "panel"; enrollment.insertBefore(panel, $("#post-steps")); }
  const pending = state.agentRequests.filter(item => item.state === "pending"); panel.hidden = !pending.length;
  panel.innerHTML = pending.length ? `<p class="eyebrow">Agents requesting approval</p><h2>Match the phrase before connecting</h2><p>These installed agents have no monitoring authority yet. Verify the phrase shown on the machine, then create or select the post it represents.</p>${pending.map(item => `<article class="evidence-row"><div><h3>${escapeHTML(item.hostname)}</h3><p>${escapeHTML(item.platform)} · expires ${escapeHTML(new Date(item.expires_at).toLocaleTimeString())}</p><code>${escapeHTML(item.phrase)}</code></div><div class="actions"><select aria-label="Existing post" data-agent-post="${escapeHTML(item.id)}"><option value="">Choose post</option>${state.posts.map(post => `<option value="${escapeHTML(post.id)}">${escapeHTML(post.name)}</option>`).join("")}</select><button type="button" data-agent-approve="${escapeHTML(item.id)}">Approve</button><button type="button" class="quiet-button" data-agent-create="${escapeHTML(item.id)}" data-hostname="${escapeHTML(item.hostname)}">Create host post</button></div></article>`).join("")}` : "";
  $$('[data-agent-approve]',panel).forEach(button=>button.onclick=()=>approveAgent(button.dataset.agentApprove,$(`[data-agent-post="${CSS.escape(button.dataset.agentApprove)}"]`).value));
  $$('[data-agent-create]',panel).forEach(button=>button.onclick=()=>createAndApproveAgent(button.dataset.agentCreate,button.dataset.hostname));
}

async function approveAgent(id,postID){if(!postID){showMessage("Choose a post first.","error");return}try{await request(`/api/v1/agent-pairing-requests/${encodeURIComponent(id)}/approve`,{method:"POST",headers:{"X-Watchpost-CSRF":state.csrf},body:JSON.stringify({post_id:postID})});showMessage("Agent approved. It can now collect its one-time credential.");await loadCore()}catch(error){showMessage(error.message,"error")}}
async function createAndApproveAgent(id,hostname){let postID=String(hostname||"host").toLowerCase().replace(/[^a-z0-9-]+/g,"-").replace(/^-+|-+$/g,"").slice(0,63)||"host";if(state.posts.some(post=>post.id===postID))postID=`${postID.slice(0,54)}-${Date.now().toString().slice(-7)}`;try{await request("/api/v1/posts",{method:"POST",headers:{"X-Watchpost-CSRF":state.csrf},body:JSON.stringify({id:postID,name:hostname||postID,address:hostname||"",kind:"host",labels:{}})});await request(`/api/v1/agent-pairing-requests/${encodeURIComponent(id)}/approve`,{method:"POST",headers:{"X-Watchpost-CSRF":state.csrf},body:JSON.stringify({post_id:postID})});showMessage(`${hostname} connected as ${postID}.`);await loadCore()}catch(error){showMessage(error.message,"error")}}

function route() {
  const routeName = location.hash.replace(/^#\/?/, "").split("?")[0] || "overview";
  const current = routes.has(routeName) ? routeName : "overview";
  $$(".view").forEach(view => { view.hidden = view.dataset.view !== current; });
  $$("[data-route]").forEach(link => { const active = link.dataset.route === current; link.classList.toggle("active", active); if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); });
  $("#primary-nav").classList.remove("open"); $("#nav-toggle").setAttribute("aria-expanded", "false");
  document.title = "Watchpost";
  $("#page").focus({ preventScroll: true });
  if (current === "survey") renderSurvey();
  if (current === "rules") renderRuleInventory();
  if (current === "checks") renderCheckSchedules();
  if (current === "devices") renderDeviceProfiles();
  if (current === "audit") renderAudit();
  if (current === "users") renderUsers();
  if (current === "edit-post") renderPostEditor(new URLSearchParams(location.hash.split("?")[1] || "").get("id"));
  if (current === "enroll") { const guide = $("#host-guide"); if (guide) guide.hidden = !state.posts.some(post => post.kind === "host" && !state.agentConnections.some(connection => connection.post_id === post.id && connection.status !== "revoked")); }
}

function updatePostSelects() {
  const options = state.posts.length ? `<option value="">Choose a post</option>${state.posts.map(post => `<option value="${escapeHTML(post.id)}">${escapeHTML(post.name)} · ${escapeHTML(post.id)}</option>`).join("")}` : `<option value="">No posts enrolled</option>`;
  $$('[data-post-select]').forEach(select => { const selected = select.value; select.innerHTML = options; if (state.posts.some(post => post.id === selected)) select.value = selected; });
}

function renderOverview() {
  const firing = state.alerts.filter(alert => alert.state === "firing").length;
  const open = state.incidents.filter(incident => (incident.Status || incident.status) !== "resolved").length;
  $("#summary").innerHTML = [[state.posts.length, "Posts"], [firing, "Firing alerts"], [open, "Open incidents"], [state.agentConnections.filter(item => ["offline", "stale", "rejected"].includes(item.status)).length, "Agent issues"]].map(([value, label]) => `<div class="summary-card"><strong>${value}</strong><span>${label}</span></div>`).join("");
  $("#overview-posts").innerHTML = state.posts.length ? state.posts.slice(0, 5).map(postRow).join("") : stateBox("No posts yet", "Enroll the first system, service, or device to begin monitoring.");
  const evidence = [...state.alerts.filter(alert => alert.state === "firing").slice(0, 3).map(alert => `<div class="evidence-row" data-alert-row="${alert.id}"><div><h3>${escapeHTML(title(alert.severity))} alert</h3><p>${escapeHTML(alert.post_id)} · ${escapeHTML(alert.state)}</p></div><div class="actions"><span class="badge ${alert.severity === "critical" ? "danger" : "warning"}">${escapeHTML(alert.state)}</span><button type="button" class="quiet-button" data-ack-alert="${alert.id}">Acknowledge</button></div></div>`), ...state.incidents.slice(0, 3).map(incident => `<div class="incident-row"><div><h3>${escapeHTML(incident.Title || incident.title)}</h3><p>${escapeHTML(incident.Severity || incident.severity)}</p></div><span class="badge">${escapeHTML(incident.Status || incident.status)}</span></div>`)];
  $("#overview-evidence").innerHTML = evidence.length ? evidence.join("") : stateBox("Nothing active", "Alerts and incidents will appear here when evidence requires attention.");
}

function sparkline(points) {
  const values = points.filter(point => point.value !== null).map(point => Number(point.value));
  if (!values.length) return `<div class="sparkline-empty">No samples</div>`;
  const path = values.map((value, index) => `${index ? "L" : "M"} ${index * 120 / Math.max(1, values.length - 1)} ${34 - Math.max(0, Math.min(100, value)) * .3}`).join(" ");
  return `<svg class="sparkline" viewBox="0 0 120 38" role="img" aria-label="Recent values from ${Math.round(values[0])} to ${Math.round(values.at(-1))} percent"><path d="${path}"/></svg><strong>${Math.round(values.at(-1) * 10) / 10}%</strong>`;
}

function compareRule(value,operator,threshold){return({gt:value>threshold,gte:value>=threshold,lt:value<threshold,lte:value<=threshold})[operator]||false}
function policyHealth(post,signal,points,connection){
  const point=[...points].reverse().find(item=>item.value!==null),value=point?Number(point.value):null,rules=state.rules.filter(rule=>(rule.PostID||rule.post_id)===post.id&&(rule.Signal||rule.signal)===signal&&(rule.Enabled??rule.enabled));
  if(post.maintenance)return{level:"maintenance",value,reason:"Post is in maintenance"};
  if(!point)return{level:"unknown",value:null,reason:"No samples received"};
  if(point.quality&&point.quality!=="good")return{level:"unknown",value,reason:`Sample quality is ${point.quality}`};
  if(Date.now()-Date.parse(point.observed_at)>180000)return{level:"unknown",value,reason:"Latest sample is stale"};
  if(connection&&!(["healthy","partial"].includes(connection.status)))return{level:"unknown",value,reason:`Agent is ${title(connection.status).toLowerCase()}`};
  const activeAlerts=state.alerts.filter(alert=>alert.post_id===post.id&&["pending","firing","acknowledged"].includes(alert.state));
  const alert=activeAlerts.find(item=>rules.some(rule=>(rule.ID||rule.id)===item.rule_id));
  if(alert)return{level:alert.severity==="critical"?"critical":"warning",value,reason:`${title(alert.severity)} alert is ${alert.state}`};
  const breached=rules.find(rule=>compareRule(value,rule.Operator||rule.operator,Number(rule.Threshold??rule.threshold)));
  if(breached)return{level:(breached.Severity||breached.severity)==="critical"?"critical":"warning",value,reason:`Beyond ${ruleCondition(breached)}`};
  if(rules.length)return{level:"safe",value,reason:`Within ${rules.map(ruleCondition).join(" and ")}`};
  return{level:"unknown",value,reason:"No policy configured"};
}
function ruleCondition(rule){const words={gt:">",gte:"≥",lt:"<",lte:"≤"};return`${words[rule.Operator||rule.operator]||rule.Operator||rule.operator} ${Number(rule.Threshold??rule.threshold)}%`}
function healthBar(post,signal,points,label,connection){const health=policyHealth(post,signal,points,connection),width=health.value===null?0:Math.max(0,Math.min(100,health.value));return `<div class="health-reading"><div class="health-meter ${health.level}" role="meter" aria-label="${escapeHTML(`${label}: ${health.reason}`)}" aria-valuemin="0" aria-valuemax="100" ${health.value===null?"":`aria-valuenow="${width}"`} title="${escapeHTML(health.reason)}"><i style="width:${width}%"></i></div><strong>${health.value===null?"—":`${Math.round(health.value*10)/10}%`}</strong></div><small class="policy-reason ${health.level}">${escapeHTML(health.reason)}</small>`}
function ensureSurveyControls(){if($("#survey-controls"))return;const heading=$('[data-view="survey"] .page-heading');const controls=document.createElement("div");controls.id="survey-controls";controls.className="survey-controls";controls.innerHTML='<label><span>Find posts</span><input id="survey-filter" type="search" placeholder="Name or ID"></label><label><span>Order</span><select id="survey-order"><option value="severity">Attention first</option><option value="name">Name</option><option value="cpu">Highest CPU</option><option value="memory">Highest memory</option><option value="disk">Highest disk</option></select></label>';heading.after(controls);$("#survey-filter").addEventListener("input",renderSurvey);$("#survey-order").addEventListener("change",renderSurvey)}

async function renderSurvey() {
  ensureSurveyControls();
  const grid = $("#survey-grid"), status = $("#survey-status");
  if (!state.posts.length) { grid.innerHTML = stateBox("No posts enrolled", "Enroll a host and connect a collector to begin the resource survey."); status.textContent = ""; return; }
  grid.innerHTML = stateBox("Loading resource survey", "Reading one hour of bounded resource history.", "loading");
  try {
    const result = await request("/api/v1/survey"), grouped = new Map();
    result.series.forEach(series => { if (!grouped.has(series.post_id)) grouped.set(series.post_id, {}); grouped.get(series.post_id)[series.signal] = series.points; });
    const latest=(signals,name)=>{const points=signals[name]||[];return points.length&&points.at(-1).value!==null?Number(points.at(-1).value):-1},query=($("#survey-filter")?.value||"").toLowerCase(),order=$("#survey-order")?.value||"severity";
    const items=state.posts.filter(post=>`${post.name} ${post.id}`.toLowerCase().includes(query)).map(post=>{const signals=grouped.get(post.id)||{},connection=state.agentConnections.find(item=>item.post_id===post.id&&item.status!=="revoked"),values={cpu:latest(signals,"cpu.percent"),memory:latest(signals,"memory.percent"),disk:latest(signals,"disk.percent")},policy=["cpu.percent","memory.percent","disk.percent"].map(signal=>policyHealth(post,signal,signals[signal]||[],connection)),rank=Math.max(...policy.map(item=>({maintenance:0,safe:1,unknown:2,warning:3,critical:4})[item.level]));return{post,signals,connection,values,rank}});
    if(order==="name")items.sort((a,b)=>a.post.name.localeCompare(b.post.name));else if(order in (items[0]?.values||{}))items.sort((a,b)=>b.values[order]-a.values[order]);else items.sort((a,b)=>b.rank-a.rank||a.post.name.localeCompare(b.post.name));
    grid.innerHTML=items.length?items.map(({post,signals,connection})=>`<article class="survey-card"><div class="survey-heading"><div><h2>${escapeHTML(post.name)}</h2><p><code>${escapeHTML(post.id)}</code> · ${escapeHTML(title(post.kind))}</p></div><span class="health-state ${escapeHTML(connection?.status||"unknown")}"><i></i>${escapeHTML(title(connection?.status||"unknown"))}</span></div><div class="resource-grid">${[["CPU","cpu.percent"],["Memory","memory.percent"],["Disk","disk.percent"]].map(([label,signal])=>`<div class="resource"><div class="resource-label"><span>${label}</span>${sparkline(signals[signal]||[])}</div>${healthBar(post,signal,signals[signal]||[],label,connection)}</div>`).join("")}</div><a class="policy-link" href="#/rules?post=${encodeURIComponent(post.id)}">Review ${state.rules.filter(rule=>(rule.PostID||rule.post_id)===post.id).length} rules</a></article>`).join(""):stateBox("No matching posts","Try a different post name or ID.");
    status.textContent = `Last hour · ${items.length} of ${state.posts.length} posts · refreshed ${new Date().toLocaleTimeString()}`;
  } catch (error) { grid.innerHTML = stateBox("Survey unavailable", error.message, error.message.includes("permission") ? "permission" : "error"); }
}

function postRow(post) {
  const stale = post.archived ? "Archived" : post.maintenance ? "Maintenance" : "Active";

  const connections=state.agentConnections.filter(item=>item.post_id===post.id),activeConnection=connections.find(item=>item.status!=="revoked"),connection=activeConnection||connections[0];
  const monitoring=connection?`<span class="badge ${["offline","rejected"].includes(connection.status)?"danger":connection.status==="healthy"?"":"warning"}">Agent · ${escapeHTML(title(connection.status))}</span>`:post.kind==="host"?`<span class="badge warning">No agent</span>`:"";
  const guidance = connection && connection.status === "revoked" ? " · unpair the local agent before re-pairing" : connection && connection.status === "rejected" ? " · rotate the credential or re-pair" : connection && ["offline", "stale", "skewed"].includes(connection.status) ? " · check the agent's local delivery status" : "";
  return `<article class="post-row" data-post-id="${escapeHTML(post.id)}"><div><h3>${escapeHTML(post.name)}</h3><p>${escapeHTML(title(post.kind))} · <code>${escapeHTML(post.id)}</code>${post.address ? ` · ${escapeHTML(post.address)}` : ""} <span class="badge">${stale}</span> ${monitoring}</p>${connection?`<p>${escapeHTML(connection.hostname)} · ${escapeHTML(connection.platform)} · ${connections.length} agent connection${connections.length===1?"":"s"}${guidance}</p>`:""}</div><div class="row-actions"><button class="quiet-button" type="button" data-post-action="edit">Edit</button>${post.kind === "host"&&!activeConnection ? `<button class="quiet-button" type="button" data-post-action="connect">Connect</button>` : ""}${activeConnection?`<button class="quiet-button" type="button" data-post-action="revoke-agent" data-agent-id="${escapeHTML(activeConnection.installation_id)}">Revoke agent</button>`:""}<button class="quiet-button" type="button" data-post-action="maintenance">${post.maintenance ? "End maintenance" : "Start maintenance"}</button><button class="quiet-button" type="button" data-post-action="archive">${post.archived ? "Restore" : "Archive"}</button></div></article>`;
}

function renderPosts() {
  const query = ($("#post-filter").value || "").trim().toLowerCase();
  const filtered = state.posts.filter(post => [post.id, post.name, post.address, post.kind].some(value => String(value || "").toLowerCase().includes(query)));
  const shown = filtered.slice(0, state.postLimit);
  $("#post-count").textContent = `${state.postTotal || filtered.length} post${state.postTotal === 1 ? "" : "s"}`;
  $("#posts").innerHTML = shown.length ? shown.map(postRow).join("") : stateBox(query ? "No matching posts" : "No posts enrolled", query ? "Try a different name, ID, or kind." : "Enroll a post to build the monitored inventory.");
  $("#more-posts").hidden = state.posts.length >= state.postTotal || shown.length === filtered.length;
  $("#more-posts").textContent = state.posts.length < state.postTotal ? `Load ${Math.min(100, state.postTotal - state.posts.length)} more posts` : `Show ${Math.min(50, filtered.length - shown.length)} more posts`;
}

async function updatePost(post, changes) {
  await request(`/api/v1/posts/${encodeURIComponent(post.id)}`, { method: "PUT", headers: { "X-Watchpost-CSRF": state.csrf, "If-Match": String(post.version) }, body: JSON.stringify({ ...post, ...changes }) });
  await loadCore();
}

function renderPostEditor(id) {
  const post = state.posts.find(item => item.id === id);
  if (!post) { location.hash = "#/posts"; if (id) showMessage("Post not found.", "error"); return; }
  const form = $("#edit-post");
  for (const name of ["id", "name", "address", "owner", "version"]) form.elements[name].value = post[name] ?? "";
  form.elements.maintenance.checked = post.maintenance;
  form.elements.archived.checked = post.archived;
  $("#delete-post-id").textContent = post.id;
  $("#delete-post").elements.confirm_id.value = "";
}

function renderRuleInventory() {
  const view = $('[data-view="rules"]');
  if (!view) return;
  let inventory = $("#rule-inventory");
  if (!inventory) {
    inventory = document.createElement("section"); inventory.id = "rule-inventory"; inventory.className = "panel rule-inventory";
    view.insertBefore(inventory, $("#rule"));
    $("#rules-title").textContent = "Rules";
    $("#rules-title").nextElementSibling.textContent = "Review starter policies, then add or pause explicit thresholds.";
  }
  const selected = new URLSearchParams(location.hash.split("?")[1] || "").get("post");
  const rules = selected ? state.rules.filter(rule => (rule.PostID || rule.post_id) === selected) : state.rules;
  inventory.innerHTML = `<div class="panel-heading"><div><h2>${selected ? `Policy for ${escapeHTML(selected)}` : "Configured policy"}</h2><p>Health bars use these thresholds, active alerts, freshness, maintenance, and agent state.</p></div>${selected ? '<a href="#/rules">All rules</a>' : ""}</div>${rules.length ? rules.map(rule => { const enabled = rule.Enabled ?? rule.enabled, duration = Number((rule.Duration ?? rule.duration) || 0) / 1e9; return `<article class="rule-row"><div><h3>${escapeHTML(rule.ID || rule.id)}</h3><p>${escapeHTML(rule.Signal || rule.signal)} ${escapeHTML(ruleCondition(rule))}${duration ? ` for ${duration}s` : " immediately"} · ${escapeHTML(title(rule.Severity || rule.severity))}</p></div><button type="button" class="quiet-button" data-rule-toggle="${escapeHTML(rule.ID || rule.id)}" data-enabled="${enabled}">${enabled ? "Pause" : "Enable"}</button></article>`; }).join("") : stateBox("No rules configured", "Add a rule below, or enroll a host with starter rules enabled.")}`;
  $$('[data-rule-toggle]', inventory).forEach(button => button.onclick = async () => { try { await request(`/api/v1/rules/${encodeURIComponent(button.dataset.ruleToggle)}/enabled`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ enabled: button.dataset.enabled !== "true" }) }); await loadCore(); showMessage(`Rule ${button.dataset.enabled === "true" ? "paused" : "enabled"}.`); } catch (error) { showMessage(error.message, "error"); } });
  if (selected && state.posts.some(post => post.id === selected)) $('#rule [name="PostID"]').value = selected;
}

function renderCheckSchedules(){const view=$('[data-view="checks"]');if(!view)return;let panel=$("#check-schedules");if(!panel){panel=document.createElement("section");panel.id="check-schedules";panel.className="panel";view.append(panel)}panel.innerHTML='<h2>Scheduled checks</h2><p>Run HTTP, TCP, TLS, DNS or ICMP centrally without installing an agent.</p>'+ (state.checkSchedules.length?state.checkSchedules.map(item=>`<article class="rule-row"><div><h3>${escapeHTML(item.ID||item.id)}</h3><p>${escapeHTML(item.PostID||item.post_id)} · ${escapeHTML(title(item.Kind||item.kind))} every ${escapeHTML(item.IntervalSeconds||item.interval_seconds)}s</p></div><span class="badge ${item.Last&&!item.Last.ok?'danger':''}">${item.Last?(item.Last.ok?'Healthy':'Failed'):'Pending'}</span></article>`).join(''):stateBox('No scheduled checks','Create one below to begin collecting availability history.'))+`<form id="scheduled-check" class="compact-form"><label>Schedule ID<input name="ID" placeholder="homepage-http" required></label><label>Post<select name="PostID" required><option value="">Choose post</option>${state.posts.map(post=>`<option value="${escapeHTML(post.id)}">${escapeHTML(post.name)}</option>`).join("")}</select></label><label>Every (seconds)<input name="IntervalSeconds" type="number" min="30" max="86400" value="60" required></label><button>Schedule current target</button></form>`;$("#scheduled-check").onsubmit=async event=>{event.preventDefault();const raw=formJSON(event.currentTarget),source=formJSON($("#check")),value={...raw,Kind:source.kind,Address:source.address,ServerName:source.serverName,IntervalSeconds:Number(raw.IntervalSeconds)};try{await request("/api/v1/check-schedules",{method:"POST",headers:{"X-Watchpost-CSRF":state.csrf},body:JSON.stringify(value)});await loadCore();showMessage("Scheduled check created.")}catch(error){showMessage(error.message,"error")}};}

function renderDeviceProfiles(){const view=$('[data-view="devices"]'),form=$("#snmp");if(!view||!form)return;if(!form.elements.post_id){const label=document.createElement("label");label.innerHTML='Post<select name="post_id" required><option value="">Choose a device post</option>'+state.posts.map(post=>`<option value="${escapeHTML(post.id)}">${escapeHTML(post.name)}</option>`).join('')+'</select>';form.querySelector('[data-snmp-step="1"]').prepend(label)}let panel=$("#device-profiles");if(!panel){panel=document.createElement("section");panel.id="device-profiles";panel.className="panel";view.append(panel)}panel.innerHTML='<h2>Saved read-only methods</h2><p>Credentials are never returned. Every adapter declares its authority explicitly.</p>'+state.deviceProfiles.map(profile=>`<article class="rule-row"><div><h3>${escapeHTML(profile.id)}</h3><p>${escapeHTML(profile.post_id)} · ${escapeHTML(title(profile.kind))} · ${escapeHTML(profile.address)}:${profile.port}</p></div><button type="button" class="quiet-button" data-delete-profile="${escapeHTML(profile.id)}">Remove</button></article>`).join('')+(state.deviceProfiles.length?'':stateBox('No device methods','Test and save an SNMPv3 profile above.'))+'<p class="adapter-boundary">'+state.deviceAdapters.map(adapter=>`${escapeHTML(adapter.name)} · ${escapeHTML(title(adapter.authority))}`).join(' · ')+'</p>';$$('[data-delete-profile]',panel).forEach(button=>button.onclick=async()=>{try{await request(`/api/v1/device-profiles/${encodeURIComponent(button.dataset.deleteProfile)}`,{method:'DELETE',headers:{'X-Watchpost-CSRF':state.csrf}});await loadCore();showMessage('Device method removed.')}catch(error){showMessage(error.message,'error')}})}

function renderIncidents() {
  $("#incidents").innerHTML = state.incidents.length ? state.incidents.map(incident => `<article class="incident-row"><div><h3>${escapeHTML(incident.Title || incident.title)}</h3><p>${escapeHTML(incident.Severity || incident.severity)} · ${escapeHTML(incident.Status || incident.status)}</p></div><div class="actions"><button type="button" class="quiet-button" data-incident-open="${incident.ID || incident.id}">Review</button></div></article>`).join("") : stateBox("No incidents", "Open an incident when related evidence needs durable coordination.");
  $$("[data-incident-open]").forEach(button => button.onclick = () => openIncidentDetail(button.dataset.incidentOpen));
}

async function openIncidentDetail(id) {
  const target = $("#incident-detail");
  target.hidden = false;
  target.innerHTML = stateBox("Loading incident", "Reading the durable timeline.", "loading");
  try {
    const data = await request(`/api/v1/incidents/${id}`);
    const incident = data.incident;
    const timeline = (data.timeline || []).map(entry => `<p><strong>${escapeHTML(entry.Kind || entry.kind)}</strong> ${escapeHTML(entry.At || "")} · ${escapeHTML(entry.Actor || entry.actor || "system")}: ${escapeHTML(entry.Body || entry.body)}</p>`).join("") || "<p>No timeline entries yet.</p>";
    target.innerHTML = `<h3>${escapeHTML(incident.Title || incident.title)}</h3><p>${escapeHTML(incident.Status || incident.status)} · ${escapeHTML(incident.Severity || incident.severity)} · owner ${escapeHTML(incident.Owner || incident.owner || "none")}</p><form id="incident-actions" class="inline-form"><label>Status<select name="status"><option value="open">open</option><option value="investigating">investigating</option><option value="mitigated">mitigated</option><option value="resolved">resolved</option></select></label><input name="summary" placeholder="summary (optional)"><button>Transition</button></form><form id="incident-note" class="inline-form"><input name="body" placeholder="Add an attributed note"><button>Add note</button></form><form id="incident-assign" class="inline-form"><input name="owner" placeholder="assign owner"><button>Assign</button></form><h4>Timeline</h4>${timeline}`;
    $("#incident-actions").onsubmit = async event => { event.preventDefault(); const value = formJSON(event.currentTarget); try { await request(`/api/v1/incidents/${id}/transition`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ status: value.status, summary: value.summary }) }); await openIncidentDetail(id); showMessage("Incident transitioned."); } catch (error) { showMessage(error.message, "error"); } };
    $("#incident-note").onsubmit = async event => { event.preventDefault(); const value = formJSON(event.currentTarget); if (!value.body) return; try { await request(`/api/v1/incidents/${id}/notes`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ body: value.body }) }); await openIncidentDetail(id); showMessage("Note added."); } catch (error) { showMessage(error.message, "error"); } };
    $("#incident-assign").onsubmit = async event => { event.preventDefault(); const value = formJSON(event.currentTarget); if (!value.owner) return; try { await request(`/api/v1/incidents/${id}/assign`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ owner: value.owner }) }); await openIncidentDetail(id); showMessage("Owner assigned."); } catch (error) { showMessage(error.message, "error"); } };
  } catch (error) {
    target.innerHTML = stateBox("Incident unavailable", error.message, error.message.includes("permission") ? "permission" : "error");
  }
}

async function renderAudit() {
  const target = $("#audit-log");
  target.innerHTML = stateBox("Loading audit log", "Reading the attributed operation record.", "loading");
  try {
    const data = await request("/api/v1/audit");
    target.innerHTML = data.audit.length ? data.audit.map(entry => `<article class="rule-row"><div><h3>${escapeHTML(entry.action)}</h3><p>${escapeHTML(entry.at)} · ${escapeHTML(entry.actor_email || "system")} · ${escapeHTML(entry.object_type)} <code>${escapeHTML(entry.object_id)}</code></p>${entry.detail ? `<p>${escapeHTML(entry.detail)}</p>` : ""}</div></article>`).join("") : stateBox("No audit records", "State-changing operations will be recorded here.");
  } catch (error) {
    target.innerHTML = stateBox("Audit unavailable", error.message, error.message.includes("permission") ? "permission" : "error");
  }
}

async function renderUsers() {
  const target = $("#user-list");
  target.innerHTML = stateBox("Loading users", "Reading the global role inventory.", "loading");
  try {
    const data = await request("/api/v1/users");
    target.innerHTML = data.users.length ? data.users.map(user => `<article class="rule-row"><div><h3>${escapeHTML(user.email)}</h3><p>Role ${escapeHTML(user.role)}</p></div><div class="actions"><select aria-label="Role for ${escapeHTML(user.email)}" data-user-role="${user.id}">${["viewer", "operator", "admin"].map(role => `<option value="${role}" ${role === user.role ? "selected" : ""}>${escapeHTML(role)}</option>`).join("")}</select><button type="button" class="quiet-button" data-user-password="${user.id}">Reset password</button><button type="button" class="quiet-button" data-user-revoke="${user.id}">Revoke sessions</button></div></article>`).join("") : stateBox("No users", "Create the first additional account above.");
    $$("[data-user-role]", target).forEach(select => select.onchange = async () => { try { await request(`/api/v1/users/${select.dataset.userRole}/role`, { method: "PUT", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ role: select.value }) }); await loadCore(); showMessage("Role updated."); } catch (error) { showMessage(error.message, "error"); } });
    $$("[data-user-password]", target).forEach(button => button.onclick = async () => { const password = prompt(`New password for user ${button.dataset.userPassword} (7+ characters)`); if (!password) return; try { await request(`/api/v1/users/${button.dataset.userPassword}/reset-password`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ password }) }); showMessage("Password reset."); } catch (error) { showMessage(error.message, "error"); } });
    $$("[data-user-revoke]", target).forEach(button => button.onclick = async () => { if (!confirm(`Revoke all sessions for user ${button.dataset.userRevoke}?`)) return; try { await request(`/api/v1/users/${button.dataset.userRevoke}/revoke-sessions`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf } }); showMessage("Sessions revoked."); } catch (error) { showMessage(error.message, "error"); } });
  } catch (error) {
    target.innerHTML = stateBox("Users unavailable", error.message, error.message.includes("permission") ? "permission" : "error");
  }
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
$("#refresh-survey").addEventListener("click", renderSurvey);

$("#overview-evidence").addEventListener("click", async event => { const button = event.target.closest("[data-ack-alert]"); if (!button) return; try { await request(`/api/v1/alerts/${button.dataset.ackAlert}/acknowledge`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf } }); await loadCore(); showMessage("Alert acknowledged."); } catch (error) { showMessage(error.message, "error"); } });

$("#post-filter").addEventListener("input", () => { state.postLimit = 100; renderPosts(); });
$("#more-posts").addEventListener("click", async () => { try { const data = await request(`/api/v1/posts?limit=100&offset=${state.posts.length}`); const existing = new Set(state.posts.map(post => post.id)); for (const post of data.posts) { if (!existing.has(post.id)) state.posts.push(post); } state.postTotal = data.total || state.postTotal; renderPosts(); } catch (error) { showMessage(error.message, "error"); } });
$("#posts").addEventListener("click", async event => { const button = event.target.closest("[data-post-action]"); if (!button) return; const post = state.posts.find(item => item.id === button.closest("[data-post-id]").dataset.postId), action = button.dataset.postAction; if (action === "edit") { location.hash = `#/edit-post?id=${encodeURIComponent(post.id)}`; return; } if (action === "connect") { location.hash = "#/enroll"; showMessage("Install the Watchpost Agent on this host and request pairing from its local interface or CLI, then approve it here."); return; } if(action==="revoke-agent"){if(!confirm(`Revoke ${button.dataset.agentId} from ${post.name}?`))return;try{await request(`/api/v1/agent-connections/${encodeURIComponent(button.dataset.agentId)}/revoke`,{method:"POST",headers:{"X-Watchpost-CSRF":state.csrf}});await loadCore();showMessage("Agent authority revoked. Unpair the local agent before pairing it again.")}catch(error){showMessage(error.message,"error")}return} try { button.disabled = true; await updatePost(post, action === "maintenance" ? { maintenance: !post.maintenance } : { archived: !post.archived }); } catch (error) { showMessage(error.message, "error"); } });

$("#edit-post").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), post = state.posts.find(item => item.id === values.id); setBusy(form, true); try { await updatePost(post, { name: values.name, address: values.address, owner: values.owner, maintenance: form.elements.maintenance.checked, archived: form.elements.archived.checked }); location.hash = "#/posts"; showMessage(`${values.name} updated.`); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });
$("#delete-post").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), id = $("#edit-post").elements.id.value; if (values.confirm_id !== id) { showMessage(`Type ${id} exactly to confirm.`, "error"); return; } setBusy(form, true); try { await request(`/api/v1/posts/${encodeURIComponent(id)}`, { method: "DELETE", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ confirm_id: values.confirm_id }) }); await loadCore(); location.hash = "#/posts"; showMessage(`${id} and its post-scoped data were permanently deleted.`); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });

const postWizard = setupWizard("post", "[data-step]", "#post-steps", "#post-back", "#post-next", "#post-submit", () => { const values = formJSON($("#create")); $("#post-review").innerHTML = `<dt>ID</dt><dd><code>${escapeHTML(values.id)}</code></dd><dt>Name</dt><dd>${escapeHTML(values.name)}</dd><dt>Address</dt><dd>${escapeHTML(values.address || "Not specified")}</dd><dt>Kind</dt><dd>${escapeHTML(title(values.kind))}</dd><dt>Starter rules</dt><dd>${values.starter_rules ? "CPU 90%, memory 90%, disk 85%" : "None"}</dd>`; });
$("#create").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), starterRules = values.starter_rules === "on", post = { id: values.id, name: values.name, address: values.address, kind: values.kind, labels: {} }; setBusy(form, true); try { await request("/api/v1/posts", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(post) }); if (starterRules && post.kind === "host") { const definitions = [["cpu", "cpu.percent", 90, 300], ["memory", "memory.percent", 90, 300], ["disk", "disk.percent", 85, 0]]; for (const [name, Signal, Threshold, DurationSeconds] of definitions) await request("/api/v1/rules", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ ID: `${post.id}-${name}-high`, PostID: post.id, Signal, Operator: "gt", Threshold, DurationSeconds, MissingPolicy: "unknown", Severity: "warning" }) }); } form.reset(); postWizard.reset(); await loadCore(); if (post.kind === "host") { const guide = $("#host-guide"); if (guide) guide.hidden = false; } location.hash = "#/posts"; if (post.kind === "host") { showMessage(`${post.name} enrolled. Install the Watchpost Agent on it, request pairing from the agent, then approve it here under Add a post.`); } else showMessage(`${post.name} enrolled.`); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });

$("#check").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, output = $("#check-result"); setBusy(form, true); output.hidden = false; output.innerHTML = stateBox("Running check", "Waiting for the target to respond.", "loading"); try { const result = await request("/api/v1/checks", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(formJSON(form)) }); output.innerHTML = `<h2>${result.ok ? "Check healthy" : "Check failed"}</h2><dl class="review-list"><dt>Result</dt><dd>${result.ok ? "Target responded successfully" : escapeHTML(result.failure || "Unknown failure")}</dd><dt>Latency</dt><dd>${escapeHTML(result.latency || "Not available")}</dd></dl>`; output.classList.toggle("permission-state", !result.ok); } catch (error) { output.innerHTML = stateBox("Check unavailable", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

$("#history").addEventListener("submit", async event => { event.preventDefault(); const values = formJSON(event.currentTarget), to = new Date(), from = new Date(to.getTime() - 3600000), signals = values.signals.split(",").map(value => value.trim()).filter(Boolean).slice(0, 4), series = []; try { for (const signal of signals) { const params = new URLSearchParams({ signal, from: from.toISOString(), to: to.toISOString() }); series.push({ signal, points: (await request(`/api/v1/posts/${encodeURIComponent(values.post)}/history?${params}`)).points }); } const all = series.flatMap(item => item.points).filter(point => point.value !== null), svg = $("#chart"); svg.replaceChildren(); if (!all.length) { $("#history-empty").innerHTML = `<h2>No numeric history</h2><p>This post has no matching numeric samples in the last hour. Recent data may be stale or collection may not have started.</p>`; $("#history-empty").hidden = false; svg.hidden = true; return; } const numbers = all.map(point => point.value), min = Math.min(...numbers), max = Math.max(...numbers), span = max - min || 1, colors = ["#9fcb78", "#dbb66f", "#dd8078", "#b7bdb7"]; series.forEach((entry, index) => { const numeric = entry.points.filter(point => point.value !== null), line = document.createElementNS("http://www.w3.org/2000/svg", "polyline"); line.setAttribute("fill", "none"); line.setAttribute("stroke", colors[index]); line.setAttribute("stroke-width", "3"); line.setAttribute("points", numeric.map((point, i) => `${20 + 760 * i / Math.max(1, numeric.length - 1)},${230 - 200 * (point.value - min) / span}`).join(" ")); svg.append(line); }); $("#history-empty").hidden = true; svg.hidden = false; const params = new URLSearchParams({ signal: signals[0], from: from.toISOString(), to: to.toISOString(), format: "csv" }); $("#export").href = `/api/v1/posts/${encodeURIComponent(values.post)}/history?${params}`; $("#export").hidden = false; } catch (error) { showMessage(error.message, "error"); } });

$("#rule").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, raw = formJSON(form), value = { ...raw, Threshold: Number(raw.Threshold), DurationSeconds: Number(raw.DurationSeconds) }, output = $("#rule-result"); output.hidden = false; output.innerHTML = stateBox("Creating rule", "Saving the deterministic threshold.", "loading"); setBusy(form, true); try { await request("/api/v1/rules", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(value) }); output.innerHTML = `<h2>Rule created</h2><p><code>${escapeHTML(value.ID)}</code> evaluates every good-quality <code>${escapeHTML(value.Signal)}</code> observation for ${escapeHTML(value.PostID)} and fires after ${escapeHTML(value.DurationSeconds)} seconds beyond ${escapeHTML(value.Threshold)}%.</p>`; form.elements.ID.value = ""; await loadCore(); } catch (error) { output.innerHTML = stateBox("Rule was not created", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

$("#log").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, value = { ...formJSON(form), observed_at: new Date().toISOString(), fields: {} }; setBusy(form, true); try { const stored = await request("/api/v1/logs", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(value) }); showMessage(`Log evidence ${stored.id} stored.`); await searchEvidence(value.post_id, "", String(stored.id)); form.elements.message.value = ""; } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });
$("#log-search").addEventListener("submit", async event => { event.preventDefault(); const value = formJSON(event.currentTarget); await searchEvidence(value.post, value.query); });
$("#evidence-results").addEventListener("click", event => { const button = event.target.closest("[data-cite-log]"); if (!button) return; $("#agent-log-id").value = button.dataset.citeLog; const select = $('#agent [name="post"]'); select.value = button.dataset.post; location.hash = "#/investigate"; showMessage(`Log ${button.dataset.citeLog} attached to the investigation form.`); });

$("#agent").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, value = formJSON(form), output = $("#investigation-result"); setBusy(form, true); output.hidden = false; output.innerHTML = stateBox("Investigating", "Reading only the evidence you supplied.", "loading"); try { const conversation = await request("/api/v1/conversations", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ post_id: value.post }) }), evidence = value.log_id ? [{ kind: "log", id: value.log_id, summary: "Operator-selected log evidence" }] : [], response = await request(`/api/v1/conversations/${conversation.id}/investigate`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ question: value.question, evidence }) }); const citations = (response.citations || []).map(citation => `<span class="citation"><button type="button" class="quiet-button" data-investigation-citation="${escapeHTML(citation.id)}" data-kind="${escapeHTML(citation.kind)}" data-post="${escapeHTML(value.post)}">${escapeHTML(citation.kind)}:${escapeHTML(citation.id)}</button></span>`).join(""); output.innerHTML = `<h2>Investigation result</h2><p>${escapeHTML(response.answer)}</p><h3>Verified evidence</h3><p>${citations || "No evidence was cited."}</p><h3>Uncertainty</h3><p>${escapeHTML(response.uncertainty)}</p>`; } catch (error) { output.innerHTML = stateBox("Investigation unavailable", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });
$("#investigation-result").addEventListener("click", async event => { const button = event.target.closest("[data-investigation-citation]"); if (!button || button.dataset.kind !== "log") return; location.hash = "#/evidence"; $('#log-search [name="post"]').value = button.dataset.post; await searchEvidence(button.dataset.post, "", button.dataset.investigationCitation); });

$("#action [name=type]").addEventListener("change", event => { $("#route-field").hidden = event.target.value !== "silence_route"; $("#check-field").hidden = event.target.value !== "rerun_check"; });
$("#action").addEventListener("submit", event => { event.preventDefault(); const value = formJSON(event.currentTarget), needsApproval = value.type === "silence_route", output = $("#action-review"), effect = needsApproval ? `Disable notification route ${value.route_id || "(route required)"}` : `Rerun the saved check for post ${value.post}`; if (needsApproval && !value.route_id) { showMessage("Route ID is required.", "error"); return; } output.hidden = false; output.innerHTML = `<h2>Review typed action</h2><dl class="review-list"><dt>Before</dt><dd>${needsApproval ? "Notification route is enabled or unchanged" : "Existing check evidence remains unchanged"}</dd><dt>Proposed change</dt><dd>${escapeHTML(effect)}</dd><dt>Approval</dt><dd>${needsApproval ? "Required from a different administrator" : "Not required for this bounded action"}</dd><dt>Verification</dt><dd>${needsApproval ? "Execution result must confirm the route was disabled" : "Execution result records the observed check evidence (ok, failure, latency)"}</dd></dl><button id="confirm-action" type="button">Confirm request</button>`; $("#confirm-action").onclick = () => requestAction(value, output); });
async function requestAction(value, output) { output.innerHTML = stateBox("Requesting action", "Writing an auditable typed request.", "loading"); const needsApproval = value.type === "silence_route", parameters = needsApproval ? { route_id: value.route_id } : { check: value.check_id }; try { const response = await request("/api/v1/actions", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ Type: value.type, PostID: value.post, IdempotencyKey: crypto.randomUUID(), Parameters: parameters }) }); output.innerHTML = `<h2>Action ${response.id} requested</h2><dl class="review-list"><dt>State</dt><dd>${needsApproval ? "Pending independent approval" : "Approved and ready"}</dd><dt>Expected result</dt><dd>${needsApproval ? "Route reports disabled: true" : "The check result records ok, failure and latency from the real run"}</dd></dl>${needsApproval ? `<p class="callout">A different administrator must approve action ${response.id} through the approval API before execution. The requester cannot approve their own action.</p>` : `<button id="execute-action" type="button">Execute and verify</button>`}`; if (!needsApproval) $("#execute-action").onclick = () => executeAction(response.id, output); } catch (error) { output.innerHTML = stateBox("Action request failed", error.message, error.message.includes("permission") ? "permission" : "error"); } }
async function executeAction(id, output) { output.innerHTML = stateBox("Executing action", "The idempotent execution claim is being verified.", "loading"); try { const result = await request(`/api/v1/actions/${id}/execute`, { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf } }); output.innerHTML = `<h2>Action completed</h2><dl class="review-list"><dt>Final state</dt><dd>Completed</dd><dt>Verification result</dt><dd><code>${escapeHTML(JSON.stringify(result))}</code></dd></dl>`; } catch (error) { output.innerHTML = stateBox("Action did not complete", error.message, "error"); } }

$("#incident").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, value = { ...formJSON(form), alert_ids: [] }; setBusy(form, true); try { await request("/api/v1/incidents", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(value) }); form.reset(); await loadCore(); showMessage("Incident opened."); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });

addOID(); $("#add-oid").addEventListener("click", () => addOID({ name: "", oid: "", unit: "" }));
$("#snmp [name=device_kind]").addEventListener("change",event=>{const preset=state.devicePresets.find(item=>(item.Kind||item.kind)===event.target.value);if(!preset)return;$("#oid-rows").replaceChildren();const oids=preset.OIDs||preset.oids||[];if(oids.length)oids.forEach(item=>addOID({name:item.Name||item.name,oid:item.OID||item.oid,unit:item.Unit||item.unit}));else addOID();showMessage(`${preset.Name||preset.name} profile loaded. Add vendor OIDs where required.`)});
const snmpWizard = setupWizard("snmp", "[data-snmp-step]", "#snmp-steps", "#snmp-back", "#snmp-next", "#snmp-test", () => { const values = formJSON($("#snmp")), count = $$(".oid-row").length; $("#snmp-review").innerHTML = `<dt>Target</dt><dd>${escapeHTML(values.address)}:${escapeHTML(values.port)}</dd><dt>Security</dt><dd>SNMPv3 authPriv · SHA-256 · AES</dd><dt>Profile</dt><dd>${escapeHTML(values.profile_id)} (${escapeHTML(title(values.device_kind))})</dd><dt>OIDs</dt><dd>${count}</dd>`; });
$("#snmp").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), output = $("#snmp-result"), OIDs = $$(".oid-row").map(row => ({ Name: $('[data-oid="name"]', row).value, OID: $('[data-oid="oid"]', row).value, Unit: $('[data-oid="unit"]', row).value })); output.hidden = false; output.innerHTML = stateBox("Testing SNMP connection", "Authenticating and polling the bounded OID profile.", "loading"); setBusy(form, true); try { const result = await request("/api/v1/devices/snmp/poll", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ config: { Address: values.address, Port: Number(values.port), Username: values.username, AuthPassword: values.auth_password, PrivacyPassword: values.privacy_password, Timeout: 5_000_000_000 }, profile: { ID: values.profile_id, Kind: values.device_kind, OIDs } }) }); await request("/api/v1/device-profiles", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify({ id: values.profile_id, post_id: values.post_id, kind: values.device_kind, address: values.address, port: Number(values.port), username: values.username, auth_password: values.auth_password, privacy_password: values.privacy_password, interval_seconds: Number(values.interval_seconds || 0), oids: OIDs }) }); await loadCore(); output.innerHTML = `<h2>Connection successful</h2><p>${result.readings.length} reading${result.readings.length === 1 ? "" : "s"} returned.</p><dl class="review-list">${result.readings.map(reading => `<dt>${escapeHTML(reading.Name)}</dt><dd>${escapeHTML(reading.Value)} ${escapeHTML(reading.Unit)} · ${escapeHTML(reading.Quality)}</dd>`).join("")}</dl>`; } catch (error) { output.innerHTML = stateBox("Connection test failed", `${error.message} Check reachability, authPriv credentials, allowed source addresses, and OIDs.`, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

$("#fleet").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, values = formJSON(form), output = $("#fleet-result"); output.hidden = false; output.innerHTML = stateBox("Creating pairing secret", "Enrolling the peer with a one-time credential.", "loading"); setBusy(form, true); try { const result = await request("/api/v1/peers", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(values) }); output.innerHTML = `<h2>Pairing ready</h2><ol><li>Copy the secret now; it will not be shown again.</li><li>On <strong>${escapeHTML(result.id)}</strong>, configure this Watchpost as its peer.</li><li>Send one signed test envelope and verify it is accepted before enabling event sharing.</li></ol><code class="secret">${escapeHTML(result.secret)}</code><button id="copy-secret" class="quiet-button" type="button">Copy secret</button><p class="callout">Each Watchpost remains independently useful. Pairing enables selective coordination, not continuous upstream dependence.</p>`; $("#copy-secret").onclick = async () => { await navigator.clipboard.writeText(result.secret); showMessage("Pairing secret copied."); }; form.reset(); } catch (error) { output.innerHTML = stateBox("Pairing failed", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

$("#create-user").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget; setBusy(form, true); try { await request("/api/v1/users", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(formJSON(form)) }); form.reset(); await loadCore(); renderUsers(); showMessage("User created."); } catch (error) { showMessage(error.message, "error"); } finally { setBusy(form, false); } });
$("#change-password").addEventListener("submit", async event => { event.preventDefault(); const form = event.currentTarget, output = $("#password-result"); setBusy(form, true); output.hidden = false; output.innerHTML = stateBox("Rotating password", "Revoking other sessions for this account.", "loading"); try { await request("/api/v1/me/password", { method: "POST", headers: { "X-Watchpost-CSRF": state.csrf }, body: JSON.stringify(formJSON(form)) }); output.innerHTML = `<h2>Password changed</h2><p>Other sessions were revoked; this session remains active.</p>`; form.reset(); } catch (error) { output.innerHTML = stateBox("Password not changed", error.message, error.message.includes("permission") ? "permission" : "error"); } finally { setBusy(form, false); } });

installResizeHandles(); bootstrap();
