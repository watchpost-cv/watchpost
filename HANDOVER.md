# Watchpost engineering handover

Current execution: WP01R through WP18R are complete as of 2026-08-28. The
recovery programme is closed as a local Linux development candidate, not a
public production release. `hardening/complete-gate.sh` is authoritative and
`RELEASE_LIMITATIONS.md` must accompany release decisions. Do not regress the
guided enrollment-to-confirmation flow.

## Operational SPA canonical source

R20 establishes canonical Nift source for the embedded operational SPA. The
SPA lives in `web/content` and `web/templates`; `web/dist` is generated output
that must be committed after every `nift build`. Never hand-edit `web/dist`.
The application script is tracked as `script.js`: Nift requires unique tracked
names, and `app.js`/`app.css` share the basename `app` so both cannot be
tracked. `web/embed_test.go` enforces that committed dist matches the source
in CI and `hardening/spa-gate.sh` proves a full regeneration produces no diff.

## Retention

R1 adds the deterministic retention worker (`internal/retention`). Per-category
windows default to 30d observations, 90d check results, 30d logs, 2y changes,
365d resolved alerts, 30d delivered notifications, 7d pairing tokens/requests,
7d federation inbox, 30d outbox and 180d orphaned conversations; each is
configurable via `WATCHPOST_RETENTION_<CATEGORY>` and zero keeps it forever.
Pruning is bounded (1,000 rows per DELETE, capped per pass), state-aware for
alerts (latest active row per rule/post preserved; superseded rows age out),
and citation-aware through immutable `conversation_evidence` snapshots that
let pruned evidence resolve as "purged by retention". `terminal_at` records
when pairing requests reach a terminal state. Capacity protection is R2.

## Storage capacity

R2 adds `internal/storage`: the total SQLite footprint (database plus WAL and
SHM sidecars) and free disk are measured against configurable caps
(`WATCHPOST_MAX_DB_BYTES`, `WATCHPOST_MIN_FREE_BYTES`, `WATCHPOST_MIN_FREE_PERCENT`).
Telemetry and log ingestion fail closed with HTTP 507 after collector
authentication, an immediate retention pass runs when the node is over budget,
and the SPA shows a storage warning. `GET /api/v1/storage` is an authenticated
diagnostic; the footprint is also reported in `/api/v1/diagnostics`. The agent
surfaces a 507 distinctly as "Watchpost storage is full". The guarantee is
that no loss is silent: Watchpost rejects explicitly, agents retry within
bounded storage, and any eventual queue loss is counted and displayed.

## Sustained capacity

R3 extends `hardening/long-run.sh` to run retention at a window shorter than
the soak and assert the database footprint stops growing once pruning catches
the ingestion rate. Flat-growth is enforced only when the soak outlives twice
the retention window, so the CI 15-second soak checks ceilings while the
longer local run produces the flat-growth evidence (90s soak with 15s
retention: db stable at 331,776 bytes). See `docs/scale-evidence.md`.

## Canonical monitoring-method contract

R4 freezes the single model every monitoring method converges on. The types
live in `internal/contract` and the authority in
`docs/monitoring-method-contract.md`: closed method kinds (`host_agent`,
`central_check`, `device_snmp`), the canonical observation envelope with
explicit quality and freshness, and lossless mapping from collector protocol
v1.

## Central checks through the pipeline

R5 routes central HTTP/TCP/TLS/DNS/ICMP results through the canonical envelope
and the rule engine. Each run emits `<kind>.ok` (1.0/0.0, good quality — a
failed check is a known fact), `<kind>.latency_ms` and `tls.expires_in_days`.
Central-check source identities are post-scoped `collector_keys` rows with
kind `central_check` and a fixed, non-credential secret marker; `collectorhealth`
filters them out of the connection view. Rules such as `http.ok < 1` now fire
when a target is down. Recurring SNMP routing is R6.

## Audit completeness

R7 records every state-changing operation in the `audit` table with the acting
user's identity: logins/logouts, posts and dependencies, collector enrollment
and pairing tokens, agent pairing approval/rejection/revocation, rules, alert
acknowledgement, notification routes, incidents, check schedules, device
profiles, peers, action request/approval/execute and investigation starts.
`GET /api/v1/audit` is administrator-only and the SPA exposes an Audit view.
Audit rows are exempt from automatic retention; audit write failures are
logged, never fatal.

## First-admin bootstrap protection

R9 gates first-admin setup behind a short-lived bootstrap token whenever the
listener is non-loopback or the operator supplies `WATCHPOST_SETUP_TOKEN` /
`WATCHPOST_SETUP_TOKEN_FILE`. Loopback-only listeners keep setup direct.
Only a SHA-256 hash is persisted; the raw token prints to the server console
once (default TTL one hour, `WATCHPOST_SETUP_TOKEN_TTL`). Token consumption and
first-admin creation are one transaction, so replay and concurrent second
winners fail closed. The token is never returned by any API or shown in the
SPA. The SPA shows a bootstrap-token field when `setup_token_required` is
reported.

## Global roles and user administration

R8 adds administrator-managed global RBAC. `admin` can list and create users,
change roles, reset passwords and revoke sessions; `operator` and `viewer`
cannot administer users or the audit log. A user can rotate their own password
(`POST /api/v1/me/password`), which revokes every other session for that
account while keeping the current one. An administrator cannot demote their
own account. The post `owner` field remains metadata; evidence is not
owner-isolated. The SPA has a Users view (admin) and an Account view. All user
administration is audited.

## Pairing hand-off recovery

R10 makes credential hand-off recoverable. When an agent crashes between the
server consuming its pairing request and the agent persisting the credential,
the next poll with the same request secret reissues a fresh credential while
the previous one is provably unused. A used credential is never rotated by a
re-poll, and expired requests are not reissued (the agent must request a new
pairing). See `internal/agentpairing`.

## Overlap-and-confirm rotation

R11 replaces the single-step credential swap. The server issues a pending
replacement with a ten-minute lifetime while keeping the active credential;
the agent persists it atomically and retains the previous credential as a
delivery fallback; the first accepted delivery authenticated with the
replacement promotes it and invalidates the old. An unconfirmed replacement
expires without affecting the old credential, so a crash or outage during
rotation cannot brick the connection. Promotion lives in `internal/ingest`.

## Unpair and revocation lifecycle

R12 makes unpair server-first. `POST /api/agent/v2/unpair` revokes the agent's
connection at Watchpost using its current credential; the agent clears local
state only after Watchpost confirms. If Watchpost is unreachable the agent
persists `revocation_pending` and retries on every delivery interval; a
credential whose revocation was never confirmed is never silently discarded.
Forced local reset remains a separate destructive operation and now warns that
the connection must be revoked centrally for a lost machine. Admin revocation
and agent self-unpair are audited.

## Private-target policy

R13 keeps private-target monitoring a core feature (no global disable) and
adds optional `WATCHPOST_CHECK_ALLOW_CIDRS`, `WATCHPOST_CHECK_DENY_CIDRS` and
`WATCHPOST_CHECK_DENY_PORTS`. The policy is enforced at schedule creation, on
on-demand checks, on SNMP targets and again at run time against the resolved
address, so a rebinding hostname is refused rather than probed. On-demand
checks are rate-limited to 60/minute and audited. See `internal/checks`.

## Remote agent-management security

R14 hardens the agent for explicit remote use. The agent now has local
`admin`, `technician` and `viewer` accounts (independent of Watchpost
sessions), a local first-admin bootstrap, a bounded local audit log, optional
client CIDR restrictions, secure-cookie and trusted-proxy opt-ins, and a
non-loopback binding that requires an explicit `WATCHPOST_AGENT_EXPOSE=1` with
a prominent warning. Forwarded scheme/host are trusted only when
`WATCHPOST_AGENT_TRUSTED_PROXY=1` is set. Service install/upgrade/status/
uninstall remain CLI-only; web and CLI offer equivalent pairing and
configuration capability.
Host enrollment records an optional address or hostname, then pairs the
bundled collector using an explicit Watchpost URL reachable from the post. The
collector is outbound-only. Post editing is optimistic-concurrency protected;
permanent deletion is administrator-only, requires the exact post ID, is
audited, and removes post-scoped evidence and credentials. Preserve the clear
archive-versus-delete distinction.

WP-A01 supersedes the bundled collector as the long-term host architecture.
The sibling `watchpost-agent` repository owns a separately installed program,
an embedded loopback-first website and an equivalent CLI for headless servers.
Installation precedes request/approval pairing. Watchpost owns the post and
approval; agent connections are monitoring details beneath posts; collectors
are implementations rather than top-level inventory. See
`docs/agent-architecture.md`.
WP-A05 implements the new cross-repository pairing contract: an installed
agent creates a ten-minute request and private request secret, both products
show the same three-word phrase, and a Watchpost administrator approves an
existing post before a one-time post-scoped credential is delivered. The old
collector token flow remains transitional compatibility only.
WP-A06 adds the first complete product path: pending agent requests appear at
post enrollment, an administrator can select an existing post or create a host
post from the request, and approval allows the agent to deliver its immediate
CPU, memory, filesystem and uptime sample. Agent connections remain monitoring
details beneath posts rather than duplicate inventory rows.
WP-A07 adds authenticated connection inventory and renders agent identity and
health inside each post row. “Collector” remains an implementation/API
compatibility term; it must not return as separate user-facing inventory.
WP-A08 lives in the agent repository: its website and CLI share a validated,
atomic local collector profile covering CPU, memory, load, uptime, bounded
filesystem paths and collection interval.
WP-A09 adds the standalone agent's restart-safe 256-batch/8-MiB ordered queue,
bounded retry state and explicit skipped-collection accounting. Watchpost's
contiguous ingestion contract remains the authority during replay.
WP-A10 makes agent revocation an administrator operation and exposes the full
connection health vocabulary beneath posts. Local unpair/reset remain agent
operations because Watchpost cannot silently mutate software on another host.
WP-A11 replaces graph-only survey cards with dense visual health bars, compact
trends and accessible values. Safe is green, warning amber, critical red and
unknown/stale grey or explicitly labelled; attention-first is the default order.
WP-A12 makes those states policy-aware. Enabled per-post rules, active alert
severity, maintenance, observation quality/freshness and agent health determine
the bar state and its visible explanation. A missing rule is unknown—not safe.
The Rules view lists starter policy and supports explicit pause/enable actions.
WP-A13 adds persistent central-check schedules for HTTP, TCP, TLS, DNS and
ICMP. They execute in bounded batches, store explicit latency/failure/expiry
facts and are configured beneath a post. They do not require an agent.
WP-A14 makes SNMPv3 a declared read-only adapter. Durable profiles contain
address, username, device kind and at most 64 OIDs; authentication/privacy
passwords remain transient. Successful tests save the method beneath its post.
WP-A15 supplies bounded network, UPS/PDU, environment and storage presets.
Vendor-neutral OIDs are prefilled where standards exist; vendor-specific
environment/storage OIDs remain explicit. Readings carry quality and freshness.
WP-A16 closes lifecycle ambiguity: upgrade preserves identity/state; rotation
atomically invalidates the old credential; moving requires unpair and approval.
Archive, permanent deletion, revoke, reset and uninstall remain separate.
WP-A17 packages the currently supported Linux agent for amd64/arm64 with
checksums, installer and tag workflow. The survey is regression-tested with
500 posts and 20,000 observations; browser dogfood remains a release limit.
WP-A18 closes this architecture programme as a local development candidate.
Both repositories pass normal/race/vet/build gates and fail closed on corrupt
state; Watchpost passes stopped-backup recovery. Accessibility foundations are
tested, but external accessibility/security/platform review remains required.
The authoritative gap inventory is
`docs/implementation-reconciliation.md`; do not restore the former claim that
WP00–WP18 are implemented.

Watchpost is an open-source, web-based monitoring and operations platform with
an agent designed into the product from the beginning. It is intended to become
a practical alternative to traditional infrastructure monitoring suites, not a
chatbot bolted onto a metrics dashboard.

The repository is at the product-definition stage. Do not describe planned
capabilities as implemented. Keep this handover and `PLAN.md` current as code,
contracts, and verification evidence appear.

## Product boundary

Watchpost observes infrastructure, applications, services, networks, logs, and
events. It evaluates rules, opens durable incidents, and helps an operator
investigate evidence. It may perform narrowly authorised operational actions.

Watchpost is not:

- a coding agent or repository IDE;
- a general server-control panel;
- an industrial SCADA/HMI or safety-control system;
- a hosted service requirement;
- an excuse to give a language model unrestricted shell access.

Warden may manage a server and Cortex may change code. Watchpost continuously
observes systems and explains operational state. Integrations between them are
welcome; collapsing their security boundaries is not.

## Working vocabulary

- **Watchpost**: one independently useful deployed node.
- **Post**: one monitored object: a host, service, endpoint, application,
  database, network device, power device, sensor, or other observable device.
  `post` is the canonical product, API, schema, and UI term; do not use
  `target` as a synonym.
- **Post kind**: the typed capability/profile of a post, such as host, HTTP
  endpoint, database, network device, UPS, or environmental sensor.
- **Collector**: code that obtains observations from a post.
- **Signal**: a timestamped measurement or state observation with provenance.
- **Event**: a meaningful state transition or externally supplied occurrence.
- **Rule**: a deterministic condition over signals and events.
- **Alert**: an active rule result requiring visibility or action.
- **Incident**: a durable operational episode that groups alerts, evidence,
  notes, actions, and resolution state.
- **Action**: a typed, policy-controlled operation against a post.
- **Fleet**: multiple Watchpost nodes coordinated without making an individual
  node useless when disconnected.

Use these terms consistently in APIs, schema, documentation, and UI copy.

## Architectural principles

1. **Useful alone, composable as a fleet.** A single node must collect, retain,
   evaluate, display, and investigate locally. Federation is additive.
2. **SQLite first.** Begin with a carefully migrated SQLite database for
   configuration, inventory, rules, incidents, audit, and modest telemetry.
   Keep storage interfaces explicit so high-volume time-series retention can
   evolve without replacing the product model.
3. **Determinism before AI.** Collection, rule evaluation, deduplication,
   notification, acknowledgement, and action policy must not depend on a model.
4. **Evidence before conclusions.** Agent answers should cite the signals,
   events, configuration, topology, logs, and changes used to reach them.
5. **Read-only by default.** Investigation is the default agent authority.
   Actions require typed capabilities, validation, narrow scope, and audit.
6. **Explicit quality.** Every signal carries timestamp, source, units where
   relevant, and quality/freshness state. Missing and stale are not zero.
7. **Durable operations.** Alerts and incidents survive restarts. State changes
   are attributable. Acknowledgement does not destroy history.
8. **Bounded failure.** Backpressure, retention, retries, cardinality, log
   volume, notification storms, and disconnected peers require explicit limits.
9. **Self-hosted without dependency theatre.** Prefer a straightforward single
   binary and embedded web UI. Optional integrations must remain optional.
10. **Compatibility is a contract.** Database migrations, collector payloads,
    rule semantics, and federation protocols need versioned tests.

## Initial technical direction

The likely first implementation is Go with an embedded Nift-built frontend and
SQLite. That matches the operational deployment story proven in Cortex and
Warden while keeping Watchpost independent. Treat this as the current design
direction until the first architecture checkpoint validates it.

Keep boundaries between:

- collection and ingestion;
- normalization and storage;
- deterministic rule evaluation;
- alert/incident lifecycle;
- notification delivery;
- read-only investigation;
- privileged actions;
- optional fleet coordination.

Avoid a single package that owns all of them. Prefer small internal interfaces
and domain types over generic maps passed through the system.

## Security invariants

- Never execute model-authored shell text directly.
- Never let prompts alter authentication, capability, approval, or audit rules.
- Treat collected logs, labels, service output, and remote metadata as untrusted
  input and possible prompt injection.
- Keep secrets encrypted at rest where feasible and redacted from UI, logs,
  exports, agent context, and diagnostic bundles.
- Require server-side authorisation on every API and WebSocket operation.
- Bind privileged actions to typed schemas, post scopes, parameter limits,
  actor identity, and an immutable audit record.
- Preserve the distinction between observation, recommendation, approval, and
  execution in both storage and UI.
- Do not position Watchpost as a safety system. Industrial control and safety
  interlocks remain outside its authority.

## Engineering workflow

Before substantial work:

1. Read this file and `PLAN.md` completely.
2. Inspect the repository status and preserve unrelated work.
3. Identify the exact contract being added or changed.
4. Define verification before broad implementation.

For each coherent step:

1. Implement the smallest complete vertical slice.
2. Add unit, integration, migration, and adversarial tests appropriate to it.
3. Run formatting, static analysis, tests, race checks, and production builds.
4. Inspect the complete diff and repository status.
5. Update `PLAN.md` with evidence and remaining uncertainty.
6. Commit the coherent checkpoint with generated artifacts only where the
   repository explicitly tracks them.

Do not claim completion from model confidence or compilation alone. A feature
is complete when its user-visible behaviour, failure modes, persistence,
authorisation, and regression evidence match its stated contract.

## Expected baseline gates

Once implementation exists, maintain at least:

```sh
gofmt -w <changed Go files>
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/watchpost
```

Add explicit tests for migrations, restart recovery, concurrency, malformed
collector input, clock/freshness behaviour, rule state transitions, retention,
notification deduplication, authorisation, audit completeness, and agent/action
separation. Release builds should cover Linux, macOS, and Windows on amd64 and
arm64 unless a target is deliberately unsupported and documented.

## Repository neighbours

The public website lives in the sibling `watchpost-ops.github.io` repository.
Its `HANDOVER.md` governs website changes. Product claims on that site must stay
aligned with actual milestones recorded here and in `PLAN.md`.
