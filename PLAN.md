# Watchpost development checkpoints

## Security repair batch

A review-driven repair batch (items 1–8) tightened the security model after the
R-programme: the agent authenticates by email and password with normalized
identities and a chosen setup email; remote first-admin setup is gated behind a
short-lived single-use bootstrap token; boolean proxy trust was replaced by
explicit trusted-proxy CIDRs with fail-closed client resolution; audit records
are written atomically with their mutations (a failing audit rollback prevents
the mutation from being reported); encrypted backups use a versioned container
with random salts and atomic writes; administrative password resets revoke the
user's sessions; the final administrator cannot be demoted and role changes
apply to existing sessions immediately; and the agent uses the central
server's versioned PBKDF2-HMAC-SHA256 KDF. A second agent-focused pass made
local state/audit atomic: every persistent agent mutation appends its audit row
in the same atomic `state.Update` (deep-cloned before the callback so a failed
save leaves both in-memory and on-disk state unchanged), each operation emits
exactly one audit entry attributed to the real acting identity, central logout
reports failure rather than success when the transactional revocation cannot
complete, and agent password-hash verification rejects malformed or excessively
expensive encodings before running PBKDF2. Local agent accounts created by
older builds must be re-established with `reset` after upgrading because their
password hashes used a now-unsupported construction.

## Active implementation programme (R checkpoints)

R20 is complete: the operational SPA now has canonical Nift source in
`web/content` and `web/templates` and `web/dist` is regenerated output. The
application script is tracked as `script.js` because Nift requires unique
tracked names. `web/embed_test.go` (CI) and `hardening/spa-gate.sh` (local)
guard source/output agreement.

R1 is complete: the retention worker (`internal/retention`) prunes every data
category to a configurable window in bounded batches, preserves the latest
active alert per rule/post, exempts incident-linked and investigation-cited
records, and resolves pruned citations through immutable
`conversation_evidence` snapshots. `agent_pairing_requests.terminal_at`
records terminal state; expired sessions are always pruned; a zero window
keeps a category forever.

R2 is complete: `internal/storage` measures the full SQLite footprint
(database plus WAL and SHM sidecars) and free disk against configurable caps.
Telemetry and log ingestion fail closed with HTTP 507 after collector
authentication, an immediate retention pass runs when the node is over budget,
and the SPA shows a storage warning. `GET /api/v1/storage` is an authenticated
diagnostic; the footprint is also reported in `/api/v1/diagnostics`. The agent
surfaces a 507 distinctly as "Watchpost storage is full".

R3 is complete: `hardening/long-run.sh` runs a race-built server and collector
with retention at a window shorter than the soak and proves the database
footprint stays flat once pruning catches the ingestion rate (90s local soak:
`db_bytes=331776 mid=331776 flat_growth=true`). The CI 15s soak enforces the
hard ceilings; flat-growth evidence requires the longer local run. See
`docs/scale-evidence.md`.

R4 is complete: the canonical monitoring-method contract is frozen in
`internal/contract` and `docs/monitoring-method-contract.md`. It pins the
closed method kinds (`host_agent`, `central_check`, `device_snmp`), the
canonical observation envelope with explicit quality and freshness, and the
lossless mapping from collector protocol v1.

R5 is complete: central HTTP, TCP, TLS, DNS and ICMP schedules now route their
stored results through the canonical observation envelope and the rule engine.
Each run emits `<kind>.ok` (1.0/0.0 with good quality), `<kind>.latency_ms`
and, for TLS, `tls.expires_in_days`. Central-check source identities are
post-scoped `collector_keys` rows with kind `central_check` whose secret hash
is a fixed marker; `collectorhealth` filters them out. A rule such as
`http.ok < 1` fires when the target is down. Recurring SNMP routing is R6.

R7 is complete: every state-changing operation now writes an attributed audit
row (logins, posts, rules, pairing, approvals, actions, incidents, schedules,
profiles, peers, investigation), `GET /api/v1/audit` exposes the record to
administrators, and the SPA has an admin-only Audit view. Audit rows are
exempt from automatic retention.

R9 is complete: first-admin setup remains direct over a loopback listener, but
an externally reachable listener or an operator-supplied
`WATCHPOST_SETUP_TOKEN`/`WATCHPOST_SETUP_TOKEN_FILE` requires a short-lived
bootstrap token. Only a SHA-256 hash of the token is persisted; the raw value
is printed to the server console exactly once (or loaded from the protected
file). Token consumption and first-admin creation happen in one transaction, so
replay and concurrent second-winner setup fail closed. The token is never
exposed through diagnostics or the SPA.

R8 is complete: global RBAC administration exists. Administrators can list and
create users, change roles (never demoting their own account), reset passwords
and revoke a user's sessions. Any user can rotate their own password, which
revokes every other session for that account. The post `owner` field remains
metadata only; no owner-isolated evidence model exists. User administration
and password rotation are audited. The SPA exposes a Users view (admin) and an
Account view (password rotation) for every role.

R10 is complete: pairing hand-off is recoverable. If an agent crashes after
its pairing request is consumed but before the credential is persisted, the
next poll with the same request secret reissues a fresh credential while the
previous one is provably unused; a used credential is never rotated by a
re-poll.

R11 is complete: credential rotation uses overlap-and-confirm. The server
issues a pending replacement with a ten-minute lifetime while retaining the
active credential; the agent persists the replacement atomically and keeps the
previous credential as a delivery fallback; the first delivery authenticated
with the replacement promotes it and the old credential stops working.
Unconfirmed replacements expire without invalidating the old credential, so a
crash or outage mid-rotation never bricks the connection.

R12 is complete: unpair is server-first. The agent requests revocation at
Watchpost (`POST /api/agent/v2/unpair`) with its current credential and only
clears local state once Watchpost confirms; when unreachable it persists
`revocation_pending` and retries each delivery interval. Forced local reset is
a separately named destructive path that warns the connection must be revoked
centrally. Watchpost-side admin revocation and agent self-unpair are audited.

R13 is complete: private-target monitoring remains a core feature with no
global disable. Optional `WATCHPOST_CHECK_ALLOW_CIDRS`/`DENY_CIDRS`/`DENY_PORTS`
restrict targets, enforced at schedule creation, on on-demand checks, on SNMP
targets and again at run time against the resolved address (DNS-rebinding
defence). On-demand checks are rate-limited to 60 per minute and audited.

R14 is complete: the agent hardens explicit remote use. Local `admin`,
`technician` and `viewer` accounts are independent of Watchpost sessions; the
first setup bootstraps the local admin; state-changing local operations are
audited in a bounded local log. Non-loopback binding requires
`WATCHPOST_AGENT_EXPOSE=1` with a prominent warning; secure cookies
(`WATCHPOST_AGENT_SECURE_COOKIES`) and explicit proxy trust
(`WATCHPOST_AGENT_TRUSTED_PROXY`) are opt-ins, forwarded headers are never
trusted by default, and client CIDR allow/deny rules are optional. Service
lifecycle remains CLI-only.

R6 is complete: recurring SNMPv3 authPriv polling is a durable monitoring
method. Profiles with a poll interval store authentication/privacy passwords
encrypted at rest (AES-256-GCM) under an installation master key supplied
outside the database (`WATCHPOST_MASTER_KEY`); without a key, credential
storage and recurring polling are refused. Each poll emits `snmp.poll_ok`
reachability plus one observation per numeric OID through the canonical
contract and the rule engine. The profile store's List was also fixed to avoid
a single-connection nested-query deadlock. No SNMP write path exists.

R15 is complete: every registered action is honest. `rerun_check` reruns the
named saved schedule for the action's post, routes the observed check evidence
through the pipeline and records `ok`/`failure`/`latency_ms` as its
verification outcome, refusing a schedule that belongs to another post;
`silence_route` disables the named route and records `disabled`. No registered
action is a no-op. The write-authority invariant is documented: read
capability never grants write authority and no write operation travels through
a generic untyped command path. 

R16 is complete: the canonical host signal registry is frozen in
`internal/contract` (`HostSignals`) and the installed agent now emits exactly
those signals (`load.1/5/15`, `collector.up`, canonical disk/filesystem
signals). Historical rows are never rewritten; a bounded alias layer maps the
deprecated `load.one` to `load.1` for rules and history queries.

R17 is complete: the bundled legacy collector lifecycle is removed.
`watchpost collector pair/run/install/status/logs/uninstall` and the
`internal/collectorclient` and `internal/collectorservice` packages are gone;
`collector sample` remains as read-only host diagnostics, and the v1 batch
contract at `/api/collector/v1/observations` stays because the agent delivers
through it. The SPA no longer has a v1 pairing view; host enrollment points to
the agent install/pair/approve journey. The host-journey and long-run hardening
gates were rewritten to drive the v2 agent flow through the API.

R18a is complete: `watchpost backup` produces a consistent online snapshot
(`VACUUM INTO`) with optional passphrase encryption (AES-256-GCM under
PBKDF2, minimum 10-character passphrase); `watchpost restore` validates the
SQLite header and schema (refusing newer databases), requires a stopped node
and `--force` to replace, and fails closed on a wrong passphrase.
`watchpost rekey` re-encrypts stored device credentials under a new master
key. The key/restore contract is documented in `docs/backup-and-recovery.md`:
backups never embed the master key; restoring credential-storing profiles
requires the matching master key; rotation either rekeys or re-enters
credentials. Scheduled backup UX is R18b.

R18b is complete: scheduled online backups run when `WATCHPOST_BACKUP_DIR` and a
positive `WATCHPOST_BACKUP_SCHEDULE` are set, optionally encrypted via
`WATCHPOST_BACKUP_PASSPHRASE_FILE` and bounded by `WATCHPOST_BACKUP_RETAIN`.
`GET /api/v1/backup-status` exposes last/next run and last error to operators.
The passphrase file is re-read each run so it can be rotated without a restart.

R19 is complete: scheduled checks run their network probes on a bounded worker
pool (`WATCHPOST_CHECK_WORKERS`, default 4) while result storage stays
sequential, and telemetry ingestion is budgeted per collector
(`WATCHPOST_INGEST_MAX_SAMPLES_PER_MINUTE`, default 3600). Both are race-tested.

R21 is complete: the SPA is agent-first for host monitoring. Host enrollment
shows a visible agent guide (install → pair → approve), unconnected host posts
display "No agent" and route Connect to the enrollment approval panel, and the
v1 pairing UI is gone. The agent web and CLI remain equivalent pairing and
configuration surfaces with the service lifecycle retained by the CLI.

R22 is complete: the SPA can acknowledge firing alerts from the overview,
review an incident with its durable timeline, transition status, add
attributed notes and assign an owner, and post rows show a next-action hint
for revoked, rejected, stale/offline and skewed agent connections. Guided
recovery states (unpair before re-pair, rotate or re-pair, check delivery)
are visible in place.

R23 is complete: `GET /api/v1/posts` is paginated (`limit` ≤ 500, `offset`,
`total`) and rules are bounded to 500 by default; the SPA loads posts a page at
a time and appends on demand instead of fetching the whole inventory every
render. A 520-post load is verified as bounded pages
(`TestPostsPaginationBoundsManyPostLoad`), and the survey remains bounded to 30
points per series. The final programme verification runs next.

## Agent architecture programme (WP-A01–WP-A18)

WP-A01 accepted a separate `watchpost-agent` program with its own embedded
loopback-first website and an equivalent CLI for headless servers and
automation. The two surfaces share one application service. The agent is
installed before request/approval pairing. Posts remain the user-facing
inventory; agent connections are monitoring details and collectors are
implementations. See `docs/agent-architecture.md` and the sibling agent plan.

WP-A02–WP-A06 establish the standalone application, installation lifecycle,
local security, pairing protocol v2 and complete web/CLI telemetry journeys.
WP-A07–WP-A18 then move agent state beneath posts, add configurable local
collectors, dense policy-aware visualisation, non-host methods, lifecycle,
packaging, scale and recovery evidence.

The detailed sibling plan is authoritative. WP-A07 is complete: authenticated
connection APIs and post inventory now expose agents as monitoring details
beneath their post, including explicit health, without creating duplicate posts.
WP-A08 through WP-A12 are complete: agent-side collector profiles and durable
delivery feed a dense survey whose safe, warning, critical, unknown and
maintenance states are derived from enabled post rules, active alerts,
freshness and connection health. Starter rules are visible and independently
pauseable; absent policy is labelled unknown rather than presented as healthy.
WP-A13 is complete: durable per-post HTTP, TCP, TLS, DNS and ICMP schedules
run centrally, retain bounded result facts, and remain a monitoring method
beneath a post rather than creating agent or collector inventory.
WP-A14 is complete: SNMPv3 authPriv is registered as an explicitly read-only
device adapter. Successful tests save bounded post-owned profile metadata and
OIDs, never passwords; operators can inspect or remove the monitoring method.
WP-A15 is complete: bounded starter evidence profiles cover network devices,
UPS/PDU equipment, environmental sensors and storage appliances. Every reading
now carries quality, observation time and a finite freshness horizon.
WP-A16 is complete: the agent supports atomic upgrades and credential rotation
through web/CLI parity. Move requires explicit unpair and new approval; archive,
delete, revoke, reset and uninstall retain distinct authority/data semantics.
WP-A17 is complete as a development packaging gate: the Linux agent produces
amd64/arm64 archives and checksums, has a checksum-verifying user/system
installer and tag workflow, while a 500-post/20,000-observation survey test
proves the server-side response bound. This is not a production scale claim.
WP-A18 is complete as a local hardening gate: normal/race/vet/build, corrupt
state fail-closed tests, backup/restore drill, Nift builds, keyboard focus,
reduced-motion and forced-colour fallbacks pass. Published limitations remain
authoritative; this does not authorize a production release.

Status: original WP00–WP18 implementation claims were reconciled on 2026-08-28.
The codebase contains useful foundations and a proven Linux host loop. The
active recovery programme now continues through WP16R below. Original
checkpoints are retained as design history, not completion
claims. See `docs/implementation-reconciliation.md`.

## Active recovery programme

These checkpoints are outcome gates. A package, endpoint, table, or form is
supporting evidence; it is not completion by itself.

- **WP01R — honest reconciliation:** inventory complete, partial, misleading,
  and absent behaviour; align UI, website, plan, and handovers.
- **WP02R — collector contract:** freeze and test identity, pairing,
  observations, sequencing, time, compatibility, retries, and freshness.
- **WP03R — Linux collector:** ship real CPU, memory, disk, load, uptime, and
  collector-health sampling in the supplied binary.
- **WP04R — secure pairing:** short-lived one-use token creates collector
  identity and writes local configuration without manual secret copying.
- **WP05R — service lifecycle:** install/run/status/logs/uninstall using systemd
  with restrictive configuration and credential permissions.
- **WP06R — reliable delivery:** restart-safe sequence state, bounded disk
  buffer, exponential backoff, ordered replay, deduplication, and visible loss.
- **WP07R — health semantics:** healthy, stale, offline, skewed, rejected,
  partial, and never-connected are explicit and absence is never zero.
- **WP08R — complete host journey:** guided creation/pairing/confirmation,
  default dashboards and starter rules, proven with separate server and
  collector processes across restart.
- **WP09R — operable rules and alerts:** list and enable/disable versioned rules,
  preserve deterministic alert transitions, and expose the lifecycle to operators.
- **WP10R — observable notification delivery:** manage routes without returning
  secrets and expose durable retry/delivery outcomes.
- **WP11R — incident ownership:** attributable assignment, notes, transitions,
  linked evidence, and a useful durable timeline.
- **WP12R — navigable evidence:** bounded logs and changes can be retrieved by
  exact citation and opened in context.
- **WP13R — durable read-only devices:** save bounded SNMPv3 profiles for device
  posts, test them, and retain readings without adding write authority.
- **WP14R — evidence-grounded investigation:** assemble bounded post evidence,
  verify citations, show uncertainty, and remain read-only.
- **WP15R — inspectable typed actions:** list requests and show approval,
  execution, and verification state without arbitrary commands.
- **WP16R — operable fleet trust:** list, pair, revoke, and inspect peers and
  bounded store-and-forward state while each node remains useful alone.
- **WP17R — release evidence:** build deterministic archives and loose binaries,
  verify checksums and installer downloads, rehearse preserved-state
  upgrade/rollback, and document secure Caddy/nginx deployment.
- **WP18R — hardening evidence:** run bounded resource campaigns, hostile-input
  and recovery gates, publish limitations, and close the development candidate.

Progress: WP01R through WP16R complete as recovery slices. These do not replace
the broader original WP09–WP16 release gates retained below. WP02R added a versioned, bounded, atomic
batch contract, contiguous acknowledgement semantics, compatibility/clock/
quality validation, integration tests, and documented retry/freshness rules.
WP03R added the supplied-binary Linux sampler for CPU, memory, root disk, load,
uptime, and collector health with deterministic fixtures and real `/proc` use.
WP04R added ten-minute, one-use, hashed pairing tokens; an HTTPS-or-loopback
pairing client; post-scoped credential exchange; and private local config.
WP05R added stable binary installation, hardened per-user or explicit system
systemd units, foreground run, status, bounded log viewing, and uninstall.
WP06R added atomic restart-safe queue state, contiguous sequences, an 8 MiB/256
batch bound, visible dropped-sample accounting, ordered acknowledgement-driven
deletion, network timeouts, and jittered exponential retry capped at five minutes.
WP07R added persisted receipt/observation/collector-clock/rejection/partial
facts and explicit never-connected, healthy, stale, offline, skewed, rejected,
partial, and revoked states in the API and SPA.
WP08R joined post creation, optional starter rules, one-use pairing, first-
delivery confirmation, collector health, and resource survey navigation. The
Linux gate builds one binary, starts separate server/collector processes,
pairs over HTTP loopback, restarts both, and proves continuing CPU history.
WP09R makes rules inspectable and independently enableable/disableable through
authenticated APIs while retaining deterministic transition and restart tests.
WP10R exposes secret-free route configuration with pending, retrying, and
delivered counts backed by the existing durable idempotent delivery queue.
WP11R adds attributable incident assignment and replaces placeholder actors in
creation, transition, and note events with the authenticated user's identity.
WP12R adds an authorised exact-evidence resolver for bounded log and change
citations, returning the complete stored record and its post context.
WP13R adds schema-versioned, post-linked SNMPv3 profile persistence for address,
username, kind, and at most 64 read-only OIDs. Authentication and privacy
passwords remain transient connection-test inputs and are never returned.
WP14R automatically assembles at most 20 recent logs, changes, and alerts when
the operator supplies no evidence, and verifies every citation belongs to the
conversation post before the provider sees it.
WP15R exposes bounded action request records including typed parameters, actor,
independent approver, lifecycle timestamps, execution state, and verification
result; no generic command or shell action is registered.
WP16R exposes active/revoked peer trust, creation/revocation time, pending and
delivered outbox work, received event counts, and an explicit admin revocation
operation. Nodes remain locally useful and federation payloads remain bounded.
WP17R builds six release targets as loose binaries and OS-native archives,
verifies their checksums and contents, installs from a local release-shaped
endpoint, and proves a post survives upgrade and rollback. HTTPS proxy mode
sets Secure session cookies explicitly and is documented for Caddy and nginx.
WP18R composes normal/race/vet/fuzz validation with release, two-process host,
stopped-backup recovery/corruption, and bounded server-plus-collector soak
evidence. A post-lifecycle usability repair subsequently added first-class
address/hostname inventory, an explicit outbound collector pairing URL, post
editing, and confirmed permanent deletion. A per-post configuration web server
remains deliberately out of scope: it would add an inbound attack surface;
future local diagnostics should remain read-only and opt-in.
gates. Remaining platform, scheduling, UI, federation, backup, capacity, model,
and external-review limits are published in `RELEASE_LIMITATIONS.md`.

Every monitored system, service, endpoint, application, or device is a
**post**. This is the canonical schema, API, code, test, UI, and documentation
term. A deployed Watchpost node is not itself a post unless explicitly enrolled.

Each checkpoint is an independently reviewable vertical slice. Complete it,
record exact evidence, and commit it before starting the next checkpoint.

## WP00 — vocabulary, architecture, and threat model

- Freeze the vocabulary and single-node data flow.
- Define package boundaries and trust zones: browser, server, collectors,
  posts, providers, reverse proxies, and future peers.
- Define signal quality, freshness, clock-skew, and alert/incident state models.
- Define observation/recommendation/approval/execution boundaries.
- Create representative fixtures and a runnable test skeleton.

Exit: reviewed decisions and threat model, architecture checks, fixture
manifest, and green empty harness.

## WP01 — process, configuration, and embedded UI

- Create the Go module, `watchpost serve`, graceful shutdown, and redacted logs.
- Embed a Nift-built frontend with an honest empty-state dashboard.
- Define configuration precedence, validation, safe defaults, and data paths.
- Add health, readiness, version, and bounded diagnostic endpoints.

Exit: configuration tests, embedded-asset test, clean build/shutdown, and a
no-runtime-dependency smoke.

## WP02 — SQLite persistence and recovery

- Add ordered, transactional, fail-closed migrations and schema identity.
- Separate inventory, operational state, audit, and telemetry interfaces.
- Define busy, corruption, backup, restore, and crash-recovery behaviour.

Exit: fresh/upgrade/downgrade/corrupt/concurrent migration tests, restart
recovery, and verified backup/restore.

## WP03 — first-run identity and authorization

- Implement race-safe first-admin setup, local accounts, passwords, secure
  sessions, logout, CSRF defence, and login throttling.
- Add server-side roles/capabilities and attributable audit.
- Make reverse-proxy trust explicit and disabled by default.
- Verify every HTTP and WebSocket route has an authorization decision.

Exit: concurrent setup, session/CSRF/authz/proxy-spoof adversarial suites,
audit completeness, and restart-safe sessions.

## WP04 — post inventory and topology

- Implement posts with stable IDs, names, typed post kinds, ownership, labels,
  maintenance/lifecycle state, and bounded metadata.
- Model dependencies between posts without assuming each post is a host.
- Add create/read/update/archive API and UI with optimistic concurrency.
- Seed host, HTTP endpoint, TCP service, and TLS certificate post kinds.

Exit: schema/API contracts, limits, cycle/concurrency/migration tests, and an
inventory UI walkthrough.

## WP05 — collector protocol and ingestion

- Define a versioned observation envelope with post/collector identity,
  observation and ingestion time, sequence, unit, quality, and provenance.
- Support bounded authenticated push and internal pull collection.
- Enforce payload, label, batch, queue, replay, clock, and rate limits.
- Expose collector failure without manufacturing healthy post data.

Exit: malformed/fuzz corpus, replay/clock/disconnect/overload tests,
compatibility fixtures, and race run.

## WP06 — host monitoring

- Ship a first remote Linux host collector while keeping the protocol portable.
- Collect CPU, memory, load, disks, uptime, network counters, and bounded
  process/service state with explicit permission failures.
- Add enrollment, key rotation/revocation, freshness, and post detail UI.
- Dogfood on the machine running the development node.

Exit: deterministic fake-host suite, real Linux dogfood, disconnect/upgrade
tests, minimum-privilege review, and restart-safe history.

## WP07 — network and endpoint checks

- Add ICMP where permitted, TCP, HTTP(S), DNS, and TLS checks as post kinds.
- Record latency, status, expiry, validation, failure category, and provenance;
  do not retain sensitive response bodies by default.
- Cover IPv4/IPv6, redirects, timeouts, DNS failures, and certificate chains.

Exit: hermetic network lab, SSRF/redirect tests, dual-stack coverage, and
scheduled-check load evidence.

## WP08 — history, retention, and charts

- Persist signals/events with explicit missing, stale, unknown, and bad-quality
  semantics; absence is never numeric zero.
- Add retention tiers, aggregation, cardinality budgets, and dropped-data state.
- Build post overview/detail, time-range charts, comparisons, and export.

Exit: virtual-clock/aggregation/retention/disk-budget tests, restart recovery,
and large-history rendering checks.

## WP09 — deterministic rules and alerts

- Implement typed rules over signal windows and event state.
- Add pending, firing, acknowledged, resolved, and suppressed transitions.
- Add duration, hysteresis, recovery, missing-data policy, dependency
  suppression, maintenance windows, and versioning.
- Replay evaluation against recorded evidence and a virtual clock.

Exit: exhaustive transition tables, property tests, live/replay equivalence,
clock/dependency tests, and restart continuity.

## WP10 — notifications and routing

- Add routes, deterministic policy, deduplication, retry/backoff, escalation,
  rate limits, schedules, and durable delivery state.
- Ship email and generic webhooks first.

Exit: storm, idempotency, provider-failure, redaction, and audit tests.

## WP11 — incidents and operator workflow

- Add manual and alert-created incidents with severity, owner, assignment,
  status, notes, acknowledgement, and resolution.
- Build a durable timeline of evidence and operator decisions.
- Suggest correlations without silently merging alert histories.
- Add responsive, keyboard-accessible incident, alert, and fleet views.

Exit: incident walkthroughs, reversible correlation, concurrent editing,
accessibility, and large-timeline tests.

## WP12 — logs and change evidence

- Add bounded log ingestion/search with identity, time, truncation, retention,
  redaction, and hostile-content treatment.
- Add deployments, configuration changes, and annotations as events.
- Link selected evidence into incidents without duplicating unbounded payloads.

Exit: hostile/log-volume corpus, query authorization, retention/redaction,
timestamp uncertainty, and link-integrity tests.

## WP13 — device monitoring expansion

- Add SNMPv3 polling/discovery with strict credential, OID, timeout, and
  cardinality controls.
- Support network-device posts first, UPS/PDU posts second, and environmental
  sensor posts third.
- Normalize a small common signal set while retaining vendor provenance.
- Keep device support read-only; configuration and control remain out of scope.

Exit: simulated SNMP lab, vendor fixtures, counter-wrap/reboot/discovery tests,
credential redaction, and verification that no write operations exist.

## WP14 — evidence-grounded agent

- Add a provider-independent model interface and per-user credentials.
- Expose read-only bounded tools over posts, signals, topology, logs, changes,
  alerts, and incidents.
- Store post/incident conversations with visible tools, citations, missing
  evidence, and uncertainty.
- Treat monitored content as untrusted prompt-injection material.

Exit: investigation evaluation corpus, citation integrity, secret redaction,
misleading-telemetry cases, and proven read-only scope.

## WP15 — typed actions and approvals

- Add action schemas, capabilities, post scopes, bounds, dry runs, idempotency,
  approval policy, and immutable audit.
- Separate recommendation, approval, execution, verification, rollback, and
  refusal states.
- Begin with low-authority actions such as re-running a check or silencing a
  route; never add arbitrary model-authored shell execution.

Exit: policy fuzzing, approval-race/replay/scope tests, post-action observation,
rollback cases, and adversarial review.

## WP16 — fleet and federation

- Keep every node independently useful while disconnected.
- Add enrollment, node identity, rotation, revocation, tenancy, compatibility,
  and selective sharing of post/event/alert/incident state.
- Add bounded store-and-forward, ordering, deduplication, conflict visibility,
  and explicit reconciliation.

Exit: lossy/partitioned network simulation, sustained offline operation,
revoked/incompatible peer tests, and reconciliation proofs.

## WP17 — releases and deployment

- Add reproducible release automation, checksums, provenance, installer,
  service definitions, upgrades/rollback, and HTTPS proxy documentation.
- Build and smoke supported Linux, macOS, and Windows amd64/arm64 artifacts;
  document deliberate exceptions rather than claiming compile-only support.

Exit: clean-consumer artifact and installer smokes, proxy tests, preserved-data
upgrade/rollback rehearsal, and exact artifact inventory.

## WP18 — hardening and first public release

- Run long-duration ingestion, evaluation, retention, notification, memory,
  CPU, disk, and database campaigns.
- Fuzz collectors, rules, imports, logs, WebSockets, agent boundaries, actions,
  and federation messages.
- Drill backup/restore/disaster recovery and perform adversarial security review.
- Dogfood Watchpost on infrastructure hosting Watchpost.

Exit: the complete gate passes, recovery is rehearsed, limitations are honest,
and no release blocker remains open.

## Recommended device order

A post is an observable operational object, not a synonym for computer, so
Watchpost can monitor non-system devices. Implement them in this order:

1. **Network devices** — switches, routers, firewalls, and access points. SNMPv3
   exposes interface state/errors, throughput, temperature, resource use, and
   reboot evidence; these devices explain many downstream incidents.
2. **UPS and intelligent PDUs** — battery health, load, runtime, transfer
   events, and input/output state provide unusually valuable outage evidence.
3. **Environmental sensors** — temperature, humidity, leak, smoke-status, and
   door/contact sensors over SNMP, Modbus TCP gateways, or documented HTTP APIs.
4. **NAS/storage appliances** — pool, disk, capacity, temperature, and
   replication health can reuse SNMP and HTTP collectors.
5. **Printers/office devices** — straightforward SNMP coverage, but lower
   operational value, so they should follow infrastructure.

Defer cameras, arbitrary consumer IoT, PLC writes, building-control commands,
and safety systems. Protocol breadth is not worth weak authentication, unclear
semantics, or accidental control authority.

These areas should be explored in the future after the read-only monitoring,
typed action, approval, and safety boundaries are proven. Cameras may begin with
availability and health rather than video ingestion; consumer IoT needs a
deliberately bounded adapter policy; PLC and building-control work requires a
separate threat model and must never imply that Watchpost is a safety system.

## Deferred deliberately

- Industrial control/SCADA functions and direct PLC writes.
- A general-purpose remote shell.
- An unbounded plugin runtime inside the server process.
- Mandatory cloud coordination.
- High-volume distributed tracing before core monitoring is proven.
- Autonomous remediation without explicit typed policy and approval.

## Completed evidence

### WP00

- Domain vocabulary and canonical post types are represented in Go contracts.
- `docs/architecture.md`, `docs/threat-model.md`, and
  `docs/state-machines.md` define the initial boundaries.
- Representative post fixtures and contract tests are runnable.

### WP01

- `watchpost` starts the service directly and provides graceful signal-driven shutdown; `watchpost serve` remains a compatibility alias.
- Configuration precedence is flags, environment, then safe defaults.
- The embedded dashboard truthfully reports that no posts are enrolled.
- Health, readiness, version, and bounded diagnostics are implemented.
- Verification commands and exact results belong in the batch handoff.

### WP02

- SQLite uses WAL, foreign keys, a busy timeout, one migration authority,
  transactional migration 1, and future-schema refusal.
- Tests cover fresh creation, reopen, future history, and unusable data paths.

### WP03

- Race-safe first-admin setup, PBKDF2-HMAC-SHA256 password storage, hashed
  sessions, SameSite cookies, CSRF tokens, throttling, roles, and setup audit
  are implemented and tested.

### WP04

- Durable posts support canonical kinds, bounded identity/labels, optimistic
  versions, maintenance/archive state, and cycle-safe dependencies.
- CRUD concurrency and topology cycles have direct tests.

### WP05

- Collector enrollment returns a one-time secret retained only as a hash.
- Versioned observations bind collector/post identity with clock bounds,
  monotonic replay defence, quality, units, labels, and a 64 KiB API limit.
- Acceptance, replay rejection, and future-clock rejection are tested.

### WP06

- A read-only Linux host collector reports CPU ticks, memory, load, uptime, and
  root filesystem capacity directly from kernel interfaces without shell use.
- Real-host collection is tested on Linux; unsupported platforms fail clearly.

### WP07

- Bounded TCP, HTTP(S), DNS, and TLS checks expose latency and typed failure.
- HTTP redirects are bounded and same-host; TLS requires 1.2 or newer.
- Hermetic HTTP/TCP and address-classification tests are present.

### WP08

- Post/signal history has bounded windows and result limits.
- Retention deletes bounded batches and preserves explicit quality values.
- History and retention are covered through real ingested observations.

### WP09

- Durable typed rules drive pending, firing, acknowledged, suppressed, and
  resolved alert states with duration, missing policy, and hysteresis.
- Live ingestion invokes the same evaluator exercised by deterministic replay.

### WP10

- Durable webhook and SMTP routes receive idempotently queued alert deliveries.
- A bounded background worker records success or capped exponential retry state.
- Deduplication, successful delivery, and provider failure are tested.

### WP11

- Durable incidents support linked alerts, status transitions, resolution,
  notes, and ordered timelines.
- The authenticated UI exposes posts, endpoint checks, alerts, and incident
  creation with responsive layouts.

### WP12

- Bounded post-scoped logs are truncated, redacted, time-bounded, and searchable.
- Deployments/configuration changes are separate durable evidence records.

### WP13

- Read-only SNMPv3 `authPriv` polling uses bounded versioned profiles for network
  devices, UPS equipment, environmental sensors, and storage appliances.
- No SNMP write path exists; weak SNMP configurations are rejected.

### WP14

- Provider-independent durable investigations attach to posts/incidents.
- Evidence IDs must exist, monitored text is untrusted, citations are bounded to
  supplied evidence, and the built-in provider makes no unsupported inference.

### WP15

- Typed action registration, parameter validation, unique idempotency keys,
  separate approval, atomic execution claims, and durable results are present.
- Only check reruns and notification-route silencing are registered.

### WP16

- Peer enrollment, signed bounded envelopes, replay deduplication, durable
  inbox/outbox state, revocation, and offline queuing are implemented.
- Full transport and reconciliation UX remain pre-release limitations.

### WP17

- CI and tagged-release workflows cover Linux, macOS, and Windows on amd64/arm64.
- Release staging emits six binaries and checksums; installer defaults to
  `~/.local/bin` and supports explicit root-only `--system` installation.

### WP18

- Normal, race, vet, fuzz, cross-build, UI syntax, live startup, migration,
  recovery, release staging, and short race-instrumented soak gates are provided.
- Public release remains intentionally unperformed. Real runner smokes,
  multi-hour campaigns, external security review, and upgrade/rollback rehearsal
  must pass before a tag can honestly be called the first public release.
