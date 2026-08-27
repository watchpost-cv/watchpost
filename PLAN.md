# Watchpost development checkpoints

Status: WP00 through WP18 implemented as a development candidate. WP18 does not
authorize or claim a public release; external real-platform, long-duration,
upgrade, and independent security evidence remains required before tagging.

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

- `watchpost serve` provides graceful signal-driven shutdown.
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
