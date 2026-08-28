# Watchpost engineering handover

Current execution: WP01R through WP18R are complete as of 2026-08-28. The
recovery programme is closed as a local Linux development candidate, not a
public production release. `hardening/complete-gate.sh` is authoritative and
`RELEASE_LIMITATIONS.md` must accompany release decisions. Do not regress the
guided enrollment-to-confirmation flow.
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
