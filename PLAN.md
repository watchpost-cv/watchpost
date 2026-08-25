# Watchpost development plan

Status: product definition. No Watchpost runtime is implemented yet.

The programme is deliberately ordered so the agent sits on trustworthy
operational foundations rather than becoming the foundation itself. Each phase
should end in a committed checkpoint with recorded verification evidence.

## Phase 0 — contracts and threat model

- Freeze the initial vocabulary in `HANDOVER.md`.
- Write the single-node architecture and data-flow decision record.
- Define trust zones: browser, server, collectors, targets, providers, peers.
- Define signal quality/freshness and clock-skew semantics.
- Define alert and incident state machines.
- Define the observation/recommendation/approval/execution boundary.
- Create a representative fixture corpus and acceptance-test skeleton.

Exit evidence: reviewed architecture notes, threat model, state-machine tests,
and a runnable empty test harness.

## Phase 1 — single-node foundation

- Go service with embedded Nift-built frontend.
- SQLite database, ordered migrations, backup/restore documentation.
- Local accounts, secure sessions, CSRF protection, capability checks, audit.
- Configuration precedence and safe first-run setup.
- Health, readiness, version, and diagnostic endpoints.
- Linux/macOS/Windows release automation for amd64 and arm64.

Exit evidence: clean install to authenticated empty dashboard, restart and
migration recovery, security tests, race tests, and six target builds.

## Phase 2 — inventory and collection

- Durable target inventory, labels, ownership, and maintenance state.
- Collector SDK/contract with versioning and strict payload limits.
- First-party host collector: CPU, memory, disks, load, uptime, processes.
- HTTP/TCP/TLS checks with latency and certificate-expiry observations.
- Pull and push ingestion with authentication, replay defence, and backpressure.
- Signal units, quality, freshness, retention, aggregation, and cardinality
  budgets made visible in the UI.

Exit evidence: deterministic simulated-target suite, disconnected/retry tests,
bounded ingestion under load, and restart-safe history.

## Phase 3 — rules, alerts, and notifications

- Typed deterministic rule expressions over signal windows and event state.
- Pending, firing, acknowledged, resolved, and suppressed transitions.
- Hysteresis, duration, missing-data policy, dependency suppression, and
  maintenance windows.
- Deduplication and notification routing with retry and rate limits.
- Initial notification integrations: email and generic webhook.
- Rule evaluation replay for reproducible debugging.

Exit evidence: virtual-clock transition suite, notification-storm tests,
replayed evaluations matching live results, and complete audit history.

## Phase 4 — incidents and operational UX

- Incident creation from alerts and manual operator reports.
- Timeline containing signals, events, alert transitions, notes, and actions.
- Correlation suggestions without silently merging unrelated incidents.
- Dashboards, topology, target detail, charts, logs, and saved views.
- Acknowledgement, assignment, severity, status, and resolution summaries.
- Responsive and keyboard-accessible web UI with light/dark/system themes.

Exit evidence: representative incident walkthroughs, accessibility checks,
large-history rendering tests, and operator usability dogfooding.

## Phase 5 — evidence-grounded agent

- Provider-independent model interface and per-user credentials.
- Read-only investigation tools over bounded signals, events, topology, logs,
  configuration, deployments, and incident history.
- Durable conversations attached to targets and incidents.
- Evidence citations and visible tool activity in every investigation.
- Prompt-injection boundaries for monitored content and secret redaction.
- Evaluation corpus covering causal investigation, uncertainty, refusal, and
  misleading telemetry.

Exit evidence: the agent can answer representative operational questions with
traceable evidence and cannot cross its read authority under adversarial input.

## Phase 6 — typed actions and approvals

- Action registry with schemas, capabilities, target scopes, and dry runs.
- Recommendation, approval, execution, verification, and rollback states.
- Initial conservative actions such as re-running a check or silencing a route;
  host mutation only after the policy model is proven.
- Multi-party approval option for high-authority actions.
- Immutable action audit and post-action observation.

Exit evidence: no arbitrary model-authored execution path, policy fuzzing,
approval-race tests, replay protection, and adversarial end-to-end review.

## Phase 7 — fleet and federation

- Independent nodes that continue operating while disconnected.
- Explicit enrollment, node identity, rotation, revocation, and compatibility.
- Selective inventory/event/incident sharing with tenancy boundaries.
- Store-and-forward delivery with ordering, deduplication, and bounded queues.
- Fleet-wide search and views without hiding local authority.
- Defined split-brain and recovery behaviour.

Exit evidence: lossy-network simulation, incompatible-version tests, revoked
peer tests, sustained offline operation, and reconciliation proofs.

## Phase 8 — hardening and first public release

- Long-run ingestion, retention, memory, CPU, disk, and database campaigns.
- Fuzz malformed collectors, rule inputs, imports, and federation messages.
- Backup/restore and disaster-recovery drills.
- Security review of authentication, WebSockets, agent context, secrets,
  actions, proxy deployment, and supply chain.
- Installers, upgrade guide, release notes, examples, and honest limitations.
- Dogfood Watchpost on the infrastructure hosting Watchpost.

Exit evidence: published guarantees backed by reproducible tests, clean release
artifacts, upgrade/rollback rehearsal, and no unresolved release-blocking issue.

## Deferred deliberately

- Industrial control/SCADA functions and direct PLC writes.
- A general-purpose remote shell.
- An unbounded plugin runtime inside the server process.
- Mandatory cloud coordination.
- High-volume distributed tracing before the core monitoring model is proven.
- Autonomous remediation without explicit typed policy and approval.

