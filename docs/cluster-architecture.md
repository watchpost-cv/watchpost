# Watchpost cluster architecture

This document defines the Watchpost-local clustering contract that Phase 2 must prove before any generic clustering code is extracted into `gantry-core`.

## Boundary

A Watchpost cluster is a set of Watchpost **server installations** that trust one another for bounded control-plane reads and, later, explicitly owned operations. It is not a shared database and it is not an extension of Watchpost Agent pairing.

The identities stay separate:

- Human users, roles and sessions belong to one Watchpost installation.
- Watchpost Agents keep their existing installation identity and pairing credential.
- Watchpost cluster nodes use a dedicated server node identity and dedicated node credentials.
- A cluster credential can never authenticate as a human or Agent credential.

Standalone mode remains the default. A server with no cluster members behaves exactly as it did before clustering was configured.

## Initial topology

Phase 2 supports a small peer set rather than a leader/follower database topology. Every installation has a stable local node identity and may have zero or more approved peer memberships. Membership is bilateral: each side stores the remote node identity, endpoint, compatibility metadata and a credential used only for that direction of authenticated requests.

There is no consensus protocol, quorum, election, shared SQL transaction, replicated SQLite database, or implicit configuration propagation in Phase 2. Network partitions are reported as partial failures; they do not stop a healthy standalone node from monitoring its own estate.

## Ownership

Operational objects have one authoritative Watchpost installation. Phase 2 does not move ownership automatically.

- Posts and their attached monitors/check schedules are owned by the node where they were created.
- Agent pairings and Agent credentials are owned by the node that approved the pairing.
- Observations, alerts, incidents, notification delivery and scheduled work stay on that owner.
- A remote node may read an owner's summary through an explicitly cluster-safe operation.
- A remote node must not independently execute another node's schedules or notifications merely because it can see them.
- Aggregate views preserve the owner node ID so identical local object IDs cannot be mistaken for one shared object.

If a node is offline, its objects are unavailable remotely but remain intact on that node. Remaining members do not silently adopt them.

## Deferred work

The following are deliberately outside Phase 2:

- database or telemetry replication;
- automatic failover of monitoring or notification execution;
- consensus or distributed locking;
- automatic object migration between nodes;
- distributed ownership of scheduled work (no scheduler/lease mechanism);
- shared human accounts or cluster-wide login;
- cross-project clustering abstractions.

Configuration propagation is **implemented** (export/preview/apply via the
`alert-policy` / `monitor` / `notification-config` kinds; see the campaign
evidence above), but it is an operation-layer concern, not database
replication, and scheduled propagation requires a profile schedule.

## Phase 2 proving sequence

The implementation order is identity, pairing, transport, membership/health, a read-only distributed health call, Watchpost-specific aggregate reads/ownership, UI parity, and then failure/recovery testing. Only after those behaviours survive real tests may their generic pieces be considered for `gantry-core` extraction.

## Phase 3 extraction boundary

After CP17, the proven generic pieces are consumed from `github.com/gantry-tools/gantry-core/cluster`:

- shared node identity and pairing value types;
- protocol version, pairing/rotation lifetimes and credential generation;
- canonical HMAC request signing and verification;
- target parsing, bounded fan-out and deterministic per-node result envelopes;
- shared cluster CLI and presentation contracts for future adopters.

Watchpost still owns its SQLite schema and transaction boundaries, audit persistence, HTTP route registration, human permissions, Watchpost object ownership, Agent pairing, and monitor/alert/incident summary queries. Existing `X-Watchpost-*` wire headers are retained during the extraction so Phase 3 does not silently create a second protocol while moving implementation code.

## Campaign evidence (four-node dogfood, September 2026)

The following was demonstrated on four independent Ubuntu nodes (geographically
separated) running the certified Watchpost build, plus deterministic local
regression coverage. This is durable campaign evidence, not a claim that the
remaining deferred items are implemented.

| Behaviour | Status |
|---|---|
| peer-server clustering (node-to-node) | implemented and remotely exercised |
| isolated 3-node topology (A+B+C, D outside) | proven; membership/health verified from all three nodes |
| 4-node topology | proven (A+B+C+D, fan-out partial=false) |
| process failure / systemd stop / SIGKILL | proven (detected partial, recovered, converged) |
| full VM reboot | proven (detected unhealthy, rejoined without re-pairing) |
| 2+2 network partition | proven (unreachable peers not reported healthy; credentials survived; converged without re-pairing) |
| pairing restart transitions (joiner restart before collect; inviter restart before approval; re-pair after revocation) | substantially proven |
| stale outbound pairing generations | fixed by `2f611fa` (see cluster-operations.md) |
| propagation export/preview/apply | proven locally by `447184e` (two-store integration test) |
| scheduled propagation | requires a profile schedule; `run-due` only runs due profiles |
| full two-sided credential rotation | PARTIAL (local expiry/replay + remote overlap window; not every distributed transition) |
| distributed scheduled-work ownership | NOT IMPLEMENTED (no Watchpost scheduler/lease) |
| duplicate-work fencing | NOT IMPLEMENTED (cluster-summary self-ownership is not distributed-work fencing) |

### Propagation semantics

- **Direct `export → preview → apply`** works independently of scheduling and is
  proven by `447184e`: A exports a rule as the `alert-policy` kind, B applies it,
  re-application is idempotent, and a source update propagates.
- **`profile → run-due`** requires a non-empty valid `schedule` on the profile;
  `Due()` treats an unscheduled profile as never due. A future campaign must not
  interpret `run-due → []` on an unscheduled profile as a propagation failure.
- Rules surface as the `alert-policy` propagation kind; posts, accounts, sessions
  and other local-only objects are not propagated.
