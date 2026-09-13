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
- configuration propagation, reconciliation or conflict resolution;
- shared human accounts or cluster-wide login;
- cross-project clustering abstractions.

Those features require evidence from the narrower model first. Configuration propagation is specifically a later operation-layer concern, not database replication.

## Phase 2 proving sequence

The implementation order is identity, pairing, transport, membership/health, a read-only distributed health call, Watchpost-specific aggregate reads/ownership, UI parity, and then failure/recovery testing. Only after those behaviours survive real tests may their generic pieces be considered for `gantry-core` extraction.
