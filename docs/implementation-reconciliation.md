# Implementation reconciliation — 2026-08-28

The earlier checkpoint report confused implemented components with complete
operator workflows. This inventory is the corrected baseline.

## Complete foundations

- Go server startup, embedded SPA, SQLite migrations, local authentication,
  posts, authenticated single-observation ingestion, basic history storage,
  threshold evaluation, bounded logs, incidents, and read-only SNMP polling.
- Immediate HTTP, TCP, DNS, ICMP, and TLS diagnostic checks.
- Nift-built public documentation and release-build automation skeleton.

## Partial or misleading

- Linux sampling exists only as a server-local snapshot function; there is no
  remote collector process.
- Collector enrollment issues a secret, but nothing supplied consumes it.
- History and the resource survey display submitted signals, but do not create
  collection.
- Rules can be created, but management and the complete alert workflow remain
  limited.
- Endpoint checks are immediate, not scheduled.
- SNMP is a live bounded poll, not durable device enrollment and scheduling.
- Fleet pairing has protocol primitives, not a complete operator workflow.
- Packaging can cross-compile, but production install/upgrade evidence is not
  complete.

## Absent recovery-critical behaviour

- Remote host collector, one-use pairing, local agent configuration, systemd
  lifecycle, restart-safe sequencing, offline buffering, retry/replay, explicit
  collector health, and a proven two-process host-monitoring journey.

No roadmap or UI copy may describe a partial item as implemented without
stating its boundary.
