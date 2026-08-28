# Implementation reconciliation — 2026-08-28

The earlier checkpoint report confused implemented components with complete
operator workflows. This inventory is the corrected baseline.

## Complete foundations

- Go server startup, embedded SPA, SQLite migrations, local authentication,
  posts, a remote Linux collector with secure pairing and durable delivery,
  history storage, threshold evaluation, bounded logs, incidents, and read-only
  SNMP polling plus durable non-secret device profiles.
- Immediate HTTP, TCP, DNS, ICMP, and TLS diagnostic checks.
- Nift-built public documentation and release-build automation skeleton.

## Partial or misleading

- Rule and notification status APIs exist, but the full policy editor,
  escalation schedules, and delivery-management UI remain limited.
- Endpoint checks are immediate, not scheduled.
- SNMP is a live bounded poll, not durable device enrollment and scheduling.
- Fleet pairing now exposes trust and queue status, but still lacks a polished
  two-node pairing UI and partition/reconciliation campaign.
- Packaging can cross-compile, but production install/upgrade evidence is not
  complete.

## Recovery-critical behaviour closed by WP02R–WP08R

- Remote host collector, one-use pairing, local agent configuration, systemd
  lifecycle, restart-safe sequencing, offline buffering, retry/replay, explicit
  collector health, and a proven two-process host-monitoring journey are now
  implemented and regression-gated.

## Remaining product gaps after WP16R

- Scheduled endpoint and SNMP collection, richer rule/notification/incident
  management screens, production model-provider configuration, complete action
  verification/rollback policy, and pleasant two-node fleet pairing.
- The original WP09–WP16 exit gates include broader property, accessibility,
  load, hostile-input, provider, and partition campaigns. WP09R–WP16R are
  independently useful recovery slices; they do not erase those release gates.

No roadmap or UI copy may describe a partial item as implemented without
stating its boundary.
