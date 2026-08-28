# WP12–WP18 implementation notes

## WP01R–WP08R recovery batch

The 2026-08-28 recovery batch corrected earlier component-level completion
claims and closed the ordinary Linux host workflow. Its final executable gate
is `hardening/host-journey.sh`. The gate builds one binary, starts separate
server and collector processes, creates the administrator and host post, pairs
with a one-use token, receives host telemetry, stops and restarts both sides,
and proves at least two CPU history points remain queryable through the API.

This evidence covers the Linux loopback development deployment. It does not by
itself prove other operating systems, hostile networks, long-duration scale,
production TLS termination, or complete rule/notification/device workflows.

## Evidence and devices

Logs are bounded, redacted at ingestion, searchable only within a post and time
window, and stored separately from explicit deployment/configuration changes.
SNMP device support requires SNMPv3 `authPriv`, bounded OID profiles, and has no
SET/write operation. Initial post kinds cover network devices, UPS equipment,
environmental sensors, and storage appliances.

## Agent and actions

The provider-independent investigation interface is read-only. Evidence IDs are
verified against durable Watchpost records before provider use, collected text
is labelled untrusted, and provider citations cannot exceed supplied evidence.
The built-in provider deliberately makes no causal inference; external model
providers can implement the interface later.

Actions are registered types, never model-authored commands. Parameters are
validated, idempotency keys are unique, approval-required actions reject
self-approval, and execution is atomically claimed. Initial actions only request
a check rerun or disable a notification route.

## Federation and release state

Fleet envelopes are HMAC-signed, authenticated, time- and size-bounded,
deduplicated, revocable, and durably queued. This proves protocol boundaries;
it is not yet a complete network reconciliation product.

CI and tagged-release workflows build six OS/architecture combinations as
loose binaries and OS-native archives with checksums. `release-smoke.sh`
verifies archive contents, checksum integrity, per-user installation from a
release-shaped HTTP endpoint, and preserved state across upgrade and rollback.
Caddy and nginx deployment examples bind Watchpost to loopback and enable
Secure cookies explicitly behind TLS termination.

No tag or public release is created by completing this checkpoint. Real macOS
and Windows execution, sustained multi-hour campaigns, and external security
review remain release-authorization evidence rather than claims made from local
cross-compilation.

## WP18R hardening gate

`hardening/complete-gate.sh` composes the full normal/race/vet suite, bounded
fuzzing, deterministic release/installer/upgrade/rollback smoke, separate
server-and-collector restart journey, stopped-backup restore/corruption drill,
and a race-built server-plus-collector soak with explicit heap, goroutine,
file-descriptor, and database-size ceilings. Its duration is a local regression bound, not a
large-fleet capacity result. See `RELEASE_LIMITATIONS.md` for the remaining
release decision boundary.
