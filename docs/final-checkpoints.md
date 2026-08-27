# WP12–WP18 implementation notes

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

CI and tagged-release workflows build six OS/architecture combinations with
checksums. The installer supports per-user and explicit `--system` destinations.
No tag or public release is created by completing this checkpoint. Real-runner
artifact smokes, installer download tests, sustained multi-hour campaigns,
external security review, and upgrade rehearsal remain release authorization
gates rather than claims made from local cross-compilation.
