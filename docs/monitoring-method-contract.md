# Canonical monitoring-method contract (R4)

This document freezes the single model every monitoring method converges on.
It is the authority for later checkpoints that route central checks (R5) and
recurring device polling (R6) through the observation, rule and survey
pipeline. See `internal/contract` for the Go types and the lossless mapping
test for collector protocol v1.

## Model

```text
post
|- method: host_agent      -> agent host collectors (installed program)
|- method: central_check   -> HTTP, TCP, TLS, DNS, ICMP schedules
`- method: device_snmp     -> read-only device adapter polling
```

A **method** identifies how a post is observed: a stable `ID`, a closed
`Kind`, and the `PostID` it belongs to. Kind-specific configuration lives in
the owning store — check schedules, device profiles, agent state. A method is
a monitoring detail beneath a post; it is never top-level inventory.

A **source** identifies the concrete collector or probe within a method that
produced an observation (`Identity`). Hostname and address are descriptive
metadata only and are never treated as identity.

An **observation** is the canonical envelope:

```text
version, post_id, source, signal, value (nullable), unit, quality,
labels, observed_at, ingested_at, fresh_until
```

## Invariants

1. **Identity:** every observation carries the durable post and source
   identity that produced it; hostname/address never substitute for identity.
2. **Explicit quality:** `good`, `uncertain`, `bad`, `missing`, `stale` are
   distinct states. Absence is never converted to numeric zero.
3. **Explicit freshness:** every observation carries a `fresh_until` horizon
   set by its producing method. Old values never become current by reuse.
4. **Bounded:** signals, units and labels are bounded; NaN/Inf and out-of-clock
   values are rejected at the boundary by the ingestion contract.
5. **Lossless compatibility:** collector protocol v1 batches map losslessly
   into this envelope (proven by `internal/contract` tests); older protocol
   versions fail closed.

## Freshness rules per method

- `host_agent`: default freshness of two minutes from observation time.
- `central_check`: freshness is at least two minutes and at least two
  intervals (so a paused schedule cannot report stale success).
- `device_snmp`: five-minute freshness horizon from observation time.

## What later checkpoints build here

- R5 routes central-check results through this envelope into the observation
  store and rule engine, so a failed check can fire an alert (`.ok` is 1.0/0.0
  with good quality: a failed check is a known fact). Central-check source
  identities are post-scoped `collector_keys` rows with kind `central_check`,
  filtered out of the collector-health view.
- R6 routes recurring SNMP polling through this envelope with the same
  pipeline, using the same source identity per saved profile.
- The survey and policy-aware status continue to consume observations, so the
  pipeline stays the single source of truth for post health.