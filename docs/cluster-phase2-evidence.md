# Phase 2 clustering evidence

Phase 2 proves Watchpost-local clustering before any generic cluster model is extracted into `gantry-core`.

## Implemented checkpoints

- CP9: server-cluster boundary, ownership and deferred replication/propagation.
- CP10: stable node and installation identity with Ed25519 public identity metadata.
- CP11: single-use invite, join, inspect, approve/reject and restart-safe collection.
- CP12: HTTPS-only signed transport, bounded bodies, request IDs, clock skew and nonce replay rejection.
- CP13: member health, compatibility, disable/re-enable, revoke/remove and overlapping credential rotation.
- CP14: deterministic per-node cluster status with partial-failure reporting.
- CP15: owner-preserving Watchpost summary fan-out without schedule/notification takeover.
- CP16: shared service-layer API, CLI and `/app/` administration surfaces.
- CP17: expiry, replay, revocation, duplicate identity, partition, rotation, standalone and re-pair recovery tests.

## Validation in this workspace

The execution sandbox could not resolve the Go module proxy and its preinstalled toolchain is Go 1.23 while this repository requires Go 1.25. To avoid weakening the repository or changing `go.mod`, validation used a disposable copy with the `go` directive lowered only for the checker and a temporary `database/sql` adapter over the sandbox's system SQLite library in place of the unavailable `modernc.org/sqlite` download.

The actual repository remains unchanged in both respects: it still requires Go 1.25 and still uses `modernc.org/sqlite`.

Completed gates in the disposable validation copy:

```text
internal/cluster compile/type-check: PASS
internal/store migration tests: PASS
internal/cluster tests: PASS
internal/cluster race tests: PASS
CLI cluster surface compile/type-check in isolation: PASS
Go parser pass over modified cluster/server/CLI packages: PASS
node --check web/dist/script.js: PASS
```

The adversarial cluster suite caught a genuine single-connection SQLite deadlock in the initial CP11 implementation: pairing code opened a transaction and then resolved local identity through the same one-connection pool. CP17 moved identity resolution outside the transaction and the complete cluster and race suites then passed under the validation adapter.

A normal connected Go 1.25 environment should still rerun the repository's complete existing test, race and vet walls with the real `modernc.org/sqlite` dependency before release certification. This document does not claim that unavailable full-project gate was executed here.
