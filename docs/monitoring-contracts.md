# Monitoring contracts (WP02R)

The canonical monitoring-method contract is documented separately in
`docs/monitoring-method-contract.md` and typed in `internal/contract`. It
defines the single envelope every method — host agents, central checks and
device adapters — must produce before later checkpoints route them through the
observation, rule and survey pipeline.

Collectors submit an authenticated batch to
`POST /api/collector/v1/observations`. A batch binds one collector to one post,
contains 1–128 samples, uses contiguous monotonically increasing sequence
numbers, and receives an acknowledgement containing `accepted_through` and the
server clock. The whole batch is accepted atomically or rejected.

Compatibility is explicit: version 1 is accepted and unknown versions fail.
Samples retain observation time, signal, nullable numeric value, unit, quality,
and bounded labels. Accepted qualities are `good`, `uncertain`, `bad`,
`missing`, and `stale`. Clock bounds are 24 hours past and five minutes future.
Collectors should sample while disconnected, retain a bounded local queue,
retry temporary failures with jittered exponential backoff, and remove data
only after an acknowledgement covers its sequence.

The contract does not define absence as zero. Default freshness is two minutes;
WP07R will materialize collector health from acknowledged delivery.

The first host collector is Linux-only and read-only. It reads `/proc` and
filesystem statistics without shell execution or elevated privileges. A failed
or unavailable source returns an error rather than a healthy value. The remote
collector transport and enrollment lifecycle remain WP06 follow-up work before
host collection should be described as production-ready on a fleet.

Endpoint checks support TCP, HTTP(S), DNS, and TLS with explicit timeouts. HTTP
redirects are bounded and cannot cross hostnames. Response bodies are discarded
after a small bounded read. TLS requires TLS 1.2 or newer. Operators can monitor
private addresses deliberately; therefore check authority is an SSRF-sensitive
operator capability rather than an unauthenticated utility.

History queries require one post, one signal, a bounded time window, and a row
limit. Retention deletes bounded batches. Missing, stale, uncertain, and bad
quality remain explicit observations rather than numeric zero.

## Retention contract

The retention worker prunes each data category to a configured window in
bounded batches (default 1,000 rows, capped per pass) so a backlogged table
cannot monopolise the single database connection or grow the WAL without limit.
A zero policy window keeps a category forever. Expired sessions are always
pruned. After pruning, an opportunistic `wal_checkpoint(TRUNCATE)` reclaims
write-ahead space.

Alert semantics are state-aware, not merely time-aware:

- the latest pending/firing/acknowledged/suppressed row per rule/post is
  preserved regardless of age;
- superseded transition rows age out after the resolved window;
- rows linked to an incident or cited by an investigation are exempt.

Evidence cited by an investigation is written as an immutable snapshot in
`conversation_evidence` at citation time. Retention never scans
`conversation_messages.evidence_json`. When raw evidence is pruned, the
evidence resolver returns the snapshot with an explicit purged-by-retention
status instead of a bare 404, so investigation citations degrade honestly.

Pairing tokens and agent pairing requests are pruned only after a terminal
state (`used_at`/`terminal_at`) or their expiry, so an in-flight request is
never removed early.

## Central checks through the canonical contract

Central HTTP, TCP, TLS, DNS and ICMP schedules now route their stored results
through the canonical observation envelope and the rule engine, exactly like
agent telemetry. Each check produces `<kind>.ok` (1.0/0.0 with good quality —
a failed check is a known fact, not a missing one), `<kind>.latency_ms`, and
for TLS a `tls.expires_in_days` horizon. The schedule's source identity is a
post-scoped `collector_keys` row with kind `central_check` whose secret hash
is a fixed marker, never a bearer credential; `collectorhealth` filters these
rows out so central checks never appear as collectors in the connection view.
A rule such as `http.ok < 1` now fires when the target is down.

## Audit completeness

Every state-changing operation is written to the `audit` table with the acting
user's identity: logins and logouts, post create/update/dependency,
collector enrollment and pairing-token issue, agent pairing approval/rejection
and connection revocation, rule create and enable/disable, alert
acknowledgement, notification-route creation, incident create/transition/
note/assignment, check-schedule creation, device-profile save/delete, peer
enroll/revoke, action request/approval/execute, and investigation starts.
Audit writes never fail the operation they describe and are bounded to 400
characters of detail. `GET /api/v1/audit` exposes the most recent records to
administrators. Audit records are exempt from automatic retention.

## Storage capacity contract

Watchpost measures its total SQLite footprint — `watchpost.db` plus the
`-wal` and `-shm` sidecars and any other `watchpost.db*` files — against a
configurable cap (`WATCHPOST_MAX_DB_BYTES`, default 2 GiB) and protects the
free space on the data filesystem (`WATCHPOST_MIN_FREE_BYTES`, default 512 MiB;
`WATCHPOST_MIN_FREE_PERCENT`, default 5%). At capacity, telemetry and log
ingestion fail closed with HTTP 507 after the collector identity has been
verified, so storage state is never disclosed to unauthenticated callers.

No loss is silent. Watchpost rejects writes explicitly with 507; collectors
and agents retry within their bounded queues; any eventual queue overflow is
counted (`collector.dropped_samples`, agent `dropped_collections`) and
displayed. A 507 also triggers an immediate retention pass so space is
reclaimed without waiting for the scheduled interval. The storage report is an
authenticated operational diagnostic (`GET /api/v1/storage`) and a visible SPA
warning; the database footprint is additionally reported in the existing
diagnostics endpoint.
