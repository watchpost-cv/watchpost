# Scale evidence

WP-A17 exercises the resource-survey query with 500 posts and 20,000 raw
observations in one SQLite transaction. The returned survey remains one series
per post and at most 30 points per series. This proves the server-side bound,
not final browser hierarchy at production scale.

Run:

```sh
go test ./internal/history -run TestSurveyBoundsFiveHundredPosts -count=1
```

## Sustained capacity (R3)

`hardening/long-run.sh` now runs a race-built server and collector with
retention enabled at a window shorter than the soak. It asserts:

- server and collector stay alive for the full duration;
- heap, file descriptors and goroutines stay under ceilings;
- the database footprint never exceeds `WATCHPOST_MAX_DB_BYTES`;
- when the soak outlives twice the retention window, the database footprint
  stops growing after the midpoint (flat growth within page granularity).

Local evidence (2026-08-30, 90-second soak, 15-second observation retention):
`db_bytes=331776 mid_db_bytes=331776 flat_growth=true enforce_flat=true`.
This proves ingestion continues while retention keeps the node's footprint
bounded; it is not a multi-day capacity result.

The next scale campaign must include real browser rendering, mixed post kinds,
active rules/alerts, slow disks, concurrent ingestion and retained history.
