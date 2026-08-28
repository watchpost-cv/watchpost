# Scale evidence

WP-A17 exercises the resource-survey query with 500 posts and 20,000 raw
observations in one SQLite transaction. The returned survey remains one series
per post and at most 30 points per series. This proves the server-side bound,
not final browser hierarchy at production scale.

Run:

```sh
go test ./internal/history -run TestSurveyBoundsFiveHundredPosts -count=1
```

The next scale campaign must include real browser rendering, mixed post kinds,
active rules/alerts, slow disks, concurrent ingestion and retained history.
