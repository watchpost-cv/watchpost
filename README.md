# Watchpost

Watchpost is an open-source, web-based monitoring and operations platform with
an evidence-grounded agent designed in from the beginning.

WP00 through WP11 establish the contracts and runnable single-node service with
SQLite persistence, authentication, posts, collection, endpoint checks,
bounded history, deterministic alerts, notifications, and incidents. The build
is still development software: no public release, production remote collector,
agent capability, or completed hardening programme is claimed yet.
Read [HANDOVER.md](HANDOVER.md) for the boundaries and [PLAN.md](PLAN.md) for the
ordered implementation programme.

```sh
go run ./cmd/watchpost serve
```

The default listener is `127.0.0.1:8080`. Command-line options override
`WATCHPOST_LISTEN` and `WATCHPOST_DATA_DIR`; defaults apply below both.

Public website source lives in the sibling `watchpost-ops.github.io`
repository.
