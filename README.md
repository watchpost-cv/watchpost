# Watchpost

Watchpost is an open-source, web-based monitoring and operations platform with
an evidence-grounded agent designed in from the beginning.

WP00 through WP18 establish a development candidate with SQLite persistence,
authentication, posts, collection, checks, history, alerts, notifications,
incidents, logs, device profiles, read-only investigation, typed actions, and
federation contracts. This remains development software—not a public release or
production-readiness claim. See `docs/final-checkpoints.md` for the evidence
boundary that remains before tagging.
Read [HANDOVER.md](HANDOVER.md) for the boundaries and [PLAN.md](PLAN.md) for the
ordered implementation programme.

Compile and run Watchpost:

```sh
go build -o watchpost ./cmd/watchpost
./watchpost
```

On Linux, inspect the host signals produced by the bundled collector sampler:

```sh
./watchpost collector sample
```

This sampling command does not yet pair or deliver telemetry; those lifecycle
commands are introduced by WP04R–WP06R.

After pairing, install and inspect a per-user systemd collector service:

```sh
./watchpost collector install
./watchpost collector status
./watchpost collector logs
./watchpost collector uninstall
```

Use `--system` as root for an explicit machine-wide service. The installer
copies the binary to a stable location; it does not depend on the downloaded
binary remaining in the current directory.

For source-tree development without keeping a binary:

```sh
go run ./cmd/watchpost
```

The early `./watchpost serve` form remains accepted for compatibility, but the
subcommand is no longer required.

The default listener is `127.0.0.1:8080`. Command-line options override
`WATCHPOST_LISTEN` and `WATCHPOST_DATA_DIR`; defaults apply below both.

Public website source lives in the sibling `watchpost-ops.github.io`
repository.
