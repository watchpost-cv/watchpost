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

The operational SPA is built from canonical Nift source in `web/content` and
`web/templates`. Edit the source, regenerate the embedded distribution, and
commit both:

```sh
cd web && nift build && nift status && cd ..
```

`web/dist` is generated output. `web/embed_test.go` enforces in CI that the
committed dist matches the canonical source, and `hardening/spa-gate.sh`
proves a full regeneration produces no diff.

On Linux, inspect the host signals produced by the bundled collector sampler:

```sh
./watchpost collector sample
```

For a monitored host, use **Add a machine or device** in the SPA. Record a
hostname or IP for inventory and active checks, choose **Host**, then generate
the one-use pairing commands. Set the Watchpost URL to an address reachable
from that machine (remote machines cannot use `127.0.0.1`). Copy the compiled
binary to the post, run the pairing commands there, and install the service.
The collector initiates outbound delivery of CPU, memory, disk, load, uptime,
and health signals; it does not expose an inbound management port.

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

The local queue is limited to 256 batches or 8 MiB. It survives restart,
replays in sequence, removes only acknowledged batches, and reports saturation
through `collector.dropped_samples`.

For source-tree development without keeping a binary:

```sh
go run ./cmd/watchpost
```

The early `./watchpost serve` form remains accepted for compatibility, but the
subcommand is no longer required.

Posts can be edited from **Posts → Edit**. Archiving preserves history;
permanent deletion is an administrator-only, ID-confirmed operation that also
removes the post's credentials, telemetry, rules, alerts, logs, and scoped
investigation records.

The default listener is `127.0.0.1:8080`. Command-line options override
`WATCHPOST_LISTEN` and `WATCHPOST_DATA_DIR`; defaults apply below both.

For an internet-facing deployment, keep that loopback binding, terminate HTTPS
with Caddy or nginx, and pass `--secure-cookies`. See
[`docs/reverse-proxy.md`](docs/reverse-proxy.md). Build release archives and
checksums with `./packaging/build-release.sh vX.Y.Z`; the release-shaped local
gate is `./packaging/release-smoke.sh`.

The complete local development-candidate gate is
`./hardening/complete-gate.sh`. Read `RELEASE_LIMITATIONS.md` before making any
deployment or production-readiness claim.

Public website source lives in the sibling `watchpost-ops.github.io`
repository.
