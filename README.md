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

On Linux, inspect the canonical host signals with the host sampler:

```sh
./watchpost collector sample
```

Host monitoring is delivered by the separately installed Watchpost Agent (see
the sibling `watchpost-agent` repository). The bundled collector lifecycle was
removed (R17); the agent is the supported host-monitoring path. For a monitored
host, use **Add a machine or device** in the SPA to create a host post, then
install and run the agent on the machine, request pairing from the agent's
local interface or CLI, and approve the matching phrase here. The agent
initiates outbound delivery of CPU, memory, disk, load, uptime and health
signals; it does not expose an inbound management port.

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

## Run as a systemd user service

Run Watchpost in the foreground with `./watchpost` or `watchpost serve`. To
keep it running without a terminal, install a per-user systemd unit:

```sh
watchpost service install                 # optional --listen, --data-dir, --secure-cookies, --env-file
watchpost service status
watchpost service logs             # or: watchpost service logs --follow
watchpost service restart
watchpost service uninstall        # stops the service but keeps Watchpost data
```

The user unit is written to `~/.config/systemd/user/watchpost.service` and
managed with `systemctl --user` and `journalctl --user-unit watchpost.service`.
`service install` resolves the executable to a stable absolute path, refuses
empty, relative or transient paths, writes the unit atomically, reloads
systemd, and enables and starts the service. An existing unit that is not
managed by Watchpost is never overwritten or removed silently. `watchpost
service status` reports enabled/running state, PID, version, listen address and
a live health check of the public `GET /healthz` endpoint, and exits nonzero
when the service is failed or missing.

`service install` records `--listen` and `--data-dir` (default from
`WATCHPOST_DATA_DIR` or `~/.config/watchpost`, both user-writable) in the unit;
`--secure-cookies` is passed through for HTTPS reverse-proxy deployments.
Because a systemd user service does not inherit the shell environment, use an
explicit protected environment file for the remaining `WATCHPOST_*`
configuration (including `WATCHPOST_MASTER_KEY`/`WATCHPOST_MASTER_KEY_FILE`,
setup tokens and network policy):

```sh
watchpost service install --env-file /absolute/protected/watchpost.env
```

The file must be an absolute, regular, non-symlink file with exactly `0600`
permissions, owned by the invoking user; it is referenced by the unit's
`EnvironmentFile=` and its path is recorded in the integrity-checked managed
metadata. Secret values are never copied into the unit or printed. The recorded
environment file is revalidated before `start`, `restart` and `status`; `stop`,
`logs` and `uninstall` remain available even if it is missing. Changing the file
takes effect on `watchpost service restart`. Install creates the data directory
with owner-only permissions and refuses symlink, non-directory or
group/world-writable data paths. The generated user unit retains the baseline
hardening (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome=read-only`, `ReadWritePaths=<data dir>`). Repeated `service
install` calls preserve the installed listen, data directory, secure-cookies
flag and environment file unless a flag is given explicitly. The `packaging/
watchpost.service` template remains the reference for system-wide
installations; `watchpost service` manages the per-user unit instead.
`service install --system` (system-wide units) is a documented follow-up and is
not yet supported; user mode is the default.

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
