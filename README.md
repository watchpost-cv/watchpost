# Watchpost

Watchpost is a self-hosted monitoring and operations service for posts, evidence, checks, alerts and incidents.

## Command line

```sh
watchpost version
watchpost --version
watchpost service status
```

Unknown commands and unsupported options fail with a non-zero exit status.
Run the binary without a subcommand to start the integrated server, or use
`watchpost serve` where that compatibility alias is supported.

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

The operational SPA builds tracked HTML from `web/content` and `web/templates`.
CSS, JavaScript and image assets are maintained directly in `web/dist`. Edit
tracked source, regenerate the HTML, and commit the result:

```sh
cd web && nift build && nift status && cd ..
```

`web/embed_test.go` enforces HTML source parity and verifies each maintained
distribution asset exists. `hardening/spa-gate.sh` proves a full tracked-source
regeneration produces no diff.

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

The default listener is `127.0.0.1:7334`. The canonical `--host`/`--port` flags
and the `WATCHPOST_HOST`/`WATCHPOST_PORT` environment variables select the bind
address with CLI > environment > default precedence; values are trimmed once
and a port must be an integer from 1 through 65535. The legacy single-address
`--listen` flag and `WATCHPOST_LISTEN` environment remain supported for
compatibility and cannot be combined with the explicit host/port form.
`WATCHPOST_DATA_DIR` and `--data-dir` select the data directory; defaults apply
below both.

## Run as a systemd machine service

Run Watchpost in the foreground with `./watchpost` or `watchpost serve`. To keep
it running unattended and boot-safely on a systemd host, install it as a system
service:

```sh
sudo watchpost service install          # optional --host/--port (or legacy --listen), --data, --secure-cookies, --env-file
sudo watchpost service install --host 127.0.0.1 --port 7404
watchpost service status
watchpost service logs                  # or: watchpost service logs --follow
sudo watchpost service restart
sudo watchpost service uninstall        # removes the service registration; keeps Watchpost data
```

The system unit is written to `/etc/systemd/system/watchpost.service` and runs
as a dedicated unprivileged `watchpost` account (`nologin`, no home). It starts
at boot with `WantedBy=multi-user.target` and does **not** depend on any user
login or on systemd lingering. The binary is installed at `/usr/local/bin/watchpost`
and the data directory is `/var/lib/watchpost` (0700, owned `watchpost:watchpost`).
`service install` creates the account, data directory and unit idempotently, so a
clean machine needs no manual prerequisites.

`service install` resolves the executable to a stable absolute path, refuses
empty, relative or transient paths, and writes the unit atomically with a
versioned SHA-256 integrity header. An existing unit that is not managed by
Watchpost is never overwritten or removed silently. Install is transactional:
the prior managed unit bytes are preserved, prior systemd enablement and activity
are inspected before mutation, only exactly-recreatable states are accepted
(`enabled`, `enabled-runtime`, `disabled` × `active`, `inactive`;
masked/static/linked/generated/transient/failed/reloading states are refused
before mutation — unmask or stop first), and rollback reproduces the exact prior
enablement and activity states, distinguishing persistent from runtime
enablement. A changed binary with an unchanged unit is still recognised as a
changed installation and the service is restarted. A byte-identical unit and
binary already enabled and active is a genuine no-op. A failed fresh install is
stopped and disabled while the unit is still loaded, then removed and systemd is
reloaded. `watchpost service status` reports enabled/running state, PID,
version, listen address and a live health check of the public `GET /healthz`
endpoint, and exits nonzero when the service is failed or missing.

The complete lifecycle family matches the Web Fleet convention:

```sh
sudo watchpost service install|uninstall|start|stop|restart|enable|disable
watchpost service status|logs [--follow]
sudo watchpost service update ARTIFACT SHA256
sudo watchpost service rollback
```

`update` replaces the binary with a checksum-verified artifact, preserving the
prior running/stopped state and enablement, and retaining rollback metadata so a
later `service rollback` restores the previous version and its operational
state. Failed updates recover to the previous binary before reactivation and
surface both the update and recovery failures when both occur.

### Configuration and secrets

`service install` records the canonical `--host` (default `127.0.0.1`) and
`--port` (default `7334`) pair in the unit's `ExecStart`, so the recorded
listener is the runtime listener across restart and reboot. The legacy
`--listen` single-address form (and `WATCHPOST_LISTEN`) remains supported:
units installed that way keep their recorded `--listen` until reinstalled.
`service install --host 127.0.0.1 --port 7404` is the canonical explicit
example. The data directory defaults to `/var/lib/watchpost`. `--secure-cookies`
is passed through for HTTPS reverse-proxy deployments. Because the machine
service does not inherit the shell environment, supply the remaining
`WATCHPOST_*` configuration (including `WATCHPOST_MASTER_KEY`/`WATCHPOST_MASTER_KEY_FILE`, setup tokens and
network policy) through a root-protected environment file:

```sh
sudo watchpost service install --env-file /etc/watchpost/watchpost.env
```

The machine configuration file must be an absolute, regular, non-symlink file
with exactly `0600` permissions, owned by `root:root`; it is read by systemd via
`EnvironmentFile=` **before** the process drops to `User=watchpost`, so the
service account cannot rewrite its own machine configuration. Secret values are
never copied into the unit or printed. The recorded environment file is
revalidated before `start`, `restart` and `status`; `stop`, `logs` and
`uninstall` remain available even if it is missing. Changing the file takes
effect on `watchpost service restart`. Repeated `service install` calls preserve
the installed listen, data directory, secure-cookies flag and environment file
unless a flag is given explicitly.

The generated unit applies the baseline hardening: `NoNewPrivileges`,
`PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`,
`ReadWritePaths=/var/lib/watchpost`, `Restart=on-failure`. The `packaging/
watchpost.service` template mirrors the generated system unit for reference.

### install.sh

`install.sh` installs the **binary** only (from a checksum-verified release
archive); machine-service configuration is owned by the Go CLI. `install.sh
--system` installs to `/usr/local/bin` and then invokes the canonical
`watchpost service install`. The shell script contains no systemd implementation.

For an internet-facing deployment, keep that loopback binding, terminate HTTPS
with Caddy or nginx, and pass `--secure-cookies`. See
[`docs/reverse-proxy.md`](docs/reverse-proxy.md). Build release archives and
checksums with `./packaging/build-release.sh vX.Y.Z`; the release-shaped local
gate is `./packaging/release-smoke.sh`.

The complete local development-candidate gate is
`./hardening/complete-gate.sh`. Read `RELEASE_LIMITATIONS.md` before making any
deployment or production-readiness claim.

Public website source lives in the sibling `watchpost-cv.github.io`
repository.
