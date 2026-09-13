# Watchpost authentication

Use `--session-file` for human administration. Agent, collector and cluster-node service protocols use separate machine credentials and are not exposed as human functional CLI commands.

The default browser session cookie is `watchpost_session` and state-changing session requests use `X-Watchpost-CSRF`. Session files are JSON credential containers created/read by the common CLI and written with mode `0600`; on Unix, token/session files accessible by group or others are rejected. Passwords and tokens are supplied through protected files or JSON input, never command-line credential flags.

Human accounts remain installation-local. Cluster/service identities are separate from human sessions wherever applicable.
