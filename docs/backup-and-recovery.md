# Backup and recovery (WP02 baseline)

Stop Watchpost cleanly before copying its data directory. The WP02 baseline
stores durable state in `watchpost.db`; SQLite WAL side files may exist while the
process runs, so copying only the main file from a live node is not supported.
Restore into an empty owner-only data directory, then start the same or a newer
compatible binary. Startup refuses a schema newer than the binary supports.

Online, scheduled, encrypted, and externally segmented telemetry backups are
not implemented. Do not claim crash-consistent live backups until Watchpost
exposes a tested SQLite backup operation.

Run `./hardening/recovery-drill.sh` from a source checkout. It creates durable
state, cleanly stops the node, copies only the stopped database, restores into
an empty directory, verifies the post through the API, and proves a deliberately
corrupt database fails closed.
