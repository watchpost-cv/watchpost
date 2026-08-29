# Backup and recovery (R18a)

## Online backup

`watchpost backup --output PATH [--passphrase-file FILE]` produces a consistent
snapshot of a running node with SQLite `VACUUM INTO`; the node does not need to
be stopped. Without a passphrase the output is a plain SQLite database. With a
passphrase (minimum 10 characters) the snapshot is encrypted with AES-256-GCM
under a PBKDF2-HMAC-SHA256 key (210,000 rounds). A backup never contains the
passphrase or master key that protects it.

## Restore

`watchpost restore --input PATH [--passphrase-file FILE] --data-dir DIR [--force]`
decrypts when required, validates the SQLite header and schema version (a
database newer than the binary is refused), and atomically installs the
database. The node must be stopped, and `--force` is required to replace an
existing database. A wrong or missing passphrase fails closed with no partial
restore.

## Key and restore contract

- Backups are protected by an operator-supplied passphrase or dedicated backup
  key; the installation master key is never embedded in a backup.
- Restoring a node whose device profiles store encrypted credentials also
  requires the same `WATCHPOST_MASTER_KEY` used when those credentials were
  stored, otherwise the profiles cannot be polled (metadata remains readable).
- Master-key rotation either runs `watchpost rekey --old-key-file ... --new-key-file ...`
  to re-encrypt existing stored device credentials, or the operator re-enters
  credentials. Rotation never silently keeps secrets under a discarded key.
- Scheduled, remote and retention-managed backups are not implemented
  (R18b covers scheduling UX); this command is the online, verified core.

## Scheduled backups (R18b)

`WATCHPOST_BACKUP_DIR` plus a positive `WATCHPOST_BACKUP_SCHEDULE` enable
automatic online backups written as `watchpost-<timestamp>.wpbk`; set
`WATCHPOST_BACKUP_PASSPHRASE_FILE` to encrypt them and `WATCHPOST_BACKUP_RETAIN`
(default 7) to bound how many are kept. Status is available to authenticated
operators at `GET /api/v1/backup-status` (last/next run, last error). The
passphrase file is re-read each run so it can be rotated without restarting.