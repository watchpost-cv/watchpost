# Development-candidate limitations

The WP01R–WP18R recovery programme closes a locally proven Linux development
candidate. It does not authorize a public production release.

- The supplied remote host collector supports Linux. macOS and Windows binaries
  are cross-built but have not received equivalent real-runner collector smokes.
- HTTP, TCP, DNS, ICMP and TLS have durable central schedules. SNMPv3
  authPriv polling is also durable and read-only; polling credentials are
  stored encrypted at rest under an installation master key supplied outside
  the database, and metadata-only profiles remain usable without a key.
- SNMP is read-only. Cameras, arbitrary consumer IoT, PLC writes, and
  building-control commands are research scope, not implemented authority.
- The built-in investigation provider is deliberately non-causal. Production
  model-provider credentials/configuration and evaluation remain unfinished.
- Rules, notifications, incidents, actions, and fleet trust have bounded APIs,
  but several management and pairing journeys still need richer UI.
- Federation does not yet prove sustained partition reconciliation between two
  independently deployed nodes.
- Backups are online and verified (`watchpost backup` / `watchpost restore`
  with optional passphrase encryption and a documented key/restore contract).
  Scheduled, encrypted-at-rest-by-default, remote and retention-managed backup
  automation is not implemented.
- The 500-post survey test proves a bounded query, not browser usability at
  production scale. The local soak is not multi-day. Accessibility has
  keyboard/focus, reduced-motion and forced-colour foundations but no external
  assistive-technology audit. No external security assessment is complete.
- Watchpost is not a safety system, SCADA/HMI, or autonomous remediation engine.

Publish a release only after the remaining limitation relevant to its advertised
scope is either closed with evidence or disclosed prominently in release notes.
