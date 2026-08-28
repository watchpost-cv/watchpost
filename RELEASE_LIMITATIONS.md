# Development-candidate limitations

The WP01R–WP18R recovery programme closes a locally proven Linux development
candidate. It does not authorize a public production release.

- The supplied remote host collector supports Linux. macOS and Windows binaries
  are cross-built but have not received equivalent real-runner collector smokes.
- HTTP, TCP, DNS, ICMP, TLS, and SNMP operations are immediate diagnostics;
  durable scheduled endpoint and device polling remains future work.
- SNMP is read-only. Cameras, arbitrary consumer IoT, PLC writes, and
  building-control commands are research scope, not implemented authority.
- The built-in investigation provider is deliberately non-causal. Production
  model-provider credentials/configuration and evaluation remain unfinished.
- Rules, notifications, incidents, actions, and fleet trust have bounded APIs,
  but several management and pairing journeys still need richer UI.
- Federation does not yet prove sustained partition reconciliation between two
  independently deployed nodes.
- Backups require a cleanly stopped node. Online backup, encryption, scheduling,
  and remote retention are not implemented.
- The local soak is intentionally bounded and is not a multi-day or large-fleet
  capacity claim. No external security assessment has been completed.
- Watchpost is not a safety system, SCADA/HMI, or autonomous remediation engine.

Publish a release only after the remaining limitation relevant to its advertised
scope is either closed with evidence or disclosed prominently in release notes.
