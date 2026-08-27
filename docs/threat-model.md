# Threat model

## Trust zones

The browser, Watchpost server, database, collector processes, monitored posts,
reverse proxy, notification providers, model providers, and federated peers are
separate trust zones. Identity and data crossing each edge must be authenticated,
authorized, bounded, versioned where durable, and auditable where consequential.

## Protected assets

Account/session material, collector and provider credentials, post inventory,
telemetry, logs, incident history, action authority, and audit history require
confidentiality and integrity appropriate to their sensitivity.

## Principal threats

- unauthenticated or cross-site requests changing operational state;
- spoofed proxy headers or collector identity;
- replayed, oversized, high-cardinality, stale, or malicious observations;
- logs and metadata attempting prompt injection;
- secret leakage through diagnostics, errors, logs, exports, or model context;
- an investigation path acquiring action authority;
- notification storms, queue exhaustion, disk exhaustion, and clock skew;
- corrupted migrations, downgrade, incompatible collectors, and hostile peers.

## Invariants

Missing evidence is not healthy evidence. Model output is not authorization.
No model-authored shell text is executed. Observation, recommendation, approval,
execution, and verification remain separately attributable. Early device
collectors are read-only. Safety systems never rely on Watchpost.
