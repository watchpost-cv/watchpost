# Security policy

Watchpost is pre-release development software. Do not expose it directly to the
internet or rely on it for safety, industrial control, or autonomous remediation.

Report suspected vulnerabilities privately to the maintainers rather than in a
public issue. Include the affected commit, deployment assumptions, reproduction,
and expected impact. Never include live credentials or sensitive telemetry.

The current security boundary is documented in `docs/threat-model.md`. Release
candidates require clean normal/race/vet/fuzz/cross-build gates, migration and
recovery tests, dependency review, and explicit disclosure of remaining limits.
