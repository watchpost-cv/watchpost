# Alerts, notifications, and incidents (WP09–WP11)

Rules are deterministic threshold contracts over named post signals. The first
engine supports duration, greater/less comparisons, recovery hysteresis,
missing-data policy, maintenance suppression, acknowledgement, resolution, and
replay using caller-supplied observation times. Later syntax must compile into
these typed semantics rather than bypass them.

Firing alerts enqueue at most one delivery per route. Delivery is durable,
bounded per worker pass, and retries with capped exponential backoff. Initial
routes are generic HTTP webhooks and SMTP email. Secrets are not returned by
read APIs. Full scheduling, escalation, and route-level rate budgets remain
future work inside WP10 hardening.

Incidents are durable records with severity, status, owner, summary, linked
alerts, notes, and an append-only timeline. Correlation is explicit through the
link table; Watchpost never silently merges alert histories. Resolving an
incident adds a transition and timestamp rather than deleting its evidence.
