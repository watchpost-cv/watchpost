# Initial state contracts

Signal quality is one of `good`, `uncertain`, `bad`, `missing`, or `stale`.
Freshness is evaluated from observation time, ingestion time, collector policy,
and an explicit clock-skew allowance; old values never become current by reuse.

The initial alert lifecycle is:

```text
inactive -> pending -> firing -> resolved
                      -> acknowledged -> resolved
pending/firing/acknowledged -> suppressed -> prior evaluated state
```

Acknowledgement records awareness and does not alter evidence. Suppression is
visible and does not discard evaluation history. Exact transition contracts and
virtual-clock tests arrive in WP09.

Incidents begin `open`, may become `investigating` or `mitigated`, and end
`resolved`. Reopening creates an attributable transition; it does not erase the
prior resolution.
