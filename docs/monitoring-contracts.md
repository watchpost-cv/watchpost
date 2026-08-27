# Monitoring contracts (WP06–WP08)

The first host collector is Linux-only and read-only. It reads `/proc` and
filesystem statistics without shell execution or elevated privileges. A failed
or unavailable source returns an error rather than a healthy value. The remote
collector transport and enrollment lifecycle remain WP06 follow-up work before
host collection should be described as production-ready on a fleet.

Endpoint checks support TCP, HTTP(S), DNS, and TLS with explicit timeouts. HTTP
redirects are bounded and cannot cross hostnames. Response bodies are discarded
after a small bounded read. TLS requires TLS 1.2 or newer. Operators can monitor
private addresses deliberately; therefore check authority is an SSRF-sensitive
operator capability rather than an unauthenticated utility.

History queries require one post, one signal, a bounded time window, and a row
limit. Retention deletes bounded batches. Missing, stale, uncertain, and bad
quality remain explicit observations rather than numeric zero.
