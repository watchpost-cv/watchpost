# Watchpost agent architecture

Status: accepted design for WP-A01, 2026-08-28.

## Product model

A **post** is the monitored object. A **monitoring method** explains how
Watchpost observes it. `watchpost-agent` is a separately installed program and
one monitoring method for machines. A **collector** is an implementation inside
Watchpost or an agent; it is not top-level user inventory.

```text
post
|- agent connection -> CPU, memory, filesystem, service collectors
|- central check    -> HTTP, TCP, TLS, DNS, ICMP
`- device adapter   -> SNMP, and future bounded protocols
```

Watchpost owns posts, approval, history, rules, alerts, incidents and fleet
policy. Watchpost Agent owns local collection, a bounded delivery queue, local
diagnostics and its connection credential.

## Equal web and CLI control surfaces

The agent embeds a loopback web application for ordinary setup and pairing.
The CLI exposes the same service operations for headless servers, SSH,
configuration management and recovery. Neither surface implements a separate
state machine: both call the same application service and persist the same
configuration.

## Install before pair

Installation creates the binary, service definition, private state directory
and unpaired local web application. An unpaired agent is a valid quiet state.
It does not manufacture post health or retry authentication.

Pairing is request and approval:

1. The agent creates an opaque installation ID and local request secret.
2. The operator supplies a Watchpost URL through the agent website or CLI.
3. The agent requests pairing and both interfaces show the same confirmation
   phrase.
4. A Watchpost administrator creates or selects a post and approves.
5. The agent polls with its private request secret, receives a post-scoped
   credential, persists it atomically and sends an immediate sample.

Requests expire, are rate limited and cannot be replayed. Hostnames and IP
addresses are descriptive metadata, never credential identity.

## Network and authority boundary

The agent UI binds to loopback by default. State-changing browser requests use
Origin checks, a local authenticated session and CSRF protection. Pairing and
delivery require HTTPS except for loopback development. Explicit non-loopback
UI binding is an advanced opt-in configuration, not an automatic convenience.

Deleting a post revokes server authority but cannot uninstall a remote agent.
The agent becomes unpaired and may request a new association. Archive, unpair,
reset and uninstall remain separate operations.

## Compatibility direction

The existing bundled `watchpost collector` commands are a transitional
compatibility path. New development belongs in the sibling `watchpost-agent`
repository. Migration must preserve existing post evidence while rotating old
collector credentials into opaque agent-installation identities.
