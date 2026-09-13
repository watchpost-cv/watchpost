# Watchpost cluster operations

Phase 2 clustering is server-to-server control-plane coordination. It does not replicate the Watchpost database, transfer Agent ownership, share human accounts, or fail monitoring work over to another node.

## Configure this node

A node must advertise an HTTPS endpoint before it can join another Watchpost:

```sh
watchpost cluster configure --name warehouse-east --endpoint https://watchpost-east.example.com
watchpost cluster identity --json
```

The node ID and installation ID are generated once and persist in the Watchpost database. The fingerprint is derived from the node public key.

## Pair two Watchposts

On the Watchpost accepting the new member:

```sh
watchpost cluster invite --secret-file /tmp/watchpost-invite
```

Transfer the invitation out of band. On the joining Watchpost:

```sh
watchpost cluster join --url https://watchpost-host.example.com --token-file /tmp/watchpost-invite --json
```

Approve the displayed node ID and public-key fingerprint from `/app/` or locally:

```sh
watchpost cluster approve join_...
```

The joining node can survive a restart before collecting the result. Finish with:

```sh
watchpost cluster joins --json
watchpost cluster collect out_... --json
```

Invitation, request, and member credentials are separate from human sessions and Watchpost Agent credentials. Invitation tokens and rotated credentials are written only to explicitly requested `0600` files by the CLI.

## Inspect the cluster

```sh
watchpost cluster members --json
watchpost cluster status --target all --json
watchpost cluster summary --target all --json
```

Distributed reads report one result per owner node and retain partial failures rather than converting them into overall success.

## Membership lifecycle

```sh
watchpost cluster disable wp_...
watchpost cluster enable wp_...
watchpost cluster rotate wp_... --secret-file /tmp/new-node-credential
watchpost cluster revoke wp_...
watchpost cluster remove wp_...
```

Removal requires the member to be disabled or revoked first. Rotation has an overlap period: the replacement inbound credential is accepted once, then atomically becomes current.
