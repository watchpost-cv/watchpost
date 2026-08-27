# Single-node architecture

The first Watchpost node is one Go process with an embedded web interface and,
from WP02, a migrated SQLite database. The browser never talks directly to a
collector or post.

```text
browser -> HTTP server -> application domains -> storage
                         -> ingestion <- collectors <- posts
```

Domain packages depend inward on explicit interfaces. Collection does not own
rules; rules do not deliver notifications; agent tools do not bypass the same
application authorization used by human requests. Optional federation remains
outside the single-node authority boundary.

The initial domains are identity, posts, collection, signals/events, rules,
alerts, notifications, incidents, investigation, actions, audit, and fleet.
Generic maps must not cross their durable boundaries.
