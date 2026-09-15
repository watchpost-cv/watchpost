package replicated

import "sync/atomic"

// replicationEnabled is a process-wide registry of whether the replicated
// adapter is the authoritative write path for replicated tables. When enabled,
// propagation (and any other direct writer) MUST NOT mutate replicated tables
// directly: it must route through the replicated adapter or be rejected.
var replicationEnabled atomic.Bool

// SetReplicatedEnabled enables/disables the replicated authoritative-write
// gate for this process.
func SetReplicatedEnabled(v bool) { replicationEnabled.Store(v) }

// IsReplicatedEnabled reports whether the gate is active.
func IsReplicatedEnabled() bool { return replicationEnabled.Load() }
