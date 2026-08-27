//go:build !linux

package host

import (
	"errors"
	"time"
)

type Snapshot struct {
	ObservedAt      time.Time `json:"observed_at"`
	CPUUser         uint64    `json:"cpu_user_ticks"`
	CPUSystem       uint64    `json:"cpu_system_ticks"`
	CPUIdle         uint64    `json:"cpu_idle_ticks"`
	MemoryTotal     uint64    `json:"memory_total_bytes"`
	MemoryAvailable uint64    `json:"memory_available_bytes"`
	UptimeSeconds   float64   `json:"uptime_seconds"`
	Load1           float64   `json:"load_1"`
	Load5           float64   `json:"load_5"`
	Load15          float64   `json:"load_15"`
	RootTotal       uint64    `json:"root_total_bytes"`
	RootFree        uint64    `json:"root_free_bytes"`
}

func Collect() (Snapshot, error) {
	return Snapshot{}, errors.New("host collection is currently implemented for Linux only")
}
