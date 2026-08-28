package hostcollector

import (
	"context"
	"errors"
	"time"

	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
	"github.com/watchpost-ops/watchpost/internal/host"
)

type SnapshotSource func() (host.Snapshot, error)

type Sampler struct {
	collect SnapshotSource
	wait    func(context.Context, time.Duration) error
}

func New() *Sampler { return NewWith(host.Collect, waitContext) }

func NewWith(collect SnapshotSource, wait func(context.Context, time.Duration) error) *Sampler {
	return &Sampler{collect: collect, wait: wait}
}

func (s *Sampler) Sample(ctx context.Context, interval time.Duration) ([]collectorcontract.Sample, error) {
	if interval < 10*time.Millisecond || interval > time.Minute {
		return nil, errors.New("invalid CPU sampling interval")
	}
	before, err := s.collect()
	if err != nil {
		return nil, err
	}
	if err = s.wait(ctx, interval); err != nil {
		return nil, err
	}
	after, err := s.collect()
	if err != nil {
		return nil, err
	}
	user := after.CPUUser - before.CPUUser
	system := after.CPUSystem - before.CPUSystem
	idle := after.CPUIdle - before.CPUIdle
	total := user + system + idle
	cpu := 0.0
	if total > 0 {
		cpu = 100 * float64(user+system) / float64(total)
	}
	memory := percentUsed(after.MemoryTotal, after.MemoryAvailable)
	disk := percentUsed(after.RootTotal, after.RootFree)
	now := after.ObservedAt
	values := []struct {
		name, unit string
		value      float64
	}{
		{"cpu.percent", "percent", cpu}, {"memory.percent", "percent", memory},
		{"disk.percent", "percent", disk}, {"load.1", "load", after.Load1},
		{"load.5", "load", after.Load5}, {"load.15", "load", after.Load15},
		{"uptime.seconds", "seconds", after.UptimeSeconds}, {"collector.up", "boolean", 1},
	}
	result := make([]collectorcontract.Sample, 0, len(values))
	for _, item := range values {
		value := item.value
		result = append(result, collectorcontract.Sample{ObservedAt: now, Signal: item.name, Value: &value, Unit: item.unit, Quality: "good", Labels: map[string]string{}})
	}
	return result, nil
}

func percentUsed(total, available uint64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(total-available) / float64(total)
}
func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
