package hostcollector

import (
	"context"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/host"
)

func TestSamplerProducesCanonicalHostSignals(t *testing.T) {
	now := time.Now().UTC()
	snapshots := []host.Snapshot{{ObservedAt: now, CPUUser: 10, CPUSystem: 10, CPUIdle: 80}, {ObservedAt: now.Add(time.Second), CPUUser: 30, CPUSystem: 20, CPUIdle: 150, MemoryTotal: 1000, MemoryAvailable: 250, RootTotal: 2000, RootFree: 500, Load1: 1, Load5: 2, Load15: 3, UptimeSeconds: 99}}
	index := 0
	sampler := NewWith(func() (host.Snapshot, error) { result := snapshots[index]; index++; return result, nil }, func(context.Context, time.Duration) error { return nil })
	samples, err := sampler.Sample(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"cpu.percent": 30, "memory.percent": 75, "disk.percent": 75, "load.1": 1, "load.5": 2, "load.15": 3, "uptime.seconds": 99, "collector.up": 1}
	if len(samples) != len(want) {
		t.Fatalf("got %d samples", len(samples))
	}
	for _, sample := range samples {
		if sample.Value == nil || *sample.Value != want[sample.Signal] || sample.Quality != "good" {
			t.Fatalf("bad sample %#v", sample)
		}
	}
}
