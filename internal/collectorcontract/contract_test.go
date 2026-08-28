package collectorcontract

import (
	"testing"
	"time"
)

func validBatch(now time.Time) Batch {
	value := 42.0
	return Batch{Version: 1, PostID: "host-a", CollectorID: "agent-a", BatchID: "batch-1", SentAt: now, Samples: []Sample{{Sequence: 1, ObservedAt: now, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}}
}

func TestBatchContract(t *testing.T) {
	now := time.Now().UTC()
	if err := validBatch(now).Validate(now); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Batch){
		"version":    func(b *Batch) { b.Version = 2 },
		"identity":   func(b *Batch) { b.PostID = "bad/id" },
		"empty":      func(b *Batch) { b.Samples = nil },
		"clock":      func(b *Batch) { b.SentAt = now.Add(6 * time.Minute) },
		"sequence":   func(b *Batch) { b.Samples = append(b.Samples, b.Samples[0]); b.Samples[1].Sequence = 3 },
		"quality":    func(b *Batch) { b.Samples[0].Quality = "healthy" },
		"old sample": func(b *Batch) { b.Samples[0].ObservedAt = now.Add(-25 * time.Hour) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			batch := validBatch(now)
			mutate(&batch)
			if batch.Validate(now) == nil {
				t.Fatal("accepted invalid batch")
			}
		})
	}
}
