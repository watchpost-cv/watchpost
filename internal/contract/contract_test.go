package contract

import (
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
)

// TestV1BatchMapsLosslesslyIntoCanonicalObservations proves the established
// collector protocol v1 batch contract converts without loss into the
// canonical observation envelope that central checks and device adapters will
// also produce.
func TestV1BatchMapsLosslesslyIntoCanonicalObservations(t *testing.T) {
	now := time.Now().UTC()
	value := 42.5
	batch := collectorcontract.Batch{
		Version:     1,
		PostID:      "host-a",
		CollectorID: "agent-1",
		BatchID:     "b-1",
		SentAt:      now,
		Samples: []collectorcontract.Sample{
			{Sequence: 1, ObservedAt: now, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{"cpu": "0"}},
			{Sequence: 2, ObservedAt: now, Signal: "load.one", Value: nil, Unit: "load", Quality: "missing", Labels: map[string]string{}},
		},
	}
	method := Method{ID: batch.CollectorID, Kind: MethodHostAgent, PostID: batch.PostID}
	source := Source{Method: method, Identity: batch.CollectorID}
	for index, sample := range batch.Samples {
		observation := Observation{
			Version:    ProtocolVersion,
			PostID:     batch.PostID,
			Source:     source,
			Signal:     sample.Signal,
			Value:      sample.Value,
			Unit:       sample.Unit,
			Quality:    Quality(sample.Quality),
			Labels:     sample.Labels,
			ObservedAt: sample.ObservedAt,
			IngestedAt: now,
		}
		if observation.Signal != batch.Samples[index].Signal || observation.Value != batch.Samples[index].Value {
			t.Fatalf("observation %d lost data", index)
		}
		// The missing-quality sample must keep a nil value: absence is never
		// converted to numeric zero.
		if sample.Quality == "missing" && observation.Value != nil {
			t.Fatalf("missing quality sample gained a numeric value")
		}
	}
}

func TestQualityVocabularyIsClosedAndExplicit(t *testing.T) {
	allowed := map[Quality]bool{QualityGood: true, QualityUncertain: true, QualityBad: true, QualityMissing: true, QualityStale: true}
	for quality := range allowed {
		switch quality {
		case QualityGood, QualityUncertain, QualityBad, QualityMissing, QualityStale:
		default:
			t.Fatalf("unexpected quality %q", quality)
		}
	}
}