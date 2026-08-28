package collectorclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
)

func TestQueueSurvivesRestartAndDrainsInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	config := Config{Version: 1, ServerURL: "unused", PostID: "host-a", CollectorID: "agent-a", Secret: "secret"}
	value := 42.0
	samples := []collectorcontract.Sample{{ObservedAt: time.Now().UTC(), Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}}
	queue, _ := OpenQueue(path, 4, 64<<10)
	if err := queue.Enqueue(config, samples, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(config, samples, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	queue, _ = OpenQueue(path, 4, 64<<10)
	if queue.Pending() != 2 {
		t.Fatalf("pending %d", queue.Pending())
	}
	var sequences []int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch collectorcontract.Batch
		_ = json.NewDecoder(r.Body).Decode(&batch)
		sequences = append(sequences, batch.Samples[0].Sequence)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(collectorcontract.Acknowledgement{Version: 1, BatchID: batch.BatchID, AcceptedThrough: batch.Samples[len(batch.Samples)-1].Sequence, ServerTime: time.Now()})
	}))
	defer server.Close()
	config.ServerURL = server.URL
	if err := Drain(context.Background(), Sender{Client: server.Client()}, config, queue); err != nil {
		t.Fatal(err)
	}
	if queue.Pending() != 0 || len(sequences) != 2 || sequences[0] != 1 || sequences[1] != 2 {
		t.Fatalf("pending=%d sequences=%v", queue.Pending(), sequences)
	}
}

func TestQueueIsBoundedAndRecordsDroppedSamples(t *testing.T) {
	queue, _ := OpenQueue(filepath.Join(t.TempDir(), "q.json"), 1, 64<<10)
	config := Config{PostID: "p", CollectorID: "c"}
	sample := []collectorcontract.Sample{{Signal: "x", Quality: "good", ObservedAt: time.Now()}}
	_ = queue.Enqueue(config, sample, time.Now())
	if queue.Enqueue(config, sample, time.Now()) != ErrQueueFull || queue.DroppedSamples() != 1 {
		t.Fatal("queue bound not enforced")
	}
}
