package collectorclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
)

var ErrQueueFull = errors.New("collector queue is full")

type QueueState struct {
	Version        int                       `json:"version"`
	NextSequence   int64                     `json:"next_sequence"`
	Pending        []collectorcontract.Batch `json:"pending"`
	DroppedSamples uint64                    `json:"dropped_samples"`
}
type Queue struct {
	path                 string
	maxBatches, maxBytes int
	state                QueueState
}

func OpenQueue(path string, maxBatches, maxBytes int) (*Queue, error) {
	if path == "" || maxBatches < 1 || maxBytes < 1024 {
		return nil, errors.New("invalid collector queue limits")
	}
	queue := &Queue{path: path, maxBatches: maxBatches, maxBytes: maxBytes, state: QueueState{Version: 1, NextSequence: 1, Pending: []collectorcontract.Batch{}}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return queue, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(data, &queue.state) != nil || queue.state.Version != 1 || queue.state.NextSequence < 1 {
		return nil, errors.New("invalid collector queue state")
	}
	return queue, nil
}

func (q *Queue) Enqueue(config Config, samples []collectorcontract.Sample, now time.Time) error {
	if len(samples) == 0 {
		return errors.New("no samples")
	}
	if len(q.state.Pending) >= q.maxBatches {
		q.state.DroppedSamples += uint64(len(samples))
		_ = q.persist()
		return ErrQueueFull
	}
	copySamples := append([]collectorcontract.Sample(nil), samples...)
	for index := range copySamples {
		copySamples[index].Sequence = q.state.NextSequence + int64(index)
	}
	batch := collectorcontract.Batch{Version: 1, PostID: config.PostID, CollectorID: config.CollectorID, BatchID: fmt.Sprintf("b-%d-%d", now.UnixNano(), q.state.NextSequence), SentAt: now.UTC(), Samples: copySamples}
	old := q.state
	q.state.Pending = append(q.state.Pending, batch)
	q.state.NextSequence += int64(len(copySamples))
	data, _ := json.Marshal(q.state)
	if len(data) > q.maxBytes {
		q.state = old
		q.state.DroppedSamples += uint64(len(samples))
		_ = q.persist()
		return ErrQueueFull
	}
	return q.persist()
}
func (q *Queue) First() (collectorcontract.Batch, bool) {
	if len(q.state.Pending) == 0 {
		return collectorcontract.Batch{}, false
	}
	return q.state.Pending[0], true
}
func (q *Queue) Acknowledge(sequence int64) error {
	index := 0
	for index < len(q.state.Pending) {
		samples := q.state.Pending[index].Samples
		if len(samples) == 0 || samples[len(samples)-1].Sequence > sequence {
			break
		}
		index++
	}
	if index == 0 {
		return errors.New("acknowledgement did not cover queued batch")
	}
	q.state.Pending = append([]collectorcontract.Batch(nil), q.state.Pending[index:]...)
	return q.persist()
}
func (q *Queue) Pending() int           { return len(q.state.Pending) }
func (q *Queue) DroppedSamples() uint64 { return q.state.DroppedSamples }
func (q *Queue) persist() error {
	if err := os.MkdirAll(filepath.Dir(q.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(q.state, "", "  ")
	if err != nil {
		return err
	}
	temporary := q.path + ".tmp"
	if err = os.WriteFile(temporary, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, q.path)
}
