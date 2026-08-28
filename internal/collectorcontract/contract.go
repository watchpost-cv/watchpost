package collectorcontract

import (
	"errors"
	"math"
	"regexp"
	"time"
)

const (
	ProtocolVersion  = 1
	MaxBatchSamples  = 128
	MaxSignalLength  = 128
	MaxLabels        = 32
	MaxClockPast     = 24 * time.Hour
	MaxClockFuture   = 5 * time.Minute
	DefaultFreshness = 2 * time.Minute
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

type Sample struct {
	Sequence   int64             `json:"sequence"`
	ObservedAt time.Time         `json:"observed_at"`
	Signal     string            `json:"signal"`
	Value      *float64          `json:"value"`
	Unit       string            `json:"unit"`
	Quality    string            `json:"quality"`
	Labels     map[string]string `json:"labels"`
}

type Batch struct {
	Version     int       `json:"version"`
	PostID      string    `json:"post_id"`
	CollectorID string    `json:"collector_id"`
	BatchID     string    `json:"batch_id"`
	SentAt      time.Time `json:"sent_at"`
	Samples     []Sample  `json:"samples"`
}

type Acknowledgement struct {
	Version         int       `json:"version"`
	BatchID         string    `json:"batch_id"`
	AcceptedThrough int64     `json:"accepted_through"`
	ServerTime      time.Time `json:"server_time"`
}

func (b Batch) Validate(now time.Time) error {
	if b.Version != ProtocolVersion {
		return errors.New("unsupported collector protocol version")
	}
	if !identifier.MatchString(b.PostID) || !identifier.MatchString(b.CollectorID) || !identifier.MatchString(b.BatchID) {
		return errors.New("invalid collector batch identity")
	}
	if b.SentAt.Before(now.Add(-MaxClockPast)) || b.SentAt.After(now.Add(MaxClockFuture)) {
		return errors.New("collector clock outside allowed bounds")
	}
	if len(b.Samples) < 1 || len(b.Samples) > MaxBatchSamples {
		return errors.New("invalid collector batch size")
	}
	previous := int64(0)
	for index, sample := range b.Samples {
		if sample.Sequence < 1 || (index > 0 && sample.Sequence != previous+1) {
			return errors.New("collector sample sequences must be contiguous")
		}
		if sample.ObservedAt.Before(now.Add(-MaxClockPast)) || sample.ObservedAt.After(now.Add(MaxClockFuture)) {
			return errors.New("observation outside clock bounds")
		}
		if len(sample.Signal) < 1 || len(sample.Signal) > MaxSignalLength || len(sample.Labels) > MaxLabels {
			return errors.New("invalid collector sample")
		}
		if !map[string]bool{"good": true, "uncertain": true, "bad": true, "missing": true, "stale": true}[sample.Quality] {
			return errors.New("invalid signal quality")
		}
		if sample.Value != nil && (math.IsNaN(*sample.Value) || math.IsInf(*sample.Value, 0)) {
			return errors.New("invalid numeric value")
		}
		previous = sample.Sequence
	}
	return nil
}
