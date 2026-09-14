package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/collectorcontract"
	"github.com/watchpost-cv/watchpost/internal/posts"
	"github.com/watchpost-cv/watchpost/internal/rules"
)

// TestReplayedBatchDoesNotRefireRules proves that an idempotent replay of an
// already-acknowledged batch (a lost 202) returns 202 without re-evaluating
// rules or re-firing alerts/notifications.
func TestReplayedBatchDoesNotRefireRules(t *testing.T) {
	s := testServer(t)
	ctx := t.Context()
	if _, err := s.posts.Create(ctx, posts.Post{ID: "host-a", Name: "Host A", Kind: "host"}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	secret, err := s.ingest.Enroll(ctx, "collector-a", "host-a", audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.rules.Create(ctx, rules.Rule{ID: "rule-1", PostID: "host-a", Signal: "cpu.percent", Operator: "gt", Threshold: 50, MissingPolicy: "unknown", Severity: "warning", Enabled: true}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	value := 90.0
	batch := collectorcontract.Batch{
		Version: 1, PostID: "host-a", CollectorID: "collector-a", BatchID: "batch-replay-1", SentAt: now,
		Samples: []collectorcontract.Sample{{Sequence: 1, ObservedAt: now, Signal: "cpu.percent", Value: &value, Unit: "percent", Quality: "good", Labels: map[string]string{}}},
	}
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	post := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/collector/v1/observations", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	if w := post(); w.Code != http.StatusAccepted {
		t.Fatalf("first batch status=%d body=%s", w.Code, w.Body.String())
	}
	var alerts int
	if err := s.store.DB.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 {
		t.Fatalf("expected one alert from the first batch, got %d", alerts)
	}

	if w := post(); w.Code != http.StatusAccepted {
		t.Fatalf("replayed batch status=%d body=%s", w.Code, w.Body.String())
	}
	if err := s.store.DB.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 {
		t.Fatalf("replayed batch re-fired rules: alerts=%d, want 1", alerts)
	}
}
