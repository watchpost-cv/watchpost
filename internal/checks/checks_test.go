package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/contract"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func TestHTTPAndTCPChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	runner := New(time.Second)
	if got := runner.HTTPCheck(context.Background(), server.URL); !got.OK || got.Status != 204 {
		t.Fatalf("%#v", got)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if got := runner.TCP(context.Background(), listener.Addr().String()); !got.OK {
		t.Fatalf("%#v", got)
	}
}
func TestPublicAddress(t *testing.T) {
	if PublicAddress("127.0.0.1") || PublicAddress("10.0.0.1") || !PublicAddress("8.8.8.8") {
		t.Fatal("address classification")
	}
}

func TestResultObservationsCanonicalContract(t *testing.T) {
	method := contract.Method{ID: "s1", Kind: contract.MethodCentralCheck, PostID: "p"}
	at := time.Now().UTC()

	failed := Result{Kind: "http", Address: "http://127.0.0.1:1", Latency: 250 * time.Millisecond, Failure: "refused"}
	failedObs := failed.Observations(method, at)
	if len(failedObs) != 2 {
		t.Fatalf("failed http observations=%d want 2", len(failedObs))
	}
	if failedObs[0].Signal != "http.ok" || failedObs[0].Value == nil || *failedObs[0].Value != 0 || failedObs[0].Quality != contract.QualityGood {
		t.Fatalf("failed http.ok observation wrong: %#v", failedObs[0])
	}
	if failedObs[1].Signal != "http.latency_ms" || failedObs[1].Quality != contract.QualityGood {
		t.Fatalf("failed http latency observation wrong: %#v", failedObs[1])
	}
	if failedObs[0].Source.Method.Kind != contract.MethodCentralCheck || failedObs[0].Source.Identity != "s1" {
		t.Fatalf("source identity lost: %#v", failedObs[0].Source)
	}

	expiry := at.Add(30 * 24 * time.Hour)
	tlsResult := Result{Kind: "tls", Address: "example.com:443", Latency: 50 * time.Millisecond, OK: true, ExpiresAt: &expiry}
	tlsObs := tlsResult.Observations(method, at)
	if len(tlsObs) != 3 {
		t.Fatalf("tls observations=%d want 3", len(tlsObs))
	}
	days := tlsObs[2].Value
	if tlsObs[2].Signal != "tls.expires_in_days" || days == nil || *days < 29 || *days > 31 {
		t.Fatalf("tls expiry observation wrong: %#v", tlsObs[2])
	}
}

func TestRunDueConcurrentWorkersReturnAllResults(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('web','Web','http_endpoint',?,?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	s := NewScheduleStore(db)
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("web-%d", i)
		if err := s.Save(ctx, Schedule{ID: id, PostID: "web", Kind: "http", Address: "http://127.0.0.1:1", IntervalSeconds: 60}, audit.Entry{Action: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	results, err := s.RunDue(ctx, New(time.Second), time.Now().UTC().Add(time.Second), 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 8 {
		t.Fatalf("results=%d want 8", len(results))
	}
	for _, result := range results {
		if result.Result.OK {
			t.Fatalf("unexpectedly healthy check: %#v", result)
		}
	}
	// All schedules advanced; a second run has nothing due.
	again, err := s.RunDue(ctx, New(time.Second), time.Now().UTC().Add(time.Second), 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("second run returned %d due", len(again))
	}
}
