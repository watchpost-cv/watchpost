package runtime

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/replicated"
)

// TestReplicatedUnhealthyAndRecovery proves the CP7D-4c contract through the
// production runtime: a committed operation that fails to apply on the local
// leader surfaces a failed HTTP mutation, drives readiness to Unhealthy
// (authoritative mutations rejected, no local fallback), and does not advance
// the durable applied position. Reconstructing the runtime over the same data
// directory (a deliberate repair/rebuild) re-applies the committed operation
// and returns to ready.
func TestReplicatedUnhealthyAndRecovery(t *testing.T) {
	ca := newTestCA(t)
	dataDir := t.TempDir()
	addr := freeAddr(t)

	// Run 1: a committed operation fails to apply locally.
	n1 := newNode(t, ca, dataDir, "A", nil, true, 0, true, addr)
	waitReadiness(t, n1, replicated.ReadinessReadyLeader)
	n1.repl.FSM.InjectNextApplyFailure(errors.New("sqlite: simulated leader storage failure"))
	if code, _ := httpPost(t, n1.http.Client(), n1.http.URL, map[string]any{"id": "bad", "name": "Bad", "kind": "host", "labels": map[string]string{}}); code == http.StatusCreated {
		t.Fatal("leader-local apply failure must surface as a failed HTTP mutation")
	}
	waitReadiness(t, n1, replicated.ReadinessUnhealthy)

	// Durable position did not advance for the failed operation.
	if applied, _ := n1.repl.FSM.AppliedIndex(); applied != 0 {
		t.Fatalf("failed apply advanced the durable position: %d", applied)
	}
	if countPosts(t, n1, "bad") != 0 {
		t.Fatal("failed operation must not be materialized locally")
	}

	// Authoritative mutations rejected while unhealthy; no local fallback.
	if code, _ := httpPost(t, n1.http.Client(), n1.http.URL, map[string]any{"id": "after", "name": "After", "kind": "host", "labels": map[string]string{}}); code == http.StatusCreated {
		t.Fatal("unhealthy node must reject authoritative HTTP mutations")
	}
	if countPosts(t, n1, "after") != 0 {
		t.Fatal("unhealthy node wrote locally (fail-open)")
	}
	n1.close()

	// Run 2: reconstruct over the SAME data directory with the failure removed
	// (a deliberate rebuild/repair). The committed operation re-applies and the
	// node returns to ready reconciled.
	n2 := newNode(t, ca, dataDir, "A", nil, false, 0, false, addr)
	waitReadiness(t, n2, replicated.ReadinessReadyLeader)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && countPosts(t, n2, "bad") != 1 {
		time.Sleep(20 * time.Millisecond)
	}
	if countPosts(t, n2, "bad") != 1 {
		t.Fatal("recovered replica did not re-apply the previously-failed committed operation")
	}
	if code, _ := httpPost(t, n2.http.Client(), n2.http.URL, map[string]any{"id": "good", "name": "Good", "kind": "host", "labels": map[string]string{}}); code != http.StatusCreated {
		t.Fatalf("post-recovery mutation: %d", code)
	}
	if countPosts(t, n2, "good") != 1 {
		t.Fatal("post-recovery mutation not committed")
	}
}
