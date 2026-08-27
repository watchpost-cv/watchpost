package incidents

import (
	"context"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
	"time"
)

func TestIncidentTimelineAndResolution(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := New(db)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	incident, e := s.Create(ctx, "API unavailable", "critical", "alice", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AddNote(ctx, incident.ID, "alice", "Investigating upstream network"); e != nil {
		t.Fatal(e)
	}
	now = now.Add(time.Minute)
	incident, e = s.Transition(ctx, incident.ID, "resolved", "alice", "Network restored")
	if e != nil || incident.ResolvedAt == nil {
		t.Fatalf("%#v %v", incident, e)
	}
	entries, e := s.Timeline(ctx, incident.ID, 10)
	if e != nil || len(entries) != 3 {
		t.Fatalf("%#v %v", entries, e)
	}
}
