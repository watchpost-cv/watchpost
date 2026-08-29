package checks

import (
	"context"
	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func TestScheduledHTTPCheckPersistsResult(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	_, err = db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES('web','Web','http_endpoint',?,?)`, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	s := NewScheduleStore(db)
	if err = s.Save(ctx, Schedule{ID: "web-http", PostID: "web", Kind: "http", Address: "http://127.0.0.1:1", IntervalSeconds: 60}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if results, err := s.RunDue(ctx, New(time.Second), now.Add(time.Second), 4); err != nil || len(results) != 1 {
		t.Fatalf("run due: %d %v", len(results), err)
	}
	items, err := s.List(ctx)
	if err != nil || len(items) != 1 || items[0].Last == nil || items[0].Last.OK {
		t.Fatalf("stored result: %#v %v", items, err)
	}
}
