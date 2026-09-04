package evidence

import (
	"context"
	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/posts"
	"github.com/watchpost-cv/watchpost/internal/store"
	"strings"
	"testing"
	"time"
)

func TestLogBoundsRedactionSearchAndChange(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "p", Name: "P", Kind: "host"}, audit.Entry{Action: "test"})
	s := New(db)
	now := time.Now().UTC()
	l, e := s.IngestLog(ctx, Log{PostID: "p", Source: "app", ObservedAt: now, Severity: "error", Message: "failure token=secret " + strings.Repeat("x", 9000), Fields: map[string]string{}})
	if e != nil {
		t.Fatal(e)
	}
	if !l.Truncated || strings.Contains(l.Message, "secret") {
		t.Fatalf("%#v", l)
	}
	found, e := s.SearchLogs(ctx, "p", "failure", now.Add(-time.Minute), now.Add(time.Minute), 10)
	if e != nil || len(found) != 1 {
		t.Fatalf("%#v %v", found, e)
	}
	if _, e = s.RecordChange(ctx, Change{PostID: "p", Kind: "deploy", Actor: "ci", Summary: "version 2"}); e != nil {
		t.Fatal(e)
	}
}
