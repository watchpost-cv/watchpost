package notify

import (
	"context"
	"errors"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
	"time"
)

type fakeSender struct {
	fail  bool
	calls int
}

func (f *fakeSender) Send(context.Context, Route, Message) error {
	f.calls++
	if f.fail {
		return errors.New("offline")
	}
	return nil
}
func TestDeduplicateDeliverAndRetry(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	_, _ = posts.New(db).Create(ctx, posts.Post{ID: "p", Name: "P", Kind: "host"}, audit.Entry{Action: "test"})
	_, _ = db.DB.Exec(`INSERT INTO rules(id,post_id,signal,operator,threshold,severity) VALUES('r','p','x','gt',1,'warning')`)
	result, _ := db.DB.Exec(`INSERT INTO alerts(rule_id,post_id,state,severity,opened_at,updated_at) VALUES('r','p','firing','warning','now','now')`)
	alert, _ := result.LastInsertId()
	sender := &fakeSender{}
	s := New(db, sender)
	now := time.Now()
	s.now = func() time.Time { return now }
	if e = s.CreateRoute(ctx, Route{ID: "web", Kind: "webhook", Destination: "https://example.invalid", Enabled: true}, audit.Entry{Action: "test"}); e != nil {
		t.Fatal(e)
	}
	_ = s.Queue(ctx, alert)
	_ = s.Queue(ctx, alert)
	if e = s.DeliverDue(ctx, 10); e != nil || sender.calls != 1 {
		t.Fatalf("calls=%d err=%v", sender.calls, e)
	}
	var count int
	_ = db.DB.QueryRow(`SELECT COUNT(*) FROM notification_deliveries`).Scan(&count)
	if count != 1 {
		t.Fatalf("count=%d", count)
	}
	sender.fail = true
	result, _ = db.DB.Exec(`INSERT INTO alerts(rule_id,post_id,state,severity,opened_at,updated_at) VALUES('r','p','firing','warning','later','later')`)
	second, _ := result.LastInsertId()
	_ = s.Queue(ctx, second)
	_ = s.DeliverDue(ctx, 10)
	var state string
	_ = db.DB.QueryRow(`SELECT state FROM notification_deliveries WHERE alert_id=?`, second).Scan(&state)
	if state != "retry" {
		t.Fatalf("state=%s", state)
	}
}
