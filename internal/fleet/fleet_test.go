package fleet

import (
	"context"
	"encoding/json"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
	"time"
)

func TestSignedDeduplicatedRevocableDelivery(t *testing.T) {
	ctx := context.Background()
	db, e := store.Open(ctx, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := New(db)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	secret, e := s.Enroll(ctx, "node-b")
	if e != nil {
		t.Fatal(e)
	}
	envelope := Sign(secret, Envelope{EventID: "event-1", Kind: "incident", CreatedAt: now, Payload: json.RawMessage(`{"id":1}`)})
	if e = s.Receive(ctx, "node-b", secret, envelope); e != nil {
		t.Fatal(e)
	}
	if e = s.Receive(ctx, "node-b", secret, envelope); e == nil {
		t.Fatal("duplicate accepted")
	}
	if e = s.Revoke(ctx, "node-b"); e != nil {
		t.Fatal(e)
	}
	envelope.EventID = "event-2"
	envelope = Sign(secret, envelope)
	if e = s.Receive(ctx, "node-b", secret, envelope); e == nil {
		t.Fatal("revoked peer accepted")
	}
}
