package posts

import (
	"context"
	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
	"testing"
)

func TestCRUDConcurrencyAndCycles(t *testing.T) {
	s, e := store.Open(context.Background(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p := New(s)
	a, e := p.Create(context.Background(), Post{ID: "host-a", Name: "A", Kind: "host", Address: "192.0.2.10", Labels: map[string]string{"env": "test"}}, audit.Entry{Action: "test"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Create(context.Background(), Post{ID: "host-b", Name: "B", Kind: "host"}, audit.Entry{Action: "test"})
	if e != nil {
		t.Fatal(e)
	}
	a.Name = "A2"
	a.Address = "host-a.example"
	a, e = p.Update(context.Background(), a, a.Version, audit.Entry{Action: "test"})
	if e != nil || a.Version != 2 || a.Address != "host-a.example" {
		t.Fatalf("%#v %v", a, e)
	}
	if _, e = p.Update(context.Background(), a, 1, audit.Entry{Action: "test"}); e == nil {
		t.Fatal("stale update accepted")
	}
	if e = p.AddDependency(context.Background(), "host-a", "host-b", audit.Entry{Action: "test"}); e != nil {
		t.Fatal(e)
	}
	if e = p.AddDependency(context.Background(), "host-b", "host-a", audit.Entry{Action: "test"}); e == nil {
		t.Fatal("cycle accepted")
	}
	if e = p.Delete(context.Background(), "host-a", audit.Entry{Action: "test"}); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Get(context.Background(), "host-a"); e == nil {
		t.Fatal("deleted post still exists")
	}
}
