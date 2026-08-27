package posts

import (
	"context"
	"github.com/watchpost-ops/watchpost/internal/store"
	"testing"
)

func TestCRUDConcurrencyAndCycles(t *testing.T) {
	s, e := store.Open(context.Background(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p := New(s)
	a, e := p.Create(context.Background(), Post{ID: "host-a", Name: "A", Kind: "host", Labels: map[string]string{"env": "test"}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Create(context.Background(), Post{ID: "host-b", Name: "B", Kind: "host"})
	if e != nil {
		t.Fatal(e)
	}
	a.Name = "A2"
	a, e = p.Update(context.Background(), a, a.Version)
	if e != nil || a.Version != 2 {
		t.Fatalf("%#v %v", a, e)
	}
	if _, e = p.Update(context.Background(), a, 1); e == nil {
		t.Fatal("stale update accepted")
	}
	if e = p.AddDependency(context.Background(), "host-a", "host-b"); e != nil {
		t.Fatal(e)
	}
	if e = p.AddDependency(context.Background(), "host-b", "host-a"); e == nil {
		t.Fatal("cycle accepted")
	}
}
