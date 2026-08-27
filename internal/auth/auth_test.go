package auth

import (
	"context"
	"sync"
	"testing"

	"github.com/watchpost-ops/watchpost/internal/store"
)

func TestConcurrentSetupCreatesOneAdministrator(t *testing.T) {
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s)
	var wg sync.WaitGroup
	successes := make(chan bool, 2)
	for _, email := range []string{"one@example.com", "two@example.com"} {
		wg.Add(1)
		go func(e string) {
			defer wg.Done()
			_, err := m.Setup(context.Background(), e, "correct-horse-battery")
			successes <- err == nil
		}(email)
	}
	wg.Wait()
	close(successes)
	n := 0
	for ok := range successes {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("successes=%d", n)
	}
}

func TestLoginAndAuthenticate(t *testing.T) {
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s)
	if _, err = m.Setup(context.Background(), "admin@example.com", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login(context.Background(), "admin@example.com", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Authenticate(context.Background(), session.Token)
	if err != nil || got.User.Role != "admin" || got.CSRF == "" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}
