package auth

import (
	"context"
	"sync"
	"testing"

	"github.com/watchpost-ops/watchpost/internal/audit"
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
			_, err := m.Setup(context.Background(), e, "correct-horse-battery", "")
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
	if _, err = m.Setup(context.Background(), "admin@example.com", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login(context.Background(), "admin@example.com", "correct-horse-battery", audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Authenticate(context.Background(), session.Token)
	if err != nil || got.User.Role != "admin" || got.CSRF == "" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestMinimumPasswordLengthIsSeven(t *testing.T) {
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	m := New(s)
	if _, err = m.Setup(context.Background(), "admin@example.com", "123456", ""); err == nil {
		t.Fatal("six-character password accepted")
	}
	if required, err := m.SetupRequired(context.Background()); err != nil || !required {
		t.Fatalf("setup required=%v err=%v", required, err)
	}
	if _, err = m.Setup(context.Background(), "admin@example.com", "1234567", ""); err != nil {
		t.Fatalf("seven-character password rejected: %v", err)
	}
	if required, err := m.SetupRequired(context.Background()); err != nil || required {
		t.Fatalf("setup required=%v err=%v", required, err)
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	ctx := context.Background()
	m := New(testDB(t))
	if _, err := m.Setup(ctx, "admin@example.com", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session1, err := m.Login(ctx, "admin@example.com", "correct-horse-battery", audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	session2, err := m.Login(ctx, "admin@example.com", "correct-horse-battery", audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ChangePassword(ctx, session1.User.ID, "correct-horse-battery", "new-password-1", session1.Token, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, session2.Token); err == nil {
		t.Fatal("session2 survived password change")
	}
	if _, err := m.Authenticate(ctx, session1.Token); err != nil {
		t.Fatal("current session revoked")
	}
	if _, err := m.Login(ctx, "admin@example.com", "correct-horse-battery", audit.Entry{Action: "test"}); err == nil {
		t.Fatal("old password accepted")
	}
	if _, err := m.Login(ctx, "admin@example.com", "new-password-1", audit.Entry{Action: "test"}); err != nil {
		t.Fatal("new password rejected")
	}
}

func TestUserManagementValidation(t *testing.T) {
	ctx := context.Background()
	m := New(testDB(t))
	if _, err := m.CreateUser(ctx, "op@example.com", "1234567", "operator", audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateUser(ctx, "bad", "1234567", "operator", audit.Entry{Action: "test"}); err == nil {
		t.Fatal("invalid email accepted")
	}
	if _, err := m.CreateUser(ctx, "v@example.com", "123", "viewer", audit.Entry{Action: "test"}); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := m.CreateUser(ctx, "x@example.com", "1234567", "superuser", audit.Entry{Action: "test"}); err == nil {
		t.Fatal("invalid role accepted")
	}
	items, err := m.ListUsers(ctx)
	if err != nil || len(items) != 1 {
		t.Fatalf("users=%d err=%v", len(items), err)
	}
}
