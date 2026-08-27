package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/watchpost-ops/watchpost/internal/config"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	database, err := store.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return New(config.Config{Listen: "127.0.0.1:0", DataDir: t.TempDir()}, "test-version", slog.New(slog.NewTextHandler(io.Discard, nil)), database)
}

func TestOperationalEndpoints(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/version", "/api/v1/diagnostics"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		testServer(t).Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: missing security headers", path)
		}
	}
}

func TestEmbeddedDashboard(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	testServer(t).Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !contains(w.Body.String(), "deterministic alerts") {
		t.Fatalf("unexpected dashboard: status=%d body=%q", w.Code, w.Body.String())
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
