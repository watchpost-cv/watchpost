package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/store"
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
	if w.Code != http.StatusOK || !contains(w.Body.String(), "Add a post") {
		t.Fatalf("unexpected dashboard: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestDashboardUXContracts(t *testing.T) {
	handler := testServer(t).Handler()
	read := func(path string) string {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Body.String()
	}
	html := read("/")
	for _, required := range []string{"id=\"logout\"", "minlength=\"7\"", "data-view=\"enroll\"", "data-view=\"checks\"", "starter_rules", "data-view=\"devices\"", "data-view=\"fleet\"", "class=\"resize-handle\""} {
		if !strings.Contains(html, required) {
			t.Errorf("dashboard missing %s", required)
		}
	}
	if strings.Contains(html, "WP00–WP18 development candidate") {
		t.Error("development checkpoint label leaked into product chrome")
	}
	css := read("/app.css")
	for _, required := range []string{"--bg:#111312", "--accent:#9fcb78", "padding-right:40px", "background-position:right 14px center", "cursor:ns-resize"} {
		if !strings.Contains(css, required) {
			t.Errorf("stylesheet missing %s", required)
		}
	}
	extra := read("/app-extra.css")
	for _, required := range []string{"health-meter.safe", "health-meter.warning", "health-meter.critical", "policy-reason", "rule-inventory", "focus-visible", "prefers-reduced-motion", "forced-colors", "grid-template-columns: repeat(2"} {
		if !strings.Contains(extra, required) {
			t.Errorf("dense survey stylesheet missing %s", required)
		}
	}
	js := read("/script.js")
	for _, required := range []string{"policyHealth", "No policy configured", "/api/v1/rules", "data-rule-toggle"} {
		if !strings.Contains(js, required) {
			t.Errorf("policy-aware survey missing %s", required)
		}
	}
}

func TestBootstrapShowsOnlyRequiredAuthState(t *testing.T) {
	s := testServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"setup_required":true`) {
		t.Fatalf("initial bootstrap: %d %s", w.Code, w.Body.String())
	}
	if _, err := s.auth.Setup(t.Context(), "admin@example.com", "1234567", ""); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"setup_required":false`) {
		t.Fatalf("completed bootstrap: %d %s", w.Code, w.Body.String())
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
