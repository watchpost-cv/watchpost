package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/checks"
	"github.com/watchpost-ops/watchpost/internal/config"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/rules"
	"github.com/watchpost-ops/watchpost/internal/store"
)

func apiRequest(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-Watchpost-CSRF", csrf)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}
func TestSetupLoginCSRFAndPostAPI(t *testing.T) {
	handler := testServer(t).Handler()
	setup := apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	if setup.Code != 201 {
		t.Fatalf("setup: %d %s", setup.Code, setup.Body.String())
	}
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	if login.Code != 200 {
		t.Fatalf("login: %d", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(login.Body.Bytes(), &session)
	post := map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}
	denied := apiRequest(t, handler, "POST", "/api/v1/posts", post, cookie, "")
	if denied.Code != 403 {
		t.Fatalf("missing csrf: %d", denied.Code)
	}
	created := apiRequest(t, handler, "POST", "/api/v1/posts", post, cookie, session.CSRF)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	listed := apiRequest(t, handler, "GET", "/api/v1/posts", nil, cookie, "")
	if listed.Code != 200 || !bytes.Contains(listed.Body.Bytes(), []byte("host-a")) {
		t.Fatalf("list: %d %s", listed.Code, listed.Body.String())
	}
}

func TestPostEditAndConfirmedDeleteAPI(t *testing.T) {
	handler := testServer(t).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	created := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "this-machine", "name": "This machine", "kind": "host", "address": "127.0.0.1", "labels": map[string]string{}}, cookie, session.CSRF)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var post posts.Post
	_ = json.Unmarshal(created.Body.Bytes(), &post)
	post.Name = "Local machine"
	data, _ := json.Marshal(post)
	request := httptest.NewRequest("PUT", "/api/v1/posts/this-machine", bytes.NewReader(data))
	request.AddCookie(cookie)
	request.Header.Set("X-Watchpost-CSRF", session.CSRF)
	request.Header.Set("If-Match", "1")
	updated := httptest.NewRecorder()
	handler.ServeHTTP(updated, request)
	if updated.Code != 200 || !bytes.Contains(updated.Body.Bytes(), []byte("Local machine")) {
		t.Fatalf("update: %d %s", updated.Code, updated.Body.String())
	}
	wrong := apiRequest(t, handler, "DELETE", "/api/v1/posts/this-machine", map[string]string{"confirm_id": "wrong"}, cookie, session.CSRF)
	if wrong.Code != 400 {
		t.Fatalf("wrong confirmation: %d", wrong.Code)
	}
	deleted := apiRequest(t, handler, "DELETE", "/api/v1/posts/this-machine", map[string]string{"confirm_id": "this-machine"}, cookie, session.CSRF)
	if deleted.Code != 204 {
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body.String())
	}
}

func TestStorageFullRejectsIngestion(t *testing.T) {
	dataDir := t.TempDir()
	database, err := store.Open(t.Context(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cfg := config.Config{Listen: "127.0.0.1:0", DataDir: dataDir, Retention: config.DefaultRetention(), Storage: config.Storage{MaxDBBytes: 1, MinFreeBytes: 0, MinFreePercent: 0}}
	handler := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), database).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}, cookie, session.CSRF); got.Code != 201 {
		t.Fatalf("post: %d", got.Code)
	}
	enrolled := apiRequest(t, handler, "POST", "/api/v1/posts/host-a/collectors", map[string]string{"id": "agent-a"}, cookie, session.CSRF)
	var result map[string]string
	_ = json.Unmarshal(enrolled.Body.Bytes(), &result)
	value := 50.0
	batch := map[string]any{"version": 1, "post_id": "host-a", "collector_id": "agent-a", "batch_id": "b-1", "sent_at": time.Now().UTC(), "samples": []map[string]any{{"sequence": 1, "observed_at": time.Now().UTC(), "signal": "cpu.percent", "value": value, "unit": "percent", "quality": "good", "labels": map[string]string{}}}}
	data, _ := json.Marshal(batch)
	request := httptest.NewRequest("POST", "/api/collector/v1/observations", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+result["secret"])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf("expected 507, got %d: %s", response.Code, response.Body.String())
	}
	var observations int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if observations != 0 {
		t.Fatalf("observations=%d want 0 (rejected by storage guard)", observations)
	}
	// Unauthenticated collectors must not learn storage state.
	unknown := httptest.NewRequest("POST", "/api/collector/v1/observations", bytes.NewReader(data))
	unknown.Header.Set("Content-Type", "application/json")
	unknown.Header.Set("Authorization", "Bearer wrong-secret")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown collector, got %d", unknownResponse.Code)
	}
}

func TestStorageEndpointReportsFootprint(t *testing.T) {
	handler := testServer(t).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	storage := apiRequest(t, handler, "GET", "/api/v1/storage", nil, cookie, "")
	if storage.Code != 200 || !bytes.Contains(storage.Body.Bytes(), []byte("total_bytes")) {
		t.Fatalf("storage endpoint: %d %s", storage.Code, storage.Body.String())
	}
	unauth := apiRequest(t, handler, "GET", "/api/v1/storage", nil, nil, "")
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("storage endpoint must require auth, got %d", unauth.Code)
	}
}

func TestFailedCentralCheckFiresRuleAlert(t *testing.T) {
	s := testServer(t)
	if _, err := s.posts.Create(t.Context(), posts.Post{ID: "web", Name: "Web", Kind: "http_endpoint", Labels: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if err := s.rules.Create(t.Context(), rules.Rule{ID: "web-http-down", PostID: "web", Signal: "http.ok", Operator: "lt", Threshold: 1, MissingPolicy: "unknown", Severity: "critical", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.checks.Save(t.Context(), checks.Schedule{ID: "web-http", PostID: "web", Kind: "http", Address: "http://127.0.0.1:1", IntervalSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	results, err := s.checks.RunDue(t.Context(), checks.New(time.Second), now)
	if err != nil || len(results) != 1 {
		t.Fatalf("run due: %d %v", len(results), err)
	}
	if err := s.ingestCheckResult(t.Context(), results[0], now); err != nil {
		t.Fatal(err)
	}
	var okValue float64
	if err := s.store.DB.QueryRow(`SELECT value FROM observations WHERE signal='http.ok'`).Scan(&okValue); err != nil {
		t.Fatal(err)
	}
	if okValue != 0 {
		t.Fatalf("http.ok=%f want 0", okValue)
	}
	var state string
	if err := s.store.DB.QueryRow(`SELECT state FROM alerts WHERE rule_id='web-http-down' ORDER BY id DESC LIMIT 1`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "firing" {
		t.Fatalf("alert state=%s want firing", state)
	}
	items, err := s.health.List(t.Context())
	if err != nil || len(items) != 0 {
		t.Fatalf("collector health must not list central-check source: %#v %v", items, err)
	}
}

func TestSecureCookieBehindHTTPSProxy(t *testing.T) {
	s := testServer(t)
	s.cfg.SecureCookies = true
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("cookies=%#v", cookies)
	}
}

func TestDensePostInventory(t *testing.T) {
	s := testServer(t)
	for i := 0; i < 125; i++ {
		id := fmt.Sprintf("dogfood-%03d", i)
		if _, err := s.posts.Create(t.Context(), posts.Post{ID: id, Name: "Dogfood " + id, Kind: "host", Labels: map[string]string{}}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.posts.List(t.Context())
	if err != nil || len(items) != 125 {
		t.Fatalf("dense inventory len=%d err=%v", len(items), err)
	}
}

func TestObservationDrivesRuleAndAlertAPI(t *testing.T) {
	handler := testServer(t).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	headers := session.CSRF
	post := map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", post, cookie, headers); got.Code != 201 {
		t.Fatalf("post: %d %s", got.Code, got.Body.String())
	}
	collector := apiRequest(t, handler, "POST", "/api/v1/posts/host-a/collectors", map[string]string{"id": "agent-a"}, cookie, headers)
	var enrolled map[string]string
	_ = json.Unmarshal(collector.Body.Bytes(), &enrolled)
	rule := map[string]any{"ID": "cpu-high", "PostID": "host-a", "Signal": "cpu", "Operator": "gt", "MissingPolicy": "unknown", "Severity": "warning", "Threshold": 80, "DurationSeconds": 0}
	if got := apiRequest(t, handler, "POST", "/api/v1/rules", rule, cookie, headers); got.Code != 201 {
		t.Fatalf("rule: %d %s", got.Code, got.Body.String())
	}
	value := 90.0
	observation := map[string]any{"version": 1, "post_id": "host-a", "collector_id": "agent-a", "observed_at": time.Now().UTC(), "sequence": 1, "signal": "cpu", "value": value, "unit": "percent", "quality": "good", "labels": map[string]string{}}
	data, _ := json.Marshal(observation)
	request := httptest.NewRequest("POST", "/api/v1/observations", bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+enrolled["secret"])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 202 {
		t.Fatalf("observation: %d %s", response.Code, response.Body.String())
	}
	alerts := apiRequest(t, handler, "GET", "/api/v1/alerts", nil, cookie, "")
	if alerts.Code != 200 || !bytes.Contains(alerts.Body.Bytes(), []byte(`"state":"firing"`)) {
		t.Fatalf("alerts: %d %s", alerts.Code, alerts.Body.String())
	}
}
