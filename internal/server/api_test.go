package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/backup"
	"github.com/watchpost-cv/watchpost/internal/checks"
	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/devices"
	"github.com/watchpost-cv/watchpost/internal/posts"
	"github.com/watchpost-cv/watchpost/internal/rules"
	"github.com/watchpost-cv/watchpost/internal/store"
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
	if len(setup.Result().Cookies()) != 1 || !bytes.Contains(setup.Body.Bytes(), []byte(`"csrf_token"`)) || !bytes.Contains(setup.Body.Bytes(), []byte(`"user"`)) {
		t.Fatalf("setup did not establish an authenticated session: cookies=%d body=%s", len(setup.Result().Cookies()), setup.Body.String())
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
	if _, err := s.posts.Create(t.Context(), posts.Post{ID: "web", Name: "Web", Kind: "http_endpoint", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.rules.Create(t.Context(), rules.Rule{ID: "web-http-down", PostID: "web", Signal: "http.ok", Operator: "lt", Threshold: 1, MissingPolicy: "unknown", Severity: "critical", Enabled: true}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.checks.Save(t.Context(), checks.Schedule{ID: "web-http", PostID: "web", Kind: "http", Address: "http://127.0.0.1:1", IntervalSeconds: 60}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	results, err := s.checks.RunDue(t.Context(), checks.New(time.Second), now, 4)
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

func TestAuditRecordsStateChanges(t *testing.T) {
	handler := testServer(t).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}, cookie, session.CSRF); got.Code != 201 {
		t.Fatalf("post: %d", got.Code)
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/rules", map[string]any{"ID": "cpu-high", "PostID": "host-a", "Signal": "cpu.percent", "Operator": "gt", "MissingPolicy": "unknown", "Severity": "warning", "Threshold": 90, "DurationSeconds": 0}, cookie, session.CSRF); got.Code != 201 {
		t.Fatalf("rule: %d", got.Code)
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/incidents", map[string]any{"title": "Incident one", "severity": "warning", "alert_ids": []int64{}}, cookie, session.CSRF); got.Code != 201 {
		t.Fatalf("incident: %d", got.Code)
	}
	audit := apiRequest(t, handler, "GET", "/api/v1/audit", nil, cookie, "")
	if audit.Code != 200 {
		t.Fatalf("audit: %d", audit.Code)
	}
	for _, action := range []string{"login", "post_create", "rule_create", "incident_create"} {
		if !bytes.Contains(audit.Body.Bytes(), []byte(action)) {
			t.Errorf("audit log missing %s: %s", action, audit.Body.String())
		}
	}
	if got := apiRequest(t, handler, "GET", "/api/v1/audit", nil, nil, ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("audit endpoint must require auth, got %d", got.Code)
	}
}

func TestExternalSetupRequiresBootstrapToken(t *testing.T) {
	dataDir := t.TempDir()
	database, err := store.Open(t.Context(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cfg := config.Config{Listen: "0.0.0.0:0", DataDir: dataDir, Retention: config.DefaultRetention(), Storage: config.DefaultStorage(), SetupTokenTTL: time.Hour}
	s := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), database)
	handler := s.Handler()
	bootstrap := apiRequest(t, handler, "GET", "/api/v1/bootstrap", nil, nil, "")
	if !bytes.Contains(bootstrap.Body.Bytes(), []byte(`"setup_token_required":true`)) {
		t.Fatalf("bootstrap must report token required: %s", bootstrap.Body.String())
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, ""); got.Code != 409 {
		t.Fatalf("setup without token: %d", got.Code)
	}
	token, err := s.auth.GenerateBootstrapToken(t.Context(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567", "token": token}, nil, ""); got.Code != 201 {
		t.Fatalf("setup with token: %d %s", got.Code, got.Body.String())
	}
	// The token is never disclosed through bootstrap or diagnostics.
	if bytes.Contains(bootstrap.Body.Bytes(), []byte(token)) {
		t.Fatal("bootstrap disclosed the setup token")
	}
	diag := apiRequest(t, handler, "GET", "/api/v1/diagnostics", nil, nil, "")
	if bytes.Contains(diag.Body.Bytes(), []byte(token)) {
		t.Fatal("diagnostics disclosed the setup token")
	}
}

func TestRBACRoleEnforcement(t *testing.T) {
	handler := testServer(t).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminCookie := adminLogin.Result().Cookies()[0]
	var adminSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(adminLogin.Body.Bytes(), &adminSession)
	if got := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "op@example.com", "password": "1234567", "role": "operator"}, adminCookie, adminSession.CSRF); got.Code != 201 {
		t.Fatalf("create operator: %d", got.Code)
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "view@example.com", "password": "1234567", "role": "viewer"}, adminCookie, adminSession.CSRF); got.Code != 201 {
		t.Fatalf("create viewer: %d", got.Code)
	}
	viewerLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "view@example.com", "password": "1234567"}, nil, "")
	viewerCookie := viewerLogin.Result().Cookies()[0]
	var viewerSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(viewerLogin.Body.Bytes(), &viewerSession)
	if got := apiRequest(t, handler, "GET", "/api/v1/posts", nil, viewerCookie, ""); got.Code != 200 {
		t.Fatalf("viewer list posts: %d", got.Code)
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "host-a", "name": "A", "kind": "host"}, viewerCookie, viewerSession.CSRF); got.Code != 403 {
		t.Fatalf("viewer create post: %d", got.Code)
	}
	if got := apiRequest(t, handler, "GET", "/api/v1/users", nil, viewerCookie, ""); got.Code != 403 {
		t.Fatalf("viewer list users: %d", got.Code)
	}
	if got := apiRequest(t, handler, "GET", "/api/v1/audit", nil, viewerCookie, ""); got.Code != 403 {
		t.Fatalf("viewer audit: %d", got.Code)
	}
	operatorLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "op@example.com", "password": "1234567"}, nil, "")
	operatorCookie := operatorLogin.Result().Cookies()[0]
	var operatorSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(operatorLogin.Body.Bytes(), &operatorSession)
	if got := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "x@example.com", "password": "1234567", "role": "viewer"}, operatorCookie, operatorSession.CSRF); got.Code != 403 {
		t.Fatalf("operator create user: %d", got.Code)
	}
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "host-b", "name": "B", "kind": "host"}, operatorCookie, operatorSession.CSRF); got.Code != 403 {
		t.Fatalf("operator create post: %d", got.Code)
	}
}

func TestCheckPolicyDeniesScheduledAndOnDemandTargets(t *testing.T) {
	dataDir := t.TempDir()
	database, err := store.Open(t.Context(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cfg := config.Config{Listen: "127.0.0.1:0", DataDir: dataDir, Retention: config.DefaultRetention(), Storage: config.DefaultStorage(), CheckPolicy: config.CheckPolicy{DenyCIDRs: []string{"127.0.0.0/8"}}}
	handler := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), database).Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "web", "name": "Web", "kind": "http_endpoint"}, cookie, session.CSRF); got.Code != 201 {
		t.Fatalf("post: %d", got.Code)
	}
	// On-demand check against a denied target is refused.
	denied := apiRequest(t, handler, "POST", "/api/v1/checks", map[string]string{"kind": "http", "address": "http://127.0.0.1:1"}, cookie, session.CSRF)
	if denied.Code != 400 || !bytes.Contains(denied.Body.Bytes(), []byte("denied by check policy")) {
		t.Fatalf("on-demand denied target: %d %s", denied.Code, denied.Body.String())
	}
	// A durable schedule against a denied target is refused.
	schedule := apiRequest(t, handler, "POST", "/api/v1/check-schedules", map[string]any{"ID": "web-http", "PostID": "web", "Kind": "http", "Address": "http://127.0.0.1:1", "IntervalSeconds": 60}, cookie, session.CSRF)
	if schedule.Code != 400 || !bytes.Contains(schedule.Body.Bytes(), []byte("denied by check policy")) {
		t.Fatalf("scheduled denied target: %d %s", schedule.Code, schedule.Body.String())
	}
	// An allowed public target passes policy.
	allowed := apiRequest(t, handler, "POST", "/api/v1/checks", map[string]string{"kind": "dns", "address": "example.com"}, cookie, session.CSRF)
	if allowed.Code == 400 && bytes.Contains(allowed.Body.Bytes(), []byte("denied by check policy")) {
		t.Fatalf("allowed target refused by policy: %s", allowed.Body.String())
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
		if _, err := s.posts.Create(t.Context(), posts.Post{ID: id, Name: "Dogfood " + id, Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.posts.List(t.Context(), 500, 0)
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

func TestRerunCheckActionExecutesRealCheck(t *testing.T) {
	s := testServer(t)
	if _, err := s.posts.Create(t.Context(), posts.Post{ID: "web", Name: "Web", Kind: "http_endpoint", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.checks.Save(t.Context(), checks.Schedule{ID: "web-http", PostID: "web", Kind: "http", Address: "http://127.0.0.1:1", IntervalSeconds: 60}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.rules.Create(t.Context(), rules.Rule{ID: "web-down", PostID: "web", Signal: "http.ok", Operator: "lt", Threshold: 1, MissingPolicy: "unknown", Severity: "critical", Enabled: true}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"check": "web-http"}
	user, _ := s.auth.Setup(t.Context(), "admin@example.com", "1234567", "")
	id, err := s.actions.Request(t.Context(), "rerun_check", "web", params, user.ID, "idem-1", audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.actions.Execute(t.Context(), id, audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := result["ok"].(bool); ok {
		t.Fatalf("rerun of a down target reported ok: %#v", result)
	}
	var okValue float64
	if err := s.store.DB.QueryRow(`SELECT value FROM observations WHERE signal='http.ok'`).Scan(&okValue); err != nil {
		t.Fatal(err)
	}
	if okValue != 0 {
		t.Fatalf("http.ok=%f want 0", okValue)
	}
	var state string
	if err := s.store.DB.QueryRow(`SELECT state FROM alerts WHERE rule_id='web-down' ORDER BY id DESC LIMIT 1`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "firing" {
		t.Fatalf("alert state=%s want firing", state)
	}
}

func TestRerunCheckActionRefusesForeignPost(t *testing.T) {
	s := testServer(t)
	if _, err := s.posts.Create(t.Context(), posts.Post{ID: "web", Name: "Web", Kind: "http_endpoint", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.posts.Create(t.Context(), posts.Post{ID: "other", Name: "Other", Kind: "http_endpoint", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.checks.Save(t.Context(), checks.Schedule{ID: "web-http", PostID: "web", Kind: "http", Address: "http://127.0.0.1:1", IntervalSeconds: 60}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	user, _ := s.auth.Setup(t.Context(), "admin@example.com", "1234567", "")
	id, err := s.actions.Request(t.Context(), "rerun_check", "other", map[string]any{"check": "web-http"}, user.ID, "idem-2", audit.Entry{Action: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.actions.Execute(t.Context(), id, audit.Entry{Action: "test"}); err == nil {
		t.Fatal("rerun_check executed a schedule belonging to another post")
	}
}

func TestScheduledBackupWritesAndPrunes(t *testing.T) {
	backupDir := t.TempDir()
	dataDir := t.TempDir()
	database, err := store.Open(t.Context(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cfg := config.Config{Listen: "127.0.0.1:0", DataDir: dataDir, Retention: config.DefaultRetention(), Storage: config.DefaultStorage(), Backup: config.Backup{Dir: backupDir, Schedule: time.Hour, Retain: 2}}
	s := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), database)
	for i := 0; i < 3; i++ {
		if err := backup.Create(t.Context(), database, filepath.Join(backupDir, fmt.Sprintf("watchpost-%d.wpbk", i)), ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.pruneBackups(time.Now()); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(backupDir)
	if len(entries) != 2 {
		t.Fatalf("pruned backups=%d want 2", len(entries))
	}
	s.runScheduledBackup(t.Context())
	entries, _ = os.ReadDir(backupDir)
	if len(entries) != 2 {
		t.Fatalf("post-schedule backups=%d want 2", len(entries))
	}
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	status := apiRequest(t, handler, "GET", "/api/v1/backup-status", nil, cookie, "")
	if status.Code != 200 || !bytes.Contains(status.Body.Bytes(), []byte(`"last_backup_at"`)) {
		t.Fatalf("backup status: %d %s", status.Code, status.Body.String())
	}
}

func TestPostsPaginationBoundsManyPostLoad(t *testing.T) {
	s := testServer(t)
	for i := 0; i < 520; i++ {
		id := fmt.Sprintf("post-%03d", i)
		if _, err := s.posts.Create(t.Context(), posts.Post{ID: id, Name: "Post " + id, Kind: "host", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "")
	cookie := login.Result().Cookies()[0]
	page := apiRequest(t, handler, "GET", "/api/v1/posts?limit=100", nil, cookie, "")
	var first struct {
		Posts []map[string]any `json:"posts"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(page.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Posts) != 100 || first.Total != 520 {
		t.Fatalf("page1 posts=%d total=%d", len(first.Posts), first.Total)
	}
	last := apiRequest(t, handler, "GET", "/api/v1/posts?limit=100&offset=500", nil, cookie, "")
	var tail struct {
		Posts []map[string]any `json:"posts"`
	}
	if err := json.Unmarshal(last.Body.Bytes(), &tail); err != nil {
		t.Fatal(err)
	}
	if len(tail.Posts) != 20 {
		t.Fatalf("tail posts=%d want 20", len(tail.Posts))
	}
	// The survey stays bounded at 500 posts with 20k observations (server-side).
}

func TestScheduledSNMPEmitsObservationsAndAlert(t *testing.T) {
	s := testServer(t)
	if _, err := s.posts.Create(t.Context(), posts.Post{ID: "ups-1", Name: "UPS", Kind: "ups", Labels: map[string]string{}}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.rules.Create(t.Context(), rules.Rule{ID: "ups-down", PostID: "ups-1", Signal: "snmp.poll_ok", Operator: "lt", Threshold: 1, MissingPolicy: "unknown", Severity: "critical", Enabled: true}, audit.Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	marker := sha256.Sum256([]byte("device-snmp:ups-poll"))
	if _, err := s.store.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash,kind) VALUES('ups-poll','ups-1',?,'device_snmp')`, marker[:]); err != nil {
		t.Fatal(err)
	}
	profile := devices.SavedProfile{ID: "ups-poll", PostID: "ups-1", Kind: "ups"}
	now := time.Now().UTC()
	readings := []devices.Reading{{Name: "battery_charge", OID: ".1.3.6.1.2.1.33.1.2.4.0", Unit: "percent", Value: int64(85), Quality: "good", ObservedAt: now, FreshUntil: now.Add(5 * time.Minute)}}
	if err := s.emitDevicePoll(t.Context(), profile, true, readings, now); err != nil {
		t.Fatal(err)
	}
	var okVal, charge float64
	if err := s.store.DB.QueryRow(`SELECT value FROM observations WHERE signal='snmp.poll_ok'`).Scan(&okVal); err != nil {
		t.Fatal(err)
	}
	if err := s.store.DB.QueryRow(`SELECT value FROM observations WHERE signal='battery_charge'`).Scan(&charge); err != nil {
		t.Fatal(err)
	}
	if okVal != 1 || charge != 85 {
		t.Fatalf("ok=%f charge=%f", okVal, charge)
	}
	// A failed poll emits snmp.poll_ok=0, which the rule fires on.
	if err := s.emitDevicePoll(t.Context(), profile, false, nil, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := s.store.DB.QueryRow(`SELECT state FROM alerts WHERE rule_id='ups-down' ORDER BY id DESC LIMIT 1`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "firing" {
		t.Fatalf("alert state=%s want firing", state)
	}
}

func TestAuditFailurePreventsUserCreation(t *testing.T) {
	s := testServer(t)
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	// Install an audit-write failure; any mutation that cannot be audited must
	// not be committed or reported as successful.
	if _, err := s.store.DB.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	created := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "op@example.com", "password": "1234567", "role": "operator"}, cookie, session.CSRF)
	if created.Code == http.StatusCreated {
		t.Fatalf("user creation reported success while audit failed")
	}
	// The mutation must be rolled back: only the administrator exists.
	list := apiRequest(t, handler, "GET", "/api/v1/users", nil, cookie, "")
	if !bytes.Contains(list.Body.Bytes(), []byte(`"email":"admin@example.com"`)) || bytes.Contains(list.Body.Bytes(), []byte(`"email":"op@example.com"`)) {
		t.Fatalf("unaudited user mutation committed: %s", list.Body.String())
	}
}

func TestAdminPasswordResetRevokesSessions(t *testing.T) {
	s := testServer(t)
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminCookie := adminLogin.Result().Cookies()[0]
	var adminSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(adminLogin.Body.Bytes(), &adminSession)
	if got := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "op@example.com", "password": "1234567", "role": "operator"}, adminCookie, adminSession.CSRF); got.Code != 201 {
		t.Fatalf("create operator: %d", got.Code)
	}
	opLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "op@example.com", "password": "1234567"}, nil, "")
	opCookie := opLogin.Result().Cookies()[0]
	var opSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(opLogin.Body.Bytes(), &opSession)
	// The operator's session works before the reset.
	if got := apiRequest(t, handler, "GET", "/api/v1/posts", nil, opCookie, ""); got.Code != 200 {
		t.Fatalf("operator session pre-reset: %d", got.Code)
	}
	// Administrator resets the operator password.
	var opID int64
	if err := s.store.DB.QueryRow(`SELECT id FROM users WHERE email='op@example.com'`).Scan(&opID); err != nil {
		t.Fatal(err)
	}
	if got := apiRequest(t, handler, "POST", fmt.Sprintf("/api/v1/users/%d/reset-password", opID), map[string]string{"password": "new-password-1"}, adminCookie, adminSession.CSRF); got.Code != 204 {
		t.Fatalf("reset password: %d", got.Code)
	}
	// The previously issued session is immediately unauthorized.
	if got := apiRequest(t, handler, "GET", "/api/v1/posts", nil, opCookie, ""); got.Code != http.StatusForbidden && got.Code != http.StatusUnauthorized {
		t.Fatalf("operator session after reset=%d want 401/403", got.Code)
	}
	// The old password no longer works; the new one does.
	if got := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "op@example.com", "password": "1234567"}, nil, ""); got.Code != 401 {
		t.Fatalf("old password after reset: %d", got.Code)
	}
	newLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "op@example.com", "password": "new-password-1"}, nil, "")
	if newLogin.Code != 200 {
		t.Fatalf("new password after reset: %d", newLogin.Code)
	}
}

func TestFinalAdministratorCannotBeDemoted(t *testing.T) {
	s := testServer(t)
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminCookie := adminLogin.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(adminLogin.Body.Bytes(), &session)
	users := apiRequest(t, handler, "GET", "/api/v1/users", nil, adminCookie, "")
	var listing struct {
		Users []struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"users"`
	}
	_ = json.Unmarshal(users.Body.Bytes(), &listing)
	if len(listing.Users) != 1 || listing.Users[0].Role != "admin" {
		t.Fatalf("unexpected users: %s", users.Body.String())
	}
	// The only administrator cannot be demoted.
	denied := apiRequest(t, handler, "PUT", fmt.Sprintf("/api/v1/users/%d/role", listing.Users[0].ID), map[string]string{"role": "viewer"}, adminCookie, session.CSRF)
	if denied.Code != http.StatusConflict {
		t.Fatalf("demote last admin=%d want 409", denied.Code)
	}
	// With a second administrator, one may be demoted.
	if got := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "admin2@example.com", "password": "1234567", "role": "admin"}, adminCookie, session.CSRF); got.Code != 201 {
		t.Fatalf("create second admin: %d", got.Code)
	}
	users = apiRequest(t, handler, "GET", "/api/v1/users", nil, adminCookie, "")
	_ = json.Unmarshal(users.Body.Bytes(), &listing)
	if len(listing.Users) != 2 || listing.Users[0].Role != "admin" || listing.Users[1].Role != "admin" {
		t.Fatalf("second admin set: %s", users.Body.String())
	}
	// With two administrators, the acting admin may demote the other.
	if got := apiRequest(t, handler, "PUT", fmt.Sprintf("/api/v1/users/%d/role", listing.Users[1].ID), map[string]string{"role": "viewer"}, adminCookie, session.CSRF); got.Code != 204 {
		t.Fatalf("demote second admin=%d want 204", got.Code)
	}
}

func TestRoleChangeTakesEffectForExistingSessions(t *testing.T) {
	s := testServer(t)
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	adminCookie := adminLogin.Result().Cookies()[0]
	var adminSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(adminLogin.Body.Bytes(), &adminSession)
	if got := apiRequest(t, handler, "POST", "/api/v1/users", map[string]string{"email": "op@example.com", "password": "1234567", "role": "operator"}, adminCookie, adminSession.CSRF); got.Code != 201 {
		t.Fatalf("create operator: %d", got.Code)
	}
	opLogin := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "op@example.com", "password": "1234567"}, nil, "")
	opCookie := opLogin.Result().Cookies()[0]
	var opSession struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(opLogin.Body.Bytes(), &opSession)
	// Operator can currently update a post (operator role).
	if got := apiRequest(t, handler, "POST", "/api/v1/posts", map[string]any{"id": "host-a", "name": "Host A", "kind": "host"}, adminCookie, adminSession.CSRF); got.Code != 201 {
		t.Fatalf("create post: %d", got.Code)
	}
	var opID int64
	if err := s.store.DB.QueryRow(`SELECT id FROM users WHERE email='op@example.com'`).Scan(&opID); err != nil {
		t.Fatal(err)
	}
	// Demote the operator to viewer; the existing session must reflect it.
	if got := apiRequest(t, handler, "PUT", fmt.Sprintf("/api/v1/users/%d/role", opID), map[string]string{"role": "viewer"}, adminCookie, adminSession.CSRF); got.Code != 204 {
		t.Fatalf("demote operator: %d", got.Code)
	}
	if got := apiRequest(t, handler, "PUT", "/api/v1/posts/host-a", map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "version": 1}, opCookie, opSession.CSRF); got.Code != http.StatusForbidden {
		t.Fatalf("demoted operator updated a post with existing session: %d", got.Code)
	}
}

func TestLogoutNeverClaimsSuccessWhileSessionRemainsActive(t *testing.T) {
	s := testServer(t)
	handler := s.Handler()
	_ = apiRequest(t, handler, "POST", "/api/v1/setup", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	login := apiRequest(t, handler, "POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "correct-horse-battery"}, nil, "")
	cookie := login.Result().Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	// The session authenticates before logout.
	if got := apiRequest(t, handler, "GET", "/api/v1/posts", nil, cookie, ""); got.Code != 200 {
		t.Fatalf("pre-logout session: %d", got.Code)
	}
	// Install an audit failure so the transactional logout rolls back.
	if _, err := s.store.DB.Exec(`CREATE TRIGGER fail_logout_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-Watchpost-CSRF", session.CSRF)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusNoContent {
		t.Fatalf("logout reported success while server-side revocation failed")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("logout failure status=%d want 500", rec.Code)
	}
	// The session must still be active server-side (transaction rolled back).
	if got := apiRequest(t, handler, "GET", "/api/v1/posts", nil, cookie, ""); got.Code != 200 {
		t.Fatalf("session not revoked after failed logout: %d", got.Code)
	}
}
