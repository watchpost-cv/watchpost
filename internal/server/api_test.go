package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/watchpost-ops/watchpost/internal/posts"
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
