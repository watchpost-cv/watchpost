package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
