package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/posts"
)

const sessionCookie = "watchpost_session"

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/setup", s.handleSetup)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/logout", s.require("viewer", s.handleLogout))
	mux.HandleFunc("POST /api/v1/posts", s.require("admin", s.handleCreatePost))
	mux.HandleFunc("GET /api/v1/posts", s.require("viewer", s.handleListPosts))
	mux.HandleFunc("GET /api/v1/posts/{id}", s.require("viewer", s.handleGetPost))
	mux.HandleFunc("PUT /api/v1/posts/{id}", s.require("operator", s.handleUpdatePost))
	mux.HandleFunc("POST /api/v1/posts/{id}/dependencies", s.require("operator", s.handleAddDependency))
	mux.HandleFunc("POST /api/v1/posts/{id}/collectors", s.require("admin", s.handleEnrollCollector))
	mux.HandleFunc("POST /api/v1/observations", s.handleObservation)
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return false
	}
	return true
}
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if !decode(w, r, &in) {
		return
	}
	user, err := s.auth.Setup(r.Context(), in.Email, in.Password)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, user)
}
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if !decode(w, r, &in) {
		return
	}
	session, err := s.auth.Login(r.Context(), in.Email, in.Password)
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 86400})
	writeJSON(w, 200, map[string]any{"user": session.User, "csrf_token": session.CSRF})
}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionCookie)
	_ = s.auth.Logout(r.Context(), cookie.Value)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) require(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, 401, map[string]string{"error": "authentication required"})
			return
		}
		session, err := s.auth.Authenticate(r.Context(), cookie.Value)
		if err != nil || rank(session.User.Role) < rank(role) {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		if r.Method != "GET" && r.Header.Get("X-Watchpost-CSRF") != session.CSRF {
			writeJSON(w, 403, map[string]string{"error": "csrf check failed"})
			return
		}
		next(w, r)
	}
}
func rank(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	}
	return 0
}
func (s *Server) handleCreatePost(w http.ResponseWriter, r *http.Request) {
	var post posts.Post
	if !decode(w, r, &post) {
		return
	}
	post, err := s.posts.Create(r.Context(), post)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, post)
}
func (s *Server) handleGetPost(w http.ResponseWriter, r *http.Request) {
	post, err := s.posts.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "post not found"})
		return
	}
	writeJSON(w, 200, post)
}
func (s *Server) handleListPosts(w http.ResponseWriter, r *http.Request) {
	items, err := s.posts.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "list posts failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"posts": items})
}
func (s *Server) handleUpdatePost(w http.ResponseWriter, r *http.Request) {
	var post posts.Post
	if !decode(w, r, &post) {
		return
	}
	post.ID = r.PathValue("id")
	expected, err := strconv.Atoi(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "If-Match version required"})
		return
	}
	post, err = s.posts.Update(r.Context(), post, expected)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, post)
}
func (s *Server) handleAddDependency(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DependsOn string `json:"depends_on"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.posts.AddDependency(r.Context(), r.PathValue("id"), in.DependsOn); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleEnrollCollector(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &in) {
		return
	}
	secret, err := s.ingest.Enroll(r.Context(), in.ID, r.PathValue("id"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]string{"id": in.ID, "secret": secret})
}
func (s *Server) handleObservation(w http.ResponseWriter, r *http.Request) {
	var observation ingest.Observation
	if !decode(w, r, &observation) {
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if secret == "" {
		writeJSON(w, 401, map[string]string{"error": "collector authentication required"})
		return
	}
	if err := s.ingest.Accept(r.Context(), secret, observation); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
