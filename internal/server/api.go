package server

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost/internal/checks"
	"github.com/watchpost-ops/watchpost/internal/host"
	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/notify"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/rules"
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
	mux.HandleFunc("GET /api/v1/host-snapshot", s.require("viewer", s.handleHostSnapshot))
	mux.HandleFunc("POST /api/v1/checks", s.require("operator", s.handleCheck))
	mux.HandleFunc("GET /api/v1/posts/{id}/history", s.require("viewer", s.handleHistory))
	mux.HandleFunc("POST /api/v1/rules", s.require("operator", s.handleCreateRule))
	mux.HandleFunc("GET /api/v1/alerts", s.require("viewer", s.handleListAlerts))
	mux.HandleFunc("POST /api/v1/alerts/{id}/acknowledge", s.require("operator", s.handleAcknowledge))
	mux.HandleFunc("POST /api/v1/notification-routes", s.require("admin", s.handleCreateRoute))
	mux.HandleFunc("POST /api/v1/incidents", s.require("operator", s.handleCreateIncident))
	mux.HandleFunc("GET /api/v1/incidents", s.require("viewer", s.handleListIncidents))
	mux.HandleFunc("GET /api/v1/incidents/{id}", s.require("viewer", s.handleGetIncident))
	mux.HandleFunc("POST /api/v1/incidents/{id}/transition", s.require("operator", s.handleTransitionIncident))
	mux.HandleFunc("POST /api/v1/incidents/{id}/notes", s.require("operator", s.handleIncidentNote))
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
	alerts, err := s.rules.EvaluateObservation(r.Context(), observation.PostID, observation.Signal, observation.ObservedAt, observation.Value, observation.Quality)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "rule evaluation failed"})
		return
	}
	for _, alert := range alerts {
		if alert.State == "firing" {
			_ = s.notify.Queue(r.Context(), alert.ID)
		}
	}
	w.WriteHeader(http.StatusAccepted)
}
func (s *Server) handleHostSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := host.Collect()
	if err != nil {
		writeJSON(w, 501, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, snapshot)
}
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var in struct{ Kind, Address, ServerName string }
	if !decode(w, r, &in) {
		return
	}
	runner := checks.New(10 * time.Second)
	var result checks.Result
	switch in.Kind {
	case "icmp":
		result = runner.ICMP(r.Context(), in.Address)
	case "http":
		result = runner.HTTPCheck(r.Context(), in.Address)
	case "tcp":
		result = runner.TCP(r.Context(), in.Address)
	case "dns":
		result = runner.DNS(r.Context(), in.Address)
	case "tls":
		result = runner.TLS(r.Context(), in.Address, in.ServerName)
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported check"})
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	from, err := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid from"})
		return
	}
	to, err := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid to"})
		return
	}
	points, err := s.history.Series(r.Context(), r.PathValue("id"), r.URL.Query().Get("signal"), from, to, 1000)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=watchpost-history.csv")
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"observed_at", "value", "unit", "quality"})
		for _, point := range points {
			value := ""
			if point.Value != nil {
				value = strconv.FormatFloat(*point.Value, 'g', -1, 64)
			}
			_ = writer.Write([]string{point.ObservedAt.Format(time.RFC3339Nano), value, point.Unit, point.Quality})
		}
		writer.Flush()
		return
	}
	writeJSON(w, 200, map[string]any{"points": points})
}
func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID, PostID, Signal, Operator, MissingPolicy, Severity string
		Threshold                                             float64
		DurationSeconds                                       int64
	}
	if !decode(w, r, &in) {
		return
	}
	err := s.rules.Create(r.Context(), rules.Rule{ID: in.ID, PostID: in.PostID, Signal: in.Signal, Operator: in.Operator, Threshold: in.Threshold, Duration: time.Duration(in.DurationSeconds) * time.Second, MissingPolicy: in.MissingPolicy, Severity: in.Severity, Enabled: true})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(201)
}
func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var route notify.Route
	if !decode(w, r, &route) {
		return
	}
	route.Enabled = true
	if err := s.notify.CreateRoute(r.Context(), route); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(201)
}
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.rules.ListAlerts(r.Context(), 500)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "list alerts failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"alerts": alerts})
}
func (s *Server) handleAcknowledge(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid alert"})
		return
	}
	if err = s.rules.Acknowledge(r.Context(), id, time.Now().UTC()); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title, Severity string
		AlertIDs        []int64 `json:"alert_ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	incident, err := s.incidents.Create(r.Context(), in.Title, in.Severity, "authenticated-user", in.AlertIDs)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, incident)
}
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid incident"})
		return
	}
	incident, err := s.incidents.Get(r.Context(), id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "incident not found"})
		return
	}
	timeline, err := s.incidents.Timeline(r.Context(), id, 1000)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "timeline failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"incident": incident, "timeline": timeline})
}
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	items, err := s.incidents.List(r.Context(), 500)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "list incidents failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"incidents": items})
}
func (s *Server) handleTransitionIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid incident"})
		return
	}
	var in struct{ Status, Summary string }
	if !decode(w, r, &in) {
		return
	}
	incident, err := s.incidents.Transition(r.Context(), id, in.Status, "authenticated-user", in.Summary)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, incident)
}
func (s *Server) handleIncidentNote(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid incident"})
		return
	}
	var in struct{ Body string }
	if !decode(w, r, &in) {
		return
	}
	if err = s.incidents.AddNote(r.Context(), id, "authenticated-user", in.Body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
