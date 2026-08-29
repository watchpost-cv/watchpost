package server

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/watchpost-ops/watchpost/internal/agent"
	"github.com/watchpost-ops/watchpost/internal/agentpairing"
	"github.com/watchpost-ops/watchpost/internal/auth"
	"github.com/watchpost-ops/watchpost/internal/checks"
	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
	"github.com/watchpost-ops/watchpost/internal/devices"
	"github.com/watchpost-ops/watchpost/internal/evidence"
	"github.com/watchpost-ops/watchpost/internal/fleet"
	"github.com/watchpost-ops/watchpost/internal/host"
	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/notify"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/rules"
)

const sessionCookie = "watchpost_session"

type userContextKey struct{}

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/v1/setup", s.handleSetup)
	mux.HandleFunc("POST /api/v1/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/logout", s.require("viewer", s.handleLogout))
	mux.HandleFunc("POST /api/v1/posts", s.require("admin", s.handleCreatePost))
	mux.HandleFunc("GET /api/v1/posts", s.require("viewer", s.handleListPosts))
	mux.HandleFunc("GET /api/v1/collectors", s.require("viewer", s.handleListCollectors))
	mux.HandleFunc("GET /api/v1/posts/{id}", s.require("viewer", s.handleGetPost))
	mux.HandleFunc("PUT /api/v1/posts/{id}", s.require("operator", s.handleUpdatePost))
	mux.HandleFunc("DELETE /api/v1/posts/{id}", s.require("admin", s.handleDeletePost))
	mux.HandleFunc("POST /api/v1/posts/{id}/dependencies", s.require("operator", s.handleAddDependency))
	mux.HandleFunc("POST /api/v1/posts/{id}/collectors", s.require("admin", s.handleEnrollCollector))
	mux.HandleFunc("POST /api/v1/posts/{id}/pairing-tokens", s.require("admin", s.handleCreatePairingToken))
	mux.HandleFunc("POST /api/collector/v1/pair", s.handlePairCollector)
	mux.HandleFunc("POST /api/agent/v2/pairing-requests", s.handleAgentPairingRequest)
	mux.HandleFunc("POST /api/agent/v2/rotate", s.handleRotateAgentCredential)
	mux.HandleFunc("POST /api/agent/v2/unpair", s.handleAgentUnpair)
	mux.HandleFunc("GET /api/agent/v2/pairing-requests/{id}", s.handleAgentPairingPoll)
	mux.HandleFunc("GET /api/v1/agent-pairing-requests", s.require("viewer", s.handleListAgentPairingRequests))
	mux.HandleFunc("GET /api/v1/agent-connections", s.require("viewer", s.handleListAgentConnections))
	mux.HandleFunc("GET /api/v1/posts/{id}/agent-connections", s.require("viewer", s.handleListPostAgentConnections))
	mux.HandleFunc("POST /api/v1/agent-connections/{id}/revoke", s.require("admin", s.handleRevokeAgentConnection))
	mux.HandleFunc("POST /api/v1/agent-pairing-requests/{id}/approve", s.require("admin", s.handleApproveAgentPairingRequest))
	mux.HandleFunc("POST /api/v1/agent-pairing-requests/{id}/reject", s.require("admin", s.handleRejectAgentPairingRequest))
	mux.HandleFunc("POST /api/v1/observations", s.handleObservation)
	mux.HandleFunc("POST /api/collector/v1/observations", s.handleCollectorBatch)
	mux.HandleFunc("GET /api/v1/host-snapshot", s.require("viewer", s.handleHostSnapshot))
	mux.HandleFunc("POST /api/v1/checks", s.require("operator", s.handleCheck))
	mux.HandleFunc("POST /api/v1/check-schedules", s.require("operator", s.handleCreateCheckSchedule))
	mux.HandleFunc("GET /api/v1/check-schedules", s.require("viewer", s.handleListCheckSchedules))
	mux.HandleFunc("GET /api/v1/posts/{id}/history", s.require("viewer", s.handleHistory))
	mux.HandleFunc("GET /api/v1/survey", s.require("viewer", s.handleSurvey))
	mux.HandleFunc("POST /api/v1/rules", s.require("operator", s.handleCreateRule))
	mux.HandleFunc("GET /api/v1/rules", s.require("viewer", s.handleListRules))
	mux.HandleFunc("POST /api/v1/rules/{id}/enabled", s.require("operator", s.handleSetRuleEnabled))
	mux.HandleFunc("GET /api/v1/alerts", s.require("viewer", s.handleListAlerts))
	mux.HandleFunc("POST /api/v1/alerts/{id}/acknowledge", s.require("operator", s.handleAcknowledge))
	mux.HandleFunc("POST /api/v1/notification-routes", s.require("admin", s.handleCreateRoute))
	mux.HandleFunc("GET /api/v1/notification-routes", s.require("viewer", s.handleListRoutes))
	mux.HandleFunc("POST /api/v1/incidents", s.require("operator", s.handleCreateIncident))
	mux.HandleFunc("GET /api/v1/incidents", s.require("viewer", s.handleListIncidents))
	mux.HandleFunc("GET /api/v1/incidents/{id}", s.require("viewer", s.handleGetIncident))
	mux.HandleFunc("POST /api/v1/incidents/{id}/transition", s.require("operator", s.handleTransitionIncident))
	mux.HandleFunc("POST /api/v1/incidents/{id}/notes", s.require("operator", s.handleIncidentNote))
	mux.HandleFunc("POST /api/v1/incidents/{id}/assign", s.require("operator", s.handleAssignIncident))
	mux.HandleFunc("POST /api/v1/logs", s.require("operator", s.handleLog))
	mux.HandleFunc("GET /api/v1/posts/{id}/logs", s.require("viewer", s.handleSearchLogs))
	mux.HandleFunc("POST /api/v1/changes", s.require("operator", s.handleChange))
	mux.HandleFunc("GET /api/v1/evidence/{kind}/{id}", s.require("viewer", s.handleGetEvidence))
	mux.HandleFunc("POST /api/v1/conversations", s.require("viewer", s.handleConversation))
	mux.HandleFunc("POST /api/v1/conversations/{id}/investigate", s.require("viewer", s.handleInvestigate))
	mux.HandleFunc("POST /api/v1/actions", s.require("operator", s.handleRequestAction))
	mux.HandleFunc("GET /api/v1/actions", s.require("viewer", s.handleListActions))
	mux.HandleFunc("POST /api/v1/actions/{id}/approve", s.require("admin", s.handleApproveAction))
	mux.HandleFunc("POST /api/v1/actions/{id}/execute", s.require("operator", s.handleExecuteAction))
	mux.HandleFunc("POST /api/v1/peers", s.require("admin", s.handleEnrollPeer))
	mux.HandleFunc("GET /api/v1/peers", s.require("viewer", s.handleListPeers))
	mux.HandleFunc("POST /api/v1/peers/{id}/revoke", s.require("admin", s.handleRevokePeer))
	mux.HandleFunc("POST /api/v1/federation/{peer}", s.handleFederation)
	mux.HandleFunc("POST /api/v1/devices/snmp/poll", s.require("operator", s.handleSNMPPoll))
	mux.HandleFunc("POST /api/v1/device-profiles", s.require("operator", s.handleSaveDeviceProfile))
	mux.HandleFunc("GET /api/v1/device-profiles", s.require("viewer", s.handleListDeviceProfiles))
	mux.HandleFunc("DELETE /api/v1/device-profiles/{id}", s.require("operator", s.handleDeleteDeviceProfile))
	mux.HandleFunc("GET /api/v1/device-adapters", s.require("viewer", s.handleListDeviceAdapters))
	mux.HandleFunc("GET /api/v1/device-presets", s.require("viewer", s.handleListDevicePresets))
	mux.HandleFunc("GET /api/v1/audit", s.require("admin", s.handleListAudit))
	mux.HandleFunc("GET /api/v1/users", s.require("admin", s.handleListUsers))
	mux.HandleFunc("POST /api/v1/users", s.require("admin", s.handleCreateUser))
	mux.HandleFunc("PUT /api/v1/users/{id}/role", s.require("admin", s.handleSetUserRole))
	mux.HandleFunc("POST /api/v1/users/{id}/reset-password", s.require("admin", s.handleResetUserPassword))
	mux.HandleFunc("POST /api/v1/users/{id}/revoke-sessions", s.require("admin", s.handleRevokeUserSessions))
	mux.HandleFunc("POST /api/v1/me/password", s.require("viewer", s.handleChangeOwnPassword))
}

func (s *Server) handleAgentPairingRequest(w http.ResponseWriter, r *http.Request) {
	var input struct {
		InstallationID string `json:"installation_id"`
		RequestSecret  string `json:"request_secret"`
		Hostname       string `json:"hostname"`
		Platform       string `json:"platform"`
		AgentVersion   string `json:"agent_version"`
	}
	if !decode(w, r, &input) {
		return
	}
	request, err := s.agentPairing.Create(r.Context(), input.InstallationID, input.RequestSecret, input.Hostname, input.Platform, input.AgentVersion)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, request)
}
func (s *Server) handleRotateAgentCredential(w http.ResponseWriter, r *http.Request) {
	installation := r.Header.Get("X-Watchpost-Installation")
	credential, err := s.agentPairing.Rotate(r.Context(), installation, agentpairing.Bearer(r.Header.Get("Authorization")))
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"credential": credential})
}

func (s *Server) handleAgentUnpair(w http.ResponseWriter, r *http.Request) {
	installation := r.Header.Get("X-Watchpost-Installation")
	if err := s.agentPairing.Unpair(r.Context(), installation, agentpairing.Bearer(r.Header.Get("Authorization"))); err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "agent_unpair", "agent_connection", installation, "agent self-unpaired")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgentPairingPoll(w http.ResponseWriter, r *http.Request) {
	secret := agentpairing.Bearer(r.Header.Get("Authorization"))
	if secret == "" {
		writeJSON(w, 401, map[string]string{"error": "pairing authentication required"})
		return
	}
	result, err := s.agentPairing.Poll(r.Context(), r.PathValue("id"), secret)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) handleListAgentPairingRequests(w http.ResponseWriter, r *http.Request) {
	result, err := s.agentPairing.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "pairing requests unavailable"})
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleListAgentConnections(w http.ResponseWriter, r *http.Request) {
	result, err := s.agentPairing.Connections(r.Context(), "")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "agent connections unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"connections": result})
}
func (s *Server) handleListPostAgentConnections(w http.ResponseWriter, r *http.Request) {
	result, err := s.agentPairing.Connections(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "agent connections unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"connections": result})
}
func (s *Server) handleRevokeAgentConnection(w http.ResponseWriter, r *http.Request) {
	if err := s.agentPairing.Revoke(r.Context(), r.PathValue("id")); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "agent_connection_revoke", "agent_connection", r.PathValue("id"), "revoked")
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleApproveAgentPairingRequest(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PostID string `json:"post_id"`
	}
	if !decode(w, r, &input) {
		return
	}
	if err := s.agentPairing.Decide(r.Context(), r.PathValue("id"), input.PostID, true); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "agent_pairing_approve", "agent_pairing_request", r.PathValue("id"), "post="+input.PostID)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleRejectAgentPairingRequest(w http.ResponseWriter, r *http.Request) {
	if err := s.agentPairing.Decide(r.Context(), r.PathValue("id"), "", false); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "agent_pairing_reject", "agent_pairing_request", r.PathValue("id"), "rejected")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	setupRequired, err := s.auth.SetupRequired(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "bootstrap state unavailable"})
		return
	}
	response := map[string]any{"setup_required": setupRequired, "setup_token_required": s.auth.BootstrapTokenRequired(), "authenticated": false}
	if cookie, cookieErr := r.Cookie(sessionCookie); cookieErr == nil {
		if session, authErr := s.auth.Authenticate(r.Context(), cookie.Value); authErr == nil {
			response["authenticated"] = true
			response["user"] = session.User
			response["csrf_token"] = session.CSRF
		}
	}
	writeJSON(w, http.StatusOK, response)
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
	var in struct{ Email, Password, Token string }
	if !decode(w, r, &in) {
		return
	}
	user, err := s.auth.Setup(r.Context(), in.Email, in.Password, in.Token)
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
	s.auditActor(r.Context(), session.User.ID, "login", "session", "", "login")
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: session.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || s.cfg.SecureCookies, MaxAge: 86400})
	writeJSON(w, 200, map[string]any{"user": session.User, "csrf_token": session.CSRF})
}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(sessionCookie)
	_ = s.auth.Logout(r.Context(), cookie.Value)
	s.audit(r, "logout", "session", "", "logout")
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
		next(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, session.User)))
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
	s.audit(r, "post_create", "post", post.ID, post.Name)
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
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	offset := 0
	if value := r.URL.Query().Get("offset"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	items, err := s.posts.List(r.Context(), limit, offset)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "list posts failed"})
		return
	}
	total, err := s.posts.Count(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "list posts failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"posts": items, "total": total, "offset": offset, "limit": limit})
}

func (s *Server) handleListCollectors(w http.ResponseWriter, r *http.Request) {
	items, err := s.health.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "collector health unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"collectors": items, "freshness_seconds": 120, "offline_seconds": 600})
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
	s.audit(r, "post_update", "post", post.ID, fmt.Sprintf("name=%s maintenance=%t archived=%t", post.Name, post.Maintenance, post.Archived))
	writeJSON(w, 200, post)
}
func (s *Server) handleDeletePost(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ConfirmID string `json:"confirm_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	if in.ConfirmID != id {
		writeJSON(w, 400, map[string]string{"error": "type the post ID to confirm permanent deletion"})
		return
	}
	user := r.Context().Value(userContextKey{}).(auth.User)
	if err := s.posts.Delete(r.Context(), id, user.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, 404, map[string]string{"error": "post not found"})
			return
		}
		writeJSON(w, 500, map[string]string{"error": "delete post failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	s.audit(r, "dependency_add", "post", r.PathValue("id"), "depends_on="+in.DependsOn)
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
	s.audit(r, "collector_enroll", "collector", in.ID, "post="+r.PathValue("id"))
	writeJSON(w, 201, map[string]string{"id": in.ID, "secret": secret})
}

func (s *Server) handleCreatePairingToken(w http.ResponseWriter, r *http.Request) {
	token, err := s.pairing.Create(r.Context(), r.PathValue("id"), 10*time.Minute)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "pairing_token_create", "post", r.PathValue("id"), "pairing token issued")
	writeJSON(w, 201, token)
}

func (s *Server) handlePairCollector(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Token       string `json:"token"`
		CollectorID string `json:"collector_id"`
	}
	if !decode(w, r, &input) {
		return
	}
	enrollment, err := s.pairing.Consume(r.Context(), input.Token, input.CollectorID)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, enrollment)
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
	if err := s.ingest.Authenticate(r.Context(), observation.CollectorID, secret); err != nil {
		writeJSON(w, 401, map[string]string{"error": "collector authentication failed"})
		return
	}
	if err := s.guardStorage(r.Context()); err != nil {
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": "storage full"})
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

func (s *Server) handleCollectorBatch(w http.ResponseWriter, r *http.Request) {
	var batch collectorcontract.Batch
	if !decode(w, r, &batch) {
		return
	}
	now := time.Now().UTC()
	if err := batch.Validate(now); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if secret == "" {
		writeJSON(w, 401, map[string]string{"error": "collector authentication required"})
		return
	}
	if err := s.ingest.Authenticate(r.Context(), batch.CollectorID, secret); err != nil {
		writeJSON(w, 401, map[string]string{"error": "collector authentication failed"})
		return
	}
	if err := s.guardStorage(r.Context()); err != nil {
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": "storage full"})
		return
	}
	items := make([]ingest.Observation, len(batch.Samples))
	for index, sample := range batch.Samples {
		items[index] = ingest.Observation{Version: 1, PostID: batch.PostID, CollectorID: batch.CollectorID, ObservedAt: sample.ObservedAt, Sequence: sample.Sequence, Signal: sample.Signal, Value: sample.Value, Unit: sample.Unit, Quality: sample.Quality, Labels: sample.Labels}
	}
	if err := s.ingest.AcceptBatch(r.Context(), secret, items, batch.SentAt); err != nil {
		s.ingest.RecordRejection(r.Context(), batch.CollectorID, err)
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	for _, item := range items {
		alerts, err := s.rules.EvaluateObservation(r.Context(), item.PostID, item.Signal, item.ObservedAt, item.Value, item.Quality)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "rule evaluation failed"})
			return
		}
		for _, alert := range alerts {
			if alert.State == "firing" {
				_ = s.notify.Queue(r.Context(), alert.ID)
			}
		}
	}
	writeJSON(w, 202, collectorcontract.Acknowledgement{Version: 1, BatchID: batch.BatchID, AcceptedThrough: items[len(items)-1].Sequence, ServerTime: now})
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
	if !s.checkLimiter.allow() {
		writeJSON(w, 429, map[string]string{"error": "too many on-demand checks"})
		return
	}
	var in struct{ Kind, Address, ServerName string }
	if !decode(w, r, &in) {
		return
	}
	if err := s.checkPolicy.Validate(r.Context(), in.Address, 0); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "check_run", "check", in.Kind, in.Address)
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
func (s *Server) handleCreateCheckSchedule(w http.ResponseWriter, r *http.Request) {
	var in checks.Schedule
	if !decode(w, r, &in) {
		return
	}
	if err := s.checks.Save(r.Context(), in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "check_schedule_create", "check_schedule", in.ID, in.Kind+" "+in.Address)
	w.WriteHeader(http.StatusCreated)
}
func (s *Server) handleListCheckSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.checks.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "check schedules unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"schedules": items})
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

func (s *Server) handleSurvey(w http.ResponseWriter, r *http.Request) {
	series, err := s.history.Survey(r.Context(), time.Now().UTC().Add(-time.Hour), 30)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "resource survey unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"series": series, "from": time.Now().UTC().Add(-time.Hour)})
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
	s.audit(r, "rule_create", "rule", in.ID, "post="+in.PostID+" signal="+in.Signal)
	w.WriteHeader(201)
}
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if value := r.URL.Query().Get("limit"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	items, err := s.rules.ListRules(r.Context(), limit)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "list rules failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"rules": items})
}
func (s *Server) handleSetRuleEnabled(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.rules.SetEnabled(r.Context(), r.PathValue("id"), in.Enabled); err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "rule_set_enabled", "rule", r.PathValue("id"), fmt.Sprintf("enabled=%t", in.Enabled))
	w.WriteHeader(http.StatusNoContent)
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
	s.audit(r, "notification_route_create", "notification_route", route.ID, route.Kind)
	w.WriteHeader(201)
}
func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	items, err := s.notify.ListRoutes(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "notification status unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"routes": items})
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
	s.audit(r, "alert_acknowledge", "alert", fmt.Sprint(id), "acknowledged")
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
	incident, err := s.incidents.Create(r.Context(), in.Title, in.Severity, currentUser(r).Email, in.AlertIDs)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "incident_create", "incident", fmt.Sprint(incident.ID), in.Title)
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
	incident, err := s.incidents.Transition(r.Context(), id, in.Status, currentUser(r).Email, in.Summary)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "incident_transition", "incident", fmt.Sprint(id), in.Status)
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
	if err = s.incidents.AddNote(r.Context(), id, currentUser(r).Email, in.Body); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "incident_note", "incident", fmt.Sprint(id), "note added")
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleAssignIncident(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid incident"})
		return
	}
	var in struct {
		Owner string `json:"owner"`
	}
	if !decode(w, r, &in) {
		return
	}
	item, err := s.incidents.Assign(r.Context(), id, in.Owner, currentUser(r).Email)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "incident_assign", "incident", fmt.Sprint(id), "owner="+in.Owner)
	writeJSON(w, 200, item)
}
func currentUser(r *http.Request) auth.User {
	user, _ := r.Context().Value(userContextKey{}).(auth.User)
	return user
}

// audit records an attributable operational state change. Failures are logged
// but never fail the operation they describe.
func (s *Server) audit(r *http.Request, action, objectType, objectID, detail string) {
	user := currentUser(r)
	s.auditActor(r.Context(), user.ID, action, objectType, objectID, detail)
}

func (s *Server) auditActor(ctx context.Context, actorID int64, action, objectType, objectID, detail string) {
	if len(detail) > 400 {
		detail = detail[:400]
	}
	var actor any
	if actorID != 0 {
		actor = actorID
	}
	if _, err := s.store.DB.ExecContext(ctx, `INSERT INTO audit(at,actor_user_id,action,object_type,object_id,detail) VALUES(?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), actor, action, objectType, objectID, detail); err != nil {
		s.logger.Warn("audit write failed", "action", action, "error", err)
	}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.auth.ListUsers(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "users unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"users": items})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email, Password, Role string
	}
	if !decode(w, r, &in) {
		return
	}
	user, err := s.auth.CreateUser(r.Context(), in.Email, in.Password, in.Role)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "user_create", "user", fmt.Sprint(user.ID), user.Email+" role="+user.Role)
	writeJSON(w, 201, user)
}

func (s *Server) handleSetUserRole(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid user"})
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if !decode(w, r, &in) {
		return
	}
	if id == currentUser(r).ID && in.Role != "admin" {
		writeJSON(w, 409, map[string]string{"error": "cannot demote your own account"})
		return
	}
	if err := s.auth.SetRole(r.Context(), id, in.Role); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "user_set_role", "user", fmt.Sprint(id), "role="+in.Role)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid user"})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.auth.ResetPassword(r.Context(), id, in.Password); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "user_reset_password", "user", fmt.Sprint(id), "password reset")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid user"})
		return
	}
	count, err := s.auth.RevokeSessions(r.Context(), id)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "sessions could not be revoked"})
		return
	}
	s.audit(r, "user_revoke_sessions", "user", fmt.Sprint(id), fmt.Sprintf("revoked=%d", count))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, &in) {
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "authentication required"})
		return
	}
	user := currentUser(r)
	if err := s.auth.ChangePassword(r.Context(), user.ID, in.CurrentPassword, in.NewPassword, cookie.Value); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "user_change_password", "user", fmt.Sprint(user.ID), "password changed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeJSON(w, 400, map[string]string{"error": "invalid limit"})
			return
		}
		limit = parsed
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT a.at,COALESCE(u.email,''),a.action,a.object_type,a.object_id,a.detail FROM audit a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "audit log unavailable"})
		return
	}
	defer rows.Close()
	type entry struct {
		At         string `json:"at"`
		ActorEmail string `json:"actor_email"`
		Action     string `json:"action"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Detail     string `json:"detail"`
	}
	items := []entry{}
	for rows.Next() {
		var item entry
		if err = rows.Scan(&item.At, &item.ActorEmail, &item.Action, &item.ObjectType, &item.ObjectID, &item.Detail); err != nil {
			writeJSON(w, 500, map[string]string{"error": "audit log unavailable"})
			return
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"audit": items})
}
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	var log evidence.Log
	if !decode(w, r, &log) {
		return
	}
	if err := s.guardStorage(r.Context()); err != nil {
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": "storage full"})
		return
	}
	stored, err := s.evidence.IngestLog(r.Context(), log)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, stored)
}
func (s *Server) handleSearchLogs(w http.ResponseWriter, r *http.Request) {
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
	items, err := s.evidence.SearchLogs(r.Context(), r.PathValue("id"), r.URL.Query().Get("q"), from, to, 500)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"logs": items})
}
func (s *Server) handleChange(w http.ResponseWriter, r *http.Request) {
	var change evidence.Change
	if !decode(w, r, &change) {
		return
	}
	stored, err := s.evidence.RecordChange(r.Context(), change)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, stored)
}
func (s *Server) handleGetEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid evidence"})
		return
	}
	switch r.PathValue("kind") {
	case "log":
		item, e := s.evidence.GetLog(r.Context(), id)
		if e == nil {
			writeJSON(w, 200, map[string]any{"kind": "log", "evidence": item})
			return
		}
		if errors.Is(e, sql.ErrNoRows) {
			if purged, refErr := s.evidence.FindPurgedReference(r.Context(), "log", id); refErr == nil {
				writeJSON(w, 200, map[string]any{"kind": "log", "purged": true, "reference": purged})
				return
			}
		}
	case "change":
		item, e := s.evidence.GetChange(r.Context(), id)
		if e == nil {
			writeJSON(w, 200, map[string]any{"kind": "change", "evidence": item})
			return
		}
		if errors.Is(e, sql.ErrNoRows) {
			if purged, refErr := s.evidence.FindPurgedReference(r.Context(), "change", id); refErr == nil {
				writeJSON(w, 200, map[string]any{"kind": "change", "purged": true, "reference": purged})
				return
			}
		}
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported evidence kind"})
		return
	}
	writeJSON(w, 404, map[string]string{"error": "evidence not found"})
}
func (s *Server) handleConversation(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PostID     string `json:"post_id"`
		IncidentID *int64 `json:"incident_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	id, err := s.agent.Start(r.Context(), currentUser(r).ID, in.PostID, in.IncidentID)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "conversation_start", "conversation", fmt.Sprint(id), "post="+in.PostID)
	writeJSON(w, 201, map[string]int64{"id": id})
}
func (s *Server) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid conversation"})
		return
	}
	var in struct {
		Question string           `json:"question"`
		Evidence []agent.Citation `json:"evidence"`
	}
	if !decode(w, r, &in) {
		return
	}
	response, err := s.agent.Investigate(r.Context(), id, currentUser(r).ID, in.Question, in.Evidence)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "investigate", "conversation", fmt.Sprint(id), "question asked")
	writeJSON(w, 200, response)
}
func (s *Server) handleRequestAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Type, PostID, IdempotencyKey string
		Parameters                   map[string]any
	}
	if !decode(w, r, &in) {
		return
	}
	id, err := s.actions.Request(r.Context(), in.Type, in.PostID, in.Parameters, currentUser(r).ID, in.IdempotencyKey)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "action_request", "action", fmt.Sprint(id), in.Type)
	writeJSON(w, 201, map[string]int64{"id": id})
}
func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	items, err := s.actions.List(r.Context(), 500)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "actions unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"actions": items})
}
func (s *Server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid action"})
		return
	}
	if err = s.actions.Approve(r.Context(), id, currentUser(r).ID); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "action_approve", "action", fmt.Sprint(id), "approved")
	w.WriteHeader(204)
}
func (s *Server) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid action"})
		return
	}
	result, err := s.actions.Execute(r.Context(), id)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "action_execute", "action", fmt.Sprint(id), "executed")
	writeJSON(w, 200, result)
}
func (s *Server) handleEnrollPeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &in) {
		return
	}
	secret, err := s.fleet.Enroll(r.Context(), in.ID)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "peer_enroll", "peer", in.ID, "enrolled")
	writeJSON(w, 201, map[string]string{"id": in.ID, "secret": secret})
}
func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	items, err := s.fleet.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "fleet status unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"peers": items})
}
func (s *Server) handleRevokePeer(w http.ResponseWriter, r *http.Request) {
	if err := s.fleet.Revoke(r.Context(), r.PathValue("id")); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "peer_revoke", "peer", r.PathValue("id"), "revoked")
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleFederation(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var envelope fleet.Envelope
	if secret == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "peer authentication required"})
		return
	}
	if !decode(w, r, &envelope) {
		return
	}
	if err := s.fleet.Receive(r.Context(), r.PathValue("peer"), secret, envelope); err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(202)
}
func (s *Server) handleSaveDeviceProfile(w http.ResponseWriter, r *http.Request) {
	var in devices.SavedProfile
	if !decode(w, r, &in) {
		return
	}
	if err := s.devices.Save(r.Context(), in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "device_profile_save", "device_profile", in.ID, in.Kind+" "+in.Address)
	w.WriteHeader(201)
}
func (s *Server) handleListDeviceProfiles(w http.ResponseWriter, r *http.Request) {
	items, err := s.devices.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "device profiles unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"profiles": items})
}
func (s *Server) handleDeleteDeviceProfile(w http.ResponseWriter, r *http.Request) {
	if err := s.devices.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "device_profile_delete", "device_profile", r.PathValue("id"), "removed")
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleListDeviceAdapters(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"adapters": devices.Adapters()})
}
func (s *Server) handleListDevicePresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"presets": devices.Presets()})
}
func (s *Server) handleSNMPPoll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Config  devices.V3Config `json:"config"`
		Profile devices.Profile  `json:"profile"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := devices.ValidateProfile(in.Profile); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.checkPolicy.Validate(r.Context(), in.Config.Address, int(in.Config.Port)); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	client, err := devices.NewV3(in.Config)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err = client.Connect(); err != nil {
		writeJSON(w, 502, map[string]string{"error": "SNMP connection failed"})
		return
	}
	defer client.Conn.Close()
	readings, err := devices.Poll(r.Context(), client, in.Profile)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "SNMP poll failed"})
		return
	}
	writeJSON(w, 200, map[string]any{"readings": readings})
}
