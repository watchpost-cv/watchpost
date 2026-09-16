package server

import (
	"net/http"
	"strings"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/cluster"
)

func (s *Server) registerClusterAPI(mux *http.ServeMux) {
	s.registerPropagationAPI(mux)
	if s.replicated != nil {
		mux.HandleFunc("POST "+ReplicatedProposePath, s.handleReplicationPropose)
	}
	mux.HandleFunc("GET /api/v1/cluster/identity", s.require("viewer", s.handleClusterIdentity))
	mux.HandleFunc("PUT /api/v1/cluster/identity", s.require("admin", s.handleClusterIdentityUpdate))
	mux.HandleFunc("POST /api/v1/cluster/invitations", s.require("admin", s.handleClusterInvite))
	mux.HandleFunc("POST /api/cluster/v1/join", s.handleClusterJoin)
	mux.HandleFunc("GET /api/cluster/v1/join/{id}", s.handleClusterJoinPoll)
	mux.HandleFunc("GET /api/v1/cluster/joins", s.require("admin", s.handleClusterPending))
	mux.HandleFunc("POST /api/v1/cluster/outbound-joins", s.require("admin", s.handleClusterOutboundBegin))
	mux.HandleFunc("GET /api/v1/cluster/outbound-joins", s.require("admin", s.handleClusterOutboundList))
	mux.HandleFunc("POST /api/v1/cluster/outbound-joins/{id}/collect", s.require("admin", s.handleClusterOutboundCollect))
	mux.HandleFunc("POST /api/v1/cluster/joins/{id}/approve", s.require("admin", s.handleClusterApprove))
	mux.HandleFunc("POST /api/v1/cluster/joins/{id}/reject", s.require("admin", s.handleClusterReject))
	mux.HandleFunc("GET /api/v1/cluster/members", s.require("viewer", s.handleClusterMembers))
	mux.HandleFunc("POST /api/v1/cluster/members/{id}/enable", s.require("admin", s.handleClusterEnable))
	mux.HandleFunc("POST /api/v1/cluster/members/{id}/disable", s.require("admin", s.handleClusterDisable))
	mux.HandleFunc("POST /api/v1/cluster/members/{id}/revoke", s.require("admin", s.handleClusterRevoke))
	mux.HandleFunc("DELETE /api/v1/cluster/members/{id}", s.require("admin", s.handleClusterRemove))
	mux.HandleFunc("POST /api/v1/cluster/members/{id}/rotate", s.require("admin", s.handleClusterRotate))
	mux.HandleFunc("PUT /api/v1/cluster/members/{id}/outbound-credential", s.require("admin", s.handleClusterOutboundCredential))
	mux.HandleFunc("GET /api/v1/cluster/status", s.require("viewer", s.handleClusterStatus))
	mux.HandleFunc("GET /api/v1/cluster/summary", s.require("viewer", s.handleClusterSummary))
	mux.HandleFunc("GET /api/cluster/v1/rpc/status", s.handleClusterRPCStatus)
	mux.HandleFunc("GET /api/cluster/v1/rpc/summary", s.handleClusterRPCSummary)
}

// handleReplicationPropose authenticates an inbound follower application RPC
// over the cluster transport and routes the forwarded mutation intent through
// the leader's authoritative Controller (its own graph revision + applied
// state). The operation identity is preserved so the durable operation-ID
// contract provides retry idempotency and same-ID/different-payload fail-closed
// behaviour.
func (s *Server) handleReplicationPropose(w http.ResponseWriter, r *http.Request) {
	handler := s.replicated.LeaderProposeHandler(func(r *http.Request) (string, error) {
		auth, err := s.clusterTransport.Authenticate(r, "replication")
		if err != nil {
			return "", err
		}
		w.Header().Set("X-Watchpost-Request-ID", auth.RequestID)
		return auth.NodeID, nil
	})
	handler.ServeHTTP(w, r)
}

func (s *Server) handleClusterIdentity(w http.ResponseWriter, r *http.Request) {
	v, err := s.clusterIdentity.Ensure(r.Context(), s.version)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"identity": v, "fingerprint": v.Fingerprint()})
}
func (s *Server) handleClusterIdentityUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DisplayName    string   `json:"display_name"`
		PublicEndpoint string   `json:"public_endpoint"`
		Capabilities   []string `json:"capabilities"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.clusterIdentity.Update(r.Context(), in.DisplayName, in.PublicEndpoint, in.Capabilities, s.version)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"identity": v, "fingerprint": v.Fingerprint()})
}
func (s *Server) handleClusterInvite(w http.ResponseWriter, r *http.Request) {
	v, err := s.clusterPairing.Invite(r.Context(), audit.Entry{ActorID: currentUser(r).ID})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, v)
}
func (s *Server) handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	var in cluster.JoinSubmission
	if !decode(w, r, &in) {
		return
	}
	v, err := s.clusterPairing.SubmitJoin(r.Context(), in)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, v)
}
func (s *Server) handleClusterJoinPoll(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	v, err := s.clusterPairing.Poll(r.Context(), r.PathValue("id"), secret)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handleClusterOutboundBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RemoteURL       string `json:"remote_url"`
		InvitationToken string `json:"invitation_token"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := s.clusterPairing.BeginOutbound(r.Context(), in.RemoteURL, in.InvitationToken, nil)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 202, v)
}
func (s *Server) handleClusterOutboundList(w http.ResponseWriter, r *http.Request) {
	v, err := s.clusterPairing.ListOutbound(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleClusterOutboundCollect(w http.ResponseWriter, r *http.Request) {
	v, err := s.clusterPairing.CollectOutbound(r.Context(), r.PathValue("id"), nil)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) handleClusterPending(w http.ResponseWriter, r *http.Request) {
	v, err := s.clusterPairing.ListPending(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) clusterDecision(w http.ResponseWriter, r *http.Request, approve bool) {
	_, err := s.clusterPairing.Decide(r.Context(), r.PathValue("id"), approve, audit.Entry{ActorID: currentUser(r).ID})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleClusterApprove(w http.ResponseWriter, r *http.Request) {
	s.clusterDecision(w, r, true)
}
func (s *Server) handleClusterReject(w http.ResponseWriter, r *http.Request) {
	s.clusterDecision(w, r, false)
}
func (s *Server) handleClusterMembers(w http.ResponseWriter, r *http.Request) {
	v, err := s.clusterMembers.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) memberAudit(r *http.Request) audit.Entry {
	return audit.Entry{ActorID: currentUser(r).ID}
}
func (s *Server) handleClusterEnable(w http.ResponseWriter, r *http.Request) {
	if err := s.clusterMembers.SetEnabled(r.Context(), r.PathValue("id"), true, s.memberAudit(r)); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleClusterDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.clusterMembers.SetEnabled(r.Context(), r.PathValue("id"), false, s.memberAudit(r)); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleClusterRevoke(w http.ResponseWriter, r *http.Request) {
	if err := s.clusterMembers.Revoke(r.Context(), r.PathValue("id"), s.memberAudit(r)); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleClusterRemove(w http.ResponseWriter, r *http.Request) {
	if err := s.clusterMembers.Remove(r.Context(), r.PathValue("id"), s.memberAudit(r)); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleClusterRotate(w http.ResponseWriter, r *http.Request) {
	secret, err := s.clusterMembers.RotateInbound(r.Context(), r.PathValue("id"), s.memberAudit(r))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"credential": secret})
}
func (s *Server) handleClusterOutboundCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Credential string `json:"credential"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := s.clusterMembers.SetOutboundCredential(r.Context(), r.PathValue("id"), in.Credential); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if err := cluster.ValidateTarget(target); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, s.clusterDistributed.ClusterStatus(r.Context(), s.version, target))
}
func (s *Server) handleClusterSummary(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if err := cluster.ValidateTarget(target); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, s.clusterDistributed.ClusterSummary(r.Context(), s.version, target))
}
func (s *Server) handleClusterRPCStatus(w http.ResponseWriter, r *http.Request) {
	auth, err := s.clusterTransport.Authenticate(r, "cluster.health")
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("X-Watchpost-Request-ID", auth.RequestID)
	writeJSON(w, 200, s.clusterDistributed.LocalStatus(r.Context(), s.version))
}
func (s *Server) handleClusterRPCSummary(w http.ResponseWriter, r *http.Request) {
	auth, err := s.clusterTransport.Authenticate(r, "cluster.summary")
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": err.Error()})
		return
	}
	v, err := s.clusterDistributed.LocalSummary(r.Context(), s.version)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("X-Watchpost-Request-ID", auth.RequestID)
	writeJSON(w, 200, v)
}
