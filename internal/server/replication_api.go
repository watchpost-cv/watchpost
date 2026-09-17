package server

import (
	"net/http"

	"github.com/hashicorp/raft"
)

// registerReplicationAPI mounts the operator surface for the replicated raft
// runtime: status inspection and explicit raft membership operations. Gantry
// membership remains separate from raft membership; joining a raft voter is an
// explicit consensus configuration operation, never inferred from
// cluster_members rows.
func (s *Server) registerReplicationAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/replication/status", s.require("admin", s.handleReplicationStatus))
	mux.HandleFunc("POST /api/v1/replication/join", s.require("admin", s.handleReplicationJoin))
	mux.HandleFunc("POST /api/v1/replication/snapshot", s.require("admin", s.handleReplicationSnapshot))
}

func (s *Server) handleReplicationStatus(w http.ResponseWriter, r *http.Request) {
	ctrl := s.replicated
	if ctrl == nil {
		writeJSON(w, 400, map[string]string{"error": "replication is not configured on this node"})
		return
	}
	node := ctrl.Node()
	mode, readiness := ctrl.State()
	leaderAddr, leaderID := node.Leader()
	applied, term := node.AppliedIndex()
	cfgServers := []map[string]any{}
	if cfg, err := node.Configuration(); err == nil {
		for _, sv := range cfg {
			cfgServers = append(cfgServers, map[string]any{
				"id":       string(sv.ID),
				"address":  string(sv.Address),
				"suffrage": sv.Suffrage.String(),
			})
		}
	}
	writeJSON(w, 200, map[string]any{
		"node_id":         string(node.ID()),
		"address":         string(node.Address()),
		"configured_mode": mode.String(),
		"readiness":       readiness.String(),
		"raft_state":      node.State().String(),
		"leader_id":       string(leaderID),
		"leader_address":  string(leaderAddr),
		"applied_index":   applied,
		"applied_term":    term,
		"last_index":      node.LastIndex(),
		"configuration":   cfgServers,
	})
}

func (s *Server) handleReplicationSnapshot(w http.ResponseWriter, r *http.Request) {
	ctrl := s.replicated
	if ctrl == nil {
		writeJSON(w, 400, map[string]string{"error": "replication is not configured on this node"})
		return
	}
	if err := ctrl.Node().Snapshot(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"snapshot": "forced"})
}

func (s *Server) handleReplicationJoin(w http.ResponseWriter, r *http.Request) {
	ctrl := s.replicated
	if ctrl == nil {
		writeJSON(w, 400, map[string]string{"error": "replication is not configured on this node"})
		return
	}
	var in struct {
		NodeID  string `json:"node_id"`
		Address string `json:"address"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.NodeID == "" || in.Address == "" {
		writeJSON(w, 400, map[string]string{"error": "node_id and address are required"})
		return
	}
	if err := ctrl.Node().AddVoter(raft.ServerID(in.NodeID), raft.ServerAddress(in.Address)); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"joined": in.NodeID, "address": in.Address})
}
