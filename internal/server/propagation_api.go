package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	core "github.com/gantry-tools/gantry-core/propagation"
	product "github.com/watchpost-cv/watchpost/internal/propagation"
)

type propagationRequest struct {
	Kinds     []string        `json:"kinds,omitempty"`
	Target    string          `json:"target,omitempty"`
	Envelopes []core.Envelope `json:"envelopes,omitempty"`
	PlanID    string          `json:"plan_id,omitempty"`
	Selector  core.Selector   `json:"selector,omitempty"`
	DryRun    bool            `json:"dry_run,omitempty"`
}

func propActor(r *http.Request) core.Actor {
	u := currentUser(r)
	return core.Actor{Kind: "user", ID: strconv.FormatInt(u.ID, 10)}
}

func (s *Server) registerPropagationAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/cluster/propagation/kinds", s.require("viewer", s.handlePropagationKinds))
	mux.HandleFunc("POST /api/v1/cluster/propagation/export", s.require("admin", s.handlePropagationExport))
	mux.HandleFunc("POST /api/v1/cluster/propagation/preview", s.require("admin", s.handlePropagationPreview))
	mux.HandleFunc("POST /api/v1/cluster/propagation/apply", s.require("admin", s.handlePropagationApply))
	mux.HandleFunc("POST /api/v1/cluster/propagation/propagate", s.require("admin", s.handlePropagationPropagate))
	mux.HandleFunc("GET /api/v1/cluster/propagation/history", s.require("viewer", s.handlePropagationHistory))
	mux.HandleFunc("GET /api/v1/cluster/propagation/profiles", s.require("viewer", s.handlePropagationProfiles))
	mux.HandleFunc("PUT /api/v1/cluster/propagation/profiles/{id}", s.require("admin", s.handlePropagationProfilePut))
	mux.HandleFunc("DELETE /api/v1/cluster/propagation/profiles/{id}", s.require("admin", s.handlePropagationProfileDelete))
	mux.HandleFunc("POST /api/cluster/v1/rpc/propagation/preview", s.handlePropagationRPCPreview)
	mux.HandleFunc("POST /api/cluster/v1/rpc/propagation/apply", s.handlePropagationRPCApply)
}
func (s *Server) handlePropagationKinds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.propagation.Adapter.Kinds())
}
func (s *Server) handlePropagationExport(w http.ResponseWriter, r *http.Request) {
	var q propagationRequest
	if !decode(w, r, &q) {
		return
	}
	v, e := s.propagation.Export(r.Context(), q.Kinds, propActor(r), q.Target)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationPreview(w http.ResponseWriter, r *http.Request) {
	var q propagationRequest
	if !decode(w, r, &q) {
		return
	}
	v, e := s.propagation.Preview(r.Context(), q.Envelopes, propActor(r))
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationApply(w http.ResponseWriter, r *http.Request) {
	var q propagationRequest
	if !decode(w, r, &q) {
		return
	}
	if q.PlanID == "" {
		q.PlanID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	v, e := s.propagation.Apply(r.Context(), q.PlanID, q.Envelopes, propActor(r), q.Target)
	if e != nil {
		writeJSON(w, 409, map[string]any{"error": e.Error(), "result": v})
		return
	}
	s.audit(r, "propagation_apply", "cluster", q.Target, q.PlanID)
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationHistory(w http.ResponseWriter, r *http.Request) {
	v, e := s.propagation.History(r.Context(), 50)
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationProfiles(w http.ResponseWriter, r *http.Request) {
	v, e := s.propagation.Profiles(r.Context())
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationProfilePut(w http.ResponseWriter, r *http.Request) {
	var p core.Profile
	if !decode(w, r, &p) {
		return
	}
	p.ID = r.PathValue("id")
	if e := s.propagation.SaveProfile(r.Context(), p); e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	s.audit(r, "propagation_profile_save", "propagation_profile", p.ID, p.Name)
	w.WriteHeader(204)
}
func (s *Server) handlePropagationProfileDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if e := product.NewStateStore(s.store).DeleteProfile(r.Context(), id); e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	s.audit(r, "propagation_profile_delete", "propagation_profile", id, "")
	w.WriteHeader(204)
}
func decodeRPCBody(r *http.Request, dst any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(dst)
}
func (s *Server) handlePropagationRPCPreview(w http.ResponseWriter, r *http.Request) {
	auth, e := s.clusterTransport.Authenticate(r, "cluster.propagation")
	if e != nil {
		writeJSON(w, 401, map[string]string{"error": e.Error()})
		return
	}
	var q propagationRequest
	if e = decodeRPCBody(r, &q); e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	v, e := s.propagation.Preview(r.Context(), q.Envelopes, core.Actor{Kind: "node", ID: auth.NodeID})
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) handlePropagationRPCApply(w http.ResponseWriter, r *http.Request) {
	auth, e := s.clusterTransport.Authenticate(r, "cluster.propagation")
	if e != nil {
		writeJSON(w, 401, map[string]string{"error": e.Error()})
		return
	}
	var q propagationRequest
	if e = decodeRPCBody(r, &q); e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	v, e := s.propagation.Apply(r.Context(), q.PlanID, q.Envelopes, core.Actor{Kind: "node", ID: auth.NodeID}, auth.NodeID)
	if e != nil {
		writeJSON(w, 409, map[string]any{"error": e.Error(), "result": v})
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) remotePropagationPreview(ctx context.Context, node string, env []core.Envelope, actor core.Actor) (core.Preview, error) {
	b, _ := json.Marshal(propagationRequest{Envelopes: env})
	resp, e := s.clusterTransport.Do(ctx, node, http.MethodPost, "/api/cluster/v1/rpc/propagation/preview", "cluster.propagation", b)
	if e != nil {
		return core.Preview{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return core.Preview{}, fmt.Errorf("remote status %d", resp.StatusCode)
	}
	var v core.Preview
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v)
	return v, e
}
func (s *Server) remotePropagationApply(ctx context.Context, node, plan string, env []core.Envelope, actor core.Actor) (core.ApplyBundleResult, error) {
	b, _ := json.Marshal(propagationRequest{PlanID: plan, Envelopes: env})
	resp, e := s.clusterTransport.Do(ctx, node, http.MethodPost, "/api/cluster/v1/rpc/propagation/apply", "cluster.propagation", b)
	if e != nil {
		return core.ApplyBundleResult{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return core.ApplyBundleResult{}, fmt.Errorf("remote status %d", resp.StatusCode)
	}
	var v core.ApplyBundleResult
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v)
	return v, e
}
func (s *Server) handlePropagationPropagate(w http.ResponseWriter, r *http.Request) {
	var q propagationRequest
	if !decode(w, r, &q) {
		return
	}
	actor := propActor(r)
	env, e := s.propagation.Export(r.Context(), q.Kinds, actor, "members")
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	members, e := s.clusterMembers.List(r.Context())
	if e != nil {
		writeJSON(w, 500, map[string]string{"error": e.Error()})
		return
	}
	ms := make([]core.Member, 0, len(members))
	for _, m := range members {
		ms = append(ms, core.Member{ID: m.NodeID, Capabilities: m.Capabilities, Enabled: m.State == "active"})
	}
	nodes, e := core.Select(q.Selector, ms)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	pre := core.PreviewNodes(r.Context(), nodes, env, actor, 4, s.remotePropagationPreview)
	blocked := false
	for _, x := range pre {
		if x.Error != "" || !x.Preview.Applicable {
			blocked = true
		}
	}
	if q.DryRun || blocked {
		writeJSON(w, 200, map[string]any{"preview": pre, "applicable": !blocked})
		return
	}
	if q.PlanID == "" {
		q.PlanID = fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	results := core.ApplyNodes(r.Context(), nodes, q.PlanID, env, actor, 4, s.remotePropagationApply)
	s.audit(r, "propagation_fanout", "cluster", "members", q.PlanID)
	writeJSON(w, 200, map[string]any{"plan_id": q.PlanID, "preview": pre, "results": results})
}
