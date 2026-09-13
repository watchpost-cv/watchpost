package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	corecluster "github.com/gantry-tools/gantry-core/cluster"

	"github.com/watchpost-cv/watchpost/internal/store"
)

type NodeStatus struct {
	NodeID          string    `json:"node_id"`
	DisplayName     string    `json:"display_name"`
	ProductVersion  string    `json:"product_version"`
	ProtocolVersion int       `json:"protocol_version"`
	CheckedAt       time.Time `json:"checked_at"`
	DatabaseReady   bool      `json:"database_ready"`
}

type StatusReport struct {
	RequestID string                               `json:"request_id"`
	Partial   bool                                 `json:"partial"`
	Results   []corecluster.NodeResult[NodeStatus] `json:"results"`
}

type DistributedService struct {
	s         *store.Store
	identity  *IdentityService
	members   *MemberService
	transport *Transport
	now       func() time.Time
}

func NewDistributedService(s *store.Store, identity *IdentityService, members *MemberService, transport *Transport) *DistributedService {
	return &DistributedService{s: s, identity: identity, members: members, transport: transport, now: time.Now}
}

func (s *DistributedService) LocalStatus(ctx context.Context, productVersion string) NodeStatus {
	identity, _ := s.identity.Ensure(ctx, productVersion)
	return NodeStatus{NodeID: identity.NodeID, DisplayName: identity.DisplayName, ProductVersion: productVersion, ProtocolVersion: ProtocolVersion, CheckedAt: s.now().UTC(), DatabaseReady: s.s.Ready(ctx) == nil}
}

func (s *DistributedService) ClusterStatus(ctx context.Context, productVersion string, target string) StatusReport {
	requestID, _ := randomID("fan_", 10)
	local := s.LocalStatus(ctx, productVersion)
	results := []corecluster.NodeResult[NodeStatus]{{NodeID: local.NodeID, OwnerNode: local.NodeID, OK: true, Value: &local}}
	members, listErr := s.members.List(ctx)
	if listErr != nil {
		return StatusReport{RequestID: requestID, Partial: true, Results: results}
	}
	selected := selectMembers(members, target)
	ids := make([]string, 0, len(selected))
	for _, member := range selected {
		ids = append(ids, member.NodeID)
	}
	remote := corecluster.FanOut(ctx, ids, 4, func(ctx context.Context, nodeID string) (NodeStatus, error) {
		resp, err := s.transport.Do(ctx, nodeID, http.MethodGet, "/api/cluster/v1/rpc/status", "cluster.health", nil)
		if err != nil {
			return NodeStatus{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return NodeStatus{}, fmt.Errorf("remote status %d", resp.StatusCode)
		}
		var value NodeStatus
		if err = json.NewDecoder(io.LimitReader(resp.Body, MaxRequestBytes)).Decode(&value); err != nil {
			return NodeStatus{}, err
		}
		return value, nil
	})
	results = append(results, remote...)
	sortNodeResults(results)
	return StatusReport{RequestID: requestID, Partial: corecluster.IsPartial(results), Results: results}
}

func sortNodeResults[T any](results []corecluster.NodeResult[T]) {
	sort.Slice(results, func(i, j int) bool { return results[i].NodeID < results[j].NodeID })
}

func selectMembers(members []Member, target string) []Member {
	parsed, err := corecluster.ParseTarget(target)
	if err != nil || parsed.Kind == corecluster.TargetLocal {
		return nil
	}
	out := []Member{}
	for _, m := range members {
		if m.State != corecluster.MemberActive {
			continue
		}
		if parsed.Kind == corecluster.TargetNode && m.NodeID != parsed.NodeID {
			continue
		}
		out = append(out, m)
	}
	return out
}

func ValidateTarget(target string) error { _, err := corecluster.ParseTarget(target); return err }
