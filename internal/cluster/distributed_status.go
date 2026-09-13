package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

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

type NodeResult[T any] struct {
	NodeID    string `json:"node_id"`
	OwnerNode string `json:"owner_node"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Value     *T     `json:"value,omitempty"`
}

type StatusReport struct {
	RequestID string                   `json:"request_id"`
	Partial   bool                     `json:"partial"`
	Results   []NodeResult[NodeStatus] `json:"results"`
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
	results := []NodeResult[NodeStatus]{{NodeID: local.NodeID, OwnerNode: local.NodeID, OK: true, Value: &local}}
	members, listErr := s.members.List(ctx)
	if listErr != nil {
		return StatusReport{RequestID: requestID, Partial: true, Results: results}
	}
	selected := selectMembers(members, target)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, member := range selected {
		member := member
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			result := NodeResult[NodeStatus]{NodeID: member.NodeID, OwnerNode: member.NodeID}
			resp, err := s.transport.Do(ctx, member.NodeID, http.MethodGet, "/api/cluster/v1/rpc/status", "cluster.health", nil)
			if err != nil {
				result.Error = err.Error()
			} else {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					result.Error = fmt.Sprintf("remote status %d", resp.StatusCode)
				} else {
					var value NodeStatus
					if err = json.NewDecoder(io.LimitReader(resp.Body, MaxRequestBytes)).Decode(&value); err != nil {
						result.Error = err.Error()
					} else {
						result.OK = true
						result.Value = &value
					}
				}
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].NodeID < results[j].NodeID })
	partial := false
	for _, r := range results {
		if !r.OK {
			partial = true
			break
		}
	}
	return StatusReport{RequestID: requestID, Partial: partial, Results: results}
}

func selectMembers(members []Member, target string) []Member {
	if target == "" || target == "all" || target == "members" {
		out := []Member{}
		for _, m := range members {
			if m.State == "active" {
				out = append(out, m)
			}
		}
		return out
	}
	for _, m := range members {
		if m.NodeID == target {
			if m.State == "active" {
				return []Member{m}
			}
			return nil
		}
	}
	return nil
}

func ValidateTarget(target string) error {
	if target == "" || target == "all" || target == "members" {
		return nil
	}
	if len(target) < 4 {
		return errors.New("invalid cluster target")
	}
	return nil
}
