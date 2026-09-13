package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	corecluster "github.com/gantry-tools/gantry-core/cluster"
)

type NodeSummary struct {
	NodeStatus
	Posts      int `json:"posts"`
	Agents     int `json:"agents"`
	Checks     int `json:"checks"`
	OpenAlerts int `json:"open_alerts"`
	Incidents  int `json:"incidents"`
}

type SummaryReport struct {
	RequestID string                                `json:"request_id"`
	Partial   bool                                  `json:"partial"`
	Results   []corecluster.NodeResult[NodeSummary] `json:"results"`
}

func (s *DistributedService) LocalSummary(ctx context.Context, productVersion string) (NodeSummary, error) {
	status := s.LocalStatus(ctx, productVersion)
	summary := NodeSummary{NodeStatus: status}
	queries := []struct {
		dst   *int
		query string
	}{
		{&summary.Posts, `SELECT COUNT(*) FROM posts WHERE archived=0`},
		{&summary.Agents, `SELECT COUNT(*) FROM agent_connections WHERE revoked_at IS NULL`},
		{&summary.Checks, `SELECT COUNT(*) FROM check_schedules WHERE enabled=1`},
		{&summary.OpenAlerts, `SELECT COUNT(*) FROM alerts WHERE state NOT IN ('resolved','closed')`},
		{&summary.Incidents, `SELECT COUNT(*) FROM incidents WHERE status!='resolved'`},
	}
	for _, q := range queries {
		if err := s.s.DB.QueryRowContext(ctx, q.query).Scan(q.dst); err != nil {
			return NodeSummary{}, err
		}
	}
	return summary, nil
}

func (s *DistributedService) ClusterSummary(ctx context.Context, productVersion, target string) SummaryReport {
	requestID, _ := randomID("fan_", 10)
	results := []corecluster.NodeResult[NodeSummary]{}
	local, localErr := s.LocalSummary(ctx, productVersion)
	if localErr == nil {
		results = append(results, corecluster.NodeResult[NodeSummary]{NodeID: local.NodeID, OwnerNode: local.NodeID, OK: true, Value: &local})
	}
	members, listErr := s.members.List(ctx)
	if listErr != nil {
		return SummaryReport{RequestID: requestID, Partial: true, Results: results}
	}
	selected := selectMembers(members, target)
	ids := make([]string, 0, len(selected))
	for _, member := range selected {
		ids = append(ids, member.NodeID)
	}
	remote := corecluster.FanOut(ctx, ids, 4, func(ctx context.Context, nodeID string) (NodeSummary, error) {
		resp, err := s.transport.Do(ctx, nodeID, http.MethodGet, "/api/cluster/v1/rpc/summary", "cluster.summary", nil)
		if err != nil {
			return NodeSummary{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return NodeSummary{}, fmt.Errorf("remote status %d", resp.StatusCode)
		}
		var value NodeSummary
		if err = json.NewDecoder(io.LimitReader(resp.Body, MaxRequestBytes)).Decode(&value); err != nil {
			return NodeSummary{}, err
		}
		return value, nil
	})
	results = append(results, remote...)
	sortNodeResults(results)
	return SummaryReport{RequestID: requestID, Partial: localErr != nil || corecluster.IsPartial(results), Results: results}
}
