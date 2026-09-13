package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
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
	RequestID string                    `json:"request_id"`
	Partial   bool                      `json:"partial"`
	Results   []NodeResult[NodeSummary] `json:"results"`
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
	results := []NodeResult[NodeSummary]{}
	local, localErr := s.LocalSummary(ctx, productVersion)
	if localErr == nil {
		results = append(results, NodeResult[NodeSummary]{NodeID: local.NodeID, OwnerNode: local.NodeID, OK: true, Value: &local})
	}
	members, listErr := s.members.List(ctx)
	if listErr != nil {
		return SummaryReport{RequestID: requestID, Partial: true, Results: results}
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
			result := NodeResult[NodeSummary]{NodeID: member.NodeID, OwnerNode: member.NodeID}
			resp, err := s.transport.Do(ctx, member.NodeID, http.MethodGet, "/api/cluster/v1/rpc/summary", "cluster.summary", nil)
			if err != nil {
				result.Error = err.Error()
			} else {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					result.Error = fmt.Sprintf("remote status %d", resp.StatusCode)
				} else {
					var value NodeSummary
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
	partial := localErr != nil
	for _, r := range results {
		if !r.OK {
			partial = true
		}
	}
	return SummaryReport{RequestID: requestID, Partial: partial, Results: results}
}
