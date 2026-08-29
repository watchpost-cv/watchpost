package history

import (
	"context"
	"errors"
	"strings"
	"github.com/watchpost-ops/watchpost/internal/contract"
	"github.com/watchpost-ops/watchpost/internal/store"
	"time"
)

type Point struct {
	ObservedAt time.Time `json:"observed_at"`
	Value      *float64  `json:"value"`
	Unit       string    `json:"unit"`
	Quality    string    `json:"quality"`
}
type Store struct{ s *store.Store }

type SurveySeries struct {
	PostID string  `json:"post_id"`
	Signal string  `json:"signal"`
	Points []Point `json:"points"`
}

func New(s *store.Store) *Store { return &Store{s: s} }

// Survey returns a bounded set of recent resource points for every post in one
// query. This keeps the overview useful for large inventories without turning
// one browser refresh into hundreds of history requests.
func (s *Store) Survey(ctx context.Context, from time.Time, pointsPerSeries int) ([]SurveySeries, error) {
	if pointsPerSeries < 2 || pointsPerSeries > 120 {
		return nil, errors.New("invalid survey limit")
	}
	rows, err := s.s.DB.QueryContext(ctx, `
		SELECT post_id,signal,observed_at,value,unit,quality FROM (
			SELECT post_id,signal,observed_at,value,unit,quality,
			ROW_NUMBER() OVER (PARTITION BY post_id,signal ORDER BY observed_at DESC) AS position
			FROM observations
			WHERE observed_at>=? AND signal IN ('cpu.percent','memory.percent','disk.percent')
		) WHERE position<=? ORDER BY post_id,signal,observed_at`, from.UTC().Format(time.RFC3339Nano), pointsPerSeries)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SurveySeries{}
	index := map[string]int{}
	for rows.Next() {
		var postID, signal, at string
		var point Point
		if err = rows.Scan(&postID, &signal, &at, &point.Value, &point.Unit, &point.Quality); err != nil {
			return nil, err
		}
		point.ObservedAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		key := postID + "\x00" + signal
		position, ok := index[key]
		if !ok {
			position = len(items)
			index[key] = position
			items = append(items, SurveySeries{PostID: postID, Signal: signal, Points: []Point{}})
		}
		items[position].Points = append(items[position].Points, point)
	}
	return items, rows.Err()
}
func (s *Store) Series(ctx context.Context, post, signal string, from, to time.Time, limit int) ([]Point, error) {
	if limit < 1 || limit > 10000 || !from.Before(to) || to.Sub(from) > 31*24*time.Hour {
		return nil, errors.New("invalid history window")
	}
	signals := []string{signal}
	if canonical, ok := contract.LegacySignalAliases[signal]; ok {
		signals = append(signals, canonical)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(signals)), ",")
	args := []any{post}
	for _, item := range signals {
		args = append(args, item)
	}
	args = append(args, from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), limit)
	rows, err := s.s.DB.QueryContext(ctx, `SELECT observed_at,value,unit,quality FROM observations WHERE post_id=? AND signal IN (`+placeholders+`) AND observed_at>=? AND observed_at<=? ORDER BY observed_at LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := []Point{}
	for rows.Next() {
		var p Point
		var at string
		if err = rows.Scan(&at, &p.Value, &p.Unit, &p.Quality); err != nil {
			return nil, err
		}
		p.ObservedAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}
func (s *Store) Retain(ctx context.Context, before time.Time, batch int) (int64, error) {
	if batch < 1 || batch > 10000 {
		return 0, errors.New("invalid retention batch")
	}
	result, err := s.s.DB.ExecContext(ctx, `DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE observed_at<? ORDER BY id LIMIT ?)`, before.UTC().Format(time.RFC3339Nano), batch)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
