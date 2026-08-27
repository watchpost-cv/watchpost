package history

import (
	"context"
	"errors"
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

func New(s *store.Store) *Store { return &Store{s: s} }
func (s *Store) Series(ctx context.Context, post, signal string, from, to time.Time, limit int) ([]Point, error) {
	if limit < 1 || limit > 10000 || !from.Before(to) || to.Sub(from) > 31*24*time.Hour {
		return nil, errors.New("invalid history window")
	}
	rows, err := s.s.DB.QueryContext(ctx, `SELECT observed_at,value,unit,quality FROM observations WHERE post_id=? AND signal=? AND observed_at>=? AND observed_at<=? ORDER BY observed_at LIMIT ?`, post, signal, from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), limit)
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
