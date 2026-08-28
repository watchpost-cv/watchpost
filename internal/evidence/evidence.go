package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/watchpost-ops/watchpost/internal/store"
	"strings"
	"time"
)

type Log struct {
	ID         int64             `json:"id"`
	PostID     string            `json:"post_id"`
	Source     string            `json:"source"`
	ObservedAt time.Time         `json:"observed_at"`
	Severity   string            `json:"severity"`
	Message    string            `json:"message"`
	Fields     map[string]string `json:"fields"`
	Truncated  bool              `json:"truncated"`
}
type Change struct {
	ID             int64     `json:"id"`
	PostID         string    `json:"post_id"`
	Kind           string    `json:"kind"`
	OccurredAt     time.Time `json:"occurred_at"`
	Actor, Summary string
	Detail         map[string]any
}
type Store struct {
	s   *store.Store
	now func() time.Time
}

func New(s *store.Store) *Store { return &Store{s: s, now: time.Now} }
func (s *Store) IngestLog(ctx context.Context, l Log) (Log, error) {
	if l.PostID == "" || l.Source == "" || l.ObservedAt.IsZero() || len(l.Fields) > 32 {
		return Log{}, errors.New("invalid log")
	}
	if len(l.Message) > 8192 {
		l.Message = l.Message[:8192]
		l.Truncated = true
	}
	l.Message = redact(l.Message)
	for k, v := range l.Fields {
		if len(k) > 64 || len(v) > 1024 {
			return Log{}, errors.New("invalid log fields")
		}
		l.Fields[k] = redact(v)
	}
	fields, _ := json.Marshal(l.Fields)
	result, err := s.s.DB.ExecContext(ctx, `INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message,fields_json,truncated) VALUES(?,?,?,?,?,?,?,?)`, l.PostID, l.Source, l.ObservedAt.UTC().Format(time.RFC3339Nano), s.now().UTC().Format(time.RFC3339Nano), l.Severity, l.Message, string(fields), l.Truncated)
	if err != nil {
		return Log{}, err
	}
	l.ID, _ = result.LastInsertId()
	return l, nil
}
func (s *Store) SearchLogs(ctx context.Context, post, query string, from, to time.Time, limit int) ([]Log, error) {
	if limit < 1 || limit > 1000 || len(query) > 200 || !from.Before(to) {
		return nil, errors.New("invalid log query")
	}
	rows, err := s.s.DB.QueryContext(ctx, `SELECT id,post_id,source,observed_at,severity,message,fields_json,truncated FROM logs WHERE post_id=? AND observed_at>=? AND observed_at<=? AND message LIKE ? ORDER BY observed_at DESC,id DESC LIMIT ?`, post, from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano), "%"+strings.ReplaceAll(query, "%", "\\%")+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Log{}
	for rows.Next() {
		var l Log
		var at, fields string
		if err = rows.Scan(&l.ID, &l.PostID, &l.Source, &at, &l.Severity, &l.Message, &fields, &l.Truncated); err != nil {
			return nil, err
		}
		l.ObservedAt, _ = time.Parse(time.RFC3339Nano, at)
		_ = json.Unmarshal([]byte(fields), &l.Fields)
		items = append(items, l)
	}
	return items, rows.Err()
}
func (s *Store) GetLog(ctx context.Context, id int64) (Log, error) {
	var l Log
	var at, fields string
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,post_id,source,observed_at,severity,message,fields_json,truncated FROM logs WHERE id=?`, id).Scan(&l.ID, &l.PostID, &l.Source, &at, &l.Severity, &l.Message, &fields, &l.Truncated)
	if err != nil {
		return Log{}, err
	}
	l.ObservedAt, _ = time.Parse(time.RFC3339Nano, at)
	_ = json.Unmarshal([]byte(fields), &l.Fields)
	return l, nil
}
func (s *Store) GetChange(ctx context.Context, id int64) (Change, error) {
	var c Change
	var at, detail string
	err := s.s.DB.QueryRowContext(ctx, `SELECT id,COALESCE(post_id,''),kind,occurred_at,actor,summary,detail_json FROM changes WHERE id=?`, id).Scan(&c.ID, &c.PostID, &c.Kind, &at, &c.Actor, &c.Summary, &detail)
	if err != nil {
		return Change{}, err
	}
	c.OccurredAt, _ = time.Parse(time.RFC3339Nano, at)
	_ = json.Unmarshal([]byte(detail), &c.Detail)
	return c, nil
}
func (s *Store) RecordChange(ctx context.Context, c Change) (Change, error) {
	if c.Kind == "" || c.Summary == "" || len(c.Summary) > 1000 {
		return Change{}, errors.New("invalid change")
	}
	if c.OccurredAt.IsZero() {
		c.OccurredAt = s.now().UTC()
	}
	detail, _ := json.Marshal(c.Detail)
	result, err := s.s.DB.ExecContext(ctx, `INSERT INTO changes(post_id,kind,occurred_at,actor,summary,detail_json) VALUES(?,?,?,?,?,?)`, nullable(c.PostID), c.Kind, c.OccurredAt.Format(time.RFC3339Nano), c.Actor, c.Summary, string(detail))
	if err != nil {
		return Change{}, err
	}
	c.ID, _ = result.LastInsertId()
	return c, nil
}
func redact(value string) string {
	words := strings.Fields(value)
	for i, w := range words {
		lower := strings.ToLower(w)
		if strings.Contains(lower, "password=") || strings.Contains(lower, "token=") || strings.Contains(lower, "authorization:") {
			parts := strings.SplitN(w, "=", 2)
			if len(parts) == 2 {
				words[i] = parts[0] + "=[REDACTED]"
			} else {
				words[i] = "[REDACTED]"
			}
		}
	}
	return strings.Join(words, " ")
}
func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}
