package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/store"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

type Route struct {
	ID, Kind, Destination, Secret string
	Enabled                       bool
}
type Message struct {
	AlertID  int64  `json:"alert_id"`
	PostID   string `json:"post_id"`
	State    string `json:"state"`
	Severity string `json:"severity"`
}
type RouteStatus struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Destination string `json:"destination"`
	Enabled     bool   `json:"enabled"`
	Pending     int    `json:"pending"`
	Retrying    int    `json:"retrying"`
	Delivered   int    `json:"delivered"`
}

func (s *Service) ListRoutes(ctx context.Context) ([]RouteStatus, error) {
	rows, err := s.s.DB.QueryContext(ctx, `SELECT r.id,r.kind,r.destination,r.enabled,COALESCE(SUM(CASE WHEN d.state='pending' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN d.state='retry' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN d.state='delivered' THEN 1 ELSE 0 END),0) FROM notification_routes r LEFT JOIN notification_deliveries d ON d.route_id=r.id GROUP BY r.id,r.kind,r.destination,r.enabled ORDER BY r.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RouteStatus{}
	for rows.Next() {
		var i RouteStatus
		if err = rows.Scan(&i.ID, &i.Kind, &i.Destination, &i.Enabled, &i.Pending, &i.Retrying, &i.Delivered); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	return items, rows.Err()
}

type Sender interface {
	Send(context.Context, Route, Message) error
}
type Service struct {
	s      *store.Store
	sender Sender
	now    func() time.Time
}

func New(s *store.Store, sender Sender) *Service {
	return &Service{s: s, sender: sender, now: time.Now}
}
func (s *Service) CreateRoute(ctx context.Context, r Route, entry audit.Entry) error {
	if r.ID == "" || !map[string]bool{"webhook": true, "email": true}[r.Kind] || r.Destination == "" {
		return errors.New("invalid route")
	}
	tx, err := s.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO notification_routes(id,kind,destination,secret,enabled) VALUES(?,?,?,?,?)`, r.ID, r.Kind, r.Destination, r.Secret, r.Enabled); err != nil {
		return err
	}
	entry.ObjectType = "notification_route"
	entry.ObjectID = r.ID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Service) Queue(ctx context.Context, alertID int64) error {
	_, err := s.s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO notification_deliveries(alert_id,route_id,state,next_attempt_at) SELECT ?,id,'pending',? FROM notification_routes WHERE enabled=1`, alertID, s.now().UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Service) DeliverDue(ctx context.Context, limit int) error {
	if limit < 1 || limit > 100 {
		return errors.New("invalid delivery limit")
	}
	rows, err := s.s.DB.QueryContext(ctx, `SELECT d.id,d.alert_id,d.attempts,r.id,r.kind,r.destination,r.secret,r.enabled,a.post_id,a.state,a.severity FROM notification_deliveries d JOIN notification_routes r ON r.id=d.route_id JOIN alerts a ON a.id=d.alert_id WHERE d.state IN ('pending','retry') AND d.next_attempt_at<=? ORDER BY d.id LIMIT ?`, s.now().UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return err
	}
	type item struct {
		id, alert int64
		attempts  int
		route     Route
		message   Message
	}
	items := []item{}
	for rows.Next() {
		var i item
		if err = rows.Scan(&i.id, &i.alert, &i.attempts, &i.route.ID, &i.route.Kind, &i.route.Destination, &i.route.Secret, &i.route.Enabled, &i.message.PostID, &i.message.State, &i.message.Severity); err != nil {
			rows.Close()
			return err
		}
		i.message.AlertID = i.alert
		items = append(items, i)
	}
	rows.Close()
	for _, i := range items {
		err = s.sender.Send(ctx, i.route, i.message)
		if err == nil {
			_, _ = s.s.DB.ExecContext(ctx, `UPDATE notification_deliveries SET state='delivered',attempts=attempts+1,delivered_at=?,last_error='' WHERE id=?`, s.now().UTC().Format(time.RFC3339Nano), i.id)
		} else {
			delay := time.Duration(1<<min(i.attempts, 6)) * time.Minute
			_, _ = s.s.DB.ExecContext(ctx, `UPDATE notification_deliveries SET state='retry',attempts=attempts+1,next_attempt_at=?,last_error=? WHERE id=?`, s.now().Add(delay).UTC().Format(time.RFC3339Nano), truncate(err.Error(), 300), i.id)
		}
	}
	return nil
}

type NetworkSender struct {
	Client      *http.Client
	SMTPAddress string
}

func (n NetworkSender) Send(ctx context.Context, r Route, m Message) error {
	switch r.Kind {
	case "webhook":
		return n.webhook(ctx, r, m)
	case "email":
		return n.email(r, m)
	}
	return errors.New("unsupported route")
}
func (n NetworkSender) webhook(ctx context.Context, r Route, m Message) error {
	u, err := url.Parse(r.Destination)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("invalid webhook URL")
	}
	body, _ := json.Marshal(m)
	request, _ := http.NewRequestWithContext(ctx, "POST", r.Destination, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if r.Secret != "" {
		request.Header.Set("Authorization", "Bearer "+r.Secret)
	}
	response, err := n.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", response.StatusCode)
	}
	return nil
}
func (n NetworkSender) email(r Route, m Message) error {
	parts := strings.Split(r.Destination, "|")
	if len(parts) != 2 {
		return errors.New("email destination must be from|to")
	}
	message := []byte(fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: Watchpost alert %d\r\n\r\nPost %s is %s (%s).\r\n", parts[1], parts[0], m.AlertID, m.PostID, m.State, m.Severity))
	return smtp.SendMail(n.SMTPAddress, nil, parts[0], []string{parts[1]}, message)
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
