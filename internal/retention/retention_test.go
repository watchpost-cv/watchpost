package retention

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/evidence"
	"github.com/watchpost-cv/watchpost/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedPost(t *testing.T, db *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC().Format(layout)
	if _, err := db.DB.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES(?,?,'host',?,?)`, id, id, now, now); err != nil {
		t.Fatal(err)
	}
}

func seedUser(t *testing.T, db *store.Store) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users(email,password_hash,role,created_at) VALUES('a@b.c',X'01','admin','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, db *store.Store, table string) int64 {
	t.Helper()
	var value int64
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func policy(overrides map[string]time.Duration) config.Retention {
	p := config.DefaultRetention()
	for name, value := range overrides {
		switch name {
		case "observations":
			p.Observations = value
		case "check_results":
			p.CheckResults = value
		case "logs":
			p.Logs = value
		case "changes":
			p.Changes = value
		case "alerts":
			p.AlertsResolved = value
		case "deliveries":
			p.Deliveries = value
		case "pairing_tokens":
			p.PairingTokens = value
		case "pairing_requests":
			p.PairingRequests = value
		case "inbox":
			p.FederationInbox = value
		case "outbox":
			p.FederationOutbox = value
		case "conversations":
			p.Conversations = value
		}
	}
	p.Interval = 0
	p.Batch = 5
	return p
}

func TestPrunesObservationsByObservedAt(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	if _, err := db.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('c','p',X'01')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, tc := range []struct {
		sequence int64
		age      time.Duration
	}{{1, 3 * time.Hour}, {2, 3 * time.Hour}, {3, 30 * time.Minute}} {
		at := now.Add(-tc.age).Format(layout)
		if _, err := db.DB.Exec(`INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,unit,quality,labels_json) VALUES('p','c',?,?,?,'cpu.percent','percent','good','{}')`, at, at, tc.sequence); err != nil {
			t.Fatal(err)
		}
	}
	service := NewAt(db, policy(map[string]time.Duration{"observations": time.Hour}), func() time.Time { return now })
	report, err := service.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "observations"); got != 1 {
		t.Fatalf("observations=%d want 1", got)
	}
	if report.Categories["observations"] != 2 {
		t.Fatalf("reported=%d want 2", report.Categories["observations"])
	}
}

func TestPrunesLogsAndChangesByTime(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	now := time.Now().UTC()
	if _, err := db.DB.Exec(`INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message) VALUES('p','sys',?,?,'info','old')`, now.Add(-3*time.Hour).Format(layout), now.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message) VALUES('p','sys',?,?,'info','new')`, now.Add(-time.Hour).Format(layout), now.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO changes(post_id,kind,occurred_at,actor,summary) VALUES('p','deploy',?,'ops','old')`, now.Add(-3*time.Hour).Format(layout)); err != nil {
		t.Fatal(err)
	}
	service := NewAt(db, policy(map[string]time.Duration{"logs": 2 * time.Hour, "changes": 2 * time.Hour}), func() time.Time { return now })
	if _, err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "logs"); got != 1 {
		t.Fatalf("logs=%d want 1", got)
	}
	if got := count(t, db, "changes"); got != 0 {
		t.Fatalf("changes=%d want 0", got)
	}
}

func seedRule(t *testing.T, db *store.Store, ruleID, postID string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO rules(id,post_id,signal,operator,threshold,missing_policy,severity) VALUES(?,?,'cpu.percent','gt',80,'unknown','warning')`, ruleID, postID); err != nil {
		t.Fatal(err)
	}
}

func seedAlert(t *testing.T, db *store.Store, ruleID, postID, state string, opened, updated, resolved *time.Time) int64 {
	t.Helper()
	var resolvedValue any
	if resolved != nil {
		resolvedValue = resolved.UTC().Format(layout)
	}
	result, err := db.DB.Exec(`INSERT INTO alerts(rule_id,post_id,state,severity,opened_at,updated_at,resolved_at) VALUES(?,?,?,'warning',?,?,?)`, ruleID, postID, state, opened.UTC().Format(layout), updated.UTC().Format(layout), resolvedValue)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	return id
}

func TestAlertSemantics(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	now := time.Now().UTC()
	old := now.Add(-10 * 24 * time.Hour)
	recent := now.Add(-time.Hour)

	// Latest active alert is preserved regardless of age.
	seedRule(t, db, "r-a", "p")
	seedAlert(t, db, "r-a", "p", "firing", &old, &old, nil)

	// Superseded firing row ages out; the latest resolved row stays until its
	// own resolved window passes.
	seedRule(t, db, "r-b", "p")
	seedAlert(t, db, "r-b", "p", "firing", &old, &old, nil)
	seedAlert(t, db, "r-b", "p", "resolved", &old, &old, &recent)

	// Incident-linked old resolved alert is preserved.
	seedRule(t, db, "r-c", "p")
	incidentID := seedAlert(t, db, "r-c", "p", "resolved", &old, &old, &old)
	if _, err := db.DB.Exec(`INSERT INTO incidents(title,severity,status,created_at,updated_at) VALUES('i','warning','open',?,?)`, old.Format(layout), old.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO incident_alerts(incident_id,alert_id) VALUES(1,?)`, incidentID); err != nil {
		t.Fatal(err)
	}

	// Conversation-referenced old resolved alert is preserved.
	seedUser(t, db)
	seedRule(t, db, "r-d", "p")
	referenced := seedAlert(t, db, "r-d", "p", "resolved", &old, &old, &old)
	if _, err := db.DB.Exec(`INSERT INTO conversations(user_id,created_at) VALUES(1,?)`, old.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO conversation_messages(conversation_id,at,role,body) VALUES(1,?,'user','q')`, old.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO conversation_evidence(conversation_id,message_id,kind,evidence_id,summary,cited_at) VALUES(1,1,'alert',?,'referenced',?)`, referenced, old.Format(layout)); err != nil {
		t.Fatal(err)
	}

	// Unreferenced old resolved alert ages out.
	seedRule(t, db, "r-e", "p")
	seedAlert(t, db, "r-e", "p", "resolved", &old, &old, &old)

	service := NewAt(db, policy(map[string]time.Duration{"alerts": 24 * time.Hour}), func() time.Time { return now })
	if _, err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	var remaining []string
	rows, err := db.DB.Query(`SELECT rule_id FROM alerts ORDER BY rule_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var rule string
		if err := rows.Scan(&rule); err != nil {
			t.Fatal(err)
		}
		remaining = append(remaining, rule)
	}
	want := []string{"r-a", "r-b", "r-c", "r-d"}
	if len(remaining) != len(want) {
		t.Fatalf("remaining rules=%v want %v", remaining, want)
	}
	for i := range want {
		if remaining[i] != want[i] {
			t.Fatalf("remaining rules=%v want %v", remaining, want)
		}
	}
}

func TestCitationSnapshotSurvivesRawPrune(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	seedUser(t, db)
	now := time.Now().UTC()
	result, err := db.DB.Exec(`INSERT INTO logs(post_id,source,observed_at,ingested_at,severity,message) VALUES('p','sys','?','?','info','cited message')`, now.Add(-3*time.Hour).Format(layout), now.Format(layout))
	if err != nil {
		t.Fatal(err)
	}
	logID, _ := result.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO conversations(user_id,created_at) VALUES(1,?)`, now.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO conversation_messages(conversation_id,at,role,body) VALUES(1,?,'user','q')`, now.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO conversation_evidence(conversation_id,message_id,kind,evidence_id,summary,cited_at) VALUES(1,1,'log',?,'cited message',?)`, logID, now.Format(layout)); err != nil {
		t.Fatal(err)
	}
	service := NewAt(db, policy(map[string]time.Duration{"logs": 2 * time.Hour}), func() time.Time { return now })
	if _, err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "logs"); got != 1 {
		t.Fatalf("cited log was pruned; logs=%d want 1", got)
	}
	// The snapshot survives even after the raw row is deliberately removed.
	if _, err := db.DB.Exec(`DELETE FROM logs WHERE id=?`, logID); err != nil {
		t.Fatal(err)
	}
	evidenceStore := evidence.New(db)
	reference, err := evidenceStore.FindPurgedReference(context.Background(), "log", logID)
	if err != nil {
		t.Fatalf("purged reference missing: %v", err)
	}
	if reference.Kind != "log" || reference.Summary != "cited message" {
		t.Fatalf("unexpected reference %#v", reference)
	}
}

func TestPairingRequestsAndTokensTerminalCleanup(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	hash := []byte{1}
	insertRequest := func(state, created, expires string, terminal any) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO agent_pairing_requests(id,request_secret_hash,installation_id,hostname,platform,agent_version,phrase,state,post_id,expires_at,created_at,terminal_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, state+created, hash, "i-"+state+created, "h", "linux", "v", "phrase", state, "p", expires, created, terminal); err != nil {
			t.Fatal(err)
		}
	}
	insertRequest("consumed", old.Format(layout), old.Format(layout), old.Format(layout))
	insertRequest("rejected", old.Format(layout), old.Format(layout), old.Format(layout))
	insertRequest("pending", now.Format(layout), now.Add(10*time.Minute).Format(layout), nil)
	insertRequest("pending", old.Format(layout), old.Format(layout), nil)

	if _, err := db.DB.Exec(`INSERT INTO collector_pairing_tokens(token_hash,post_id,expires_at,used_at) VALUES(?,?,?,?)`, []byte{2}, "p", old.Format(layout), old.Format(layout)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO collector_pairing_tokens(token_hash,post_id,expires_at) VALUES(?,?,?)`, []byte{3}, "p", now.Add(10*time.Minute).Format(layout)); err != nil {
		t.Fatal(err)
	}

	service := NewAt(db, policy(map[string]time.Duration{"pairing_requests": 7 * 24 * time.Hour, "pairing_tokens": 7 * 24 * time.Hour}), func() time.Time { return now })
	if _, err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "agent_pairing_requests"); got != 1 {
		t.Fatalf("pairing requests=%d want 1", got)
	}
	if got := count(t, db, "collector_pairing_tokens"); got != 1 {
		t.Fatalf("pairing tokens=%d want 1", got)
	}
}

func TestDisabledPolicyKeepsData(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	if _, err := db.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('c','p',X'01')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.DB.Exec(`INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,unit,quality,labels_json) VALUES('p','c',?,?,1,'cpu.percent','percent','good','{}')`, now.Add(-30*24*time.Hour).Format(layout), now.Format(layout)); err != nil {
		t.Fatal(err)
	}
	p := policy(nil)
	p.Observations = 0
	service := NewAt(db, p, func() time.Time { return now })
	if _, err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "observations"); got != 1 {
		t.Fatalf("observations=%d want 1 (disabled)", got)
	}
}

func TestRunOnceIsIdempotentAndBounded(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	if _, err := db.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('c','p',X'01')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for sequence := int64(1); sequence <= 12; sequence++ {
		at := now.Add(-3 * time.Hour).Format(layout)
		if _, err := db.DB.Exec(`INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,unit,quality,labels_json) VALUES('p','c',?,?,?,'cpu.percent','percent','good','{}')`, at, at, sequence); err != nil {
			t.Fatal(err)
		}
	}
	service := NewAt(db, policy(map[string]time.Duration{"observations": time.Hour}), func() time.Time { return now })
	report, err := service.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Categories["observations"] != 12 {
		t.Fatalf("reported=%d want 12", report.Categories["observations"])
	}
	if got := count(t, db, "observations"); got != 0 {
		t.Fatalf("observations=%d want 0", got)
	}
	second, err := service.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Total() != 0 {
		t.Fatalf("second pass removed %d rows", second.Total())
	}
}

func TestConcurrentRetentionAndIngestion(t *testing.T) {
	db := testStore(t)
	seedPost(t, db, "p")
	if _, err := db.DB.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES('c','p',X'01')`); err != nil {
		t.Fatal(err)
	}
	service := NewAt(db, policy(map[string]time.Duration{"observations": time.Hour}), time.Now)
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if _, err := service.RunOnce(context.Background()); err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for sequence := int64(1); sequence <= 30; sequence++ {
			at := time.Now().UTC().Add(-2 * time.Hour).Format(layout)
			if _, err := db.DB.Exec(`INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,unit,quality,labels_json) VALUES('p','c',?,?,?,'cpu.percent','percent','good','{}')`, at, at, sequence); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent run failed: %v", err)
	}
	if _, err := service.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := count(t, db, "observations"); got != 0 {
		t.Fatalf("observations=%d want 0 after draining", got)
	}
}

func TestMigrationProvidesEvidenceSnapshotTable(t *testing.T) {
	db := testStore(t)
	var present int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='conversation_evidence'`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present != 1 {
		t.Fatal("conversation_evidence table missing after migration")
	}
}
