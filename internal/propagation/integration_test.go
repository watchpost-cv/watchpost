package propagation

import (
	"context"
	"testing"
	"time"

	coreprop "github.com/gantry-tools/gantry-core/propagation"
	"github.com/watchpost-cv/watchpost/internal/store"
)

func newPropStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedPost(t *testing.T, s *store.Store, id string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO posts(id,name,kind,owner,labels_json,maintenance,archived,version,created_at,updated_at) VALUES(?,?,?,?,'{}',0,0,1,?,?)`, id, id, "host", "", now, now); err != nil {
		t.Fatal(err)
	}
}

func seedRule(t *testing.T, s *store.Store, id, postID, threshold string, version int64) {
	t.Helper()
	if _, err := s.DB.Exec(`INSERT INTO rules(id,post_id,signal,operator,threshold,duration_seconds,recovery_threshold,missing_policy,severity,enabled,version) VALUES(?,?,?,?,?,?,?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET threshold=excluded.threshold,version=excluded.version`, id, postID, "cpu.percent", "gt", threshold, 120, nil, "unknown", "warning", version); err != nil {
		t.Fatal(err)
	}
}

func ruleCount(t *testing.T, s *store.Store, id string) (int64, string) {
	t.Helper()
	var v int64
	var threshold string
	if err := s.DB.QueryRow(`SELECT version,threshold FROM rules WHERE id=?`, id).Scan(&v, &threshold); err != nil {
		t.Fatalf("rule %s missing on target: %v", id, err)
	}
	return v, threshold
}

// TestPropagationRoundTripAtoB exercises the exact export -> preview -> apply
// path between two real Watchpost stores using the production Manager and
// adapter machinery. It proves a rule exported on A as the alert-policy kind
// is applied on B, is idempotent, tracks an update, and leaves unsupported
// local-only objects untouched.
func TestPropagationRoundTripAtoB(t *testing.T) {
	ctx := context.Background()
	a := newPropStore(t)
	b := newPropStore(t)
	seedPost(t, a, "shared-post")
	seedPost(t, b, "shared-post") // dependency present on target
	seedRule(t, a, "shared-cpu-high", "shared-post", "95", 1)

	ma := &coreprop.Manager{Adapter: New(a), Store: NewStateStore(a)}
	mb := &coreprop.Manager{Adapter: New(b), Store: NewStateStore(b)}
	actor := coreprop.Actor{Kind: "user", ID: "1", Permission: "alert.update"}

	// Export from A.
	envs, err := ma.Export(ctx, []string{"alert-policy"}, actor, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 1 || envs[0].Kind != "alert-policy" || envs[0].ID != "shared-cpu-high" {
		t.Fatalf("unexpected export: %+v", envs)
	}

	// Preview on B.
	pv, err := mb.Preview(ctx, envs, actor)
	if err != nil {
		t.Fatal(err)
	}
	if !pv.Applicable {
		t.Fatalf("preview not applicable: %+v", pv)
	}

	// Apply on B.
	if _, err := mb.Apply(ctx, "plan-1", envs, actor, "all"); err != nil {
		t.Fatal(err)
	}
	if v, th := ruleCount(t, b, "shared-cpu-high"); v != 1 || th != "95" {
		t.Fatalf("B rule after apply: version=%d threshold=%q", v, th)
	}

	// Idempotent re-apply: no error, same revision, no duplicate rows.
	if _, err := mb.Apply(ctx, "plan-2", envs, actor, "all"); err != nil {
		t.Fatalf("re-apply failed: %v", err)
	}
	var count int
	if err := b.DB.QueryRow(`SELECT COUNT(*) FROM rules WHERE id='shared-cpu-high'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("idempotent apply produced %d rows", count)
	}

	// Update on A propagates to B.
	seedRule(t, a, "shared-cpu-high", "shared-post", "99", 2)
	envs2, err := ma.Export(ctx, []string{"alert-policy"}, actor, "all")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mb.Apply(ctx, "plan-3", envs2, actor, "all"); err != nil {
		t.Fatal(err)
	}
	if v, th := ruleCount(t, b, "shared-cpu-high"); v != 2 || th != "99" {
		t.Fatalf("B rule after update: version=%d threshold=%q", v, th)
	}

	// Unsupported / local-only objects remain local: exporting a kind that has
	// no adapter mapping yields no envelopes, and local-only state (e.g. a
	// post) is never emitted.
	envs3, err := ma.Export(ctx, []string{"does-not-exist"}, actor, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(envs3) != 0 {
		t.Fatalf("unknown kind exported envelopes: %+v", envs3)
	}
	var postCount int
	if err := b.DB.QueryRow(`SELECT COUNT(*) FROM posts WHERE id='shared-post'`).Scan(&postCount); err != nil || postCount != 1 {
		t.Fatalf("B post count=%d", postCount)
	}

}