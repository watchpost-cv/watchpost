package history

import (
	"context"
	"fmt"
	"github.com/watchpost-ops/watchpost/internal/store"
	"path/filepath"
	"testing"
	"time"
)

func TestSurveyBoundsFiveHundredPosts(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		post := fmt.Sprintf("p-%03d", i)
		if _, err = tx.Exec(`INSERT INTO posts(id,name,kind,created_at,updated_at) VALUES(?,?,'host',?,?)`, post, post, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`INSERT INTO collector_keys(id,post_id,secret_hash) VALUES(?,?,X'01')`, "c-"+post, post); err != nil {
			t.Fatal(err)
		}
		for n := 0; n < 40; n++ {
			if _, err = tx.Exec(`INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES(?,?,?,?,?,'cpu.percent',42,'percent','good','{}')`, post, "c-"+post, now.Add(time.Duration(n-40)*time.Minute).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), n+1); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	series, err := New(db).Survey(ctx, now.Add(-time.Hour), 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 500 {
		t.Fatalf("series=%d", len(series))
	}
	for _, item := range series {
		if len(item.Points) > 30 {
			t.Fatalf("unbounded points=%d", len(item.Points))
		}
	}
}
