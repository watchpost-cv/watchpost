package collectorclient

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPairWritesPrivateConfigAndRequiresTLS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"version":1,"post_id":"host-a","collector_id":"agent-a","secret":"secret"}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "collector.json")
	config, err := Pair(server.URL, "token", "agent-a", path, server.Client())
	if err != nil || config.PostID != "host-a" {
		t.Fatalf("%#v %v", config, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if _, err = Pair("http://example.com", "token", "agent", path, nil); err == nil {
		t.Fatal("allowed cleartext remote pairing")
	}
}
