package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/server"
	"github.com/watchpost-cv/watchpost/internal/store"
)

// writeTLSFiles materializes a cluster CA + a node cert/key as PEM files so the
// real config -> LoadReplicationTLS path reads them from disk.
func writeTLSFiles(t *testing.T, ca *testCA, nodeID, dir string) (certFile, keyFile, caFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: nodeID}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(dir, "ca.crt")
	certFile = filepath.Join(dir, "node.crt")
	keyFile = filepath.Join(dir, "node.key")
	for path, data := range map[string][]byte{
		caFile:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}),
		certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyFile:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile, caFile
}

// TestReplicationConfigToRuntime proves the real operator configuration path:
// WATCHPOST_REPLICATION_* environment variables -> config.Load ->
// cfg.Replication -> LoadReplicationTLS -> runtime.New (the cmd/watchpost
// construction path) -> durable raft files -> readiness -> HTTP mutation.
func TestReplicationConfigToRuntime(t *testing.T) {
	ca := newTestCA(t)
	dataDir := t.TempDir()
	addr := freeAddr(t)
	certFile, keyFile, caFile := writeTLSFiles(t, ca, "A", t.TempDir())

	t.Setenv("WATCHPOST_DATA_DIR", dataDir)
	t.Setenv("WATCHPOST_REPLICATION_ENABLED", "true")
	t.Setenv("WATCHPOST_REPLICATION_NODE_ID", "A")
	t.Setenv("WATCHPOST_REPLICATION_BOOTSTRAP", "true")
	t.Setenv("WATCHPOST_REPLICATION_LISTEN", addr)
	t.Setenv("WATCHPOST_REPLICATION_TLS_CERT", certFile)
	t.Setenv("WATCHPOST_REPLICATION_TLS_KEY", keyFile)
	t.Setenv("WATCHPOST_REPLICATION_TLS_CA", caFile)

	cfg, err := config.Load(config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Replication.Enabled || cfg.Replication.NodeID != "A" || !cfg.Replication.Bootstrap || cfg.Replication.Listen != addr {
		t.Fatalf("config.Load did not populate replication: %#v", cfg.Replication)
	}
	tlsConfig, err := LoadReplicationTLS(cfg)
	if err != nil {
		t.Fatalf("LoadReplicationTLS: %v", err)
	}

	db, err := store.Open(t.Context(), dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedNode(t, db.DB, "A", nil)
	srv := server.New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), db)
	repl, err := New(t.Context(), Options{
		Database: db, DataDir: dataDir, NodeID: cfg.Replication.NodeID,
		Bootstrap: cfg.Replication.Bootstrap, Address: cfg.Replication.Listen,
		TLSConfig: tlsConfig, Transport: srv.ClusterTransport(),
	})
	if err != nil {
		t.Fatalf("runtime.New from loaded config: %v", err)
	}
	t.Cleanup(repl.Close)
	srv.InstallReplicated(repl.Controller)

	raftDB := filepath.Join(dataDir, "replication", "raft.db")
	if _, err := os.Stat(raftDB); err != nil {
		t.Fatalf("durable raft log/stable store not created: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dataDir, "replication", "snapshots")); err != nil || !fi.IsDir() {
		t.Fatalf("durable snapshot dir not created: %v", err)
	}

	n := &node{store: db, srv: srv, repl: repl, http: httptest.NewTLSServer(srv.Handler())}
	t.Cleanup(n.http.Close)
	srv.ClusterTransport().SetHTTPClient(&http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}})
	waitReadiness(t, n, replicated.ReadinessReadyLeader)
	code, _ := httpPost(t, n.http.Client(), n.http.URL, map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusCreated {
		t.Fatalf("HTTP mutation from config-driven runtime: %d", code)
	}
	if countPosts(t, n, "host-a") != 1 {
		t.Fatal("config-driven replicated mutation not committed")
	}
}
