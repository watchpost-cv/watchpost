package cluster

import (
	"context"
	"github.com/watchpost-cv/watchpost/internal/store"
	"strings"
	"testing"
)

func TestIdentityStableAndSeparated(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := NewIdentityService(db)
	first, err := svc.Ensure(ctx, "0.1.2")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Ensure(ctx, "0.1.3")
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID != second.NodeID || first.InstallationID != second.InstallationID {
		t.Fatal("identity changed")
	}
	if !strings.HasPrefix(first.NodeID, "wp_") || !strings.HasPrefix(first.InstallationID, "wi_") || first.NodeID == first.InstallationID {
		t.Fatal("identity namespaces invalid")
	}
	if second.ProductVersion != "0.1.3" || second.ProtocolVersion != ProtocolVersion {
		t.Fatal("metadata not updated")
	}
	if first.PublicKey == "" || first.Fingerprint() == "" {
		t.Fatal("public identity missing")
	}
}

func TestIdentityRequiresHTTPSEndpoint(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := NewIdentityService(db)
	if _, err = svc.Update(ctx, "node", "http://example.test", nil, "dev"); err == nil {
		t.Fatal("insecure endpoint accepted")
	}
	got, err := svc.Update(ctx, "node", "https://example.test/", []string{"cluster.health", "cluster.health"}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicEndpoint != "https://example.test" || len(got.Capabilities) != 1 {
		t.Fatalf("unexpected metadata: %#v", got)
	}
}
