package cluster

import (
	"context"
	"testing"

	"github.com/watchpost-cv/watchpost/internal/store"

	corecluster "github.com/gantry-tools/gantry-core/cluster"
)

func TestSharedProtocolCompatibilityFailsClosed(t *testing.T) {
	if ProtocolVersion != corecluster.ProtocolVersion {
		t.Fatalf("Watchpost protocol=%d core protocol=%d", ProtocolVersion, corecluster.ProtocolVersion)
	}
	if err := corecluster.Compatible(ProtocolVersion, ProtocolVersion, DefaultCapabilities, DefaultCapabilities, "cluster.health"); err != nil {
		t.Fatal(err)
	}
	if err := corecluster.Compatible(ProtocolVersion, ProtocolVersion+1, DefaultCapabilities, DefaultCapabilities, ""); err == nil {
		t.Fatal("mixed incompatible protocol accepted")
	}
}

func TestClusterIdentityPersistsAcrossStoreReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := newClusterTestStoreAt(t, dir)
	first, err := NewIdentityService(db).Ensure(ctx, "before")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = newClusterTestStoreAt(t, dir)
	defer db.Close()
	second, err := NewIdentityService(db).Ensure(ctx, "after")
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID != second.NodeID || first.InstallationID != second.InstallationID || first.PublicKey != second.PublicKey {
		t.Fatal("cluster identity changed across restart")
	}
}

func newClusterTestStoreAt(t *testing.T, dir string) *store.Store {
	t.Helper()
	db, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
