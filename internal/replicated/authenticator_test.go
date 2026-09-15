package replicated

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

const authSchema = `
CREATE TABLE IF NOT EXISTS cluster_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),node_id TEXT NOT NULL UNIQUE,installation_id TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL DEFAULT '',public_endpoint TEXT NOT NULL DEFAULT '',public_key BLOB NOT NULL,private_key BLOB NOT NULL,capabilities_json TEXT NOT NULL DEFAULT '[]',protocol_version INTEGER NOT NULL,product_version TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,paired_at TEXT,last_seen_at TEXT,revoked_at TEXT);
CREATE TABLE IF NOT EXISTS cluster_members(node_id TEXT PRIMARY KEY,installation_id TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL DEFAULT '',public_endpoint TEXT NOT NULL,public_key BLOB NOT NULL,capabilities_json TEXT NOT NULL DEFAULT '[]',protocol_version INTEGER NOT NULL,product_version TEXT NOT NULL DEFAULT '',inbound_secret_hash BLOB NOT NULL,outbound_secret TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','disabled','revoked')),created_at TEXT NOT NULL,paired_at TEXT NOT NULL,last_seen_at TEXT,last_latency_ms INTEGER,revoked_at TEXT,credential_version INTEGER NOT NULL DEFAULT 1,pending_inbound_secret_hash BLOB,pending_inbound_expires_at TEXT);
CREATE TABLE IF NOT EXISTS cluster_nonces(node_id TEXT NOT NULL REFERENCES cluster_members(node_id) ON DELETE CASCADE,nonce TEXT NOT NULL,seen_at TEXT NOT NULL,PRIMARY KEY(node_id,nonce));
CREATE INDEX IF NOT EXISTS cluster_nonces_seen ON cluster_nonces(seen_at);
`

func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func insertMember(t *testing.T, db *sql.DB, nodeID, secret, state, caps string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO cluster_members(node_id,installation_id,public_endpoint,public_key,capabilities_json,protocol_version,inbound_secret_hash,outbound_secret,state,created_at,paired_at,credential_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)`,
		nodeID, nodeID+"-inst", "https://"+nodeID+".example", []byte("key"), caps, 1, hashSecret(secret), "out-"+secret, state, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
}

func newAuthFixture(t *testing.T) (*sql.DB, *WatchpostAuthenticator) {
	t.Helper()
	db := openTestDB(t)
	if _, err := db.Exec(authSchema); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,created_at) VALUES(1,'self','self-inst',?,?,'["health","replication"]',1,?)`, []byte("key"), []byte("key"), time.Now().UTC().Format(time.RFC3339Nano))
	insertMember(t, db, "n1", "secret-n1", "active", `["health","replication"]`)
	insertMember(t, db, "n2", "secret-n2", "active", `["health","replication"]`)
	return db, NewWatchpostAuthenticator(db, replication.Version)
}

func authReq(secret, nodeID, nonce string) *replication.AuthRequest {
	caps := replication.Capabilities{ID: raft.ServerID(nodeID), OperationSchemaVersions: []int{1, replication.Version}, SnapshotFormatVersions: []int{replication.SnapshotFormatVersion}}
	req, err := replication.SignHandshake(secret, raft.ServerID(nodeID), raft.ServerID(nodeID), raft.ServerAddress("node-"+nodeID), replication.Version, caps, nonce, time.Now())
	if err != nil {
		panic(err)
	}
	return req
}

func TestAuthCurrentCredentialAccepted(t *testing.T) {
	db, auth := newAuthFixture(t)
	defer db.Close()
	res, err := auth.Authenticate(context.Background(), *authReq("secret-n1", "n1", "nonce-1"))
	if err != nil || !res.Allowed {
		t.Fatalf("current credential must be accepted: res=%+v err=%v", res, err)
	}
	// Mutual: the server's reciprocal handshake verifies against the client's
	// stored credential for that peer.
	if err := auth.VerifyPeer(context.Background(), "n1", *authReq("secret-n1", "n1", "nonce-2")); err != nil {
		t.Fatalf("VerifyPeer: %v", err)
	}
}

func TestAuthPendingCredentialPromotes(t *testing.T) {
	db, auth := newAuthFixture(t)
	defer db.Close()
	exp := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano)
	mustExec(t, db, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id='n1'`, hashSecret("pending-n1"), exp)
	res, err := auth.Authenticate(context.Background(), *authReq("pending-n1", "n1", "nonce-1"))
	if err != nil || !res.Allowed {
		t.Fatalf("valid pending credential must be accepted: %v", err)
	}
	// Existing Watchpost promotion semantic: pending becomes current, pending
	// cleared, credential_version advances.
	var cur []byte
	var pending []byte
	var cv int
	if err := db.QueryRow(`SELECT inbound_secret_hash,pending_inbound_secret_hash,credential_version FROM cluster_members WHERE node_id='n1'`).Scan(&cur, &pending, &cv); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 || string(cur) != string(hashSecret("pending-n1")) || cv != 2 {
		t.Fatalf("pending promotion did not occur: cv=%d", cv)
	}
}

func TestAuthExpiredPendingRejected(t *testing.T) {
	db, auth := newAuthFixture(t)
	defer db.Close()
	exp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	mustExec(t, db, `UPDATE cluster_members SET pending_inbound_secret_hash=?,pending_inbound_expires_at=? WHERE node_id='n1'`, hashSecret("pending-n1"), exp)
	if _, err := auth.Authenticate(context.Background(), *authReq("pending-n1", "n1", "nonce-1")); err == nil {
		t.Fatal("expired pending credential must be rejected")
	}
}

func TestAuthWrongCredentialRejected(t *testing.T) {
	_, auth := newAuthFixture(t)
	if _, err := auth.Authenticate(context.Background(), *authReq("wrong", "n1", "nonce-1")); err == nil {
		t.Fatal("wrong credential must be rejected")
	}
}

func TestAuthMemberStatesRejected(t *testing.T) {
	for _, state := range []string{"disabled", "revoked"} {
		db, auth := newAuthFixture(t)
		mustExec(t, db, `UPDATE cluster_members SET state=? WHERE node_id='n1'`, state)
		if _, err := auth.Authenticate(context.Background(), *authReq("secret-n1", "n1", "nonce-1")); err == nil {
			t.Fatalf("%s member must be rejected", state)
		}
		db.Close()
	}
	// Unknown member.
	_, auth := newAuthFixture(t)
	if _, err := auth.Authenticate(context.Background(), *authReq("secret-ghost", "ghost", "nonce-1")); err == nil {
		t.Fatal("unknown member must be rejected")
	}
}

func TestAuthReplicationCapabilityAbsentRejected(t *testing.T) {
	db, auth := newAuthFixture(t)
	defer db.Close()
	mustExec(t, db, `UPDATE cluster_members SET capabilities_json='["health"]' WHERE node_id='n1'`)
	if _, err := auth.Authenticate(context.Background(), *authReq("secret-n1", "n1", "nonce-1")); err == nil {
		t.Fatal("member without replication capability must be rejected")
	}
}

func TestAuthProtocolAndIdentityRejected(t *testing.T) {
	_, auth := newAuthFixture(t)
	req := authReq("secret-n1", "n1", "nonce-1")
	req.Protocol = replication.Version + 1
	if _, err := auth.Authenticate(context.Background(), *req); err == nil {
		t.Fatal("incompatible protocol must be rejected")
	}
	req2 := authReq("secret-n1", "n1", "nonce-1")
	req2.RaftServerID = "n9"
	if _, err := auth.Authenticate(context.Background(), *req2); err == nil {
		t.Fatal("raft identity mismatch must be rejected")
	}
}

func TestAuthHandshakeReplayAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(authSchema); err != nil {
		t.Fatal(err)
	}
	insertMember(t, db, "n1", "secret-n1", "active", `["health","replication"]`)
	auth := NewWatchpostAuthenticator(db, replication.Version)
	req := authReq("secret-n1", "n1", "nonce-replay")
	if _, err := auth.Authenticate(context.Background(), *req); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if _, err := auth.Authenticate(context.Background(), *req); err == nil {
		t.Fatal("exact handshake replay must be rejected")
	}
	// Restart: a fresh authenticator over the SAME durable DB still rejects the
	// consumed nonce.
	db.Close()
	db2, err := sql.Open("sqlite", "file:"+path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	auth2 := NewWatchpostAuthenticator(db2, replication.Version)
	if _, err := auth2.Authenticate(context.Background(), *req); err == nil {
		t.Fatal("consumed handshake nonce must remain rejected after restart")
	}
}

func TestAuthReplayNamespaceIndependent(t *testing.T) {
	db, auth := newAuthFixture(t)
	defer db.Close()
	// An ordinary RPC consumed the raw nonce X.
	mustExec(t, db, `INSERT INTO cluster_nonces(node_id,nonce,seen_at) VALUES('n1','nonce-X','now')`)
	// A replication handshake using the same raw nonce value must NOT be
	// poisoned (purpose-prefixed key).
	if _, err := auth.Authenticate(context.Background(), *authReq("secret-n1", "n1", "nonce-X")); err != nil {
		t.Fatalf("handshake with RPC-consumed raw nonce must be independent: %v", err)
	}
	// A replication handshake consumed nonce-Y (prefixed key); an ordinary RPC
	// with the raw nonce-Y must remain independent (raw key).
	if _, err := auth.Authenticate(context.Background(), *authReq("secret-n1", "n1", "nonce-Y")); err != nil {
		t.Fatalf("handshake nonce-Y: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO cluster_nonces(node_id,nonce,seen_at) VALUES('n1','nonce-Y','now')`); err != nil {
		t.Fatalf("ordinary RPC with same raw nonce must not be poisoned: %v", err)
	}
}

func TestMembershipAndCapabilities(t *testing.T) {
	db, auth := newAuthFixture(t)
	defer db.Close()
	ctx := context.Background()
	st, err := auth.Membership(ctx, "n1")
	if err != nil || st.State != replication.MembershipActive || !st.ReplicationEnabled {
		t.Fatalf("active member: %+v err=%v", st, err)
	}
	caps, ok := auth.CapabilitiesOf("n1")
	if !ok || len(caps.OperationSchemaVersions) != replication.Version {
		t.Fatalf("capabilities: %+v ok=%v", caps, ok)
	}
	// Revoked -> inactive, channel must terminate.
	mustExec(t, db, `UPDATE cluster_members SET state='revoked' WHERE node_id='n2'`)
	st2, err := auth.Membership(ctx, "n2")
	if err != nil || st2.State != replication.MembershipRevoked {
		t.Fatalf("revoked member: %+v err=%v", st2, err)
	}
	// Replication authorization removed.
	mustExec(t, db, `UPDATE cluster_members SET capabilities_json='["health"]' WHERE node_id='n1'`)
	st3, _ := auth.Membership(ctx, "n1")
	if st3.ReplicationEnabled {
		t.Fatal("replication authorization removal must be reflected")
	}
	// Unknown member.
	if _, err := auth.Membership(ctx, "ghost"); err == nil {
		t.Fatal("unknown member membership must error")
	}
	if _, ok := auth.CapabilitiesOf("ghost"); ok {
		t.Fatal("unknown member capabilities must not resolve")
	}
}

var _ = fmt.Sprintf
