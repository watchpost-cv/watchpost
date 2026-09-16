package cluster

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	corecluster "github.com/gantry-tools/gantry-core/cluster"

	"github.com/watchpost-cv/watchpost/internal/store"
)

const ProtocolVersion = corecluster.ProtocolVersion

// DefaultCapabilities are the capabilities every node's identity advertises.
// "replication" is included so paired members are authorized to participate in
// the replicated raft transport (the WatchpostAuthenticator rejects the
// replication handshake for members without it); the actual replicated operating
// mode remains explicitly configured, never inferred from the capability.
var DefaultCapabilities = []string{"cluster.health", "cluster.summary", "cluster.propagation", "replication"}

type Identity = corecluster.Identity

type IdentityService struct {
	s   *store.Store
	now func() time.Time
}

func NewIdentityService(s *store.Store) *IdentityService {
	return &IdentityService{s: s, now: time.Now}
}

func (s *IdentityService) Ensure(ctx context.Context, productVersion string) (Identity, error) {
	identity, _, err := s.ensureWithPrivate(ctx, productVersion)
	return identity, err
}

func (s *IdentityService) PrivateKey(ctx context.Context, productVersion string) (ed25519.PrivateKey, error) {
	_, key, err := s.ensureWithPrivate(ctx, productVersion)
	return key, err
}

func (s *IdentityService) Update(ctx context.Context, displayName, endpoint string, capabilities []string, productVersion string) (Identity, error) {
	if endpoint != "" && !strings.HasPrefix(endpoint, "https://") {
		return Identity{}, errors.New("cluster public endpoint must use https")
	}
	if len(capabilities) == 0 {
		capabilities = append([]string(nil), DefaultCapabilities...)
	}
	if _, _, err := s.ensureWithPrivate(ctx, productVersion); err != nil {
		return Identity{}, err
	}
	encoded, _ := json.Marshal(corecluster.NormalizeCapabilities(capabilities))
	_, err := s.s.DB.ExecContext(ctx, `UPDATE cluster_identity SET display_name=?,public_endpoint=?,capabilities_json=?,product_version=? WHERE singleton=1`, strings.TrimSpace(displayName), strings.TrimRight(endpoint, "/"), string(encoded), productVersion)
	if err != nil {
		return Identity{}, err
	}
	return s.load(ctx)
}

func (s *IdentityService) ensureWithPrivate(ctx context.Context, productVersion string) (Identity, ed25519.PrivateKey, error) {
	identity, privateKey, err := s.loadWithPrivate(ctx)
	if err == nil {
		if productVersion != "" && identity.ProductVersion != productVersion {
			_, _ = s.s.DB.ExecContext(ctx, `UPDATE cluster_identity SET product_version=? WHERE singleton=1`, productVersion)
			identity.ProductVersion = productVersion
		}
		return identity, privateKey, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Identity{}, nil, err
	}
	generated, err := corecluster.GenerateIdentity("wp_", "wi_", DefaultCapabilities, ProtocolVersion, productVersion, s.now().UTC())
	if err != nil {
		return Identity{}, nil, err
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(generated.Identity.PublicKey)
	if err != nil {
		return Identity{}, nil, err
	}
	privateKey = ed25519.PrivateKey(generated.PrivateKey)
	caps, _ := json.Marshal(generated.Identity.Capabilities)
	now := generated.Identity.CreatedAt.Format(time.RFC3339Nano)
	_, err = s.s.DB.ExecContext(ctx, `INSERT INTO cluster_identity(singleton,node_id,installation_id,public_key,private_key,capabilities_json,protocol_version,product_version,created_at) VALUES(1,?,?,?,?,?,?,?,?)`, generated.Identity.NodeID, generated.Identity.InstallationID, publicKey, []byte(privateKey), string(caps), ProtocolVersion, productVersion, now)
	if err != nil {
		identity, privateKey, loadErr := s.loadWithPrivate(ctx)
		return identity, privateKey, loadErr
	}
	return s.loadWithPrivate(ctx)
}

func (s *IdentityService) load(ctx context.Context) (Identity, error) {
	i, _, err := s.loadWithPrivate(ctx)
	return i, err
}
func (s *IdentityService) loadWithPrivate(ctx context.Context) (Identity, ed25519.PrivateKey, error) {
	var i Identity
	var public, private []byte
	var caps, created string
	var paired, seen, revoked sql.NullString
	err := s.s.DB.QueryRowContext(ctx, `SELECT node_id,installation_id,display_name,public_endpoint,public_key,private_key,capabilities_json,protocol_version,product_version,created_at,paired_at,last_seen_at,revoked_at FROM cluster_identity WHERE singleton=1`).Scan(&i.NodeID, &i.InstallationID, &i.DisplayName, &i.PublicEndpoint, &public, &private, &caps, &i.ProtocolVersion, &i.ProductVersion, &created, &paired, &seen, &revoked)
	if err != nil {
		return Identity{}, nil, err
	}
	i.PublicKey = base64.RawURLEncoding.EncodeToString(public)
	_ = json.Unmarshal([]byte(caps), &i.Capabilities)
	i.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	i.PairedAt = parseNullTime(paired)
	i.LastSeenAt = parseNullTime(seen)
	i.RevokedAt = parseNullTime(revoked)
	return i, ed25519.PrivateKey(private), nil
}

func randomID(prefix string, n int) (string, error) { return corecluster.NewID(prefix, n) }
func parseNullTime(v sql.NullString) *time.Time {
	if !v.Valid {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil
	}
	return &t
}
