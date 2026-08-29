package devices

import (
	"context"
	"crypto/sha256"
	"fmt"
	"database/sql"
	"errors"
	"time"

	"github.com/watchpost-ops/watchpost/internal/audit"
	"github.com/watchpost-ops/watchpost/internal/secrets"
	"github.com/watchpost-ops/watchpost/internal/store"
)

type SavedProfile struct {
	ID       string `json:"id"`
	PostID   string `json:"post_id"`
	Kind     string `json:"kind"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Username string `json:"username"`
	OIDs     []OID  `json:"oids"`
	// Credentials are accepted once at save time and stored only encrypted with
	// the installation master key. They are never returned.
	AuthPassword    string `json:"auth_password,omitempty"`
	PrivacyPassword string `json:"privacy_password,omitempty"`
	IntervalSeconds int64  `json:"interval_seconds,omitempty"`
	Enabled         bool   `json:"enabled"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
}

// Credentials returns the decrypted polling credentials for a profile.
func (p SavedProfile) Credentials(port uint16) (V3Config, error) {
	if p.AuthPassword == "" || p.PrivacyPassword == "" {
		return V3Config{}, errors.New("stored credentials unavailable")
	}
	return V3Config{Address: p.Address, Port: port, Username: p.Username, AuthPassword: p.AuthPassword, PrivacyPassword: p.PrivacyPassword, Timeout: 10 * time.Second}, nil
}

type ProfileStore struct {
	s   *store.Store
	box *secrets.Box
}

func NewProfileStore(s *store.Store) *ProfileStore { return &ProfileStore{s: s, box: secrets.New("")} }

// NewProfileStoreWithKey enables encrypted credential storage and recurring
// polling under the installation master key.
func NewProfileStoreWithKey(s *store.Store, box *secrets.Box) *ProfileStore {
	return &ProfileStore{s: s, box: box}
}

func (p *ProfileStore) Save(ctx context.Context, v SavedProfile, entry audit.Entry) error {
	if v.PostID == "" || v.Address == "" || v.Username == "" || v.Port == 0 {
		return errors.New("invalid saved device profile")
	}
	if err := ValidateProfile(Profile{ID: v.ID, Kind: v.Kind, OIDs: v.OIDs}); err != nil {
		return err
	}
	var encryptedAuth, encryptedPrivacy []byte
	hasCredentials := v.AuthPassword != "" || v.PrivacyPassword != ""
	if hasCredentials || v.IntervalSeconds > 0 {
		if !p.box.Enabled() {
			return errors.New("no master key configured (WATCHPOST_MASTER_KEY); credentials cannot be stored for recurring polling")
		}
		if v.AuthPassword == "" || v.PrivacyPassword == "" {
			return errors.New("both authentication and privacy passwords are required for recurring polling")
		}
		var err error
		if encryptedAuth, err = p.box.Encrypt([]byte(v.AuthPassword)); err != nil {
			return err
		}
		if encryptedPrivacy, err = p.box.Encrypt([]byte(v.PrivacyPassword)); err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	tx, err := p.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_profiles(id,post_id,kind,address,port,username,created_at,encrypted_auth,encrypted_privacy,interval_seconds,next_run_at,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, v.ID, v.PostID, v.Kind, v.Address, v.Port, v.Username, now.Format(time.RFC3339Nano), nullableBlob(encryptedAuth), nullableBlob(encryptedPrivacy), v.IntervalSeconds, now.Format(time.RFC3339Nano), v.IntervalSeconds > 0); err != nil {
		return err
	}
	for i, oid := range v.OIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO device_profile_oids(profile_id,position,name,oid,unit) VALUES(?,?,?,?,?)`, v.ID, i, oid.Name, oid.OID, oid.Unit); err != nil {
			return err
		}
	}
	if v.IntervalSeconds > 0 {
		// A recurring profile owns a post-scoped source identity so its
		// observations satisfy the observation FK; the marker is never a
		// bearer credential.
		marker := sha256.Sum256([]byte("device-snmp:" + v.ID))
		if _, err = tx.ExecContext(ctx, `INSERT INTO collector_keys(id,post_id,secret_hash,kind) VALUES(?,?,?,'device_snmp') ON CONFLICT(id) DO NOTHING`, v.ID, v.PostID, marker[:]); err != nil {
			return err
		}
	}
	entry.ObjectType = "device_profile"
	entry.ObjectID = v.ID
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

// Due returns enabled recurring profiles whose next run has passed, bounded to
// a safe batch.
func (p *ProfileStore) Due(ctx context.Context, now time.Time, limit int) ([]SavedProfile, error) {
	rows, err := p.s.DB.QueryContext(ctx, `SELECT id,post_id,kind,address,port,username,interval_seconds FROM device_profiles WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT ?`, now.UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SavedProfile{}
	for rows.Next() {
		var item SavedProfile
		if err = rows.Scan(&item.ID, &item.PostID, &item.Kind, &item.Address, &item.Port, &item.Username, &item.IntervalSeconds); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// Credentials decrypts the stored polling credentials for a profile.
func (p *ProfileStore) Credentials(ctx context.Context, id string) (SavedProfile, V3Config, error) {
	var item SavedProfile
	var authBlob, privacyBlob []byte
	err := p.s.DB.QueryRowContext(ctx, `SELECT id,post_id,kind,address,port,username,encrypted_auth,encrypted_privacy FROM device_profiles WHERE id=?`, id).Scan(&item.ID, &item.PostID, &item.Kind, &item.Address, &item.Port, &item.Username, &authBlob, &privacyBlob)
	if err != nil {
		return item, V3Config{}, err
	}
	if len(authBlob) == 0 || len(privacyBlob) == 0 {
		return item, V3Config{}, errors.New("stored credentials unavailable")
	}
	auth, err := p.box.Decrypt(authBlob)
	if err != nil {
		return item, V3Config{}, err
	}
	privacy, err := p.box.Decrypt(privacyBlob)
	if err != nil {
		return item, V3Config{}, err
	}
	item.AuthPassword = string(auth)
	item.PrivacyPassword = string(privacy)
	return item, V3Config{Address: item.Address, Port: item.Port, Username: item.Username, AuthPassword: string(auth), PrivacyPassword: string(privacy), Timeout: 10 * time.Second}, nil
}

// Advance reschedules a recurring profile after a completed run.
func (p *ProfileStore) Advance(ctx context.Context, id string, interval int64, now time.Time) error {
	result, err := p.s.DB.ExecContext(ctx, `UPDATE device_profiles SET next_run_at=? WHERE id=? AND interval_seconds=?`, now.UTC().Add(time.Duration(interval)*time.Second).Format(time.RFC3339Nano), id, interval)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (p *ProfileStore) List(ctx context.Context) ([]SavedProfile, error) {
	rows, err := p.s.DB.QueryContext(ctx, `SELECT id,post_id,kind,address,port,username,interval_seconds,enabled FROM device_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	items := []SavedProfile{}
	for rows.Next() {
		var v SavedProfile
		if err = rows.Scan(&v.ID, &v.PostID, &v.Kind, &v.Address, &v.Port, &v.Username, &v.IntervalSeconds, &v.Enabled); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, v)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	// OIDs are fetched after the outer scan is closed: with a single database
	// connection, a nested query while the outer rows are open would deadlock.
	for i := range items {
		o, err := p.s.DB.QueryContext(ctx, `SELECT name,oid,unit FROM device_profile_oids WHERE profile_id=? ORDER BY position`, items[i].ID)
		if err != nil {
			return nil, err
		}
		for o.Next() {
			var x OID
			if err = o.Scan(&x.Name, &x.OID, &x.Unit); err != nil {
				o.Close()
				return nil, err
			}
			items[i].OIDs = append(items[i].OIDs, x)
		}
		o.Close()
	}
	return items, nil
}
func (p *ProfileStore) Delete(ctx context.Context, id string, entry audit.Entry) error {
	tx, err := p.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM device_profiles WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("device profile not found")
	}
	entry.ObjectType = "device_profile"
	entry.ObjectID = id
	if err = audit.Insert(ctx, tx, entry); err != nil {
		return err
	}
	return tx.Commit()
}

func nullableBlob(value []byte) any {
	if value == nil {
		return nil
	}
	return value
}

// RekeyCredentials re-encrypts stored device polling credentials with a new
// master key. The node must be stopped. Rotation therefore either re-encrypts
// existing secrets with this command or, if the old key is lost, requires the
// operator to re-enter credentials; it never silently keeps secrets under a
// discarded key.
func RekeyCredentials(ctx context.Context, database *store.Store, oldKey, newKey string) (int, error) {
	if oldKey == "" || newKey == "" || oldKey == newKey {
		return 0, errors.New("old and new master keys are required and must differ")
	}
	oldBox := secrets.New(oldKey)
	newBox := secrets.New(newKey)
	if !oldBox.Enabled() || !newBox.Enabled() {
		return 0, errors.New("master keys unavailable")
	}
	rows, err := database.DB.QueryContext(ctx, `SELECT id,encrypted_auth,encrypted_privacy FROM device_profiles WHERE encrypted_auth IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id            string
		auth, privacy []byte
	}
	var items []row
	for rows.Next() {
		var item row
		if err = rows.Scan(&item.id, &item.auth, &item.privacy); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}
	tx, err := database.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, item := range items {
		auth, err := oldBox.Decrypt(item.auth)
		if err != nil {
			return 0, fmt.Errorf("profile %s: %w", item.id, err)
		}
		privacy, err := oldBox.Decrypt(item.privacy)
		if err != nil {
			return 0, fmt.Errorf("profile %s: %w", item.id, err)
		}
		nextAuth, err := newBox.Encrypt(auth)
		if err != nil {
			return 0, err
		}
		nextPrivacy, err := newBox.Encrypt(privacy)
		if err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE device_profiles SET encrypted_auth=?,encrypted_privacy=? WHERE id=?`, nextAuth, nextPrivacy, item.id); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}