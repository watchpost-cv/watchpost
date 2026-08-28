package devices

import (
	"context"
	"errors"
	"time"

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
}
type ProfileStore struct{ s *store.Store }

func NewProfileStore(s *store.Store) *ProfileStore { return &ProfileStore{s: s} }
func (p *ProfileStore) Save(ctx context.Context, v SavedProfile) error {
	if v.PostID == "" || v.Address == "" || v.Username == "" || v.Port == 0 {
		return errors.New("invalid saved device profile")
	}
	if err := ValidateProfile(Profile{ID: v.ID, Kind: v.Kind, OIDs: v.OIDs}); err != nil {
		return err
	}
	tx, err := p.s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_profiles(id,post_id,kind,address,port,username,created_at) VALUES(?,?,?,?,?,?,?)`, v.ID, v.PostID, v.Kind, v.Address, v.Port, v.Username, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	for i, oid := range v.OIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO device_profile_oids(profile_id,position,name,oid,unit) VALUES(?,?,?,?,?)`, v.ID, i, oid.Name, oid.OID, oid.Unit); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (p *ProfileStore) List(ctx context.Context) ([]SavedProfile, error) {
	rows, err := p.s.DB.QueryContext(ctx, `SELECT id,post_id,kind,address,port,username FROM device_profiles ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SavedProfile{}
	for rows.Next() {
		var v SavedProfile
		if err = rows.Scan(&v.ID, &v.PostID, &v.Kind, &v.Address, &v.Port, &v.Username); err != nil {
			return nil, err
		}
		o, err := p.s.DB.QueryContext(ctx, `SELECT name,oid,unit FROM device_profile_oids WHERE profile_id=? ORDER BY position`, v.ID)
		if err != nil {
			return nil, err
		}
		for o.Next() {
			var x OID
			if err = o.Scan(&x.Name, &x.OID, &x.Unit); err != nil {
				o.Close()
				return nil, err
			}
			v.OIDs = append(v.OIDs, x)
		}
		o.Close()
		items = append(items, v)
	}
	return items, rows.Err()
}
func (p *ProfileStore) Delete(ctx context.Context, id string) error {
	result, err := p.s.DB.ExecContext(ctx, `DELETE FROM device_profiles WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return errors.New("device profile not found")
	}
	return nil
}
