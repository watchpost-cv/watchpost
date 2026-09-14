package auth

import (
	"errors"
	"strconv"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
	"github.com/watchpost-cv/watchpost/internal/store"
)

const accountSchemaVersion = 1

var watchpostRoles = coreauth.RolesFile{Version: accountSchemaVersion, Roles: []coreauth.Role{
	{ID: "administrator", Name: "Administrator", Capabilities: []string{"*"}, BuiltIn: true},
	{ID: "operator", Name: "Operator", Capabilities: []string{"monitor.read", "monitor.manage"}, BuiltIn: true},
	{ID: "viewer", Name: "Viewer", Capabilities: []string{"monitor.read"}, BuiltIn: true},
}}

type accountPersistence struct{ store *store.Store }

func (p accountPersistence) LoadAccounts() (coreauth.AccountsFile, error) {
	result := coreauth.AccountsFile{Version: accountSchemaVersion, Accounts: []coreauth.Account{}}
	rows, err := p.store.DB.Query("SELECT id,username,email,password_hash,role,created_at FROM users ORDER BY email")
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var username, email, role, created string
		var hash []byte
		if err := rows.Scan(&id, &username, &email, &hash, &role, &created); err != nil {
			return result, err
		}
		createdAt, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return result, err
		}
		accountID := strconv.FormatInt(id, 10)
		roleID := role
		if role == "admin" {
			roleID = "administrator"
		}
		result.Accounts = append(result.Accounts, coreauth.Account{
			ID: accountID, DisplayName: username, Enabled: true, Roles: []string{roleID}, CreatedAt: createdAt,
			Identities: []coreauth.Identity{{ID: "pwd_" + accountID, Type: "password", Username: username, Email: email, PasswordHash: string(hash), Enabled: true}},
		})
	}
	return result, rows.Err()
}

func (p accountPersistence) LoadRoles() (coreauth.RolesFile, error) { return watchpostRoles, nil }
func (p accountPersistence) SaveAccounts(coreauth.AccountsFile) error {
	return errors.New("Watchpost account mutations use the transactional SQL adapter")
}
func (p accountPersistence) SaveRoles(coreauth.RolesFile) error {
	return errors.New("Watchpost built-in roles are immutable")
}

func watchpostAccountPolicy() coreauth.AccountPolicy {
	return coreauth.AccountPolicy{SchemaVersion: accountSchemaVersion, ProductName: "Watchpost", KnownCapability: func(key string) bool {
		return key == "monitor.read" || key == "monitor.manage"
	}}
}

func userFromAccount(account coreauth.Account) (User, error) {
	id, err := strconv.ParseInt(account.ID, 10, 64)
	if err != nil {
		return User{}, err
	}
	role := "viewer"
	for _, assigned := range account.Roles {
		if assigned == "administrator" {
			role = "admin"
			break
		}
		if assigned == "operator" {
			role = "operator"
		}
	}
	email := account.DisplayName
	for _, identity := range account.Identities {
		if identity.Email != "" {
			email = identity.Email
			break
		}
	}
	return User{ID: id, Email: email, Role: role}, nil
}
