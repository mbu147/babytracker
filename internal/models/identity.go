package models

import (
	"time"

	"github.com/jmoiron/sqlx"
)

// GetUserByIdentity returns the local user linked to an external identity.
func GetUserByIdentity(db *sqlx.DB, issuer, subject string) (*User, error) {
	var user User
	err := db.Get(&user,
		`SELECT u.* FROM users u
		 JOIN user_identities i ON i.user_id = u.id
		 WHERE i.issuer = $1 AND i.subject = $2`, issuer, subject)
	return &user, err
}

// CreateIdentity links an external identity to a local user.
func CreateIdentity(db *sqlx.DB, userID int, issuer, subject string) error {
	_, err := db.Exec(
		`INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, $2, $3)`,
		userID, issuer, subject)
	return err
}

// OIDCAuthState is an in-flight OIDC authorization request.
type OIDCAuthState struct {
	Nonce        string    `db:"nonce"`
	CodeVerifier string    `db:"code_verifier"`
	ExpiresAt    time.Time `db:"expires_at"`
}

// SaveOIDCAuthState records a pending authorization request.
func SaveOIDCAuthState(db *sqlx.DB, state, nonce, codeVerifier string, expiresAt time.Time) error {
	_, err := db.Exec(
		`INSERT INTO oidc_auth_states (state, nonce, code_verifier, expires_at) VALUES ($1, $2, $3, $4)`,
		state, nonce, codeVerifier, expiresAt)
	return err
}

// ConsumeOIDCAuthState fetches and deletes a pending request in one step, so a
// state value can only ever be redeemed once.
func ConsumeOIDCAuthState(db *sqlx.DB, state string) (*OIDCAuthState, error) {
	var st OIDCAuthState
	err := db.Get(&st,
		`DELETE FROM oidc_auth_states WHERE state = $1
		 RETURNING nonce, code_verifier, expires_at`, state)
	return &st, err
}

// DeleteExpiredOIDCAuthStates removes abandoned authorization requests.
func DeleteExpiredOIDCAuthStates(db *sqlx.DB) error {
	_, err := db.Exec(`DELETE FROM oidc_auth_states WHERE expires_at < NOW()`)
	return err
}
