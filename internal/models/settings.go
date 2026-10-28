package models

import (
	"github.com/jmoiron/sqlx"
)

// Keys for the runtime auth toggles stored in the settings table.
const (
	SettingAllowSelfRegistration   = "allow_self_registration"
	SettingAllowManualUserCreation = "allow_manual_user_creation"
)

// GetBoolSetting returns the boolean stored under key, or def when the key is
// absent or unreadable.
func GetBoolSetting(db *sqlx.DB, key string, def bool) bool {
	var value string
	if err := db.Get(&value, `SELECT value FROM settings WHERE key = $1`, key); err != nil {
		return def
	}
	return value == "true"
}

// SetBoolSetting stores v under key using the same upsert as the other
// settings handlers.
func SetBoolSetting(db *sqlx.DB, key string, v bool) error {
	value := "false"
	if v {
		value = "true"
	}
	_, err := db.Exec(
		`INSERT INTO settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = $2`, key, value)
	return err
}
