package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jmoiron/sqlx"
	"github.com/mbentancour/babytracker/internal/config"
	"github.com/mbentancour/babytracker/internal/middleware"
	"github.com/mbentancour/babytracker/internal/models"
	"github.com/mbentancour/babytracker/internal/pagination"
)

// AuthSettingsHandler exposes the runtime auth toggles to admins.
type AuthSettingsHandler struct {
	db  *sqlx.DB
	cfg *config.Config
}

func NewAuthSettingsHandler(db *sqlx.DB, cfg *config.Config) *AuthSettingsHandler {
	return &AuthSettingsHandler{db: db, cfg: cfg}
}

type authSettingsRequest struct {
	AllowSelfRegistration   *bool `json:"allow_self_registration"`
	AllowManualUserCreation *bool `json:"allow_manual_user_creation"`
}

// Get returns the current toggles plus read-only OIDC status.
func (h *AuthSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	if !requestIsAdmin(r) {
		pagination.WriteError(w, http.StatusForbidden, "admin access required")
		return
	}
	h.respond(w)
}

// Set updates any subset of the toggles. Omitted fields keep their value.
func (h *AuthSettingsHandler) Set(w http.ResponseWriter, r *http.Request) {
	if !requestIsAdmin(r) {
		pagination.WriteError(w, http.StatusForbidden, "admin access required")
		return
	}

	var req authSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		pagination.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AllowSelfRegistration != nil {
		if err := models.SetBoolSetting(h.db, models.SettingAllowSelfRegistration, *req.AllowSelfRegistration); err != nil {
			pagination.WriteError(w, http.StatusInternalServerError, "failed to save setting")
			return
		}
	}
	if req.AllowManualUserCreation != nil {
		if err := models.SetBoolSetting(h.db, models.SettingAllowManualUserCreation, *req.AllowManualUserCreation); err != nil {
			pagination.WriteError(w, http.StatusInternalServerError, "failed to save setting")
			return
		}
	}

	h.respond(w)
}

func (h *AuthSettingsHandler) respond(w http.ResponseWriter) {
	pagination.WriteJSON(w, http.StatusOK, map[string]any{
		"allow_self_registration":    models.GetBoolSetting(h.db, models.SettingAllowSelfRegistration, false),
		"allow_manual_user_creation": models.GetBoolSetting(h.db, models.SettingAllowManualUserCreation, true),
		"oidc": map[string]any{
			"enabled": h.cfg.OIDCEnabled(),
			"name":    h.cfg.OIDCProvName,
		},
	})
}

func requestIsAdmin(r *http.Request) bool {
	isAdmin, _ := r.Context().Value(middleware.IsAdminKey).(bool)
	return isAdmin
}
