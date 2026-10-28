package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/mbentancour/babytracker/internal/config"
	"github.com/mbentancour/babytracker/internal/models"
)

const (
	oidcStateTTL       = 10 * time.Minute
	oidcCacheTTL       = time.Hour
	oidcKeyRefreshWait = time.Minute
)

var errOIDCRegistrationDisabled = errors.New("oidc: account creation is disabled")

// OIDCHandler implements the OpenID Connect authorization code flow with PKCE.
// Password login stays available; this is an optional second way in.
//
// The sign-in ends by setting the same refresh cookie as password login, so the
// frontend's normal bootstrap (cookie → refresh) picks up the session.
type OIDCHandler struct {
	db   *sqlx.DB
	cfg  *config.Config
	auth *AuthHandler
	http *http.Client

	mu     sync.Mutex
	meta   *oidcMetadata
	metaAt time.Time
	keys   map[string]*rsa.PublicKey
	keysAt time.Time
}

type oidcMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func NewOIDCHandler(db *sqlx.DB, cfg *config.Config, auth *AuthHandler) *OIDCHandler {
	return &OIDCHandler{
		db:   db,
		cfg:  cfg,
		auth: auth,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// Login starts the flow: it records state, nonce and a PKCE verifier, then
// redirects the browser to the provider.
func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.OIDCEnabled() {
		http.NotFound(w, r)
		return
	}

	meta, err := h.metadata(r.Context())
	if err != nil {
		h.fail(w, r, "provider_unavailable", err)
		return
	}

	state, err1 := oidcRandomToken()
	nonce, err2 := oidcRandomToken()
	verifier, err3 := oidcRandomToken()
	if err := errors.Join(err1, err2, err3); err != nil {
		h.fail(w, r, "server_error", err)
		return
	}

	// Stale requests are dropped opportunistically; the table stays small.
	_ = models.DeleteExpiredOIDCAuthStates(h.db)
	if err := models.SaveOIDCAuthState(h.db, state, nonce, verifier, time.Now().Add(oidcStateTTL)); err != nil {
		h.fail(w, r, "server_error", err)
		return
	}

	challenge := sha256.Sum256([]byte(verifier))
	authURL, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		h.fail(w, r, "provider_unavailable", err)
		return
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", h.cfg.OIDCClientID)
	q.Set("redirect_uri", h.cfg.OIDCRedirectURL)
	q.Set("scope", h.cfg.OIDCScopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// Callback completes the flow: it validates state, exchanges the code, verifies
// the ID token, finds or creates the local user, and starts a session.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.OIDCEnabled() {
		http.NotFound(w, r)
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		h.fail(w, r, "provider_error", fmt.Errorf("provider returned %q", params.Get("error")))
		return
	}
	state, code := params.Get("state"), params.Get("code")
	if state == "" || code == "" {
		h.fail(w, r, "invalid_response", errors.New("missing state or code"))
		return
	}

	// Single-use: consuming deletes the row, so a replayed callback fails here.
	pending, err := models.ConsumeOIDCAuthState(h.db, state)
	if err != nil || time.Now().After(pending.ExpiresAt) {
		h.fail(w, r, "invalid_state", err)
		return
	}

	meta, err := h.metadata(r.Context())
	if err != nil {
		h.fail(w, r, "provider_unavailable", err)
		return
	}

	rawIDToken, err := h.exchangeCode(r, meta, code, pending.CodeVerifier)
	if err != nil {
		h.fail(w, r, "token_exchange_failed", err)
		return
	}

	claims, err := h.verifyIDToken(r.Context(), meta, rawIDToken, pending.Nonce)
	if err != nil {
		h.fail(w, r, "invalid_id_token", err)
		return
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		h.fail(w, r, "invalid_id_token", errors.New("missing sub claim"))
		return
	}

	user, err := h.resolveUser(claims, sub)
	if errors.Is(err, errOIDCRegistrationDisabled) {
		h.fail(w, r, "registration_disabled", err)
		return
	}
	if err != nil {
		h.fail(w, r, "server_error", err)
		return
	}

	if _, err := h.auth.createSession(w, r, user); err != nil {
		h.fail(w, r, "server_error", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// resolveUser maps an identity to a local account. An existing link always
// wins. A new identity creates an account only when self-registration is on,
// and never links to a local account that happens to share the username.
func (h *OIDCHandler) resolveUser(claims jwt.MapClaims, sub string) (*models.User, error) {
	issuer := h.cfg.OIDCIssuer

	user, err := models.GetUserByIdentity(h.db, issuer, sub)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// The first account must come from the setup flow, so it can be the admin.
	count, err := models.CountUsers(h.db)
	if err != nil {
		return nil, err
	}
	if count == 0 || !models.GetBoolSetting(h.db, models.SettingAllowSelfRegistration, false) {
		return nil, errOIDCRegistrationDisabled
	}

	username := oidcCandidateUsername(claims, sub)
	user, err = models.CreateUser(h.db, username, "", false) // empty hash: password login is refused
	if err != nil {
		// Taken by a local account. Do not link to it; use a suffixed name.
		user, err = models.CreateUser(h.db, oidcUniqueUsername(username, sub), "", false)
		if err != nil {
			return nil, err
		}
	}
	if err := models.CreateIdentity(h.db, user.ID, issuer, sub); err != nil {
		return nil, err
	}
	return user, nil
}

// exchangeCode trades the authorization code for tokens and returns the ID token.
func (h *OIDCHandler) exchangeCode(r *http.Request, meta *oidcMetadata, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", h.cfg.OIDCRedirectURL)
	form.Set("client_id", h.cfg.OIDCClientID)
	form.Set("code_verifier", verifier)
	if h.cfg.OIDCSecret != "" {
		form.Set("client_secret", h.cfg.OIDCSecret)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	if tr.IDToken == "" {
		return "", errors.New("token response has no id_token")
	}
	return tr.IDToken, nil
}

// verifyIDToken checks signature (RS256 only), issuer, audience, expiry and
// nonce, and returns the claims.
func (h *OIDCHandler) verifyIDToken(ctx context.Context, meta *oidcMetadata, raw, nonce string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return h.signingKey(ctx, meta, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(h.cfg.OIDCIssuer),
		jwt.WithAudience(h.cfg.OIDCClientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	got, _ := claims["nonce"].(string)
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, errors.New("nonce mismatch")
	}
	return claims, nil
}

// metadata returns the provider's discovery document, cached for an hour.
func (h *OIDCHandler) metadata(ctx context.Context) (*oidcMetadata, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.meta != nil && time.Since(h.metaAt) < oidcCacheTTL {
		return h.meta, nil
	}

	discoveryURL := h.cfg.OIDCIssuer + "/.well-known/openid-configuration"
	resp, err := h.getJSON(ctx, discoveryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var meta oidcMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, err
	}
	// The issuer in the document must match the configured one exactly,
	// otherwise tokens from a different issuer could be accepted.
	if strings.TrimRight(meta.Issuer, "/") != h.cfg.OIDCIssuer {
		return nil, fmt.Errorf("discovery issuer %q does not match configured issuer", meta.Issuer)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
		return nil, errors.New("discovery document is incomplete")
	}

	h.meta = &meta
	h.metaAt = time.Now()
	h.keys = nil // key set may belong to a previous provider config
	return h.meta, nil
}

// signingKey returns the RSA key for kid. An unknown kid triggers at most one
// JWKS refresh per minute, to handle key rotation without hammering the provider.
func (h *OIDCHandler) signingKey(ctx context.Context, meta *oidcMetadata, kid string) (*rsa.PublicKey, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if key, ok := h.keys[kid]; ok && time.Since(h.keysAt) < oidcCacheTTL {
		return key, nil
	}
	if h.keys != nil && time.Since(h.keysAt) < oidcKeyRefreshWait {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}

	resp, err := h.getJSON(ctx, meta.JWKSURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nb, errN := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
		eb, errE := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
		if errN != nil || errE != nil || len(nb) == 0 || len(eb) == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
	}
	h.keys = keys
	h.keysAt = time.Now()

	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func (h *OIDCHandler) getJSON(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s returned %d", target, resp.StatusCode)
	}
	return resp, nil
}

// fail logs the detail server-side and sends the browser back to the login
// screen with a short, non-sensitive error code.
func (h *OIDCHandler) fail(w http.ResponseWriter, r *http.Request, code string, err error) {
	slog.Warn("oidc sign-in failed", "reason", code, "err", err)
	http.Redirect(w, r, "/?oidc_error="+url.QueryEscape(code), http.StatusFound)
}

func oidcRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oidcCandidateUsername prefers preferred_username, then the email local part,
// keeping only characters that are safe in a local username.
func oidcCandidateUsername(claims jwt.MapClaims, sub string) string {
	preferred, _ := claims["preferred_username"].(string)
	email, _ := claims["email"].(string)
	if i := strings.Index(email, "@"); i > 0 {
		email = email[:i]
	}
	for _, v := range []string{preferred, email} {
		if name := oidcSanitizeUsername(v); len(name) >= 3 {
			return name
		}
	}
	return "user-" + oidcSubjectHash(sub)
}

func oidcUniqueUsername(base, sub string) string {
	return base + "-" + oidcSubjectHash(sub)
}

func oidcSanitizeUsername(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return -1
	}, s)
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func oidcSubjectHash(sub string) string {
	sum := sha256.Sum256([]byte(sub))
	return fmt.Sprintf("%x", sum[:3])
}
