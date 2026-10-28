-- OIDC login support.
--
-- user_identities links an external identity (issuer + subject) to a local
-- user. Linking is keyed on issuer+subject, never on email.
CREATE TABLE IF NOT EXISTS user_identities (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);

-- oidc_auth_states holds in-flight authorization requests (state, nonce and
-- PKCE verifier) between /login and /callback. Single-use, short-lived.
CREATE TABLE IF NOT EXISTS oidc_auth_states (
    state         TEXT PRIMARY KEY,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);
