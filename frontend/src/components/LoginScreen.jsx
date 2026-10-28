import { useState } from "react";
import { api, setAccessToken } from "../api";
import { Icons } from "./Icons";
import { colors } from "../utils/colors";
import { useI18n } from "../utils/i18n";

const linkButtonStyle = {
  background: "none", border: "none", color: "var(--text-muted)",
  fontSize: 13, cursor: "pointer", fontFamily: "inherit", marginTop: 4, padding: 8,
};

export default function LoginScreen({
  isSetup,
  onAuthenticated,
  onBack,
  registrationEnabled = false,
  oidc = null,
  oidcError = null,
}) {
  const { t } = useI18n();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  // The sign-in screen can switch to account creation when self-registration is on.
  const [registerMode, setRegisterMode] = useState(false);
  const isRegister = isSetup || registerMode;
  const canToggleRegister = !isSetup && registrationEnabled;
  const showOidc = !isSetup && !!oidc?.enabled;
  const oidcMessage = oidcError
    ? t(oidcError === "registration_disabled" ? "auth.oidcRegistrationDisabled" : "auth.oidcError")
    : "";
  const shownError = error || oidcMessage;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (isRegister) {
        if (password !== confirmPassword) {
          setError("Passwords do not match");
          setLoading(false);
          return;
        }
        if (password.length < 8) {
          setError("Password must be at least 8 characters");
          setLoading(false);
          return;
        }
        const data = await api.register(username, password);
        setAccessToken(data.access_token);
      } else {
        const data = await api.login(username, password);
        setAccessToken(data.access_token);
      }
      onAuthenticated();
    } catch (err) {
      setError(err.error || err.message || "Authentication failed");
      setLoading(false);
    }
  };

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-header">
          <div className="login-icon">
            <Icons.Baby />
          </div>
          <h1 className="login-title">BabyTracker</h1>
          <p className="login-subtitle">
            {isRegister
              ? t("auth.createAccountHint")
              : t("auth.signInHint")}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {shownError && <div className="login-error">{shownError}</div>}

          <div className="login-field">
            <label className="login-label">{t("auth.username")}</label>
            <input
              type="text"
              className="login-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              autoComplete="username"
              autoFocus
            />
          </div>

          <div className="login-field">
            <label className="login-label">{t("auth.password")}</label>
            <input
              type="password"
              className="login-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete={isRegister ? "new-password" : "current-password"}
            />
          </div>

          {isRegister && (
            <div className="login-field">
              <label className="login-label">{t("auth.confirmPassword")}</label>
              <input
                type="password"
                className="login-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
          )}

          <button
            type="submit"
            className="login-button"
            style={{ background: colors.feeding }}
            disabled={loading}
          >
            {loading
              ? t("auth.pleaseWait")
              : isRegister
                ? t("auth.createAccount")
                : t("auth.signIn")}
          </button>

          {canToggleRegister && (
            <button
              type="button"
              onClick={() => { setRegisterMode(!registerMode); setError(""); }}
              disabled={loading}
              style={linkButtonStyle}
            >
              {registerMode ? t("auth.haveAccount") : t("auth.noAccount")}
            </button>
          )}

          {isSetup && onBack && (
            <button
              type="button"
              onClick={onBack}
              disabled={loading}
              style={{
                background: "none", border: "none", color: "var(--text-muted)",
                fontSize: 13, cursor: loading ? "not-allowed" : "pointer",
                fontFamily: "inherit", marginTop: 4, padding: 8,
              }}
            >
              {t("form.back")}
            </button>
          )}
        </form>

        {showOidc && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10, padding: "0 16px 16px" }}>
            <div style={{ textAlign: "center", color: "var(--text-dim)", fontSize: 12 }}>{t("auth.oidcOr")}</div>
            <a
              href={api.oidcLoginUrl}
              className="login-button"
              style={{ background: colors.feeding, display: "block", textAlign: "center", textDecoration: "none", boxSizing: "border-box" }}
            >
              {t("auth.oidcSignIn")} {oidc.name}
            </a>
          </div>
        )}
      </div>
    </div>
  );
}
