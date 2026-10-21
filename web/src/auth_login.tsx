import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { api, User } from "./api";
import { BrandLogo } from "./BrandLogo";
import { ErrorState } from "./ui";

type LoginStep = "password" | "mfa";

export function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfa, setMfa] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [step, setStep] = useState<LoginStep>("password");
  const [error, setError] = useState("");

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const value = await api<{ user?: User; mfa_required?: boolean; challenge_id?: string }>(
        "/auth/login",
        { method: "POST", body: JSON.stringify({ email: email.trim(), password }) },
      );
      if (value.mfa_required && value.challenge_id) {
        setChallengeId(value.challenge_id);
        setStep("mfa");
        setMfa("");
        return;
      }
      if (value.user) onLogin(value.user);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Login failed");
    }
  }

  async function submitMfa(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const value = await api<{ user: User }>("/auth/login/mfa", {
        method: "POST",
        body: JSON.stringify({ challenge_id: challengeId, mfa_code: mfa.trim() }),
      });
      onLogin(value.user);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Login failed");
    }
  }

  return (
    <main className="auth-shell">
      <form className="card auth-card" onSubmit={step === "password" ? submitPassword : submitMfa}>
        <div className="auth-brand-hero">
          <BrandLogo variant="hero" />
          <p className="auth-brand-tag">Secure access · TIP-first · Blue team</p>
        </div>
        <ErrorState error={error} />
        {step === "password" ? (
          <>
            <label>
              Email
              <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            <label>
              Password
              <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
            <button type="submit">Sign in</button>
          </>
        ) : (
          <>
            <p className="muted">Enter the code from your authenticator app, or a recovery code.</p>
            <label>
              MFA or recovery code
              <input autoComplete="one-time-code" inputMode="numeric" value={mfa} onChange={(e) => setMfa(e.target.value)} required autoFocus />
            </label>
            <button type="submit">Verify and sign in</button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setStep("password");
                setChallengeId("");
                setMfa("");
                setError("");
              }}
            >
              Back
            </button>
          </>
        )}
        {step === "password" ? <Link to="/forgot-password">Forgot password?</Link> : null}
      </form>
    </main>
  );
}
