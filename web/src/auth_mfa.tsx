import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, User } from "./api";
import { Chips, ErrorState, Heading, Notice } from "./ui";

function secretFromProvisioningUri(uri: string): string {
  try {
    const query = uri.split("?")[1] || "";
    const params = new URLSearchParams(query);
    return params.get("secret") || "";
  } catch {
    return "";
  }
}

export function ProfileMfa({ user, onUserUpdate }: { user: User; onUserUpdate: (user: User) => void }) {
  const enabled = Boolean(user.mfa_enabled);
  const [step, setStep] = useState<"idle" | "scan" | "recovery">(enabled ? "idle" : "idle");
  const [enrollPassword, setEnrollPassword] = useState("");
  const [currentFactor, setCurrentFactor] = useState("");
  const [uri, setUri] = useState("");
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[]>([]);
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [savedAck, setSavedAck] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const manualSecret = useMemo(() => secretFromProvisioningUri(uri), [uri]);

  useEffect(() => {
    let cancelled = false;
    if (!uri) {
      setQrDataUrl("");
      return;
    }
    void import("qrcode")
      .then((QRCode) =>
        QRCode.toDataURL(uri, { width: 220, margin: 1, color: { dark: "#0B0B0E", light: "#FFFFFF" } }),
      )
      .then((url) => {
        if (!cancelled) setQrDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl("");
      });
    return () => {
      cancelled = true;
    };
  }, [uri]);

  async function beginEnrollment(e: FormEvent) {
    e.preventDefault();
    setError("");
    setNotice("");
    try {
      const value = await api<{ provisioning_uri: string }>("/auth/mfa/begin", {
        method: "POST",
        body: JSON.stringify({
          password: enrollPassword,
          current_code: currentFactor.trim() || null,
        }),
      });
      setUri(value.provisioning_uri);
      setStep("scan");
      setCode("");
      setRecovery([]);
      setSavedAck(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to begin MFA enrollment");
    }
  }

  async function confirmEnrollment(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const value = await api<{ recovery_codes: string[] }>("/auth/mfa/confirm", {
        method: "POST",
        body: JSON.stringify({ code: code.trim() }),
      });
      setRecovery(value.recovery_codes);
      setUri("");
      setCode("");
      setEnrollPassword("");
      setCurrentFactor("");
      setStep("recovery");
      onUserUpdate({ ...user, mfa_enabled: true });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to confirm MFA");
    }
  }

  async function disableMfa(e: FormEvent) {
    e.preventDefault();
    setError("");
    setNotice("");
    try {
      await api("/auth/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ password: disablePassword, code: disableCode.trim() }),
      });
      setDisablePassword("");
      setDisableCode("");
      setNotice("MFA is disabled for this account.");
      setStep("idle");
      setRecovery([]);
      onUserUpdate({ ...user, mfa_enabled: false });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to disable MFA");
    }
  }

  function copyRecovery() {
    void navigator.clipboard.writeText(recovery.join("\n"));
    setNotice("Recovery codes copied to the clipboard.");
  }

  function downloadRecovery() {
    const blob = new Blob([recovery.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "black-onyx-mfa-recovery-codes.txt";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <ErrorState error={error} />
      {notice ? <Notice>{notice}</Notice> : null}
      <section className="card">
        <h2>Authenticator MFA</h2>
        <p className="muted">
          Status: <strong>{enabled && step !== "scan" ? "On" : "Off"}</strong>
          {step === "scan" ? " · Enrollment in progress (expires in about 10 minutes)" : null}
        </p>

        {step === "recovery" && recovery.length > 0 ? (
          <>
            <h3>Save these recovery codes</h3>
            <p className="muted">They are shown once. Store them somewhere offline before you leave this page.</p>
            <Chips items={recovery} tone="accent" />
            <div className="button-row">
              <button type="button" className="secondary" onClick={copyRecovery}>Copy all</button>
              <button type="button" className="secondary" onClick={downloadRecovery}>Download .txt</button>
            </div>
            <label className="checkbox-row">
              <input type="checkbox" checked={savedAck} onChange={(e) => setSavedAck(e.target.checked)} />
              I saved these recovery codes
            </label>
            <button type="button" disabled={!savedAck} onClick={() => { setStep("idle"); setRecovery([]); setNotice("MFA is enabled."); }}>
              Done
            </button>
          </>
        ) : null}

        {step === "scan" ? (
          <form onSubmit={confirmEnrollment}>
            <p>Scan this QR code with your authenticator app, or enter the secret manually.</p>
            {qrDataUrl ? <img className="mfa-qr" src={qrDataUrl} alt="MFA enrollment QR code" width={220} height={220} /> : null}
            {manualSecret ? (
              <label>
                Manual secret
                <input readOnly value={manualSecret} onFocus={(e) => e.currentTarget.select()} />
              </label>
            ) : null}
            <details>
              <summary>Advanced: full provisioning URI</summary>
              <label>
                Provisioning URI
                <input readOnly value={uri} onFocus={(e) => e.currentTarget.select()} />
              </label>
            </details>
            <label>
              Verification code from the app
              <input autoComplete="one-time-code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} required />
            </label>
            <div className="button-row">
              <button type="submit">Confirm MFA</button>
              <button
                type="button"
                className="secondary"
                onClick={() => {
                  setStep("idle");
                  setUri("");
                  setCode("");
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : null}

        {step === "idle" && !enabled ? (
          <form onSubmit={beginEnrollment}>
            <p>Protect sign-in with a TOTP authenticator. You will confirm a code and receive one-time recovery codes.</p>
            <label>
              Password
              <input type="password" autoComplete="current-password" value={enrollPassword} onChange={(e) => setEnrollPassword(e.target.value)} required />
            </label>
            <button type="submit">Start MFA setup</button>
          </form>
        ) : null}

        {step === "idle" && enabled ? (
          <>
            <p>MFA is required at sign-in for this account. You can replace the authenticator or turn MFA off.</p>
            <form onSubmit={beginEnrollment}>
              <h3>Replace authenticator</h3>
              <label>
                Password
                <input type="password" autoComplete="current-password" value={enrollPassword} onChange={(e) => setEnrollPassword(e.target.value)} required />
              </label>
              <label>
                Current MFA or recovery code
                <input autoComplete="one-time-code" value={currentFactor} onChange={(e) => setCurrentFactor(e.target.value)} required />
              </label>
              <button type="submit">Begin replacement</button>
            </form>
            <form onSubmit={disableMfa}>
              <h3>Disable MFA</h3>
              <p>Confirm with your password and a current authenticator or recovery code.</p>
              <label>
                Password
                <input type="password" autoComplete="current-password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} required />
              </label>
              <label>
                MFA or recovery code
                <input autoComplete="one-time-code" value={disableCode} onChange={(e) => setDisableCode(e.target.value)} required />
              </label>
              <button type="submit" className="danger">Disable MFA</button>
            </form>
          </>
        ) : null}
      </section>
    </>
  );
}

export function ProfilePage({ user, onUserUpdate }: { user: User; onUserUpdate: (user: User) => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [error, setError] = useState("");

  return (
    <>
      <Heading title="Profile" subtitle="Change your password and configure authenticator MFA." />
      <ErrorState error={error} />
      <div className="result-grid">
        <form
          className="card"
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api("/auth/password/change", {
                method: "POST",
                body: JSON.stringify({ current_password: current, new_password: next }),
              });
              location.reload();
            } catch (reason) {
              setError(reason instanceof Error ? reason.message : "Change failed");
            }
          }}
        >
          <h2>Change password</h2>
          <label>
            Current password
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </label>
          <label>
            New password
            <input type="password" minLength={12} value={next} onChange={(e) => setNext(e.target.value)} required />
          </label>
          <button type="submit">Change and sign out</button>
        </form>
        <ProfileMfa user={user} onUserUpdate={onUserUpdate} />
      </div>
    </>
  );
}
