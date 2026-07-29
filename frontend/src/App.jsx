import React, { useState } from "react";
import { Shield, ShieldCheck, KeyRound, HelpCircle, AlertCircle, Fingerprint, UserPlus } from "lucide-react";
import { unlockPrivateKey, signChallenge, hasLocalIdentity } from "./cryptoUtils";
import SignUp from "./SignUp";
import "./App.css";

const API_BASE = "";

export default function IndexPage() {
  const [view, setView] = useState("login"); // "login" | "signup"
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const [focusField, setFocusField] = useState(null);

  const handleAuthenticate = async (e) => {
    e.preventDefault();
    setError("");

    if (!username || !password) {
      setError("Please enter both username and password.");
      return;
    }

    if (!hasLocalIdentity(username)) {
      setError("No identity for this username on this device. Create an account first.");
      return;
    }

    setLoading(true);
    try {
      // 1. Decrypt the locally-stored private key using the password.
      //    Wrong password -> this throws, and the private key is never recovered.
      const privateKey = await unlockPrivateKey(username, password);

      // 2. Ask the server for a one-time challenge tied to this username.
      const challengeRes = await fetch(`${API_BASE}/api/challenge?username=${encodeURIComponent(username)}`);
      if (!challengeRes.ok) {
        const body = await challengeRes.json().catch(() => ({}));
        throw new Error(body.detail || "Could not get challenge from server.");
      }
      const { challenge } = await challengeRes.json();

      // 3. Sign the challenge with the private key (still only in this browser).
      const signature = await signChallenge(privateKey, challenge);

      // 4. Send only the signature to the server for verification.
      const verifyRes = await fetch(`${API_BASE}/api/login-verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, signature }),
      });

      if (!verifyRes.ok) {
        const body = await verifyRes.json().catch(() => ({}));
        throw new Error(body.detail || "Wrong password.");
      }

      setLoggedIn(true);
    } catch (err) {
      // Decryption failures and server rejections both land here.
      setError("Wrong password. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setLoggedIn(false);
    setUsername("");
    setPassword("");
    setError("");
  };

  if (view === "signup") {
    return <SignUp onBackToLogin={() => setView("login")} />;
  }

  if (loggedIn) {
    return (
      <div className="portal-bg">
        <div className="grid-overlay" />
        <div className="portal-card glow-green">
          <div className="corner corner-tl" />
          <div className="corner corner-tr" />
          <div className="corner corner-bl" />
          <div className="corner corner-br" />
          <div className="portal-header">
            <Shield size={30} className="header-icon" strokeWidth={2} />
            <div>
              <div className="brand">
                <span className="brand-bold">FORTRESS</span> SECURITY
              </div>
              <div className="brand-sub">ACCESS PORTAL</div>
            </div>
          </div>
          <div className="portal-body">
            <div className="result-state anim-in">
              <ShieldCheck size={64} className="result-icon icon-green" />
              <div className="result-title text-green">LOGIN SUCCESSFUL</div>
              <div className="result-sub">Welcome, {username}.</div>
              <button className="secondary-btn" onClick={handleLogout}>
                LOCK &amp; LOG OUT
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="portal-bg">
      <div className="grid-overlay" />
      <div className={`portal-card ${error ? "glow-red" : ""}`}>
        <div className="corner corner-tl" />
        <div className="corner corner-tr" />
        <div className="corner corner-bl" />
        <div className="corner corner-br" />

        <div className="portal-header">
          <Shield size={30} className="header-icon" strokeWidth={2} />
          <div>
            <div className="brand">
              <span className="brand-bold">FORTRESS</span> SECURITY
            </div>
            <div className="brand-sub">ACCESS PORTAL</div>
          </div>
        </div>

        <div className="portal-body">
          {loading ? (
            <div className="result-state anim-in">
              <div className="scan-ring">
                <Fingerprint size={40} className="scan-icon" />
              </div>
              <div className="scan-text">VERIFYING SIGNATURE…</div>
            </div>
          ) : (
            <>
              <div className="section-label">CRYPTOGRAPHIC CHALLENGE AUTHENTICATION</div>
              <form onSubmit={handleAuthenticate}>
                <div className={`input-wrap ${focusField === "user" ? "input-focused" : ""}`}>
                  <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    onFocus={() => setFocusField("user")}
                    onBlur={() => setFocusField(null)}
                    className="portal-input"
                    autoComplete="off"
                  />
                </div>
                <div className={`input-wrap ${focusField === "pass" ? "input-focused" : ""}`}>
                  <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onFocus={() => setFocusField("pass")}
                    onBlur={() => setFocusField(null)}
                    className="portal-input"
                  />
                </div>
                <button type="submit" className="authenticate-btn">
                  <span className="btn-shine" />
                  AUTHENTICATE <KeyRound size={18} />
                </button>
              </form>

              {error && (
                <div className="error-msg anim-in">
                  <AlertCircle size={14} /> {error}
                </div>
              )}

              <div className="trouble-link">
                <a href="#new" onClick={(e) => { e.preventDefault(); setView("signup"); }}>
                  New user? Create an account
                </a>{" "}
                <UserPlus size={13} />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}