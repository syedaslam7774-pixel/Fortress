import React, { useState } from "react";
import { Shield, LogIn, AlertCircle } from "lucide-react";
import { unlockPrivateKey, signChallenge } from "./cryptoUtils";
import "./App.css";

const API_BASE = "";

export default function Login({ onDone, onBackToSignUp }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");

    if (!username || !password) {
      setError("Email and password are required.");
      return;
    }

    setLoading(true);
    try {
      // 1. Unlock the locally-stored private key with the password.
      //    This throws if the password is wrong, or if no identity for this
      //    email was ever created on this specific device/browser.
      const privateKey = await unlockPrivateKey(username, password);

      // 2. Ask the server for a fresh, one-time challenge tied to this account.
      const challengeRes = await fetch(`${API_BASE}/api/auth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: username }),
      });
      if (!challengeRes.ok) {
        const body = await challengeRes.json().catch(() => ({}));
        throw new Error(body.detail || "Could not start login.");
      }
      const { challenge_id, challenge } = await challengeRes.json();

      // 3. Sign the challenge locally. The private key never leaves the browser.
      const signature = await signChallenge(privateKey, challenge);

      // 4. Send the signature back — the server verifies it against the
      //    public key it stored at registration, and issues tokens.
      const verifyRes = await fetch(`${API_BASE}/api/auth/challenge/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: username, challenge_id, signature }),
      });
      if (!verifyRes.ok) {
        const body = await verifyRes.json().catch(() => ({}));
        throw new Error(body.detail || "Login failed.");
      }
      const tokens = await verifyRes.json();

      localStorage.setItem("fortress_access_token", tokens.access_token);
      localStorage.setItem("fortress_refresh_token", tokens.refresh_token);

      onDone && onDone(tokens);
    } catch (err) {
      if (err.message && err.message.includes("No local identity found")) {
        setError(
          "No identity found for this email on this device. " +
          "Your private key only lives on the device you created it on."
        );
      } else {
        setError(err.message || "Something went wrong.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="portal-bg">
      <div className="grid-overlay" />
      <div className="portal-card">
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
            <div className="brand-sub">VERIFY IDENTITY</div>
          </div>
        </div>

        <div className="portal-body">
          <div className="section-label">SIGN A CHALLENGE WITH YOUR KEY</div>
          <form onSubmit={handleLogin}>
            <input
              type="text"
              placeholder="Your email"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="portal-input"
              autoComplete="off"
            />
            <input
              type="password"
              placeholder="Your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="portal-input"
            />
            <button type="submit" className="authenticate-btn" disabled={loading}>
              <span className="btn-shine" />
              {loading ? "VERIFYING…" : "LOG IN"} <LogIn size={18} />
            </button>
          </form>

          {error && (
            <div className="error-msg anim-in">
              <AlertCircle size={14} /> {error}
            </div>
          )}

          <div className="trouble-link">
            <a href="#signup" onClick={(e) => { e.preventDefault(); onBackToSignUp(); }}>
              Need an account? Create identity
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
