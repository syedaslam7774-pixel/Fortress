import React, { useState } from "react";
import { Shield, UserPlus, ShieldCheck, AlertCircle } from "lucide-react";
import { createIdentity } from "./cryptoUtils";
import "./App.css";

const API_BASE = "";

export default function SignUp({ onDone, onBackToLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [created, setCreated] = useState(false);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError("");

    if (!username || !password) {
      setError("Username and password are required.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      // 1. Generate key pair + encrypt private key with password, entirely in-browser
      const { publicKey } = await createIdentity(username, password);

      // 2. Only the public key is sent to the server
      const res = await fetch(`${API_BASE}/api/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, publicKey }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || "Registration failed.");
      }

      setCreated(true);
    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="portal-bg">
      <div className="grid-overlay" />
      <div className={`portal-card ${created ? "glow-green" : ""}`}>
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
            <div className="brand-sub">CREATE IDENTITY</div>
          </div>
        </div>

        <div className="portal-body">
          {created ? (
            <div className="result-state anim-in">
              <ShieldCheck size={64} className="result-icon icon-green" />
              <div className="result-title text-green">YOUR ACCOUNT IS CREATED</div>
              <div className="result-sub">
                Your private key is encrypted and stored only on this device.
                It never leaves your browser.
              </div>
              <button className="secondary-btn" onClick={onBackToLogin}>
                GO TO LOGIN
              </button>
            </div>
          ) : (
            <>
              <div className="section-label">GENERATE A CRYPTOGRAPHIC IDENTITY</div>
              <form onSubmit={handleCreate}>
                <input
                  type="text"
                  placeholder="Choose a username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="portal-input"
                  autoComplete="off"
                />
                <input
                  type="password"
                  placeholder="Choose a password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="portal-input"
                />
                <input
                  type="password"
                  placeholder="Confirm password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  className="portal-input"
                />
                <button type="submit" className="authenticate-btn" disabled={loading}>
                  <span className="btn-shine" />
                  {loading ? "GENERATING KEYS…" : "CREATE ACCOUNT"} <UserPlus size={18} />
                </button>
              </form>

              {error && (
                <div className="error-msg anim-in">
                  <AlertCircle size={14} /> {error}
                </div>
              )}

              <div className="trouble-link">
                <a href="#back" onClick={(e) => { e.preventDefault(); onBackToLogin(); }}>
                  Already have an account? Log in
                </a>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}