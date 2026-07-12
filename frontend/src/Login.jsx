import React, { useState } from "react";
import { Shield, ShieldCheck, ShieldX, KeyRound, HelpCircle, Fingerprint } from "lucide-react";
import "./App.css";

const VALID_USER = "admin";
const VALID_PASS = "fortress123";

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("idle"); // idle | scanning | granted | denied

  const handleAuthenticate = (e) => {
    e.preventDefault();
    if (!username || !password) return;
    setStatus("scanning");
    setTimeout(() => {
      const ok = username === VALID_USER && password === VALID_PASS;
      setStatus(ok ? "granted" : "denied");
    }, 1100);
  };

  const reset = () => {
    setStatus("idle");
    setPassword("");
  };

  return (
    <div className="portal-bg">
      <div className={`portal-card ${status === "granted" ? "glow-green" : status === "denied" ? "glow-red" : ""}`}>
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
          {status === "idle" && (
            <>
              <div className="section-label">BIOMETRIC &amp; CREDENTIAL VERIFICATION</div>
              <form onSubmit={handleAuthenticate}>
                <input
                  type="text"
                  placeholder="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="portal-input"
                  autoComplete="off"
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="portal-input"
                />
                <button type="submit" className="authenticate-btn">
                  AUTHENTICATE <KeyRound size={18} />
                </button>
              </form>
              <div className="trouble-link">
                <a href="#trouble" onClick={(e) => e.preventDefault()}>
                  Having trouble?
                </a>{" "}
                <HelpCircle size={13} />
              </div>
              <div className="hint">demo: admin / fortress123</div>
            </>
          )}

          {status === "scanning" && (
            <div className="result-state">
              <div className="scan-ring">
                <Fingerprint size={48} className="scan-icon" />
              </div>
              <div className="scan-text">VERIFYING CREDENTIALS…</div>
              <div className="scan-bar">
                <div className="scan-bar-fill" />
              </div>
            </div>
          )}

          {status === "granted" && (
            <div className="result-state">
              <ShieldCheck size={64} className="result-icon icon-green" />
              <div className="result-title text-green">ACCESS GRANTED</div>
              <div className="result-sub">Welcome back, {username}.</div>
              <button className="secondary-btn" onClick={reset}>
                LOCK &amp; RETURN
              </button>
            </div>
          )}

          {status === "denied" && (
            <div className="result-state">
              <ShieldX size={64} className="result-icon icon-red" />
              <div className="result-title text-red">ACCESS DENIED</div>
              <div className="result-sub">Invalid username or password.</div>
              <button className="secondary-btn" onClick={reset}>
                TRY AGAIN
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}