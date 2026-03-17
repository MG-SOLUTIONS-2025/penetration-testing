import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login, register } from "../api/client";

export default function Login() {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      if (isRegister) {
        await register(email, password, fullName);
      }
      const res = await login(email, password);
      localStorage.setItem("token", res.access_token);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "100vh",
        background: "var(--bg)",
      }}
    >
      <div className="card" style={{ width: 380 }}>
        <h2 style={{ marginBottom: 4, color: "var(--accent)" }}>PenTest Platform</h2>
        <p style={{ color: "var(--text-dim)", fontSize: 14, marginBottom: 24 }}>
          {isRegister ? "Create an account" : "Sign in to continue"}
        </p>

        <form onSubmit={handleSubmit}>
          {isRegister && (
            <input
              type="text"
              placeholder="Full name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              style={{ width: "100%", marginBottom: 12 }}
              required
            />
          )}
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{ width: "100%", marginBottom: 12 }}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ width: "100%", marginBottom: 16 }}
            required
          />
          {error && (
            <p style={{ color: "var(--critical)", fontSize: 13, marginBottom: 12 }}>{error}</p>
          )}
          <button type="submit" className="btn-primary" style={{ width: "100%", padding: 10 }}>
            {isRegister ? "Register" : "Sign In"}
          </button>
        </form>

        <p style={{ textAlign: "center", marginTop: 16, fontSize: 13, color: "var(--text-dim)" }}>
          {isRegister ? "Already have an account?" : "Need an account?"}{" "}
          <a href="#" onClick={() => setIsRegister(!isRegister)}>
            {isRegister ? "Sign in" : "Register"}
          </a>
        </p>
      </div>
    </div>
  );
}
