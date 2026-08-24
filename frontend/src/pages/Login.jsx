import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import ShieldLogo from "../components/ShieldLogo";

const FEATURES = [
  { icon: "\u{1F916}", label: "Agentic tool-calling, no hardcoded pipelines" },
  { icon: "\u{1F6E1}️", label: "Red vs blue team cyber-range simulation" },
  { icon: "\u{1F4DA}", label: "Answers grounded in your own runbooks" },
];

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      navigate("/chat");
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.page}>
      <div className="login-hero" style={styles.hero}>
        <div style={styles.heroGrid} />
        <div style={{ ...styles.glow, top: -80, left: -60 }} />
        <div style={{ ...styles.glow, bottom: -100, right: -40, animationDelay: "-4s" }} />

        <div style={styles.heroContent}>
          <ShieldLogo size={128} />
          <h1 style={styles.heroTitle}>Cyber Defense Assistant</h1>
          <p style={styles.heroTagline}>
            An autonomous SOC copilot that reasons over real MCP tool calls -
            detection, response, and training, all agent-driven.
          </p>

          <div style={styles.featureList}>
            {FEATURES.map((f) => (
              <div key={f.label} style={styles.featureRow}>
                <span style={styles.featureIcon}>{f.icon}</span>
                <span>{f.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={styles.formSide}>
        <div style={styles.card}>
          <div style={styles.badge}>CD</div>
          <h2 style={styles.title}>Welcome back</h2>
          <p style={styles.subtitle}>Sign in to continue</p>

          <form onSubmit={handleSubmit} style={styles.form}>
            <label style={styles.label}>
              Username
              <input
                style={styles.input}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                required
              />
            </label>
            <label style={styles.label}>
              Password
              <input
                style={styles.input}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>

            {error && <div style={styles.error}>{error}</div>}

            <button style={styles.button} type="submit" disabled={loading}>
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <p style={styles.hint}>
            Don't have an account? <Link to="/signup" style={styles.link}>Sign up</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

const styles = {
  page: {
    height: "100%",
    display: "flex",
    background: "var(--bg)",
  },
  hero: {
    position: "relative",
    overflow: "hidden",
    background: "linear-gradient(160deg, #211f1c 0%, #2b2a27 55%, #35281f 100%)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  heroGrid: {
    position: "absolute",
    inset: 0,
    backgroundImage:
      "linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px)",
    backgroundSize: "48px 48px",
    animation: "gridPan 18s linear infinite",
    maskImage: "radial-gradient(circle at 50% 40%, black 0%, transparent 75%)",
  },
  glow: {
    position: "absolute",
    width: 320,
    height: 320,
    borderRadius: "50%",
    background: "radial-gradient(circle, rgba(193,95,60,0.45) 0%, transparent 70%)",
    filter: "blur(10px)",
    animation: "glowDrift 12s ease-in-out infinite",
    pointerEvents: "none",
  },
  heroContent: {
    position: "relative",
    zIndex: 1,
    maxWidth: 420,
    textAlign: "center",
    padding: "0 32px",
    color: "#ece8e1",
  },
  heroTitle: {
    fontSize: 26,
    fontWeight: 700,
    margin: "24px 0 10px",
    color: "#fff",
  },
  heroTagline: {
    fontSize: 14.5,
    lineHeight: 1.6,
    color: "#c7c2b8",
    margin: "0 0 28px",
  },
  featureList: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
    textAlign: "left",
  },
  featureRow: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    fontSize: 13,
    color: "#e2ddd2",
    background: "rgba(255,255,255,0.04)",
    border: "1px solid rgba(255,255,255,0.07)",
    borderRadius: 10,
    padding: "9px 12px",
  },
  featureIcon: {
    fontSize: 15,
  },
  formSide: {
    flex: 1,
    minWidth: 380,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background: "var(--bg)",
  },
  card: {
    width: 360,
    background: "var(--bg-elevated)",
    border: "1px solid var(--border)",
    borderRadius: 16,
    padding: "36px 32px",
    boxShadow: "0 1px 3px rgba(0,0,0,0.04), 0 8px 24px rgba(0,0,0,0.06)",
    textAlign: "center",
  },
  badge: {
    width: 44,
    height: 44,
    borderRadius: 12,
    background: "var(--accent)",
    color: "#fff",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: 700,
    margin: "0 auto 18px",
    fontSize: 15,
  },
  title: {
    fontSize: 20,
    fontWeight: 600,
    margin: "0 0 4px",
    color: "var(--text-primary)",
  },
  subtitle: {
    fontSize: 14,
    color: "var(--text-secondary)",
    margin: "0 0 24px",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: 14,
    textAlign: "left",
  },
  label: {
    fontSize: 13,
    color: "var(--text-secondary)",
    display: "flex",
    flexDirection: "column",
    gap: 6,
  },
  input: {
    border: "1px solid var(--border)",
    borderRadius: 10,
    padding: "10px 12px",
    fontSize: 14,
    outline: "none",
    color: "var(--text-primary)",
    background: "var(--bg)",
  },
  button: {
    marginTop: 6,
    background: "var(--accent)",
    color: "#fff",
    border: "none",
    borderRadius: 10,
    padding: "11px 14px",
    fontSize: 14,
    fontWeight: 600,
  },
  error: {
    color: "var(--danger)",
    fontSize: 13,
    background: "#fbeae6",
    borderRadius: 8,
    padding: "8px 10px",
  },
  hint: {
    marginTop: 20,
    fontSize: 12,
    color: "var(--text-secondary)",
  },
  link: {
    color: "var(--accent)",
    fontWeight: 600,
    textDecoration: "none",
  },
};
