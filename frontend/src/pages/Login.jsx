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
  const { login, verifyOtp } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [otp, setOtp] = useState("");
  const [showOtp, setShowOtp] = useState(false);
  const [maskedEmail, setMaskedEmail] = useState("");
  // "credentials" | "otp" - flips to "otp" when the security gateway has
  // put this account on an account-takeover hold (a correct password
  // alone isn't enough; the emailed one-time code still is).
  const [step, setStep] = useState("credentials");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await login(username, password);
      if (result.mfaRequired) {
        setMaskedEmail(result.maskedEmail || "");
        setStep("otp");
      } else {
        navigate("/chat");
      }
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyOtp(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await verifyOtp(username, otp);
      navigate("/chat");
    } catch (err) {
      setError(err.message || "Verification failed");
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

          {step === "credentials" ? (
            <>
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
                  <div style={styles.inputWrap}>
                    <input
                      style={{ ...styles.input, ...styles.inputWithButton }}
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((v) => !v)}
                      style={styles.eyeButton}
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      tabIndex={-1}
                    >
                      {showPassword ? "🙈" : "👁"}
                    </button>
                  </div>
                </label>

                {error && <div style={styles.error}>{error}</div>}

                <button style={styles.button} type="submit" disabled={loading}>
                  {loading ? "Signing in..." : "Sign in"}
                </button>
              </form>

              <p style={styles.hint}>
                Don't have an account? <Link to="/signup" style={styles.link}>Sign up</Link>
              </p>
            </>
          ) : (
            <>
              <h2 style={styles.title}>Verify it's you</h2>
              <p style={styles.subtitle}>
                This account was flagged for a suspicious sign-in pattern. We
                emailed a 6-digit code to{" "}
                {maskedEmail ? <b style={styles.emailHighlight}>{maskedEmail}</b> : "the address on file"} -
                enter it below to finish signing in.
              </p>

              <form onSubmit={handleVerifyOtp} style={styles.form}>
                <label style={styles.label}>
                  Verification code
                  <div style={styles.inputWrap}>
                    <input
                      style={{ ...styles.input, ...styles.inputWithButton }}
                      type={showOtp ? "text" : "password"}
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      inputMode="numeric"
                      maxLength={6}
                      autoFocus
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowOtp((v) => !v)}
                      style={styles.eyeButton}
                      aria-label={showOtp ? "Hide code" : "Show code"}
                      tabIndex={-1}
                    >
                      {showOtp ? "🙈" : "👁"}
                    </button>
                  </div>
                </label>

                {error && <div style={styles.error}>{error}</div>}

                <button style={styles.button} type="submit" disabled={loading}>
                  {loading ? "Verifying..." : "Verify and sign in"}
                </button>
              </form>

              <p style={styles.hint}>
                Wrong account?{" "}
                <button
                  type="button"
                  onClick={() => {
                    setStep("credentials");
                    setOtp("");
                    setShowOtp(false);
                    setMaskedEmail("");
                    setError("");
                  }}
                  style={styles.linkButton}
                >
                  Start over
                </button>
              </p>
            </>
          )}
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
    width: "100%",
  },
  inputWrap: {
    position: "relative",
    display: "flex",
  },
  inputWithButton: {
    paddingRight: 40,
  },
  eyeButton: {
    position: "absolute",
    right: 4,
    top: "50%",
    transform: "translateY(-50%)",
    background: "none",
    border: "none",
    cursor: "pointer",
    fontSize: 16,
    lineHeight: 1,
    padding: 6,
    borderRadius: 6,
  },
  emailHighlight: {
    color: "var(--text-primary)",
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
  linkButton: {
    color: "var(--accent)",
    fontWeight: 600,
    background: "none",
    border: "none",
    padding: 0,
    font: "inherit",
    cursor: "pointer",
  },
};
