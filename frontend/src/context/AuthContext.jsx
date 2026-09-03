import { createContext, useContext, useState, useCallback } from "react";
import { api } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [username, setUsername] = useState(() => localStorage.getItem("username"));
  const [role, setRole] = useState(() => localStorage.getItem("role") || "user");
  const [token, setToken] = useState(() => localStorage.getItem("token"));

  function persistSession(data) {
    localStorage.setItem("token", data.access_token);
    localStorage.setItem("username", data.username);
    localStorage.setItem("role", data.role || "user");
    setToken(data.access_token);
    setUsername(data.username);
    setRole(data.role || "user");
  }

  const login = useCallback(async (user, pass) => {
    const data = await api.login(user, pass);
    // Correct password, but the account is on an account-takeover OTP
    // hold (security_gateway/mcp_gateway.py's require_mfa) - no token
    // yet, the caller (Login.jsx) needs to prompt for the emailed code.
    if (data.mfa_required) return { mfaRequired: true, username: data.username, maskedEmail: data.masked_email };
    persistSession(data);
    return { mfaRequired: false };
  }, []);

  const verifyOtp = useCallback(async (user, otp) => {
    const data = await api.verifyOtp(user, otp);
    persistSession(data);
  }, []);

  const signup = useCallback(async (user, email, pass) => {
    const data = await api.signup(user, email, pass);
    persistSession(data);
  }, []);

  const logout = useCallback(async () => {
    try {
      // Best-effort: revoke the token server-side so it can't be reused
      // even before it expires. Still clear local state below if this
      // fails (e.g. offline) - the user's intent to sign out wins either way.
      await api.logout();
    } catch {
      // ignore - fall through to clearing local session regardless
    }
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
    setToken(null);
    setUsername(null);
    setRole("user");
  }, []);

  return (
    <AuthContext.Provider
      value={{
        username,
        role,
        isAdmin: role === "admin",
        token,
        isAuthenticated: !!token,
        login,
        verifyOtp,
        signup,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
