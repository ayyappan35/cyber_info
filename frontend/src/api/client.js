// VITE_API_BASE_URL is read at build time - set it in Render's environment
// variables to the deployed backend's URL; falls back to localhost for
// local dev (`npm run dev`), where the backend runs on :8000 by default.
export const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

function getToken() {
  return localStorage.getItem("token");
}

async function request(path, { method = "GET", body, isForm = false } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (!isForm && body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: isForm ? body : body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    window.location.href = "/login";
    throw new Error("Not authenticated");
  }

  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `Request failed (${res.status})`);
  }

  if (res.status === 204) return null;
  return res.json();
}

// Server-Sent Events over a POST body: native EventSource only supports GET,
// so this reads the streamed response body directly and parses the
// `data: {...}\n\n` frames as they arrive. Calls onEvent for each event as
// it's received (thinking/tool_call/tool_result/reasoning/...), and
// resolves with the final "done" event's payload once the stream ends.
async function requestStream(path, body, onEvent) {
  const token = getToken();
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });

  if (res.status === 401) {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    window.location.href = "/login";
    throw new Error("Not authenticated");
  }
  if (!res.ok || !res.body) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || `Request failed (${res.status})`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalPayload = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const frames = buffer.split("\n\n");
    buffer = frames.pop(); // last chunk may be incomplete, keep it for next read

    for (const frame of frames) {
      const line = frame.split("\n").find((l) => l.startsWith("data: "));
      if (!line) continue;
      const event = JSON.parse(line.slice(6));
      if (event.type === "error") throw new Error(event.message);
      if (event.type === "done") finalPayload = event;
      onEvent?.(event);
    }
  }

  if (!finalPayload) throw new Error("Stream ended without a result");
  return finalPayload;
}

export const api = {
  signup: (username, email, password) =>
    request("/api/auth/signup", { method: "POST", body: { username, email, password } }),
  login: (username, password) =>
    request("/api/auth/login", { method: "POST", body: { username, password } }),
  logout: () => request("/api/auth/logout", { method: "POST" }),
  me: () => request("/api/auth/me"),

  listConversations: () => request("/api/conversations"),
  createConversation: () => request("/api/conversations", { method: "POST" }),
  getMessages: (conversationId) => request(`/api/conversations/${conversationId}/messages`),
  deleteConversation: (conversationId) =>
    request(`/api/conversations/${conversationId}`, { method: "DELETE" }),

  query: (message, conversationId) =>
    request("/api/query", { method: "POST", body: { message, conversation_id: conversationId } }),

  queryStream: (message, conversationId, onEvent) =>
    requestStream("/api/query/stream", { message, conversation_id: conversationId }, onEvent),

  upload: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/api/upload", { method: "POST", body: form, isForm: true });
  },
  trainingHistory: () => request("/api/upload/history"),

  listUsers: () => request("/api/admin/users"),
  setUserRole: (username, role) =>
    request(`/api/admin/users/${encodeURIComponent(username)}/role`, { method: "PATCH", body: { role } }),

  listSecurityEvents: (limit = 50) => request(`/api/security/events?limit=${limit}`),
  listGatewayDecisions: (limit = 50, category) =>
    request(`/api/security/decisions?limit=${limit}${category ? `&category=${encodeURIComponent(category)}` : ""}`),
  listSandbox: (released = false) => request(`/api/security/sandbox?released=${released}`),
  releaseSandboxItem: (sandboxId) =>
    request(`/api/security/sandbox/${encodeURIComponent(sandboxId)}/release`, { method: "POST" }),
  listBlockedIdentities: () => request("/api/security/blocked"),

  listToolCalls: (status = "pending") => request(`/api/security/tool-calls?status=${status}`),
  approveToolCall: (callId) =>
    request(`/api/security/tool-calls/${callId}/approve`, { method: "POST" }),
  denyToolCall: (callId) =>
    request(`/api/security/tool-calls/${callId}/deny`, { method: "POST" }),
  getChain: (identity) => request(`/api/security/chain/${encodeURIComponent(identity)}`),

  getLlmConfig: () => request("/api/security/llm-config"),
  setLlmProvider: (provider) =>
    request("/api/security/llm-config", { method: "POST", body: { provider } }),
};
