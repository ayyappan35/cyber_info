import {
  Activity, AlertTriangle, Archive, Ban, Check, CheckCircle2, ChevronRight, Clock, Database,
  FileArchive, FileCode2, FileSpreadsheet, FileText, Lock, Plus, ShieldAlert, ShieldCheck,
  UploadCloud, Users as UsersIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";

const ACCEPTED = ".md,.txt,.pdf,.xlsx,.docx,.zip";
const ACCEPTED_CHIPS = ["md", "txt", "pdf", "xlsx", "docx", "zip"];

const STATUS_STYLE = {
  pending: "bg-amber-400",
  done: "bg-emerald-500",
  error: "bg-red-500",
};

const FILE_ICON = {
  pdf: FileText,
  docx: FileText,
  md: FileCode2,
  txt: FileCode2,
  xlsx: FileSpreadsheet,
  zip: FileArchive,
};

function fileIconFor(name) {
  const ext = name?.split(".").pop()?.toLowerCase();
  return FILE_ICON[ext] || FileText;
}

const TABS = [
  { key: "security", label: "Overview", icon: ShieldAlert },
  { key: "kb", label: "Knowledge Base", icon: Database },
  { key: "users", label: "Users", icon: UsersIcon },
];

export default function TrainingPanel() {
  const [tab, setTab] = useState("security"); // "security" | "kb" | "users"

  return (
    <div className="flex-1 overflow-y-auto bg-charcoal text-ink">
      <div className={`mx-auto px-6 py-10 ${tab === "security" ? "max-w-5xl" : "max-w-2xl"}`}>
        <div className="mb-7 flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-copper-soft text-copper">
            <ShieldCheck size={20} />
          </div>
          <div>
            <h1 className="font-serif text-2xl leading-tight text-ink">Admin Dashboard</h1>
            <p className="text-xs text-ink-dim">Security gateway, knowledge base &amp; access control</p>
          </div>
        </div>

        <div className="mb-8 flex gap-1 rounded-xl border border-line bg-surface p-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = tab === t.key;
            return (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`flex flex-1 items-center justify-center gap-1.5 rounded-lg px-3 py-2 text-sm font-medium transition ${
                  active ? "bg-surface-active text-ink shadow-sm" : "text-ink-dim hover:text-ink"
                }`}
              >
                <Icon size={14} className={active ? "text-copper" : ""} /> {t.label}
              </button>
            );
          })}
        </div>

        {tab === "kb" ? <KnowledgeBaseTab /> : tab === "users" ? <UsersTab /> : <SecurityTab />}
      </div>
    </div>
  );
}

function SectionHeading({ icon: Icon, children, action }) {
  return (
    <div className="mb-3 flex items-center justify-between gap-2 border-b border-line pb-2.5">
      <h2 className="flex items-center gap-1.5 text-sm font-semibold text-ink">
        {Icon && <Icon size={14} className="text-copper" />} {children}
      </h2>
      {action}
    </div>
  );
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function KnowledgeBaseTab() {
  const [items, setItems] = useState([]); // {id, name, status: pending|done|error, detail}
  const [history, setHistory] = useState([]); // persisted rows: {filename, filesize, trained_by, date}
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  async function refreshHistory() {
    try {
      setHistory(await api.trainingHistory());
    } catch {
      // non-fatal - the session-local "items" list still shows upload progress
    }
  }

  useEffect(() => {
    refreshHistory();
  }, []);

  function addFiles(fileList) {
    const files = Array.from(fileList || []);
    files.forEach(uploadOne);
  }

  async function uploadOne(file) {
    const id = `${file.name}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setItems((prev) => [{ id, name: file.name, status: "pending", detail: "Ingesting..." }, ...prev]);

    try {
      const resp = await api.upload(file);
      const detail = resp.chunks_quarantined > 0
        ? `${resp.chunks_ingested} chunk(s) added · ${resp.chunks_quarantined} quarantined (see Overview → Sandbox)`
        : `${resp.chunks_ingested} chunk(s) added`;
      setItems((prev) =>
        prev.map((it) =>
          it.id === id
            ? { ...it, status: resp.chunks_quarantined > 0 ? "pending" : "done", detail }
            : it,
        ),
      );
      refreshHistory();
    } catch (err) {
      setItems((prev) =>
        prev.map((it) => (it.id === id ? { ...it, status: "error", detail: err.message } : it)),
      );
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    addFiles(e.dataTransfer.files);
  }

  return (
    <div>
      <p className="mb-5 text-sm leading-relaxed text-ink-dim">
        Upload runbooks, threat intel, or reference docs to add them into the
        cyber-defense knowledge base used by chat, the SOC agents, and MITRE/OWASP
        lookups.
      </p>

      <div className="mb-6 flex flex-wrap gap-1.5">
        {ACCEPTED_CHIPS.map((ext) => (
          <span
            key={ext}
            className="rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-[11px] uppercase text-ink-dim"
          >
            .{ext}
          </span>
        ))}
      </div>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`cursor-pointer rounded-2xl border-2 border-dashed px-6 py-12 text-center transition ${
          dragOver ? "scale-[1.01] border-copper bg-copper-soft" : "border-line bg-surface hover:border-copper/40"
        }`}
      >
        <div
          className={`mx-auto mb-3.5 flex h-12 w-12 items-center justify-center rounded-full bg-copper-soft text-copper transition ${
            dragOver ? "scale-110" : ""
          }`}
        >
          <UploadCloud size={22} />
        </div>
        <div className="text-sm font-medium text-ink">Drop files here, or click to browse</div>
        <div className="mt-1 text-xs text-ink-dim">Ingested straight into the vector knowledge base</div>
        <input
          ref={fileInputRef}
          type="file"
          accept={ACCEPTED}
          multiple
          className="hidden"
          onChange={(e) => {
            addFiles(e.target.files);
            e.target.value = "";
          }}
        />
      </div>

      <div className="mb-2.5 mt-8 text-xs font-semibold uppercase tracking-wide text-ink-dim">
        Upload history
      </div>
      <div className="flex flex-col gap-1.5">
        {items.length === 0 && (
          <div className="rounded-xl border border-dashed border-line px-3 py-3 text-sm text-ink-dim">
            No files uploaded this session yet
          </div>
        )}
        {items.map((it) => {
          const Icon = fileIconFor(it.name);
          return (
            <div
              key={it.id}
              className="flex items-center gap-3 rounded-xl border border-line bg-surface px-3 py-2.5 text-sm transition hover:bg-surface-hover"
            >
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-copper-soft text-copper">
                <Icon size={14} />
              </div>
              <span className="max-w-[240px] truncate font-medium text-ink">{it.name}</span>
              {it.status === "done" ? (
                <CheckCircle2 size={14} className="ml-auto shrink-0 text-emerald-500" />
              ) : (
                <span className={`ml-auto h-2 w-2 shrink-0 rounded-full ${STATUS_STYLE[it.status]}`} />
              )}
              <span className="shrink-0 text-right text-xs text-ink-dim">{it.detail}</span>
            </div>
          );
        })}
      </div>

      <button
        onClick={() => fileInputRef.current?.click()}
        className="mt-6 inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-xs text-ink-dim transition hover:border-copper/40 hover:text-ink"
      >
        <Plus size={12} /> Add another file
      </button>

      <div className="mb-2.5 mt-8 text-xs font-semibold uppercase tracking-wide text-ink-dim">
        Trained files
      </div>
      <div className="flex flex-col gap-1.5">
        {history.length === 0 && (
          <div className="rounded-xl border border-dashed border-line px-3 py-3 text-sm text-ink-dim">
            No files trained yet
          </div>
        )}
        {history.map((f) => {
          const Icon = fileIconFor(f.filename);
          return (
            <div
              key={f.filename}
              className="flex items-center gap-3 rounded-xl border border-line bg-surface px-3 py-2.5 text-sm transition hover:bg-surface-hover"
            >
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-surface-active text-ink-dim">
                <Icon size={14} />
              </div>
              <span className="max-w-[220px] truncate font-medium text-ink">{f.filename}</span>
              <span className="shrink-0 rounded-md bg-surface-active px-1.5 py-0.5 font-mono text-[11px] text-ink-dim">
                {formatFileSize(f.filesize)}
              </span>
              <span className="ml-auto shrink-0 text-right text-xs text-ink-dim">
                {f.trained_by} &middot; {new Date(f.date).toLocaleString()}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function UsersTab() {
  const { username: currentUsername } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updating, setUpdating] = useState(null); // username currently being changed

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      setUsers(await api.listUsers());
    } catch (err) {
      setError(err.message || "Failed to load users");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function handleRoleChange(user, role) {
    if (role === user.role) return;
    setUpdating(user.username);
    setError("");
    try {
      const updated = await api.setUserRole(user.username, role);
      setUsers((prev) => prev.map((u) => (u.username === updated.username ? updated : u)));
    } catch (err) {
      setError(err.message || "Failed to update role");
    } finally {
      setUpdating(null);
    }
  }

  return (
    <div>
      <p className="mb-6 flex items-center gap-1.5 text-sm leading-relaxed text-ink-dim">
        <UsersIcon size={14} className="shrink-0" />
        All registered accounts. Set who has admin access - admins can manage the
        knowledge base and other users' roles.
      </p>

      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="px-0.5 py-2 text-sm text-ink-dim">Loading users...</div>
      ) : (
        <div className="flex flex-col gap-1.5">
          {users.map((user) => {
            const isSelf = user.username === currentUsername;
            const initials = user.username.slice(0, 2).toUpperCase();
            const isLocked = user.locked === 1 || user.locked === true;
            return (
              <div
                key={user.username}
                className="flex items-center gap-3 rounded-xl border border-line bg-surface px-3 py-2.5 text-sm transition hover:bg-surface-hover"
              >
                <div
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${
                    user.role === "admin" ? "bg-copper-soft text-copper" : "bg-surface-active text-ink-dim"
                  }`}
                >
                  {initials}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate font-medium text-ink">{user.username}</span>
                    {isLocked && <Lock size={11} className="shrink-0 text-red-400" aria-label="Locked account" />}
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                        user.role === "admin"
                          ? "bg-[var(--color-badge-bg)] text-[var(--color-badge-text)]"
                          : "bg-surface-active text-ink-dim"
                      }`}
                    >
                      {user.role}
                    </span>
                  </div>
                  <div className="truncate text-xs text-ink-dim">{user.email || "no email"}</div>
                </div>
                <select
                  value={user.role}
                  disabled={isSelf || updating === user.username}
                  onChange={(e) => handleRoleChange(user, e.target.value)}
                  title={isSelf ? "You can't change your own role" : "Set role"}
                  className="shrink-0 rounded-md border border-line bg-charcoal px-2 py-1 text-xs text-ink disabled:opacity-50"
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

const ACTION_STYLE = {
  ALLOW: "border-emerald-500/30 text-emerald-500",
  MITIGATE: "border-amber-400/30 text-amber-400",
  BLOCK: "border-red-500/30 text-red-400",
};

const STAT_TILES = [
  { key: "sandbox", label: "Items in sandbox", icon: Archive, tone: "text-amber-400", tint: "bg-amber-400/10" },
  { key: "blocked", label: "Blocked identities", icon: Ban, tone: "text-red-400", tint: "bg-red-500/10" },
  { key: "pending", label: "Pending tool approvals", icon: ShieldAlert, tone: "text-copper", tint: "bg-copper-soft" },
  { key: "mitigated", label: "Recent MITIGATE", icon: AlertTriangle, tone: "text-amber-400", tint: "bg-amber-400/10" },
  { key: "blockedDecisions", label: "Recent BLOCK", icon: Ban, tone: "text-red-400", tint: "bg-red-500/10" },
];

function SecurityTab() {
  const [events, setEvents] = useState([]);
  const [decisions, setDecisions] = useState([]);
  const [sandbox, setSandbox] = useState([]);
  const [blocked, setBlocked] = useState([]);
  const [toolCalls, setToolCalls] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [releasing, setReleasing] = useState(null);
  const [deciding, setDeciding] = useState(null);
  const [expandedSandbox, setExpandedSandbox] = useState(() => new Set());
  const [approvedResults, setApprovedResults] = useState([]); // session-local: [{callId, toolName, identity, result}]

  function toggleSandboxExpanded(sandboxId) {
    setExpandedSandbox((prev) => {
      const next = new Set(prev);
      if (next.has(sandboxId)) next.delete(sandboxId);
      else next.add(sandboxId);
      return next;
    });
  }

  async function refresh() {
    setError("");
    try {
      const [ev, dec, sbx, blk, calls] = await Promise.all([
        api.listSecurityEvents(30),
        api.listGatewayDecisions(30),
        api.listSandbox(false),
        api.listBlockedIdentities(),
        api.listToolCalls("pending"),
      ]);
      setEvents(ev);
      setDecisions(dec);
      setSandbox(sbx);
      setBlocked(blk);
      setToolCalls(calls);
    } catch (err) {
      setError(err.message || "Failed to load security data");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
    // Auto-refresh every 8s while this tab is open - a new pending tool
    // approval (e.g. a chat request just flagged by pii-exposure) must
    // show up here without the admin having to navigate away and back to
    // remount this component. Real observed gap (2026-08-24): the
    // one-shot mount-only fetch left this list stale during a live demo.
    const interval = setInterval(refresh, 8000);
    return () => clearInterval(interval);
  }, []);

  async function handleRelease(sandboxId) {
    setReleasing(sandboxId);
    setError("");
    try {
      await api.releaseSandboxItem(sandboxId);
      setSandbox((prev) => prev.filter((s) => s.sandbox_id !== sandboxId));
    } catch (err) {
      setError(err.message || "Failed to release sandbox item");
    } finally {
      setReleasing(null);
    }
  }

  async function handleToolCallDecision(call, decision) {
    setDeciding(call.id);
    setError("");
    try {
      if (decision === "approve") {
        const resp = await api.approveToolCall(call.id);
        // The tool's real result (e.g. disclose_pii_answer's generated
        // answer) is only computed at approval time - shown here so the
        // admin actually sees what they just approved, not just that
        // "approved" happened.
        setApprovedResults((prev) => [
          { callId: call.id, toolName: call.tool_name, identity: call.identity, result: resp.result },
          ...prev,
        ]);
      } else {
        await api.denyToolCall(call.id);
      }
      setToolCalls((prev) => prev.filter((c) => c.id !== call.id));
    } catch (err) {
      setError(err.message || "Failed to record decision");
    } finally {
      setDeciding(null);
    }
  }

  function dismissApprovedResult(callId) {
    setApprovedResults((prev) => prev.filter((r) => r.callId !== callId));
  }

  const blockedDecisions = decisions.filter((d) => d.action === "BLOCK").length;
  const mitigatedDecisions = decisions.filter((d) => d.action === "MITIGATE").length;

  if (loading) {
    return <div className="px-0.5 py-2 text-sm text-ink-dim">Loading security data...</div>;
  }

  const statValues = {
    sandbox: sandbox.length,
    blocked: blocked.length,
    pending: toolCalls.length,
    mitigated: mitigatedDecisions,
    blockedDecisions,
  };

  return (
    <div className="flex flex-col gap-9">
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <section>
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="flex items-center gap-1.5 text-sm font-semibold text-ink">
            <Activity size={14} className="text-copper" /> Security Gateway Status
          </h2>
          <button
            onClick={refresh}
            className="flex items-center gap-1 rounded-md border border-line px-2 py-1 text-[11px] text-ink-dim transition hover:border-copper/40 hover:text-ink"
          >
            <Clock size={11} /> Refresh &middot; auto-updates every 8s
          </button>
        </div>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-5">
          {STAT_TILES.map((t) => {
            const Icon = t.icon;
            const value = statValues[t.key];
            const urgent = t.key === "pending" && value > 0;
            return (
              <div
                key={t.key}
                className={`relative overflow-hidden rounded-xl border bg-surface px-3.5 py-3.5 transition hover:bg-surface-hover ${
                  urgent ? "border-copper/40" : "border-line"
                }`}
              >
                <div className={`mb-2.5 flex h-7 w-7 items-center justify-center rounded-lg ${t.tint} ${t.tone}`}>
                  <Icon size={14} />
                </div>
                <div className="font-sans text-2xl font-semibold leading-none text-ink">{value}</div>
                <div className="mt-1.5 text-xs leading-tight text-ink-dim">{t.label}</div>
                {urgent && <span className="pulse-dot absolute right-3 top-3 !mr-0" />}
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <SectionHeading icon={ShieldAlert}>Pending Tool Approvals</SectionHeading>
        {toolCalls.length === 0 ? (
          <div className="rounded-xl border border-dashed border-line px-3 py-3 text-xs text-ink-dim">
            Nothing awaiting approval - critical MCP tools (block_ip, terminate_session, remove_vector,
            disclose_pii_answer) queue here instead of auto-executing.
          </div>
        ) : (
          <div className="flex flex-col gap-1.5">
            {toolCalls.map((c) => (
              <div key={c.id}
                   className="flex items-center gap-3 rounded-xl border border-l-[3px] border-line border-l-copper bg-surface px-3 py-2.5 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="font-medium text-ink">
                    <span className="text-copper">{c.tool_name}</span> &rarr; {c.identity}
                  </div>
                  <div className="truncate text-xs text-ink-dim">{JSON.stringify(c.arguments)}</div>
                  <div className="mt-0.5 flex items-center gap-1 text-[11px] text-ink-dim">
                    <Clock size={10} /> {c.ts}
                  </div>
                </div>
                <button
                  onClick={() => handleToolCallDecision(c, "approve")}
                  disabled={deciding === c.id}
                  title="Approve"
                  className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-emerald-500/30 text-emerald-500 transition hover:bg-emerald-500/10 disabled:opacity-50"
                >
                  <Check size={14} />
                </button>
                <button
                  onClick={() => handleToolCallDecision(c, "deny")}
                  disabled={deciding === c.id}
                  title="Deny"
                  className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-red-500/30 text-red-400 transition hover:bg-red-500/10 disabled:opacity-50"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {approvedResults.length > 0 && (
        <section>
          <SectionHeading icon={Check}>Approved &mdash; Admin-Only Result</SectionHeading>
          <p className="mb-2 px-0.5 text-xs text-ink-dim">
            Computed only now, at approval time. Visible here to you only - relay it out of band if
            appropriate; nothing is delivered back into the requester's chat automatically.
          </p>
          <div className="flex flex-col gap-1.5">
            {approvedResults.map((r) => (
              <div key={r.callId} className="rounded-xl border border-emerald-500/30 bg-surface px-3 py-2.5 text-xs">
                <div className="mb-1.5 flex items-center gap-2">
                  <span className="font-medium text-ink">
                    <span className="text-emerald-500">{r.toolName}</span> &rarr; {r.identity}
                  </span>
                  <button
                    onClick={() => dismissApprovedResult(r.callId)}
                    className="ml-auto text-ink-dim hover:text-ink"
                    title="Dismiss"
                  >
                    &times;
                  </button>
                </div>
                {r.result?.answer ? (
                  <div className="rounded-md border border-line bg-charcoal p-2.5 text-ink">{r.result.answer}</div>
                ) : (
                  <pre className="max-h-[200px] overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-charcoal p-2.5 font-mono text-ink">
                    {JSON.stringify(r.result, null, 2)}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="grid grid-cols-1 gap-9 lg:grid-cols-2">
        <section>
          <SectionHeading icon={Archive}>Sandbox (needs review)</SectionHeading>
          <p className="mb-2 px-0.5 text-xs text-ink-dim">
            Admin-only view - the full withheld question/context (including any detected PII) is
            shown here so you can review and, if appropriate, relay it out of band. Nothing here
            is ever shown to the requesting user.
          </p>
          {sandbox.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line px-3 py-3 text-xs text-ink-dim">
              Nothing sandboxed
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {sandbox.map((s) => {
                const isOpen = expandedSandbox.has(s.sandbox_id);
                return (
                  <div key={s.sandbox_id} className="rounded-lg border border-line bg-surface text-xs">
                    <div
                      onClick={() => toggleSandboxExpanded(s.sandbox_id)}
                      className="flex cursor-pointer items-center gap-2 px-3 py-2.5"
                    >
                      <ChevronRight size={12} className={`shrink-0 text-ink-dim transition-transform ${isOpen ? "rotate-90" : ""}`} />
                      <span className="shrink-0 rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 font-medium text-amber-400">
                        {s.category}
                      </span>
                      {s.metadata?.per_chunk && (
                        <span className="shrink-0 rounded-full border border-copper/30 bg-copper-soft px-2 py-0.5 font-medium text-copper">
                          chunk {s.metadata?.chunk_index}
                        </span>
                      )}
                      {s.metadata?.skill_ids?.includes("pii-exposure") && (
                        <span className="shrink-0 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 font-medium text-red-400">
                          PII
                        </span>
                      )}
                      <span className="min-w-0 flex-1 truncate text-ink-dim">
                        {s.metadata?.filename || s.identity} &middot; {s.metadata?.reasoning || ""}
                      </span>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleRelease(s.sandbox_id); }}
                        disabled={releasing === s.sandbox_id}
                        title={s.metadata?.per_chunk
                          ? "Approve - embeds this chunk into the knowledge base"
                          : "Approve / mark reviewed"}
                        className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-emerald-500/30 text-emerald-500 transition hover:bg-emerald-500/10 disabled:opacity-50"
                      >
                        <Check size={12} />
                      </button>
                    </div>
                    {isOpen && (
                      <div className="border-t border-line px-3 py-2.5">
                        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-ink-dim">
                          Withheld content ({s.kind}) &middot; requested by {s.identity} &middot; {s.ts}
                          {s.metadata?.per_chunk && ` · chunk ${s.metadata?.chunk_index} of "${s.metadata?.filename}"`}
                          {typeof s.metadata?.injection_score === "number"
                            && ` · injection score ${s.metadata.injection_score.toFixed(3)}`}
                        </div>
                        <pre className="max-h-[300px] overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-charcoal p-2.5 font-mono text-[11px] text-ink">
                          {s.content || "(no content stored)"}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section>
          <SectionHeading icon={Ban}>Blocked Identities</SectionHeading>
          {blocked.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line px-3 py-3 text-xs text-ink-dim">
              Nothing currently blocked
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {blocked.map((b) => (
                <div key={`${b.identity}-${b.category}`}
                     className="flex items-center gap-2 rounded-lg border border-l-[3px] border-line border-l-red-500/50 bg-surface px-3 py-2.5 text-xs">
                  <span className="shrink-0 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 font-medium text-red-400">
                    {b.category}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-ink-dim">{b.identity} - {b.reason}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      <div className="grid grid-cols-1 gap-9 lg:grid-cols-2">
        <section>
          <SectionHeading icon={ShieldCheck}>Gateway Decisions</SectionHeading>
          <div className="flex flex-col gap-1.5">
            {decisions.length === 0 ? (
              <div className="rounded-xl border border-dashed border-line px-3 py-3 text-xs text-ink-dim">
                No decisions recorded yet
              </div>
            ) : (
              decisions.map((d) => (
                <div key={d.id} className="rounded-lg border border-line bg-surface px-3 py-2.5 text-xs">
                  <div className="flex items-center gap-2">
                    <span className={`shrink-0 rounded-full border px-2 py-0.5 font-medium ${ACTION_STYLE[d.action] || ""}`}>
                      {d.action}
                    </span>
                    <span className="font-medium text-ink">{d.category}</span>
                    <span className="text-ink-dim">{d.identity}</span>
                  </div>
                  <div className="mt-1 line-clamp-2 text-ink-dim">{d.reasoning}</div>
                </div>
              ))
            )}
          </div>
        </section>

        <section>
          <SectionHeading icon={Activity}>Recent Security Events</SectionHeading>
          <div className="flex flex-col gap-1">
            {events.map((e) => (
              <div key={e.id} className="flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2 text-xs">
                <span className="w-36 shrink-0 truncate font-mono text-[11px] text-ink-dim">{e.ts}</span>
                <span className="shrink-0 font-medium text-ink">{e.agent_id}</span>
                <span className="min-w-0 flex-1 truncate text-ink-dim">{e.tool_name} &rarr; {e.decision}</span>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
