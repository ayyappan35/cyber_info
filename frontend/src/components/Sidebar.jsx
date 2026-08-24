import { LogOut, Moon, Plus, Shield, Sun, X } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";

export default function Sidebar({
  conversations,
  activeId,
  onSelect,
  onNewChat,
  onDelete,
  view,
  onOpenTraining,
}) {
  const { username, role, isAdmin, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const initials = (username || "?").slice(0, 2).toUpperCase();

  return (
    <aside className="flex h-full w-[260px] shrink-0 flex-col border-r border-line bg-charcoal text-ink">
      <div className="flex items-center gap-3 px-4 pb-4 pt-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-copper text-sm font-bold text-white">
          CD
        </div>
        <div className="flex-1 leading-tight">
          <div className="text-sm font-semibold text-ink">Cyber Defense</div>
          <div className="text-xs text-ink-dim">Agentic threat response</div>
        </div>
        <button
          onClick={toggleTheme}
          title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-ink-dim transition hover:bg-surface-hover hover:text-ink"
        >
          {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
        </button>
      </div>

      <button
        onClick={onNewChat}
        className="mx-3 mb-2 flex items-center justify-center gap-2 rounded-lg border border-line bg-surface px-3 py-2.5 text-sm font-medium text-ink transition hover:bg-surface-hover"
      >
        <Plus size={15} /> New chat
      </button>

      {isAdmin && (
        <button
          onClick={onOpenTraining}
          className={`mx-3 mb-4 flex items-center gap-2 rounded-lg border px-3 py-2.5 text-sm font-medium transition ${
            view === "training"
              ? "border-copper/50 bg-copper-soft text-copper"
              : "border-transparent text-ink-dim hover:bg-surface-hover hover:text-ink"
          }`}
        >
          <Shield size={15} /> Admin Dashboard
        </button>
      )}

      <div className="px-4 pb-2 pt-1 text-[11px] font-semibold uppercase tracking-wide text-ink-dim">
        Recent
      </div>

      <div className="flex-1 space-y-0.5 overflow-y-auto px-2">
        {conversations.length === 0 && (
          <div className="px-2 py-2 text-xs text-ink-dim">No conversations yet</div>
        )}
        {conversations.map((c) => (
          <div
            key={c.id}
            onClick={() => onSelect(c.id)}
            className={`group flex cursor-pointer items-center justify-between gap-2 rounded-lg px-3 py-2 text-sm transition ${
              c.id === activeId && view === "chat"
                ? "bg-surface-active text-ink"
                : "text-ink-dim hover:bg-surface-hover hover:text-ink"
            }`}
          >
            <span className="truncate">{c.title || "New chat"}</span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onDelete(c.id);
              }}
              title="Delete conversation"
              className="shrink-0 text-ink-dim opacity-0 transition hover:text-copper group-hover:opacity-100"
            >
              <X size={13} />
            </button>
          </div>
        ))}
      </div>

      <div className="space-y-3 border-t border-line p-3">
        <div className="flex items-center gap-2 px-1">
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-surface-hover text-xs font-semibold text-ink">
            {initials}
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-medium text-ink">{username}</span>
            <span className="mt-0.5 w-fit rounded bg-[var(--color-badge-bg)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--color-badge-text)]">
              {role.toUpperCase()}
            </span>
          </div>
        </div>
        <button
          onClick={logout}
          className="flex w-full items-center justify-center gap-2 rounded-lg border border-line px-3 py-2 text-sm text-ink-dim transition hover:border-copper/40 hover:text-ink"
        >
          <LogOut size={14} /> Sign out
        </button>
      </div>
    </aside>
  );
}
