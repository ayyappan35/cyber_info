import { ArrowUp, Check, ChevronRight, Cpu, Lock, Paperclip, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import AgentTrace from "./AgentTrace";

const PROMPTS = [
  { text: "What should I do about a brute force login attempt?" },
  { text: "What MITRE technique covers session hijacking?" },
  { text: "What should I watch for with impossible travel logins?" },
];

export default function ChatWindow({
  messages,
  onSend,
  onUpload,
  onMessageApproval,
  sending,
  liveStatus,
  liveTrace,
  uploadStatus,
}) {
  const { username, isAdmin } = useAuth();
  const [input, setInput] = useState("");
  const [metaOpen, setMetaOpen] = useState(false);
  const [llmConfig, setLlmConfig] = useState(null); // {provider, model, ...} from GET /api/security/llm-config
  const [decidingIndex, setDecidingIndex] = useState(null);
  const [switchingProvider, setSwitchingProvider] = useState(false);
  const fileInputRef = useRef(null);
  const bottomRef = useRef(null);

  async function handleApproval(index, decision) {
    setDecidingIndex(index);
    try {
      await onMessageApproval(index, decision);
    } finally {
      setDecidingIndex(null);
    }
  }

  async function handleSwitchProvider(provider) {
    if (llmConfig?.provider === provider) return;
    setSwitchingProvider(true);
    try {
      setLlmConfig(await api.setLlmProvider(provider));
    } catch {
      // Non-fatal for the chat view - the model badge just won't update;
      // most likely cause is ANTHROPIC_API_KEY not set yet in .env.
    } finally {
      setSwitchingProvider(false);
    }
  }

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, sending]);

  useEffect(() => {
    api.getLlmConfig().then(setLlmConfig).catch(() => {});
  }, [sending]); // re-fetch after each turn so a mid-session provider switch shows up

  function handleSubmit(e) {
    e.preventDefault();
    const text = input.trim();
    if (!text || sending) return;
    onSend(text);
    setInput("");
  }

  function handlePrompt(text) {
    if (sending) return;
    onSend(text);
  }

  function handleFileChange(e) {
    const file = e.target.files?.[0];
    if (file) onUpload(file);
    e.target.value = "";
  }

  const isEmpty = messages.length === 0;

  return (
    <div className="flex h-full flex-1 flex-col bg-charcoal text-ink">
      <div className="border-b border-line px-8 py-4">
        <h1 className="font-serif text-xl text-ink">Chat</h1>
        <p className="mt-0.5 text-xs text-ink-dim">
          Agentic &middot; skill-grounded tool use &middot; Security Gateway check
        </p>
      </div>

      {isEmpty && !sending ? (
        <div className="flex flex-1 flex-col items-center justify-center overflow-y-auto px-6 text-center">
          <span className="mb-6 rounded-full border border-copper/30 bg-copper-soft px-3 py-1 text-[11px] font-semibold uppercase tracking-wide text-copper">
            Signed in as {(username || "").toUpperCase()}
          </span>

          <h2 className="font-serif text-3xl text-ink">What would you like to know?</h2>
          <p className="mt-3 max-w-md text-sm leading-relaxed text-ink-dim">
            Ask a detection or response question. The assistant can search the knowledge base
            more than once and pull a security skill's real methodology before answering -
            everything it gathers is checked by the RAG Security gateway before an answer
            reaches you.
          </p>

          <div className="mt-8 flex w-full max-w-lg flex-col gap-2">
            {PROMPTS.map((p) => (
              <button
                key={p.text}
                onClick={() => handlePrompt(p.text)}
                className="flex w-full items-center justify-between gap-3 rounded-full border border-line bg-surface px-5 py-3 text-left text-sm text-ink transition hover:border-copper/40 hover:bg-surface-hover"
              >
                <span>{p.text}</span>
                {p.tag && (
                  <span className="shrink-0 rounded-full bg-red-500/15 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide text-red-400">
                    {p.tag}
                  </span>
                )}
              </button>
            ))}
          </div>

          <div className="mt-6 w-full max-w-lg">
            <button
              onClick={() => setMetaOpen((v) => !v)}
              className="mx-auto flex items-center gap-1.5 text-xs text-ink-dim transition hover:text-ink"
            >
              <ChevronRight size={13} className={`transition-transform ${metaOpen ? "rotate-90" : ""}`} />
              How this works &middot; model {llmConfig?.model || "..."}
            </button>
            {metaOpen && (
              <div className="mt-3 rounded-xl border border-line bg-surface px-4 py-3 text-left text-xs leading-relaxed text-ink-dim">
                <div>
                  <span className="font-semibold text-ink">Pipeline:</span> agentic tool-use loop
                  (search the knowledge base, re-search with refined queries, or read a security
                  skill's real methodology) &rarr; RAG Security gateway check over everything
                  gathered &rarr; answer only reaches you once approved
                </div>
                <div className="mt-1.5">
                  <span className="font-semibold text-ink">Tools:</span> search_knowledge_base,
                  get_skill_methodology (reads the actual SKILL.md this system runs)
                </div>
                <div className="mt-1.5">
                  <span className="font-semibold text-ink">Runbooks:</span> brute force &amp;
                  credential stuffing, session hijacking &amp; replay, impossible travel,
                  user enumeration, account lockout policy
                </div>
                <div className="mt-1.5">
                  <span className="font-semibold text-ink">Model:</span> {llmConfig?.model || "loading..."}{" "}
                  ({llmConfig?.provider === "anthropic" ? "Claude, hosted" : "Ollama, local"})
                  {llmConfig?.is_override && " - switched at runtime, not the .env default"}
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto px-8 py-6 md:px-[14%]">
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[80%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-[14.5px] leading-relaxed ${
                  m.role === "user"
                    ? "rounded-br-sm border border-copper/20 bg-copper-soft text-ink"
                    : "rounded-bl-sm border border-line bg-surface text-ink"
                }`}
              >
                <div>{m.content}</div>
                {m.pendingApproval && m.pendingCallId && isAdmin && (
                  <div className="mt-2 rounded-lg border border-amber-400/30 bg-amber-400/10 p-2.5">
                    <div className="mb-1.5 inline-flex items-center gap-1.5 text-[11px] font-medium text-amber-400">
                      <Lock size={11} /> Withheld pending your approval (skills/rag/pii-exposure)
                    </div>
                    <div className="flex gap-1.5">
                      <button
                        onClick={() => handleApproval(i, "approve")}
                        disabled={decidingIndex === i}
                        className="flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-500 transition hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        <Check size={12} /> Approve &amp; reveal
                      </button>
                      <button
                        onClick={() => handleApproval(i, "deny")}
                        disabled={decidingIndex === i}
                        className="flex items-center gap-1 rounded-md border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-400 transition hover:bg-red-500/20 disabled:opacity-50"
                      >
                        <X size={12} /> Deny
                      </button>
                    </div>
                  </div>
                )}
                {m.pendingApproval && (!m.pendingCallId || !isAdmin) && (
                  <div className="mt-2 inline-flex items-center gap-1.5 rounded-full border border-amber-400/30 bg-amber-400/10 px-2.5 py-1 text-[11px] font-medium text-amber-400">
                    <Lock size={11} /> Pending admin approval &middot; Admin Dashboard &rarr; Pending Tool Approvals
                  </div>
                )}
                {m.approvedAnswer && (
                  <div className="mt-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5">
                    <div className="mb-1 inline-flex items-center gap-1.5 text-[11px] font-medium text-emerald-500">
                      <Check size={11} /> Approved by you - revealed just now
                    </div>
                    <div className="text-ink">{m.approvedAnswer}</div>
                  </div>
                )}
                {m.denied && (
                  <div className="mt-2 inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-[11px] font-medium text-red-400">
                    <X size={11} /> Denied - this content will not be disclosed
                  </div>
                )}
                {m.approvalError && (
                  <div className="mt-2 text-[11px] text-red-400">{m.approvalError}</div>
                )}
                {m.sources?.length > 0 && (
                  <div className="mt-2 text-[11.5px] text-ink-dim">
                    Sources: {m.sources.join(", ")}
                  </div>
                )}
                {m.role === "assistant" && <AgentTrace transcript={m.transcript} />}
              </div>
            </div>
          ))}

          {sending && (
            <div className="flex justify-start">
              <div className="max-w-[80%] rounded-2xl rounded-bl-sm border border-line bg-surface px-4 py-3 text-[14.5px] text-ink">
                <span className="inline-flex items-center italic text-ink-dim">
                  <span className="pulse-dot" />
                  {liveStatus || "Thinking..."}
                </span>
                {liveTrace?.length > 0 && <AgentTrace transcript={liveTrace} defaultOpen />}
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>
      )}

      <div className="border-t border-line bg-surface px-8 py-4 md:px-[14%]">
        {uploadStatus && <div className="mb-2 text-xs text-copper">{uploadStatus}</div>}

        <form
          onSubmit={handleSubmit}
          className="flex items-center gap-2 rounded-2xl border border-line bg-charcoal px-2 py-2"
        >
          <button
            type="button"
            title="Upload a training file (.md/.txt/.pdf/.xlsx/.docx/.zip)"
            onClick={() => fileInputRef.current?.click()}
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-ink-dim transition hover:bg-surface-hover hover:text-ink"
          >
            <Paperclip size={16} />
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".md,.txt,.pdf,.xlsx,.docx,.zip"
            className="hidden"
            onChange={handleFileChange}
          />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about detection, response, threat intel, incidents..."
            className="flex-1 bg-transparent px-2 text-sm text-ink outline-none placeholder:text-ink-dim"
          />
          <button
            type="submit"
            disabled={sending || !input.trim()}
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-copper text-white transition disabled:opacity-40"
          >
            <ArrowUp size={16} />
          </button>
        </form>

        <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 px-1">
          {isAdmin ? (
            <details className="group relative">
              <summary
                className="inline-flex list-none items-center gap-1.5 rounded-full border border-line bg-charcoal px-3 py-1 text-[11px] text-ink-dim [&::-webkit-details-marker]:hidden"
              >
                <Cpu size={12} /> <span className="font-semibold text-ink">MODEL</span> &middot;
                {llmConfig?.model || "..."}
                <ChevronRight size={11} className="ml-0.5 transition-transform group-open:rotate-90" />
              </summary>
              <div className="absolute bottom-full left-0 z-10 mb-1.5 w-48 rounded-lg border border-line bg-surface p-1 text-xs shadow-lg">
                {["ollama", "anthropic"].map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={(e) => {
                      handleSwitchProvider(p);
                      e.currentTarget.closest("details").removeAttribute("open");
                    }}
                    disabled={switchingProvider || (p === "anthropic" && !llmConfig?.anthropic_available)}
                    title={p === "anthropic" && !llmConfig?.anthropic_available
                      ? "Set ANTHROPIC_API_KEY in .env first" : ""}
                    className={`flex w-full items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-left transition disabled:opacity-40 ${
                      llmConfig?.provider === p ? "bg-copper-soft text-copper" : "text-ink-dim hover:bg-surface-hover hover:text-ink"
                    }`}
                  >
                    <span>{p === "anthropic" ? "Claude" : "Ollama"}</span>
                    {llmConfig?.provider === p && <Check size={12} />}
                  </button>
                ))}
              </div>
            </details>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-charcoal px-3 py-1 text-[11px] text-ink-dim">
              <Cpu size={12} /> <span className="font-semibold text-ink">MODEL</span> &middot;
              {llmConfig?.model || "..."}
            </span>
          )}
          <span className="text-right text-[11px] italic text-ink-dim">
            Every message passes the RAG Security gateway before an answer is generated.
          </span>
        </div>
      </div>
    </div>
  );
}
