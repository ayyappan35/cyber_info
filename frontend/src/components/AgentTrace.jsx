import { ChevronRight, Wrench } from "lucide-react";
import { useState } from "react";

function formatJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export default function AgentTrace({ transcript, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);

  const toolCalls = (transcript || []).filter((t) => t.role === "tool_call");
  if (toolCalls.length === 0) return null;

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 text-[11px] text-ink-dim transition hover:text-ink"
      >
        <ChevronRight size={12} className={`transition-transform ${open ? "rotate-90" : ""}`} />
        {open ? "Hide" : "Show"} agent trace &middot; {toolCalls.length} tool call
        {toolCalls.length === 1 ? "" : "s"}
      </button>

      {open && (
        <div className="mt-2 flex flex-col gap-2">
          {transcript.map((step, i) =>
            step.role === "tool_call" ? (
              <div key={i} className="rounded-lg border border-line bg-charcoal p-2.5">
                <div className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-copper">
                  <Wrench size={12} /> {step.name}
                </div>
                <div className="mt-1.5 text-[10px] font-semibold uppercase tracking-wide text-ink-dim">
                  arguments
                </div>
                <pre className="mt-1 max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-surface p-2 font-mono text-[11px] text-ink">
                  {formatJson(step.arguments)}
                </pre>
                <div className="mt-1.5 text-[10px] font-semibold uppercase tracking-wide text-ink-dim">
                  result
                </div>
                <pre className="mt-1 max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-md border border-line bg-surface p-2 font-mono text-[11px] text-ink">
                  {step.result === null ? "(pending...)" : formatJson(step.result)}
                </pre>
              </div>
            ) : (
              <div key={i} className="text-xs italic text-ink-dim">
                <span className="not-italic font-semibold">reasoning</span> {step.content}
              </div>
            ),
          )}
        </div>
      )}
    </div>
  );
}
