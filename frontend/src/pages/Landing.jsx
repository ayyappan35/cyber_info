import { GitBranch, KeyRound, LogOut, MessageSquare, TestTube2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { BASE_URL } from "../api/client";
import { useAuth } from "../context/AuthContext";

// The very first screen after login - just a few entry points, nothing else.
// Chat navigates into the SPA's chat app; Pipeline/Scenario/Login Scenario
// are static docs served by the backend (backend/main.py's /docs-pages
// mount) and redirect this same tab there, not a new one.
const CARDS = [
  { key: "chat", label: "Ask & Chat", desc: "Ask a detection or response question", icon: MessageSquare },
  { key: "pipeline", label: "Pipeline", desc: "Full architecture pipeline diagram",
    icon: GitBranch, href: `${BASE_URL}/docs-pages/architecture_flowchart.html` },
  { key: "scenario", label: "A2A & LLM Defense Scenario", desc: "10 real attack questions, live gateway results",
    icon: TestTube2, href: `${BASE_URL}/docs-pages/live_test_results.html` },
  { key: "login-scenario", label: "Login Scenario", desc: "4 authentication skills, live step by step",
    icon: KeyRound, href: `${BASE_URL}/docs-pages/login_auth_skills_live_test.html` },
];

export default function Landing() {
  const { username, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="flex h-full flex-col bg-charcoal text-ink">
      <div className="flex items-center justify-between px-6 py-5">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-copper text-sm font-bold text-white">
            CD
          </div>
          <span className="text-sm font-semibold text-ink">Cyber Defense</span>
        </div>
        <button
          onClick={logout}
          className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink-dim transition hover:border-copper/40 hover:text-ink"
        >
          <LogOut size={13} /> Sign out
        </button>
      </div>

      <div className="flex flex-1 flex-col items-center justify-center px-6 text-center">
        <span className="mb-6 rounded-full border border-copper/30 bg-copper-soft px-3 py-1 text-[11px] font-semibold uppercase tracking-wide text-copper">
          Signed in as {(username || "").toUpperCase()}
        </span>
        <h1 className="font-serif text-3xl text-ink">Where would you like to go?</h1>

        <div className="mt-10 grid w-full max-w-3xl grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {CARDS.map((card) => {
            const Icon = card.icon;
            const body = (
              <>
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-copper-soft text-copper">
                  <Icon size={22} />
                </div>
                <div className="mt-4 text-base font-semibold text-ink">{card.label}</div>
                <div className="mt-1 text-xs leading-relaxed text-ink-dim">{card.desc}</div>
              </>
            );
            const className =
              "flex flex-col items-center rounded-2xl border border-line bg-surface px-6 py-8 text-center transition hover:border-copper/40 hover:bg-surface-hover";
            return card.href ? (
              <a key={card.key} href={card.href} className={className}>
                {body}
              </a>
            ) : (
              <button key={card.key} onClick={() => navigate("/chat")} className={className}>
                {body}
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
