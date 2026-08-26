import { useCallback, useEffect, useState } from "react";
import Sidebar from "../components/Sidebar";
import ChatWindow from "../components/ChatWindow";
import TrainingPanel from "../components/TrainingPanel";
import { api } from "../api/client";
import { describeEvent } from "../utils/describeEvent";

export default function Chat() {
  const [view, setView] = useState("chat"); // "chat" | "training"
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [sending, setSending] = useState(false);
  const [liveStatus, setLiveStatus] = useState("");
  const [liveTrace, setLiveTrace] = useState([]);

  const refreshConversations = useCallback(async () => {
    const list = await api.listConversations();
    setConversations(list);
    return list;
  }, []);

  useEffect(() => {
    refreshConversations();
  }, [refreshConversations]);

  useEffect(() => {
    if (!activeId) {
      setMessages([]);
      return;
    }
    api.getMessages(activeId).then(setMessages);
  }, [activeId]);

  function handleNewChat() {
    setView("chat");
    setActiveId(null);
    setMessages([]);
  }

  async function handleSelect(id) {
    setView("chat");
    setActiveId(id);
  }

  function handleOpenTraining() {
    setView("training");
  }

  async function handleDelete(id) {
    await api.deleteConversation(id);
    if (id === activeId) handleNewChat();
    refreshConversations();
  }

  async function handleSend(text) {
    setMessages((prev) => [...prev, { role: "user", content: text, sources: [], transcript: [] }]);
    setSending(true);
    setLiveStatus("Thinking...");
    setLiveTrace([]);

    function handleEvent(event) {
      setLiveStatus(describeEvent(event));
      if (event.type === "tool_call") {
        setLiveTrace((prev) => [...prev, { role: "tool_call", name: event.name, arguments: event.arguments, result: null }]);
      } else if (event.type === "tool_result") {
        setLiveTrace((prev) => {
          const next = [...prev];
          for (let i = next.length - 1; i >= 0; i--) {
            if (next[i].role === "tool_call" && next[i].name === event.name && next[i].result === null) {
              next[i] = { ...next[i], result: event.result };
              break;
            }
          }
          return next;
        });
      } else if (event.type === "reasoning") {
        setLiveTrace((prev) => [...prev, { role: "assistant", content: event.content }]);
      }
    }

    try {
      const resp = await api.queryStream(text, activeId, handleEvent);
      // skills_selected comes from the threat_router.route step already in
      // the transcript - "pii-exposure" + a BLOCK means this specific
      // refusal is sitting in the Admin Dashboard's Pending Tool Approvals
      // queue (security_gateway/mcp_gateway.py's disclose_pii_answer),
      // not just a generic refusal - the badge below reflects that.
      const routeStep = resp.transcript?.find((t) => t.name === "threat_router.route");
      const pendingApproval = resp.gateway_action === "BLOCK"
        && routeStep?.result?.skills_selected?.includes("pii-exposure");
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: resp.answer, sources: resp.sources, transcript: resp.transcript,
          pendingApproval, pendingCallId: resp.pending_call_id ?? null },
      ]);
      if (!activeId) {
        setActiveId(resp.conversation_id);
      }
      refreshConversations();
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: `Error: ${err.message}`, sources: [], transcript: [] },
      ]);
    } finally {
      setSending(false);
      setLiveStatus("");
      setLiveTrace([]);
    }
  }

  async function handleMessageApproval(messageIndex, decision) {
    const msg = messages[messageIndex];
    if (!msg?.pendingCallId) return;
    try {
      if (decision === "approve") {
        const resp = await api.approveToolCall(msg.pendingCallId);
        setMessages((prev) => prev.map((m, i) => (i === messageIndex
          ? { ...m, pendingApproval: false, pendingCallId: null, approvedAnswer: resp.result?.answer }
          : m)));
      } else {
        await api.denyToolCall(msg.pendingCallId);
        setMessages((prev) => prev.map((m, i) => (i === messageIndex
          ? { ...m, pendingApproval: false, pendingCallId: null, denied: true }
          : m)));
      }
    } catch (err) {
      setMessages((prev) => prev.map((m, i) => (i === messageIndex
        ? { ...m, approvalError: err.message || "Failed to record decision" }
        : m)));
    }
  }

  return (
    <div className="flex h-full bg-charcoal">
      <Sidebar
        conversations={conversations}
        activeId={activeId}
        onSelect={handleSelect}
        onNewChat={handleNewChat}
        onDelete={handleDelete}
        view={view}
        onOpenTraining={handleOpenTraining}
      />
      {view === "training" ? (
        <TrainingPanel />
      ) : (
        <ChatWindow
          messages={messages}
          onSend={handleSend}
          onMessageApproval={handleMessageApproval}
          sending={sending}
          liveStatus={liveStatus}
          liveTrace={liveTrace}
        />
      )}
    </div>
  );
}
