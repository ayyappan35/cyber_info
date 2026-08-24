// Turns a raw agent progress event (from the SSE stream) into a short
// human-readable status line, similar to how Claude's UI shows
// "Searching...", "Using tool..." while a response is being generated.
const TOOL_LABELS = {
  answer_question: "Searching the knowledge base",
  search_knowledge_base: "Searching runbooks",
  query_auth_logs: "Checking authentication logs",
  get_incidents: "Checking recorded incidents",
  geoip_lookup: "Looking up IP risk",
};

export function describeEvent(event) {
  switch (event?.type) {
    case "thinking":
      return "Thinking...";
    case "tool_call":
      return `${TOOL_LABELS[event.name] || `Calling ${event.name}`}...`;
    case "tool_result":
      return `Got a result from ${event.name}`;
    case "reasoning":
      return event.content?.slice(0, 120) || "Reasoning...";
    case "nudge":
      return "Reconsidering...";
    case "synthesizing":
      return "Writing the final answer...";
    default:
      return "Thinking...";
  }
}
