# Data Exfiltration (via an AI system)

## What it is

A request, whether from a user directly or embedded in retrieved content,
designed to get an AI system to reveal information it should not disclose:
credentials, other users' private data, internal system prompts/
configuration, or to take an action that sends data somewhere it
shouldn't go (e.g. "send the retrieved records to this external address").

## Detection signals

- Explicit requests for secrets, credentials, API keys, or tokens.
- Requests for other users' personal data, not the requester's own.
- Requests to reveal the system prompt, internal instructions, or tool
  definitions verbatim.
- Instructions (especially embedded in retrieved content) directing the
  assistant to transmit information to an external destination - an email
  address, URL, or "webhook" not part of the system's own legitimate
  tools.
- A combination of an otherwise-ordinary request plus a suspicious
  destination or recipient for the answer.

## What is NOT exfiltration

A user asking about their OWN account's data, or a SOC analyst
legitimately querying audit logs/incident history through the tools
provided for exactly that purpose, is normal operation, not exfiltration -
the distinguishing factor is whether the request is for data the
requester is authorized to see through an authorized path, versus an
attempt to route data somewhere or to someone unauthorized.

## Defensive posture

1. Screen for exfiltration intent at the same input-classification point
   used for prompt injection - the two often overlap (an injection attempt
   frequently exists specifically to cause exfiltration).
2. The AI system should never have a generic "send data externally" tool -
   every action it can take should be through a specific, scoped,
   authorized tool, so there is no generic exfiltration primitive to
   misuse even if a request slips past classification.
3. Fail closed: an ambiguous request touching sensitive data categories
   should default to refusal, not disclosure.
