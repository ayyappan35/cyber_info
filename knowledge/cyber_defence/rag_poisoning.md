# RAG Poisoning

## What it is

An attacker (or a compromised/careless uploader) introduces a document
into a knowledge base whose purpose is not to inform a human reader but to
manipulate whatever AI system later retrieves it as context. Unlike a
direct prompt injection (attacker talks to the AI system directly), RAG
poisoning is indirect: the payload sits dormant in storage until a later,
unrelated query happens to retrieve it.

## Detection signals

- Text addressed to an AI system rather than a human reader: "as an AI
  system reading this", "when an assistant processes this document".
- Instruction-override phrasing embedded in otherwise-plausible content:
  "ignore previous instructions", "disregard prior guidance", "you must
  now...".
- A forged system/admin message embedded mid-document, formatted to look
  like a trusted instruction (e.g. "SYSTEM OVERRIDE:", "[ADMIN NOTICE]").
- Content that contradicts already-trusted security guidance in a way
  that looks designed to be picked up as authoritative (e.g. a "policy
  update" claiming lockout thresholds should be disabled).
- Requests embedded in the text for the assistant to take a specific
  action or reveal specific information when this document is retrieved.

## What is NOT poisoning

Legitimate security/operational documentation routinely *discusses* these
same concepts - a runbook describing what prompt injection looks like, or
a policy document explaining lockout thresholds, is not itself an attack.
The distinguishing question is: is the text trying to get an AI system to
DO something, or merely describing something for a human reader?

## Defensive posture

1. Never trust newly-ingested content by default - a document's chunks
   should be embedded but excluded from retrieval until reviewed.
2. Review per-chunk, not just per-document - a single malicious paragraph
   in an otherwise-legitimate 40-page document should not make the whole
   document either fully trusted or fully quarantined.
3. Distinguish reversible containment (quarantine - stays in storage,
   simply unreachable, can be restored after human review) from
   irreversible rejection (a chunk assessed as clearly malicious, at high
   confidence, should not remain in the vector store at all).
4. Fail closed: if the reviewing system cannot produce a confident
   assessment, treat the content as untrusted rather than defaulting it to
   trusted.
