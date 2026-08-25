# Prompt Injection

## What it is

A user (or any content reaching the model as input) attempts to override
the AI system's actual instructions with its own, directly - as opposed to
indirect/RAG-based injection, where the payload arrives via retrieved
content rather than the immediate input. OWASP's LLM Top 10 lists this as
LLM01: Prompt Injection.

## Detection signals

- Direct instruction-override phrasing: "ignore previous instructions",
  "disregard your system prompt", "forget everything you were told".
- A claimed change of operating mode: "you are now in developer/debug/
  unrestricted mode", "DAN" ("do anything now")-style role-play framing.
- A forged system or administrator message embedded in what should be
  ordinary user input.
- Requests to reveal the system prompt, internal instructions, or
  configuration verbatim.
- Encoding/obfuscation tricks intended to smuggle an instruction past a
  naive keyword filter (base64, leetspeak, unusual whitespace, translated
  text) - a keyword-matching detector is trivially defeated by these; an
  LLM-based reviewer that reasons about *intent* rather than surface
  pattern is comparatively more robust, though not immune.

## What is NOT injection

An ordinary, even blunt or urgent, security question is not injection -
"what should I do right now, my account is locked and I need in
immediately" is a legitimate (if impatient) request, not an attack. Being
overly aggressive about flagging urgency or bluntness as suspicious
produces false positives that erode trust in the detector.

## Defensive posture

1. Treat all retrieved/input content the model sees as data, never as
   instructions, regardless of what it claims to be - this framing should
   appear explicitly in the system prompt of anything that consumes
   untrusted text.
2. A dedicated classification pass (not the same call that will go on to
   act on the user's request) reduces the chance the injection succeeds
   against the very call meant to detect it.
3. Fail closed on an ambiguous/unparsable classification result.
