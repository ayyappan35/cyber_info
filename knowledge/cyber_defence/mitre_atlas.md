# MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)

## Honesty note (read this first)

Unlike `knowledge/mitre_attack/brute_force_ttp_mapping.md` (which cites
specific, verified MITRE ATT&CK technique IDs - T1110, T1087, T1078 - that
were checked against real ATT&CK naming), this file deliberately does
**not** assert specific ATLAS technique ID numbers (the `AML.T####` format)
from memory. ATLAS is MITRE's newer, AI/ML-specific framework, published
and maintained at atlas.mitre.org, and its exact IDs should be looked up
against that live source before being cited as a verified mapping
anywhere in this codebase - inventing a plausible-looking `AML.T0051`-style
ID without checking it against the real matrix would violate this
project's own "do not claim a MITRE mapping unless verified" rule.

## What ATLAS covers, conceptually

ATLAS organizes adversary behavior against AI/ML systems into tactics
(the "why") and techniques (the "how"), the same structural shape as
ATT&CK, but scoped to attacks that specifically target machine learning
pipelines and, in its more recent additions, generative-AI/LLM systems.
Tactic categories relevant to this project's actual attack surface
include (by concept, not by asserted ID):

- **Reconnaissance** against an ML/LLM system - probing what a model will
  reveal about its own configuration, training, or the data it has
  access to.
- **Resource Development** - acquiring or crafting adversarial inputs
  ahead of an attack.
- **Initial Access** via a poisoned input - this is the conceptual home of
  both direct and indirect prompt injection, and of RAG/training-data
  poisoning, as this project implements them.
- **Execution** - getting the target system to act on adversary-controlled
  instructions once they're accepted as input.
- **Exfiltration** - getting the system to reveal data it should not.

## How this project's implemented scenarios relate to ATLAS conceptually

| This project's scenario | ATLAS tactic concept |
|---|---|
| `prompt_injection`, `indirect_prompt_injection` (agents/red_team_scenarios.py) | Initial Access via a crafted/poisoned input |
| `rag_poisoning` | Initial Access (poisoned knowledge source) |
| `data_exfiltration` | Exfiltration |
| `agent_impersonation`, `malicious_a2a_message` | Not ATLAS-specific - closer to general identity/authorization attack concepts, since ATLAS's published techniques are ML-pipeline-centric rather than multi-agent-orchestration-centric as of this writing |

## Recommended next step if precise mappings are needed

Pull the actual published ATLAS STIX/JSON data (atlas.mitre.org publishes
a machine-readable matrix) and cross-reference each implemented scenario
against it directly, rather than extending this document's table from
memory. This document is intentionally a conceptual bridge, not a
citation-grade mapping.
