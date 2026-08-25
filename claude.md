# CLAUDE CODE MASTER PROMPT

# Agentic AI Cyber Defence Platform for LLM/RAG Systems

## ROLE

You are the Lead Architect, Security Engineer, Agentic AI Engineer, and Python Developer responsible for building a production-quality proof-of-concept Agentic AI Cyber Defence Platform.

The platform protects an LLM/RAG/Agentic AI application against:

1. Prompt Injection
2. Indirect Prompt Injection
3. RAG Poisoning
4. Memory Poisoning
5. Retrieval Security Issues
6. Agent-to-Agent Communication Attacks
7. Agent Impersonation
8. Rogue Agent Behaviour
9. Tool/MCP Misuse
10. External API Abuse
11. Runtime Anomalies
12. Data Exfiltration attempts
13. Unauthorized Security Actions

The system must support both:

* BLUE TEAM — detection, investigation, response, containment, recovery
* RED TEAM — controlled security attack simulation and evaluation

The objective is to create a demonstrable end-to-end Agentic AI Cyber Defence platform, not a simple chatbot.

---

# 1. CORE ARCHITECTURE

Build the following architecture:

```text
                         ┌───────────────────────┐
                         │       React UI        │
                         │ Cyber Defence Console │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │      FastAPI API      │
                         │     Gateway Layer     │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │   LangGraph Security  │
                         │      Orchestrator     │
                         └───────────┬───────────┘
                                     │
          ┌──────────────────────────┼─────────────────────────┐
          │                          │                         │
          ▼                          ▼                         ▼
 ┌────────────────┐        ┌────────────────┐        ┌────────────────┐
 │ Input Defence  │        │ RAG Defence     │        │ Agent Security │
 │     Agent      │        │     Agent       │        │     Agent      │
 └───────┬────────┘        └───────┬────────┘        └───────┬────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   ▼
                         ┌───────────────────────┐
                         │ Threat Analysis Agent │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ Risk / Decision Agent │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ Incident Response     │
                         │       Agent           │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ Security MCP Server   │
                         │ Controlled Tools      │
                         └───────────┬───────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
       revoke_session()       quarantine_agent()       block_ip()
       disable_agent()        quarantine_memory()      create_incident()
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ Verification Agent   │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │ PostgreSQL / Audit DB │
                         └───────────────────────┘
```

---

# 2. REQUIRED TECHNOLOGY STACK

Use:

## Backend

* Python 3.12+
* FastAPI
* Pydantic
* SQLAlchemy
* PostgreSQL

## Agent Framework

* LangGraph
* LangChain where useful

## LLM

Support:

* Claude
* OpenAI
* Ollama

Default local development model:

```text
llama3.2:3b
```

LLM provider must be configurable through environment variables.

Do not hardcode API keys.

---

# 3. RAG

Use:

* ChromaDB initially
* Embeddings through configurable provider
* Hybrid retrieval where practical
* Metadata filtering
* Source provenance

Knowledge sources:

```text
knowledge/
├── mitre_attack/
├── owasp_agentic/
├── security_policies/
├── incident_playbooks/
├── tool_policies/
├── agent_roles/
└── skills/
```

The system must preserve:

```text
document_id
source
version
timestamp
trust_status
provenance
metadata
```

---

# 4. SECURITY AGENTS

Implement these agents.

## 4.1 Input Defence Agent

Responsibilities:

* Analyze user input
* Detect prompt injection
* Detect jailbreak attempts
* Detect instruction override
* Detect data-exfiltration attempts
* Classify suspicious input
* Retrieve applicable security knowledge
* Produce security evidence

Do not rely on a giant Python `if/elif` attack-signature list.

---

## 4.2 RAG Defence Agent

Responsibilities:

* Inspect documents before ingestion
* Detect indirect prompt injection
* Detect suspicious instructions
* Validate provenance
* Assess document trust
* Detect conflicting security information
* Quarantine suspicious documents
* Validate retrieved chunks
* Prevent untrusted retrieved text from becoming authoritative instructions

Pipeline:

```text
Document
 ↓
Security Scan
 ↓
Provenance
 ↓
Trust Assessment
 ↓
Injection Analysis
 ↓
Sanitization
 ↓
Embedding
 ↓
Vector DB
```

---

## 4.3 Retrieval Security Agent

Responsibilities:

* Validate user identity
* Validate authorization
* Filter documents by access permissions
* Validate source trust
* Validate provenance
* Detect suspicious retrieved content
* Separate instructions from data
* Provide only authorized context to the LLM

---

## 4.4 Memory Defence Agent

Protect:

* Conversation memory
* Agent memory
* Long-term memory
* Security memory

Detect:

* Memory poisoning
* Unauthorized memory modification
* Fake authorization memories
* Cross-user contamination
* Persistent malicious instructions

Every memory record should contain provenance.

---

## 4.5 Agent Security Agent

Protect agent-to-agent communication.

Validate:

```text
agent_identity
authentication
authorization
message_integrity
sender_role
receiver_role
requested_operation
security_context
```

Do not automatically trust another agent.

---

## 4.6 Rogue Agent Detection Agent

Monitor:

* Agent identity
* Agent role
* Tool usage
* Resource access
* Agent messages
* Workflow transitions
* Permission changes
* Sensitive operations

Detect abnormal behavior.

Possible response:

```text
suspend_agent
revoke_agent_credentials
remove_tool_access
isolate_agent
stop_workflow
create_incident
alert_admin
```

---

## 4.7 Tool/MCP Security Agent

All security-sensitive tool calls must pass through an authorization layer.

Flow:

```text
LLM
 ↓
Tool Request
 ↓
Identity Validation
 ↓
Authorization
 ↓
Policy Validation
 ↓
Risk Assessment
 ↓
Approval if Required
 ↓
MCP Tool
 ↓
Execution
 ↓
Result Validation
```

Never allow arbitrary shell execution from the LLM.

Never expose unrestricted database operations.

Use typed Pydantic schemas for tool arguments.

---

## 4.8 Threat Analysis Agent

Correlate:

```text
security event
+
agent activity
+
RAG evidence
+
memory evidence
+
tool activity
+
historical incidents
+
MITRE/OWASP knowledge
```

Produce:

```text
threat_type
evidence
affected_assets
attack_stage
confidence
potential_impact
recommended_response
```

---

## 4.9 Risk / Decision Agent

The decision agent should reason from:

* Evidence
* Retrieved knowledge
* Security policy
* Agent role
* Asset impact
* Current context
* Previous activity

Do not create a huge hardcoded security decision tree.

The LLM should perform contextual reasoning.

However, deterministic security controls must still enforce:

* Authentication
* Authorization
* Tool schemas
* Approval requirements
* Access boundaries
* Emergency shutdown
* Audit logging

The LLM cannot bypass these controls.

---

## 4.10 Incident Response Agent

Responsibilities:

* Create incident
* Assign severity
* Contain threat
* Revoke sessions
* Revoke agent credentials
* Disable tools
* Quarantine documents
* Quarantine memory
* Stop compromised workflows
* Alert administrators
* Verify containment

Every action must be followed by verification.

---

## 4.11 Verification Agent

After every security action:

```text
ACTION
 ↓
EXECUTION
 ↓
VERIFY
 ↓
CONFIRM SECURITY STATE
 ↓
UPDATE INCIDENT
```

Example:

```text
disable_agent(agent_id)
        ↓
get_agent_status(agent_id)
        ↓
verify disabled
        ↓
record evidence
```

Never report an action as successful without verification evidence.

---

# 5. SECURITY MCP SERVER

Create a dedicated MCP security server.

Example tools:

```text
get_agent_identity
get_agent_activity
get_agent_permissions
inspect_agent_message
search_security_knowledge

validate_document
quarantine_document
restore_document

get_memory_record
validate_memory
quarantine_memory
delete_memory

disable_agent
isolate_agent
revoke_agent_credentials
remove_agent_tool_access

revoke_session
block_ip

validate_tool_request
execute_authorized_action

create_incident
update_incident
get_incident

send_security_alert
```

Every tool must have:

* Pydantic input schema
* Authorization validation
* Audit logging
* Safe error handling
* Result schema

---

# 6. SKILL SYSTEM

Create independent security skills.

```text
skills/
├── input_defence/
│   └── skill.md
├── rag_defence/
│   └── skill.md
├── retrieval_security/
│   └── skill.md
├── memory_defence/
│   └── skill.md
├── agent_security/
│   └── skill.md
├── rogue_agent_detection/
│   └── skill.md
├── tool_mcp_security/
│   └── skill.md
├── anomaly_detection/
│   └── skill.md
├── incident_response/
│   └── skill.md
└── red_team/
    └── skill.md
```

A skill describes:

```text
WHAT SECURITY TASK IS BEING PERFORMED
HOW THE AGENT SHOULD INVESTIGATE
WHAT EVIDENCE SHOULD BE COLLECTED
WHAT KNOWLEDGE SHOULD BE RETRIEVED
WHAT SECURITY BOUNDARIES APPLY
HOW THE RESULT SHOULD BE VERIFIED
```

Skills are not security authorization.

---

# 7. POLICY SYSTEM

Create a separate policy system.

```text
policies/
├── agent_policy.yaml
├── tool_policy.yaml
├── rag_policy.yaml
├── memory_policy.yaml
├── data_access_policy.yaml
├── incident_response_policy.yaml
└── human_approval_policy.yaml
```

Important distinction:

```text
SKILL
= How to perform a security task

POLICY
= What is permitted

LLM
= Reason about context

MCP
= Execute authorized operation
```

The LLM must never modify policies.

---

# 8. NO HARDCODED SECURITY DECISION LOGIC

Do NOT implement security intelligence as:

```python
if attack == "prompt_injection":
    risk = 90
elif attack == "jailbreak":
    risk = 80
```

Do not create giant rule chains.

Instead use:

```text
Event
 ↓
Evidence
 ↓
RAG
 ↓
Skill
 ↓
Policy
 ↓
LLM reasoning
 ↓
Decision
 ↓
MCP authorization
 ↓
Action
 ↓
Verification
```

Hardcoded deterministic controls are allowed only for security boundaries and infrastructure safety.

---

# 9. RED TEAM

Create a controlled Red Team agent.

Red Team scenarios:

```text
prompt_injection
indirect_prompt_injection
rag_poisoning
memory_poisoning
tool_misuse
agent_impersonation
malicious_a2a_message
unauthorized_api_access
rogue_agent_behavior
data_exfiltration
```

The Red Team must operate only against the local test environment.

Do not create uncontrolled real-world attack capabilities.

Each attack produces:

```text
attack_id
scenario
target
payload
expected_defence
observed_result
defence_status
evidence
```

---

# 10. BLUE TEAM

Blue Team must consume Red Team events.

Flow:

```text
RED TEAM ATTACK
      ↓
TARGET APPLICATION
      ↓
DETECTION
      ↓
INVESTIGATION
      ↓
RAG KNOWLEDGE
      ↓
THREAT ANALYSIS
      ↓
RISK DECISION
      ↓
RESPONSE
      ↓
MCP ACTION
      ↓
VERIFICATION
      ↓
INCIDENT
```

The dashboard must show this lifecycle.

---

# 11. DEMO SCENARIOS

Implement these demo scenarios first.

## Scenario 1 — RAG Poisoning

```text
Upload malicious document
 ↓
RAG Defence Agent
 ↓
Detect suspicious instructions
 ↓
Quarantine document
 ↓
Create incident
 ↓
Verify quarantine
```

---

## Scenario 2 — Indirect Prompt Injection

```text
User asks normal question
 ↓
Retriever returns malicious content
 ↓
Input/RAG Defence detects injection
 ↓
Untrusted content isolated
 ↓
LLM receives safe context
 ↓
Incident recorded
```

---

## Scenario 3 — Rogue Agent

```text
Normal Agent
 ↓
Unexpected sensitive tool request
 ↓
Agent Security Agent
 ↓
Behavior analysis
 ↓
Rogue Agent detected
 ↓
Risk/Decision Agent
 ↓
MCP
 ↓
Agent isolated
 ↓
Verification
 ↓
Incident
```

---

## Scenario 4 — Malicious Agent-to-Agent Message

```text
Agent A
 ↓
malicious instruction
 ↓
Agent B
 ↓
A2A Security Agent
 ↓
Identity + authorization + integrity validation
 ↓
Message rejected
 ↓
Incident created
```

---

## Scenario 5 — Tool Misuse

```text
Agent
 ↓
dangerous tool request
 ↓
MCP Security
 ↓
authorization failure
 ↓
tool execution denied
 ↓
incident created
```

---

# 12. DATABASE MODEL

Create PostgreSQL models for:

```text
User
Agent
AgentCredential
AgentMessage
AgentActivity
SecurityEvent
Threat
Incident
IncidentAction
Tool
ToolExecution
Document
DocumentVersion
Memory
SecurityPolicy
SecuritySkill
AuditLog
RedTeamTest
```

Every security-sensitive operation must create an audit record.

---

# 13. API

Create FastAPI endpoints.

Examples:

```text
POST /api/v1/security/events
POST /api/v1/security/investigate
POST /api/v1/security/respond

POST /api/v1/rag/scan
POST /api/v1/rag/ingest
POST /api/v1/rag/quarantine

POST /api/v1/agents/investigate
POST /api/v1/agents/isolate
POST /api/v1/agents/revoke

POST /api/v1/red-team/run
GET  /api/v1/red-team/tests

GET /api/v1/incidents
GET /api/v1/incidents/{incident_id}

GET /api/v1/audit
GET /api/v1/security/events
```

Use Pydantic request/response models.

---

# 14. FRONTEND

Create a React Cyber Defence Dashboard.

Dashboard should display:

```text
Security Status
Active Threats
Open Incidents
Rogue Agents
RAG Poisoning Events
Blocked Tool Calls
Agent-to-Agent Violations
Recent Security Events
Red Team Results
Blue Team Response
```

Include a security event timeline:

```text
09:30 Attack detected
09:30 RAG Defence activated
09:31 Threat identified
09:31 Risk assessed
09:31 Document quarantined
09:31 Verification completed
09:31 Incident created
```

---

# 15. OBSERVABILITY

Add tracing for:

```text
User request
Agent invocation
RAG retrieval
Retrieved documents
LLM call
Decision
Tool call
MCP execution
Verification
Incident
```

Support MLflow and/or LangSmith through configuration.

Never log secrets, credentials, API keys, or sensitive tokens.

---

# 16. PROJECT STRUCTURE

Create:

```text
cyber-defense-agent/
│
├── CLAUDE.md
├── README.md
├── .env.example
├── docker-compose.yml
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── api/
│   │   ├── agents/
│   │   ├── graph/
│   │   ├── security/
│   │   ├── rag/
│   │   ├── memory/
│   │   ├── mcp/
│   │   ├── policies/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── observability/
│   │
│   └── tests/
│
├── mcp_server/
│   ├── server.py
│   ├── tools/
│   ├── schemas/
│   └── security/
│
├── skills/
│   ├── input_defence/
│   ├── rag_defence/
│   ├── retrieval_security/
│   ├── memory_defence/
│   ├── agent_security/
│   ├── rogue_agent_detection/
│   ├── tool_mcp_security/
│   ├── anomaly_detection/
│   ├── incident_response/
│   └── red_team/
│
├── policies/
│
├── knowledge/
│   ├── mitre_attack/
│   ├── owasp_agentic/
│   ├── incident_playbooks/
│   └── security_policies/
│
├── red_team/
│
├── frontend/
│
└── docs/
    ├── architecture.md
    ├── threat_model.md
    ├── security_model.md
    └── demo.md
```

---

# 17. DEVELOPMENT RULES

Follow these rules strictly.

### Rule 1

Do not build the entire system in one step.

Build incrementally.

### Rule 2

After each major implementation:

1. Run tests.
2. Fix errors.
3. Start the service.
4. Test the API.
5. Verify the agent graph.
6. Document the result.

### Rule 3

Do not create fake implementations just to make the demo pass.

Security actions must have real local implementations.

### Rule 4

For destructive operations, use a safe local simulation environment.

### Rule 5

Never expose production credentials.

### Rule 6

Use environment variables for secrets and configuration.

### Rule 7

Use typed schemas.

### Rule 8

Write unit tests and integration tests.

### Rule 9

Every autonomous security action must produce an audit event.

### Rule 10

Every containment action must have verification.

---

# 18. IMPLEMENTATION ORDER

Do NOT start by implementing all agents.

Follow this sequence.

## Phase 1

Create:

```text
Project structure
FastAPI
PostgreSQL
SQLAlchemy
Pydantic
Configuration
Logging
```

Run tests.

---

## Phase 2

Implement:

```text
SecurityEvent
Incident
AuditLog
Agent
Tool
```

Run database tests.

---

## Phase 3

Implement LangGraph orchestrator.

Start with:

```text
Event
 ↓
Detection
 ↓
Threat Analysis
 ↓
Decision
 ↓
Response
 ↓
Verification
```

Use a mock security event initially.

---

## Phase 4

Implement RAG.

Add:

```text
ChromaDB
Knowledge ingestion
Embedding
Retrieval
Metadata filtering
Provenance
```

---

## Phase 5

Implement RAG Defence Agent.

First working scenario:

```text
Malicious Document
 ↓
Detection
 ↓
Quarantine
 ↓
Incident
 ↓
Verification
```

---

## Phase 6

Implement MCP security server.

Implement only safe local tools first:

```text
create_incident
quarantine_document
get_agent_activity
disable_test_agent
isolate_test_agent
verify_agent_status
```

---

## Phase 7

Implement Rogue Agent Detection.

Create a simulated agent environment.

Demonstrate:

```text
Normal Agent
 ↓
Malicious Behavior
 ↓
Detection
 ↓
Decision
 ↓
Isolation
 ↓
Verification
```

---

## Phase 8

Implement Agent-to-Agent security.

Add:

```text
agent identity
message authentication
authorization
integrity
role validation
```

---

## Phase 9

Implement Memory Defence.

---

## Phase 10

Implement Red Team.

---

## Phase 11

Implement React dashboard.

---

## Phase 12

Add MLflow/LangSmith observability and final end-to-end testing.

---

# 19. FIRST TASK

Do not implement everything immediately.

Start by inspecting the repository.

Perform:

```text
1. List existing files.
2. Detect existing Python/React/FastAPI/LangGraph code.
3. Identify reusable components.
4. Identify missing components.
5. Create architecture.md.
6. Create the project structure.
7. Create CLAUDE.md if it does not exist.
8. Create requirements/pyproject configuration.
9. Implement Phase 1 only.
10. Run tests.
```

Before modifying existing code, understand it.

Do not unnecessarily rewrite working components.

---

# 20. CLAUDE CODE WORKING STYLE

For every task:

```text
PLAN
 ↓
INSPECT
 ↓
IMPLEMENT
 ↓
TEST
 ↓
RUN
 ↓
VERIFY
 ↓
DOCUMENT
```

After completing each phase, report:

```text
Implemented:
Files changed:
Tests:
Test result:
API result:
Known issues:
Next phase:
```

Do not claim completion without running the relevant tests.

---

# 21. FINAL SUCCESS CONDITION

The final system must demonstrate this complete flow:

```text
RED TEAM
   ↓
Attack Simulation
   ↓
LLM/RAG Application
   ↓
Cyber Defence Orchestrator
   ↓
Security Detection Agent
   ↓
RAG / Security Knowledge
   ↓
Threat Analysis Agent
   ↓
Risk / Decision Agent
   ↓
Policy Authorization
   ↓
MCP Security Tool
   ↓
Containment
   ↓
Verification Agent
   ↓
Incident
   ↓
Audit Trail
   ↓
React Dashboard
```

The final demo should clearly show:

```text
ATTACK
  ↓
DETECT
  ↓
INVESTIGATE
  ↓
REASON
  ↓
DECIDE
  ↓
ACT
  ↓
VERIFY
  ↓
RECOVER
```

This is the primary acceptance criterion for the Agentic AI Cyber Defence platform.
