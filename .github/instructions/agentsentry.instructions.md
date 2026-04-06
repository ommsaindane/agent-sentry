---
name: AgentSentry
description: Project-wide rules for realtime LLM guardrail enforcement (input/output validation, prompt defense, tool checks, HITL)
applyTo: '**'
---

# LLM Guard Proxy — Workspace Instructions

Use these instructions when generating code, refactoring, reviewing changes, or answering implementation questions in this workspace.

## Project context

- This is a **FastAPI middleware/proxy** that enforces **guardrails on LLM inputs and outputs in real time**.
- Core pipeline:
	- Input → validation + prompt defense
	- Agent classification (risk + decision)
	- LLM call
	- Output → filtering + enforcement
	- human-in-the-loop escalation
- Agents are for classification/decision only, not for orchestration.

---

# Coding Guidelines

* Use Python only
* Use existing libraries (OpenAI API, LangChain optional, Pydantic, etc.)
* Use context7 MCP wherever possible
* Avoid overengineering — keep logic minimal and explicit
* Prefer deterministic logic over probabilistic flows wherever possible

---

# Folder structure

guard-proxy/
│
├── app/
│   ├── main.py                  # FastAPI entrypoint
│   ├── config.py                # env + settings
│   ├── schemas/                 # Pydantic models
│   │   ├── guard.py
│   │   ├── agent.py
│   │   └── api.py
│   │
│   ├── core/                    # core pipeline logic
│   │   ├── pipeline.py          # orchestration logic
│   │   └── enums.py
│   │
│   ├── guards/
│   │   ├── input_guard.py
│   │   ├── output_guard.py
│   │   └── patterns.py          # regex rules
│   │
│   ├── agent/
│   │   ├── agent.py
│   │   ├── tools.py
│   │   └── prompts.py
│   │
│   ├── llm/
│   │   └── client.py
│   │
│   ├── policy/
│   │   ├── policy_engine.py
│   │   └── rules.json
│   │
│   ├── hitl/
│   │   ├── service.py
│   │   └── db.py
│   │
│   ├── logging/
│   │   └── logger.py
│   │
│   └── utils/
│       └── helpers.py
│
├── tests/
│   ├── test_input_guard.py
│   ├── test_output_guard.py
│   └── test_pipeline.py
│
├── streamlit_app/               # later
│   └── app.py
│
├── .env
├── requirements.txt
└── README.md

---

## Non-negotiable behavior (user preferences)

- Prefer **strict, deterministic behavior**
	- Use `temperature=0` for all LLM calls
	- Use structured outputs (Pydantic models / tool schemas)
- **Fail fast**
	- Missing `OPENAI_API_KEY` or model access → hard error
- No silent fallbacks:
	- No hidden defaults
	- No silent retries
	- No exception swallowing
- All decisions must be **explicit and traceable**

---

## Architectural rules

### API layer (FastAPI)

- Acts as a **proxy layer** between client and LLM
- Single primary endpoint:
	- `/chat` or `/completion`
- Must:
	- Log every request/response
	- Pass through only validated/sanitized inputs
	- Return blocked/sanitized responses deterministically

---

### Guard Pipeline (core system)


input
→ input_guard
→ (agent decision)
→ LLM call
→ output_guard
→ (HITL)
→ response



- Each stage must be:
	- Independent
	- Testable
	- Deterministic

---

### Input Guard Layer

Responsibilities:
- Detect prompt injection
- Enforce policy rules
- Sanitize unsafe inputs

Rules:
- Use:
	- LLM classifier (secondary)
- Must detect:
	- instruction override attempts
	- role hijacking
	- data exfiltration attempts

Prompt defense (mandatory):
- Strip or flag patterns like:
	- "ignore previous instructions"
	- "you are now"
- Inject system prefix:
	- enforce rule adherence

---

### Agent Layer (strictly limited)

- Agent is **NOT a planner**
- Used only for:
	- risk scoring
	- decision classification

Allowed outputs:
- `allow`
- `block`
- `sanitize`
- `escalate`

Agent must:
- use structured output
- be single-step (no loops, no chains)

---

### Tool Layer

Agents may call tools:

Examples:
- `policy_lookup(rule_id)`
- `risk_score(text)`
- `redact_sensitive(text)`


---

### LLM Layer

- LLM is treated as **untrusted**
- Must:
	- receive guarded input only
	- never bypass guard layers

---

### Output Guard Layer

Responsibilities:
- Validate LLM output
- Enforce policies post-generation

Checks:
- PII leakage
- unsafe content
- hallucinated sensitive info

Actions:
- mask
- reject
- replace with safe response

---

### Human-in-the-Loop (HITL)

- Trigger condition:
	- high risk score
	- uncertain classification

Behavior:
- Store request in queue (MySQL/JSON)
- Return:
	- `"Pending review"`

Rules:
- No blocking synchronous review
- Must be async-compatible

---

### Storage layer

- MySQL (default) stores:
	- requests
	- responses
	- risk scores
	- decisions
	- HITL queue

- Keep schema minimal and explicit

---

## Observability (required)

Must log:

- input (raw + sanitized)
- risk score
- agent decision
- output (raw + filtered)

Rules:
- Logs must be structured (JSON)
- Observability must not affect execution

---

## Error handling rules

- Raise explicit exceptions
- Do not suppress failures
- If guard fails → block request
- If LLM fails → return error, do not retry silently

---

## Configuration rules

- Use `.env` via `python-dotenv`

Required:
- `OPENAI_API_KEY`
- `OPENAI_MODEL`

Optional:
- `RISK_THRESHOLD`

- Validate config at startup

---

## When making changes

- Keep system simple and modular
- Do not introduce:
	- multi-agent orchestration
	- complex workflows
	- unnecessary abstractions

- Prefer:
	- small functions
	- clear flow
	- explicit logic

---

## Quick review checklist

- Is input validated before LLM call? 
- Is prompt injection defense applied?
- Is output validated after LLM call?
- Are decisions deterministic and logged?
- Is agent usage minimal and scoped?
- Are failures explicit (no silent fallback)?

---

# .env configuration

```env
OPENAI_API_KEY=""
OPENAI_MODEL=gpt-5-mini

RISK_THRESHOLD=0.7
ENABLE_HITL=true
```
