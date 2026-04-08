# AgentSentry — Repository Report

## 1) What this repo is

AgentSentry is a **FastAPI proxy** that enforces **real-time guardrails** around LLM usage.

It applies a deterministic, traceable pipeline:

- **Deterministic policy evaluation** (rules.json → PolicyEngine)
- **Input guard** (LLM classifier → signals only; policy used as context)
- **Resolver agent** (deterministic final decision: allow/block/sanitize/escalate)
- **LLM proxy call** (temperature=0)
- **Output guard** (one-pass: LLM classifier → policy enforcement once → mask/block)
- Optional **Human-in-the-loop (HITL)** escalation to an async SQLite queue + reviewer resolve endpoint

Key non-negotiables (as implemented):

- **Fail-fast configuration**: missing `OPENAI_API_KEY` / `OPENAI_MODEL` is a hard error.
- **No silent fallbacks**: errors bubble up as explicit failures.
- **Determinism**: `temperature=0`, stable sorting/deduping of violations/matches, deterministic JSON logging.
- **No regex-based detection**: policy matching uses tokenization + exact phrase windows.

---

## 2) End-to-end request flow (ASCII)

```
Client
  |
  |  POST /chat { message, max_output_tokens }
  v
FastAPI (main.py)
  |
  |  request_id := uuid4().hex
  v
run_chat_pipeline (app/core/pipeline.py)
  |
  |--> PolicyEngine.evaluate(message)
  |        |
  |        +--> (signals: risk_score, matched rules, matches, thresholds)
  |
  |--> InputGuard.evaluate(message, policy_result)
  |        |
  |        +--> Classify via OpenAI structured output (temperature=0)
  |        +--> Output is signals only: risk_score + attack_type + sanitized_text suggestion
  |
  |--> ResolverAgent.decide(guard_result, policy_result)
  |        |
  |        +--> Deterministic precedence + confidence
  |
  |--> Risk-threshold override:
  |        if decision not in {block, escalate} AND guard_risk > RISK_THRESHOLD
  |        then escalate
  |
  +--> Branch:
         |
         | decision=block
         |   -> return 403 (blocked)
         |
         | decision=escalate
         |   -> enqueue HITL (aiosqlite) -> return 202 (pending_review + queue_id)
         |   -> reviewer can later POST /hitl/resolve {queue_id, action, note, max_output_tokens}
         |
         | decision=allow|sanitize
         |   -> OpenAIProxyClient.generate(temperature=0)
         |   -> OutputGuard.evaluate(raw_llm_output)
         |        - LLM classifies output
         |        - policy enforces once on classifier final_output
         |        - mask sensitive terms deterministically; unsafe => SAFE_REPLACEMENT_MESSAGE
         |   -> if unsafe => decision becomes block
         |   -> else return 200 (output text)
```

**HTTP outcomes**

- **200**: `allow` or `sanitize` (output returned)
- **202**: `escalate` (queued for review)
- **403**: `block`
- **500**: unexpected failures (pipeline raises `PipelineError` for guarded failures)

---

## 3) Component map (ASCII)

```
                         +--------------------+
                         |  PolicyEngine      |
                         |  (rules.json)      |
                         +---------+----------+
                                   |
                                   v
+-------------+      +-------------+-------------+      +------------------+
| FastAPI     | ---> | InputGuard                | ---> | ResolverAgent     |
| /chat       |      | (signals-only + LLM)      |      | ResolverAgent     |
+------+------+      +-------------+-------------+      +--------+---------+
       |                              |                          |
       |                              v                          |
       |                     +--------+---------+                |
       |                     | HITL Service     |<---------------+
       |                     | (SQLite queue)   |
       |                     +------------------+
       |
       v
+------+------------------+
| OpenAIProxyClient       |
| (responses.create)      |
| temperature=0           |
+------+------------------+
       |
       v
+------+------------------+
| OutputGuard              |
| (LLM -> policy -> mask)  |
| one-pass enforcement     |
+--------------------------+
```

---

## 4) Decisions and precedence

### 4.1 Policy engine decisions
Policy produces signals by:

1. Scoring keyword/phrase matches across enabled rules.
2. Computing a `risk_score` (sum of rule scores × match counts).
3. Returning thresholds (`sanitize_at`, `escalate_at`, `block_at`) as signals.

PolicyEngine is intentionally **signals-only**; interpretation is centralized in `app/policy/decision.py` via `policy_decision_from_signals(policy_result)`.

Precedence is deterministic:

`allow < sanitize < escalate < block`

### 4.2 Input guard decisions
Input guard produces **signals only** (it does not decide allow/block/sanitize/escalate).

- **LLM classifier output** (structured JSON validated by Pydantic)
- Policy signals are passed in only as **prompt context** to help classification

InputGuard outputs:

- `risk_score` in [0,1]
- `attack_type`
- optional `sanitized_text` suggestion

### 4.3 Resolver agent
ResolverAgent merges policy + guard signals deterministically:

- `policy_decision := policy_decision_from_signals(policy_result)`
- `guard_decision` derived from guard `risk_score` (block ≥ 0.9; escalate ≥ 0.7; sanitize > 0; else allow)
- `final_decision := max(policy_decision, guard_decision)` by precedence

One explicit safety rule is enforced:

- If `final_decision == sanitize` but `sanitized_text` is missing/blank → escalate (fail closed).

### 4.4 Pipeline risk-threshold override (HITL)
Even if the agent says allow/sanitize, the pipeline may force escalation:

- If `guard_risk_score > RISK_THRESHOLD`, decision is overridden to `escalate`.

This provides a deterministic “belt-and-suspenders” escalation path.

---

## 5) Policy engine details (deterministic, no regex)

### 5.1 Where rules live
Rules are defined in `app/policy/rules.json`.

Requirements enforced by code:

- Exactly **one enabled** rule with `policy_type = "escalation_threshold"` must exist.
- Each non-threshold rule must define `score` and match conditions.

### 5.2 Matching algorithm
- Text is normalized with `unicodedata.normalize("NFKC", ...)` and casefolded.
- Punctuation is converted to spaces using a deterministic translation table.
- Tokenization is `.split()`.
- Keyword matches are exact token membership.
- Phrase matches are exact contiguous windows (no regex).

### 5.3 Output
Policy returns:

- `risk_score`: non-negative int
- `thresholds`: `sanitize_at` / `escalate_at` / `block_at`
- `matched_rule_ids`: stable sorted tuple
- `matches`: stable sorted tuple of match objects

Policy does **not** return a decision directly; the decision is derived via `policy_decision_from_signals()`.

---

## 6) LLM integration

### 6.1 Two OpenAI clients with different roles
This repo uses the OpenAI Python SDK’s **Responses API** in two ways:

1. **Structured classifier** for guards (`app/llm/client.py`)
   - Uses `client.responses.parse(..., text_format=YourPydanticModel)`
   - Returns `parsed.model_dump()`

2. **Text generation proxy** (`app/llm/llm_client.py`)
   - Uses `client.responses.create(...)`
   - Reads `response.output_text`

### 6.2 Determinism requirement
Both classifier and generation calls set:

- `temperature=0`

Important operational note:

- Your configured `OPENAI_MODEL` must support the `temperature` parameter. If the model rejects it, requests fail.

### 6.3 Failure behavior
- Missing SDK package `openai` → hard error.
- OpenAI request errors → hard error (`LlmClientError` / `LlmProxyError`).
- Classifier output that fails schema validation → hard error.

There are no silent retries.

---

## 7) Output safety model

### 7.1 One-pass enforcement
Output guard uses a one-pass deterministic flow:

1) Classify the raw output
2) Evaluate policy **once** on the classifier's `final_output`
3) Mask / block based on classifier + policy

### 7.2 LLM classifier and schema
Output classifier returns structured JSON validated as `OutputGuardClassification`:

- `is_safe: bool`
- `violations: list[str]`
- `final_output: str`

### 7.3 Deterministic masking
If either is true:

- policy matches any `sensitive_topic` terms, OR
- classifier violations include `pii_leakage`

…then the output guard masks **only matched sensitive-topic phrases** (exact substring, case-insensitive) using `[REDACTED]`.

Masking behavior is deterministic:

- terms are deduped and ordered longest-first, then lexicographic.
- replacement uses a case-insensitive find loop (no regex).

### 7.4 Unsafe output handling
If classifier indicates unsafe (`is_safe=False`), output is replaced with:

`SAFE_REPLACEMENT_MESSAGE = "I can't help with that request."`

Policy enforcement is already applied once (post-classification) in the one-pass flow.

---

## 8) Observability and logging

### 8.1 Trace logger
Logging emits **one JSON object per line**.

Properties:

- stable JSON serialization (`sort_keys=True`, compact separators)
- logging is non-throwing (logger failures must not crash execution)

### 8.2 What is logged
The pipeline logs events such as:

- `chat.request.received`
- `chat.policy.evaluated`
- `chat.input_guard.done`
- `chat.agent.decided`
- `chat.llm.generated`
- `chat.output_guard.done`
- `chat.terminated.*`, `chat.completed`, `chat.error`

Log fields include masked input/output variants (masking terms derived from policy `sensitive_topic` matches).

### 8.3 What is not logged (by design intent)
- API keys / secrets
- System/developer prompts (should not be logged)

---

## 9) HITL (Human-in-the-loop) queue

### 9.1 When HITL is used
HITL is enabled via env:

- `ENABLE_HITL=true`

Escalation occurs when:

- agent decision == `escalate`, OR
- guard risk exceeds `RISK_THRESHOLD` (override)

### 9.2 Storage: async SQLite
The queue is stored in SQLite via `aiosqlite`.

Conceptual schema (as created by ensure_schema):

```
+-------------------+
| hitl_queue        |
+-------------------+
| id (PK)           |
| request_id        |
| created_at (UTC)  |
| risk_score        |
| decision          |
| status            |
| input_raw         |
| input_sanitized   |
| guard_json        |
| policy_json       |
| agent_json        |
| review_note       |
| reviewed_at       |
+-------------------+
```

JSON fields are serialized deterministically (`sort_keys=True`).

### 9.3 SQLite file placement constraint
To prevent accidental DB files in the repo root:

- `HITL_SQLITE_PATH` must include a directory (e.g., `./data/hitl.db`) unless it is absolute or `:memory:`.

The connector also creates parent directories as needed.

### 9.4 Reviewer resolve endpoint
Reviewers resolve queued items via an authenticated endpoint:

- `POST /hitl/resolve`
- Header: `X-HITL-REVIEW-KEY: <HITL_REVIEW_API_KEY>`
- Body: `{ queue_id, action: approve|decline, note?, max_output_tokens? }`

Actions:

- `decline` → marks the queue item as `declined` (adds optional `review_note`, sets `reviewed_at`)
- `approve` → runs generation using the stored `input_sanitized`, then runs OutputGuard
  - if OutputGuard blocks, the item is recorded as `declined` deterministically
  - if safe, the item is recorded as `approved`

---

## 10) Configuration (env vars)

Required:

- `OPENAI_API_KEY`
- `OPENAI_MODEL`

Logging (optional):

- `LOG_LEVEL` (default INFO)

HITL:

- `ENABLE_HITL` (default true)
- If enabled:
  - `HITL_SQLITE_PATH` (must include a directory)
  - `RISK_THRESHOLD` (must be in [0,1])
  - `HITL_REVIEW_API_KEY` (required; authenticates `/hitl/resolve`)
- Optional:
  - `HITL_SQLITE_TABLE` (defaults to `hitl_queue`)

Example config is provided in `.env.example`.

---

## 11) Tests (summary)

- `tests/test_input_guard.py`
  - Policy matches do not short-circuit classification
  - Signals-only classifier output validates against schema

- `tests/test_output_guard.py`
  - One-pass flow: classifier runs before policy enforcement
  - Safe pass-through
  - PII masking redacts matched sensitive phrase
  - Unsafe output replaced
  - Schema violation raises OutputGuardError

- `tests/test_pipeline.py`
  - Block short-circuits LLM proxy
  - Escalate enqueues HITL (when enabled)
  - Escalate fails when HITL disabled
  - Output guard can block response

- `tests/test_hitl_resolve_endpoint.py`
  - Auth required for reviewer endpoint
  - Approve triggers generation + output guard
  - Decline marks item reviewed

---

## 12) File-by-file manifest (concise)

### Root
- `main.py`
  - Creates FastAPI app and wires `/chat` to the pipeline.
  - Instantiates shared dependencies (policy engine, guards, ResolverAgent, OpenAI clients, HITL service).
  - Exposes `/hitl/resolve` for reviewer approve/decline.

- `pyproject.toml`
  - Project metadata + runtime dependencies.

- `.env.example`
  - Example environment variables (no secrets).

- `.gitignore`
  - Ignores runtime artifacts like `data/` and `*.db`.
  - Also currently ignores `tests/` and `.github/` (see Gotchas).

- `README.md`
  - Currently empty.

### app/config.py
- `Settings.from_env()` performs fail-fast env validation.
- `_validate_hitl_sqlite_path()` prevents DB files in repo root (unless absolute or `:memory:`).

### app/core/pipeline.py
- `run_chat_pipeline()` is the async orchestrator.
- Uses `anyio.to_thread.run_sync` to run sync stages without blocking the event loop.
- Emits trace events and enforces explicit branching.

### app/policy/policy_engine.py
- `PolicyEngine` loads and validates `rules.json`.
- Deterministic token/phrase matching and threshold-based signals.

### app/policy/decision.py
- `policy_decision_from_signals()` centralizes interpretation of PolicyEngine signals.

### app/policy/rules.json
- Defines thresholds and a small set of example rules (injection blocks, sensitive-topic escalation, benign allow).

### app/guards/input_guard.py
- `InputGuard.evaluate()` runs LLM classification (structured) and returns signals only.

### app/guards/output_guard.py
- `OutputGuard.evaluate()` is one-pass: classify → policy enforce once on classifier output → mask/block.

### app/guards/prompts.py
- Contains system prompts for the input/output classifier and helper functions to build user prompts.

### app/agent/agent.py
- `ResolverAgent.decide()` resolves the final action from policy + guard signals.

### app/agent/tools.py
- `DecisionTools` exposes deterministic helpers (policy lookup, risk_score derived from policy decision).

### app/llm/client.py
- Structured classifier client (`responses.parse` + Pydantic `text_format`).

### app/llm/llm_client.py
- Proxy generation client (`responses.create` + output_text).

### app/hitl/db.py
- `SqliteConnector.connect()` opens an async SQLite connection and ensures the directory exists.

### app/hitl/service.py
- `HitlService.ensure_schema()` creates the queue table/index.
- `HitlService.enqueue()` inserts a pending-review record and returns `queue_id`.
- `HitlService.get_item()` loads a queue item for review.
- `HitlService.mark_reviewed()` records `approved` / `declined` with `review_note` and `reviewed_at`.

### app/logging/logger.py
- `TraceLogger.event()` emits stable JSON logs and never throws.
- Masking helpers implement deterministic case-insensitive redaction.

### app/schemas/*
- `api.py`: request/response models for `/chat` and `/hitl/resolve`.
- `guard.py`: input guard schema + result models.
- `agent.py`: resolver agent output model.
- `output_guard.py`: output guard classifier schema.
- `llm.py`: proxy request/response models.

---

## 13) Tech stack & libraries/tools

Runtime dependencies (from pyproject.toml):

- **FastAPI**: HTTP API framework (`POST /chat`).
- **uvicorn**: ASGI server to run FastAPI.
- **Pydantic v2**: strict validation for request/response and structured guard/agent outputs.
- **openai**: OpenAI Responses API client.
- **python-dotenv**: loads `.env` in development (still fail-fast if required vars missing).
- **aiosqlite**: async SQLite driver for HITL queue.

Key stdlib / built-ins used:

- `dataclasses`: lightweight immutable containers.
- `logging` + `json`: structured JSON logs.
- `pathlib`: path handling and directory creation.
- `unicodedata`, `string`: deterministic text normalization for policy matching.

---

## 14) Gotchas / operational notes

- `README.md` is empty (documentation currently lives in this report).
- `.gitignore` currently ignores `tests/` and `.github/`.
  - If you want tests committed and CI configured, adjust this separately.
- Model compatibility: the app enforces `temperature=0` in all OpenAI calls; choose a model that accepts it.
- HITL DB placement: `HITL_SQLITE_PATH` must include a directory to avoid repo-root `*.db` files.
