from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import anyio

from app.agent.agent import DecisionAgent
from app.guards.input_guard import InputGuard
from app.guards.input_guard import InputGuardError
from app.guards.output_guard import OutputGuard
from app.guards.output_guard import OutputGuardError
from app.llm.llm_client import OpenAIProxyClient
from app.llm.llm_client import LlmProxyError
from app.logging.logger import TraceLogger, mask_terms_case_insensitive
from app.policy.policy_engine import PolicyEngine
from app.schemas.llm import LlmProxyRequest


class PipelineError(RuntimeError):
    pass


class HitlServiceLike(Protocol):
    async def enqueue(
        self,
        *,
        request_id: str,
        decision: str,
        input_raw: str,
        input_sanitized: str,
        risk_score: float,
        guard_obj: dict[str, Any],
        policy_obj: dict[str, Any],
        agent_obj: dict[str, Any],
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class ChatPipelineDeps:
    policy_engine: PolicyEngine
    input_guard: InputGuard
    decision_agent: DecisionAgent
    llm_proxy: OpenAIProxyClient
    output_guard: OutputGuard
    hitl_service: HitlServiceLike | None
    enable_hitl: bool
    risk_threshold: float


@dataclass(frozen=True, slots=True)
class ChatPipelineResult:
    decision: str
    output_text: str
    queue_id: int | None


async def run_chat_pipeline(
    *,
    request_id: str,
    message: str,
    max_output_tokens: int,
    deps: ChatPipelineDeps,
    trace: TraceLogger,
) -> ChatPipelineResult:
    if not request_id or not str(request_id).strip():
        raise PipelineError("request_id is required")
    if not isinstance(message, str) or not message.strip():
        raise PipelineError("message must be a non-empty string")
    if not isinstance(max_output_tokens, int) or max_output_tokens <= 0:
        raise PipelineError("max_output_tokens must be a positive integer")

    policy_result = await anyio.to_thread.run_sync(lambda: deps.policy_engine.evaluate(message))

    redact_terms_input = [m.matched for m in policy_result.matches if m.policy_type == "sensitive_topic"]
    masked_input_raw = mask_terms_case_insensitive(message, redact_terms_input)

    trace.event(
        "chat.request.received",
        request_id=request_id,
        input_raw=masked_input_raw,
        max_output_tokens=max_output_tokens,
    )
    trace.event(
        "chat.policy.evaluated",
        request_id=request_id,
        policy_decision=policy_result.decision,
        policy_risk_score=policy_result.risk_score,
        matched_rule_ids=list(policy_result.matched_rule_ids),
    )

    try:
        guard_result = await anyio.to_thread.run_sync(lambda: deps.input_guard.evaluate(message))
    except InputGuardError as exc:
        raise PipelineError(str(exc)) from exc
    except Exception as exc:
        raise PipelineError(f"Input guard failed: {exc}") from exc
    guard_risk_score = float(guard_result.classification.risk_score)
    masked_input_sanitized = mask_terms_case_insensitive(guard_result.final_text, redact_terms_input)
    trace.event(
        "chat.input_guard.done",
        request_id=request_id,
        guard_decision=guard_result.decision,
        is_malicious=bool(guard_result.classification.is_malicious),
        guard_attack_type=guard_result.classification.attack_type.value,
        guard_risk_score=guard_risk_score,
        input_sanitized=masked_input_sanitized,
        matched_rule_ids=list(guard_result.matched_rule_ids),
    )

    try:
        agent_out = await anyio.to_thread.run_sync(
            lambda: deps.decision_agent.decide(
                guard_result=guard_result,
                policy_result=policy_result,
            )
        )
    except Exception as exc:
        raise PipelineError(f"Decision agent failed: {exc}") from exc
    trace.event(
        "chat.agent.decided",
        request_id=request_id,
        decision=agent_out.decision,
        confidence=float(agent_out.confidence),
        reason=str(agent_out.reason),
    )

    # HITL trigger: either agent requests escalation OR guard risk exceeds threshold.
    effective_decision = agent_out.decision
    if effective_decision not in {"block", "escalate"} and guard_risk_score > float(deps.risk_threshold):
        effective_decision = "escalate"
        trace.event(
            "chat.agent.overridden_by_risk_threshold",
            request_id=request_id,
            threshold=float(deps.risk_threshold),
            guard_risk_score=guard_risk_score,
        )

    if effective_decision == "block":
        trace.event("chat.terminated.blocked", request_id=request_id)
        return ChatPipelineResult(decision="block", output_text="", queue_id=None)

    if effective_decision == "escalate":
        if not deps.enable_hitl or deps.hitl_service is None:
            raise PipelineError("HITL is disabled or not configured, but escalation was required")

        guard_obj = guard_result.model_dump()
        policy_obj = policy_result.to_dict()
        agent_obj = agent_out.model_dump()

        enqueue_result = await deps.hitl_service.enqueue(
            request_id=request_id,
            decision="escalate",
            input_raw=message,
            input_sanitized=guard_result.final_text,
            risk_score=guard_risk_score,
            guard_obj=guard_obj,
            policy_obj=policy_obj,
            agent_obj=agent_obj,
        )

        queue_id = int(getattr(enqueue_result, "queue_id", 0) or 0)
        if queue_id <= 0:
            raise PipelineError("HITL enqueue did not return a valid queue_id")

        trace.event(
            "chat.terminated.escalated",
            request_id=request_id,
            queue_id=queue_id,
        )

        return ChatPipelineResult(decision="escalate", output_text="", queue_id=queue_id)

    # allow/sanitize path -> LLM proxy
    llm_req = LlmProxyRequest(
        sanitized_text=guard_result.final_text,
        max_output_tokens=max_output_tokens,
        system_prompt=None,
    )

    try:
        llm_resp = await anyio.to_thread.run_sync(lambda: deps.llm_proxy.generate(llm_req))
    except LlmProxyError as exc:
        raise PipelineError(str(exc)) from exc
    except Exception as exc:
        raise PipelineError(f"LLM proxy failed: {exc}") from exc

    # Mask logged outputs using policy sensitive-topic matches on the output itself.
    llm_policy_for_log = await anyio.to_thread.run_sync(lambda: deps.policy_engine.evaluate(llm_resp.raw_text))
    redact_terms_output = [m.matched for m in llm_policy_for_log.matches if m.policy_type == "sensitive_topic"]
    redact_terms_output = list(dict.fromkeys(redact_terms_input + redact_terms_output))
    masked_llm_output = mask_terms_case_insensitive(llm_resp.raw_text, redact_terms_output)

    trace.event(
        "chat.llm.generated",
        request_id=request_id,
        llm_model=llm_resp.model,
        output_raw=masked_llm_output,
        usage=llm_resp.usage,
    )

    try:
        out_guard = await anyio.to_thread.run_sync(lambda: deps.output_guard.evaluate(llm_resp.raw_text))
    except OutputGuardError as exc:
        raise PipelineError(str(exc)) from exc
    except Exception as exc:
        raise PipelineError(f"Output guard failed: {exc}") from exc
    masked_final_output = mask_terms_case_insensitive(out_guard.final_output, redact_terms_output)
    trace.event(
        "chat.output_guard.done",
        request_id=request_id,
        is_safe=bool(out_guard.is_safe),
        violations=list(out_guard.violations),
        output_final=masked_final_output,
        output_policy_decision=out_guard.policy_decision,
        output_policy_risk_score=int(out_guard.policy_risk_score),
        matched_rule_ids=list(out_guard.matched_rule_ids),
    )

    if not out_guard.is_safe:
        trace.event("chat.terminated.output_blocked", request_id=request_id)
        return ChatPipelineResult(decision="block", output_text=out_guard.final_output, queue_id=None)

    trace.event("chat.completed", request_id=request_id)
    return ChatPipelineResult(decision=str(effective_decision), output_text=out_guard.final_output, queue_id=None)
