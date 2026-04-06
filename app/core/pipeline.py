from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from app.agent.agent import DecisionAgent
from app.guards.input_guard import InputGuard
from app.guards.output_guard import OutputGuard
from app.llm.llm_client import OpenAIProxyClient
from app.logging.logger import TraceLogger
from app.policy.policy_engine import PolicyEngine
from app.schemas.llm import LlmProxyRequest


class PipelineError(RuntimeError):
    pass


class HitlServiceLike(Protocol):
    def enqueue(
        self,
        *,
        request_id: str,
        decision: str,
        input_raw: str,
        input_sanitized: str,
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


@dataclass(frozen=True, slots=True)
class ChatPipelineResult:
    decision: str
    output_text: str
    queue_id: int | None


def run_chat_pipeline(
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

    trace.event(
        "chat.request.received",
        request_id=request_id,
        input_raw=message,
        max_output_tokens=max_output_tokens,
    )

    policy_result = deps.policy_engine.evaluate(message)
    trace.event(
        "chat.policy.evaluated",
        request_id=request_id,
        policy_decision=policy_result.decision,
        policy_risk_score=policy_result.risk_score,
        matched_rule_ids=list(policy_result.matched_rule_ids),
    )

    guard_result = deps.input_guard.evaluate(message)
    trace.event(
        "chat.input_guard.done",
        request_id=request_id,
        guard_decision=guard_result.decision,
        guard_attack_type=guard_result.classification.attack_type.value,
        guard_risk_score=float(guard_result.classification.risk_score),
        input_sanitized=guard_result.final_text,
        matched_rule_ids=list(guard_result.matched_rule_ids),
    )

    agent_out = deps.decision_agent.decide(
        guard_result=guard_result,
        policy_result=policy_result,
    )
    trace.event(
        "chat.agent.decided",
        request_id=request_id,
        decision=agent_out.decision,
        confidence=float(agent_out.confidence),
        reason=str(agent_out.reason),
    )

    if agent_out.decision == "block":
        trace.event("chat.terminated.blocked", request_id=request_id)
        return ChatPipelineResult(decision="block", output_text="", queue_id=None)

    if agent_out.decision == "escalate":
        if not deps.enable_hitl or deps.hitl_service is None:
            raise PipelineError("HITL is disabled or not configured, but escalation was required")

        guard_obj = guard_result.model_dump()
        policy_obj = policy_result.to_dict()
        agent_obj = agent_out.model_dump()

        enqueue_result = deps.hitl_service.enqueue(
            request_id=request_id,
            decision="escalate",
            input_raw=message,
            input_sanitized=guard_result.final_text,
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

    llm_resp = deps.llm_proxy.generate(llm_req)
    trace.event(
        "chat.llm.generated",
        request_id=request_id,
        llm_model=llm_resp.model,
        output_raw=llm_resp.raw_text,
        usage=llm_resp.usage,
    )

    out_guard = deps.output_guard.evaluate(llm_resp.raw_text)
    trace.event(
        "chat.output_guard.done",
        request_id=request_id,
        is_safe=bool(out_guard.is_safe),
        violations=list(out_guard.violations),
        output_final=out_guard.final_output,
        output_policy_decision=out_guard.policy_decision,
        output_policy_risk_score=int(out_guard.policy_risk_score),
        matched_rule_ids=list(out_guard.matched_rule_ids),
    )

    if not out_guard.is_safe:
        trace.event("chat.terminated.output_blocked", request_id=request_id)
        return ChatPipelineResult(decision="block", output_text=out_guard.final_output, queue_id=None)

    trace.event("chat.completed", request_id=request_id)
    return ChatPipelineResult(decision=str(agent_out.decision), output_text=out_guard.final_output, queue_id=None)
