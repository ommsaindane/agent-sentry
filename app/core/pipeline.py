from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from datetime import datetime, timezone

import anyio

from app.agent.agent import ResolverAgent
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


class RequestLogServiceLike(Protocol):
    async def ensure_schema(self) -> None: ...

    async def record(
        self,
        *,
        request_id: str,
        decision: str,
        status: str,
        created_at: str,
        risk_score: float,
        policy_risk_score: float,
        queue_id: int | None,
        input_raw: str,
        input_sanitized: str,
        output_text: str | None,
        guard_obj: dict[str, Any],
        policy_obj: dict[str, Any],
        agent_obj: dict[str, Any],
        output_obj: dict[str, Any] | None,
    ) -> None: ...

    async def update_status_by_request_id(self, *, request_id: str, status: str) -> None: ...

    async def list_requests(
        self,
        *,
        limit: int,
        offset: int,
        decision: str | None = None,
        status: str | None = None,
    ) -> list[Any]: ...

    async def get_request(self, *, request_id: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class ChatPipelineDeps:
    policy_engine: PolicyEngine
    input_guard: InputGuard
    resolver_agent: ResolverAgent
    llm_proxy: OpenAIProxyClient
    output_guard: OutputGuard
    hitl_service: HitlServiceLike | None
    request_log_service: RequestLogServiceLike | None
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

    created_at = datetime.now(timezone.utc).isoformat()

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
        policy_risk_score=policy_result.risk_score,
        policy_thresholds=dict(policy_result.thresholds),
        matched_rule_ids=list(policy_result.matched_rule_ids),
    )

    try:
        guard_result = await anyio.to_thread.run_sync(
            lambda: deps.input_guard.evaluate(message, policy_result=policy_result)
        )
    except InputGuardError as exc:
        raise PipelineError(str(exc)) from exc
    except Exception as exc:
        raise PipelineError(f"Input guard failed: {exc}") from exc
    guard_risk_score = float(guard_result.risk_score)
    sanitized_suggestion = guard_result.sanitized_text or ""
    masked_input_sanitized = mask_terms_case_insensitive(sanitized_suggestion, redact_terms_input)
    trace.event(
        "chat.input_guard.done",
        request_id=request_id,
        guard_attack_type=guard_result.attack_type.value,
        guard_risk_score=guard_risk_score,
        input_sanitized=masked_input_sanitized,
    )

    try:
        agent_out = await anyio.to_thread.run_sync(
            lambda: deps.resolver_agent.decide(
                input_guard_result=guard_result,
                policy_result=policy_result,
            )
        )
    except Exception as exc:
        raise PipelineError(f"Resolver agent failed: {exc}") from exc
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

        if deps.request_log_service is not None:
            try:
                await deps.request_log_service.record(
                    request_id=request_id,
                    decision="block",
                    status="completed",
                    created_at=created_at,
                    risk_score=float(guard_risk_score),
                    policy_risk_score=float(policy_result.risk_score),
                    queue_id=None,
                    input_raw=message,
                    input_sanitized=(guard_result.sanitized_text or ""),
                    output_text=None,
                    guard_obj=guard_result.model_dump(),
                    policy_obj=policy_result.to_dict(),
                    agent_obj=agent_out.model_dump(),
                    output_obj=None,
                )
            except Exception as exc:
                raise PipelineError(f"Request log failed: {exc}") from exc

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
            input_sanitized=(guard_result.sanitized_text or message),
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

        if deps.request_log_service is not None:
            try:
                await deps.request_log_service.record(
                    request_id=request_id,
                    decision="escalate",
                    status="pending_review",
                    created_at=created_at,
                    risk_score=float(guard_risk_score),
                    policy_risk_score=float(policy_result.risk_score),
                    queue_id=int(queue_id),
                    input_raw=message,
                    input_sanitized=(guard_result.sanitized_text or message),
                    output_text=None,
                    guard_obj=guard_obj,
                    policy_obj=policy_obj,
                    agent_obj=agent_obj,
                    output_obj=None,
                )
            except Exception as exc:
                raise PipelineError(f"Request log failed: {exc}") from exc

        return ChatPipelineResult(decision="escalate", output_text="", queue_id=queue_id)

    # allow/sanitize path -> LLM proxy
    if effective_decision == "sanitize":
        if not guard_result.sanitized_text or not guard_result.sanitized_text.strip():
            raise PipelineError("Resolver decided sanitize, but sanitized_text is missing")
        sanitized_text_for_llm = guard_result.sanitized_text
    else:
        sanitized_text_for_llm = message

    llm_req = LlmProxyRequest(
        sanitized_text=sanitized_text_for_llm,
        max_output_tokens=max_output_tokens,
        system_prompt=None,
    )

    try:
        llm_resp = await anyio.to_thread.run_sync(lambda: deps.llm_proxy.generate(llm_req))
    except LlmProxyError as exc:
        raise PipelineError(str(exc)) from exc
    except Exception as exc:
        raise PipelineError(f"LLM proxy failed: {exc}") from exc

    try:
        out_guard = await anyio.to_thread.run_sync(lambda: deps.output_guard.evaluate(llm_resp.raw_text))
    except OutputGuardError as exc:
        raise PipelineError(str(exc)) from exc
    except Exception as exc:
        raise PipelineError(f"Output guard failed: {exc}") from exc

    # Log raw output after OutputGuard evaluation so we can deterministically redact
    # without re-evaluating policy in the pipeline.
    redact_terms_output = list(dict.fromkeys(redact_terms_input + list(getattr(out_guard, "redact_terms", []))))
    masked_llm_output = mask_terms_case_insensitive(llm_resp.raw_text, redact_terms_output)
    trace.event(
        "chat.llm.generated",
        request_id=request_id,
        llm_model=llm_resp.model,
        output_raw=masked_llm_output,
        usage=llm_resp.usage,
    )

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

        if deps.request_log_service is not None:
            try:
                await deps.request_log_service.record(
                    request_id=request_id,
                    decision="block",
                    status="completed",
                    created_at=created_at,
                    risk_score=float(guard_risk_score),
                    policy_risk_score=float(policy_result.risk_score),
                    queue_id=None,
                    input_raw=message,
                    input_sanitized=(guard_result.sanitized_text or ""),
                    output_text=str(out_guard.final_output),
                    guard_obj=guard_result.model_dump(),
                    policy_obj=policy_result.to_dict(),
                    agent_obj=agent_out.model_dump(),
                    output_obj={
                        "is_safe": bool(out_guard.is_safe),
                        "violations": list(out_guard.violations),
                        "output_policy_decision": out_guard.policy_decision,
                        "output_policy_risk_score": int(out_guard.policy_risk_score),
                        "matched_rule_ids": list(out_guard.matched_rule_ids),
                    },
                )
            except Exception as exc:
                raise PipelineError(f"Request log failed: {exc}") from exc
        return ChatPipelineResult(decision="block", output_text=out_guard.final_output, queue_id=None)

    trace.event("chat.completed", request_id=request_id)

    if deps.request_log_service is not None:
        try:
            await deps.request_log_service.record(
                request_id=request_id,
                decision=str(effective_decision),
                status="completed",
                created_at=created_at,
                risk_score=float(guard_risk_score),
                policy_risk_score=float(policy_result.risk_score),
                queue_id=None,
                input_raw=message,
                input_sanitized=(guard_result.sanitized_text or ""),
                output_text=str(out_guard.final_output),
                guard_obj=guard_result.model_dump(),
                policy_obj=policy_result.to_dict(),
                agent_obj=agent_out.model_dump(),
                output_obj={
                    "is_safe": bool(out_guard.is_safe),
                    "violations": list(out_guard.violations),
                    "output_policy_decision": out_guard.policy_decision,
                    "output_policy_risk_score": int(out_guard.policy_risk_score),
                    "matched_rule_ids": list(out_guard.matched_rule_ids),
                },
            )
        except Exception as exc:
            raise PipelineError(f"Request log failed: {exc}") from exc

    return ChatPipelineResult(decision=str(effective_decision), output_text=out_guard.final_output, queue_id=None)
