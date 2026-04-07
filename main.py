from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from app.agent.agent import ResolverAgent
from app.config import Settings, SettingsError
from app.core.pipeline import ChatPipelineDeps, PipelineError, run_chat_pipeline
from app.guards.input_guard import InputGuard
from app.guards.output_guard import OutputGuard
from app.hitl.service import HitlService
from app.llm.client import OpenAIClient
from app.llm.llm_client import OpenAIProxyClient
from app.logging.logger import TraceLogger, get_trace_logger
from app.policy.policy_engine import PolicyEngine
from app.schemas.api import (
    ChatBlockedResponse,
    ChatOkResponse,
    ChatPendingResponse,
    ChatRequest,
    HitlResolveRequest,
    HitlResolveResponse,
)
from app.schemas.llm import LlmProxyRequest


@dataclass(frozen=True, slots=True)
class AppState:
    deps: ChatPipelineDeps
    trace: TraceLogger
    settings: Settings


def create_app(
    *,
    settings_override: Settings | None = None,
    deps_override: ChatPipelineDeps | None = None,
    trace_override: TraceLogger | None = None,
) -> FastAPI:
    # Explicitly load .env if present; config still fails fast if required vars missing.
    load_dotenv(override=False)

    if settings_override is not None:
        settings = settings_override
    else:
        try:
            settings = Settings.from_env()
        except SettingsError as exc:
            raise RuntimeError(f"Configuration error: {exc}") from exc

    trace = trace_override or get_trace_logger()

    if deps_override is not None:
        deps = deps_override
    else:
        rules_path = Path(__file__).parent / "app" / "policy" / "rules.json"
        policy_engine = PolicyEngine(rules_path=rules_path)

        # Shared structured-output client for input/output guards.
        classifier_client = OpenAIClient.from_env()
        input_guard = InputGuard(policy_engine=policy_engine, llm_client=classifier_client)
        output_guard = OutputGuard(policy_engine=policy_engine, llm_client=classifier_client)

        resolver_agent = ResolverAgent()
        llm_proxy = OpenAIProxyClient.from_env()

        hitl_service = None
        if settings.enable_hitl:
            hitl_service = HitlService.from_settings(settings)

        deps = ChatPipelineDeps(
            policy_engine=policy_engine,
            input_guard=input_guard,
            resolver_agent=resolver_agent,
            llm_proxy=llm_proxy,
            output_guard=output_guard,
            hitl_service=hitl_service,
            enable_hitl=settings.enable_hitl,
            risk_threshold=settings.risk_threshold,
        )

    app = FastAPI(title="AgentSentry", version="0.1.0")
    app.state.state = AppState(deps=deps, trace=trace, settings=settings)

    @app.on_event("startup")
    async def _startup() -> None:
        state: AppState = app.state.state
        if state.deps.enable_hitl and state.deps.hitl_service is not None:
            await state.deps.hitl_service.ensure_schema()

    @app.post(
        "/chat",
        responses={
            200: {"model": ChatOkResponse},
            202: {"model": ChatPendingResponse},
            403: {"model": ChatBlockedResponse},
        },
    )
    async def chat(req: ChatRequest):
        request_id = uuid4().hex
        state: AppState = app.state.state

        try:
            result = await run_chat_pipeline(
                request_id=request_id,
                message=req.message,
                max_output_tokens=req.max_output_tokens,
                deps=state.deps,
                trace=state.trace,
            )
        except PipelineError as exc:
            state.trace.event("chat.error", request_id=request_id, error=str(exc))
            raise HTTPException(status_code=500, detail=str(exc))
        except Exception as exc:
            state.trace.event("chat.error", request_id=request_id, error=str(exc))
            raise HTTPException(status_code=500, detail="Internal error") from exc

        if result.decision == "block":
            body = ChatBlockedResponse(
                decision="block",
                request_id=request_id,
                error=(result.output_text.strip() if result.output_text else "Blocked by guardrails."),
            ).model_dump()
            return JSONResponse(status_code=403, content=body)

        if result.decision == "escalate":
            if result.queue_id is None:
                raise HTTPException(status_code=500, detail="Escalation missing queue_id")
            body = ChatPendingResponse(
                decision="escalate",
                request_id=request_id,
                status="pending_review",
                queue_id=int(result.queue_id),
            ).model_dump()
            return JSONResponse(status_code=202, content=body)

        body = ChatOkResponse(
            decision=result.decision,  # allow/sanitize
            request_id=request_id,
            output_text=result.output_text,
        ).model_dump()
        return JSONResponse(status_code=200, content=body)

    @app.post(
        "/hitl/resolve",
        responses={
            200: {"model": HitlResolveResponse},
            400: {"description": "Bad Request"},
            401: {"description": "Unauthorized"},
            404: {"description": "Queue item not found"},
            409: {"description": "Queue item already reviewed"},
        },
    )
    async def hitl_resolve(
        req: HitlResolveRequest,
        review_key: str | None = Header(default=None, alias="X-HITL-REVIEW-KEY"),
    ):
        state: AppState = app.state.state

        if not state.settings.enable_hitl:
            raise HTTPException(status_code=400, detail="HITL is disabled")

        expected = state.settings.hitl_review_api_key
        if not expected or not expected.strip():
            raise HTTPException(status_code=500, detail="HITL review API key not configured")
        if not review_key or review_key != expected:
            raise HTTPException(status_code=401, detail="Unauthorized")

        hitl_service = state.deps.hitl_service
        if hitl_service is None or not hasattr(hitl_service, "get_item") or not hasattr(hitl_service, "mark_reviewed"):
            raise HTTPException(status_code=500, detail="HITL service is not configured")

        try:
            item = await hitl_service.get_item(queue_id=int(req.queue_id))  # type: ignore[attr-defined]
        except Exception as exc:
            state.trace.event("hitl.resolve.error", queue_id=int(req.queue_id), error=str(exc))
            raise HTTPException(status_code=500, detail="Failed to load HITL queue item") from exc

        if item is None:
            raise HTTPException(status_code=404, detail="Queue item not found")

        if str(item.status) != "pending_review":
            raise HTTPException(status_code=409, detail="Queue item already reviewed")

        note = (req.note.strip() if isinstance(req.note, str) and req.note.strip() else None)

        if req.action == "decline":
            try:
                await hitl_service.mark_reviewed(  # type: ignore[attr-defined]
                    queue_id=int(req.queue_id),
                    status="declined",
                    review_note=note,
                )
            except Exception as exc:
                state.trace.event("hitl.resolve.error", queue_id=int(req.queue_id), error=str(exc))
                raise HTTPException(status_code=500, detail="Failed to update HITL queue item") from exc

            state.trace.event(
                "hitl.resolve.declined",
                queue_id=int(req.queue_id),
                request_id=str(item.request_id),
            )
            body = HitlResolveResponse(
                queue_id=int(req.queue_id),
                request_id=str(item.request_id),
                status="declined",
                output_text=None,
            ).model_dump()
            return JSONResponse(status_code=200, content=body)

        # approve path
        if req.max_output_tokens is None:
            raise HTTPException(status_code=400, detail="max_output_tokens is required for approve")

        if not isinstance(item.input_sanitized, str) or not item.input_sanitized.strip():
            raise HTTPException(status_code=500, detail="HITL queue item missing input_sanitized")

        llm_req = LlmProxyRequest(
            sanitized_text=str(item.input_sanitized),
            max_output_tokens=int(req.max_output_tokens),
            system_prompt=None,
        )

        try:
            llm_resp = state.deps.llm_proxy.generate(llm_req)
        except Exception as exc:
            state.trace.event("hitl.resolve.error", queue_id=int(req.queue_id), error=str(exc))
            raise HTTPException(status_code=500, detail="LLM proxy failed") from exc

        try:
            out_guard = state.deps.output_guard.evaluate(llm_resp.raw_text)
        except Exception as exc:
            state.trace.event("hitl.resolve.error", queue_id=int(req.queue_id), error=str(exc))
            raise HTTPException(status_code=500, detail="Output guard failed") from exc

        final_output = str(getattr(out_guard, "final_output", "") or "").strip()
        is_safe = bool(getattr(out_guard, "is_safe", False))

        if not is_safe:
            appended = "output_guard_blocked"
            review_note = appended if note is None else f"{note}\n{appended}"
            try:
                await hitl_service.mark_reviewed(  # type: ignore[attr-defined]
                    queue_id=int(req.queue_id),
                    status="declined",
                    review_note=review_note,
                )
            except Exception as exc:
                state.trace.event("hitl.resolve.error", queue_id=int(req.queue_id), error=str(exc))
                raise HTTPException(status_code=500, detail="Failed to update HITL queue item") from exc

            state.trace.event(
                "hitl.resolve.approve_blocked",
                queue_id=int(req.queue_id),
                request_id=str(item.request_id),
            )
            body = HitlResolveResponse(
                queue_id=int(req.queue_id),
                request_id=str(item.request_id),
                status="declined",
                output_text=(final_output or "Blocked by output guard."),
            ).model_dump()
            return JSONResponse(status_code=200, content=body)

        try:
            await hitl_service.mark_reviewed(  # type: ignore[attr-defined]
                queue_id=int(req.queue_id),
                status="approved",
                review_note=note,
            )
        except Exception as exc:
            state.trace.event("hitl.resolve.error", queue_id=int(req.queue_id), error=str(exc))
            raise HTTPException(status_code=500, detail="Failed to update HITL queue item") from exc

        state.trace.event(
            "hitl.resolve.approved",
            queue_id=int(req.queue_id),
            request_id=str(item.request_id),
        )
        body = HitlResolveResponse(
            queue_id=int(req.queue_id),
            request_id=str(item.request_id),
            status="approved",
            output_text=final_output,
        ).model_dump()
        return JSONResponse(status_code=200, content=body)

    return app


app = create_app()
