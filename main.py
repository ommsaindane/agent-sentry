from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from app.agent.agent import DecisionAgent
from app.agent.tools import DecisionTools
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
)


@dataclass(frozen=True, slots=True)
class AppState:
    deps: ChatPipelineDeps
    trace: TraceLogger


def create_app() -> FastAPI:
    # Explicitly load .env if present; config still fails fast if required vars missing.
    load_dotenv(override=False)

    try:
        settings = Settings.from_env()
    except SettingsError as exc:
        raise RuntimeError(f"Configuration error: {exc}") from exc

    trace = get_trace_logger()

    rules_path = Path(__file__).parent / "app" / "policy" / "rules.json"
    policy_engine = PolicyEngine(rules_path=rules_path)

    # Shared structured-output client for input/output guards.
    classifier_client = OpenAIClient.from_env()
    input_guard = InputGuard(policy_engine=policy_engine, llm_client=classifier_client)
    output_guard = OutputGuard(policy_engine=policy_engine, llm_client=classifier_client)

    decision_agent = DecisionAgent(tools=DecisionTools(policy_engine=policy_engine))
    llm_proxy = OpenAIProxyClient.from_env()

    hitl_service = None
    if settings.enable_hitl:
        hitl_service = HitlService.from_settings(settings)

    deps = ChatPipelineDeps(
        policy_engine=policy_engine,
        input_guard=input_guard,
        decision_agent=decision_agent,
        llm_proxy=llm_proxy,
        output_guard=output_guard,
        hitl_service=hitl_service,
        enable_hitl=settings.enable_hitl,
        risk_threshold=settings.risk_threshold,
    )

    app = FastAPI(title="AgentSentry", version="0.1.0")
    app.state.state = AppState(deps=deps, trace=trace)

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

    return app


app = create_app()
