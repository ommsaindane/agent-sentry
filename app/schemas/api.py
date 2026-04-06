from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    max_output_tokens: int = Field(gt=0, le=8192)
    metadata: dict[str, Any] | None = None


class ChatOkResponse(BaseModel):
    decision: Literal["allow", "sanitize"]
    request_id: str
    output_text: str


class ChatBlockedResponse(BaseModel):
    decision: Literal["block"]
    request_id: str
    error: str


class ChatPendingResponse(BaseModel):
    decision: Literal["escalate"]
    request_id: str
    status: Literal["pending_review"]
    queue_id: int
