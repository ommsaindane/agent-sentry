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


class HitlResolveRequest(BaseModel):
    queue_id: int = Field(gt=0)
    action: Literal["approve", "decline"]
    note: str | None = Field(default=None, max_length=2000)
    # Required for approve (explicit to avoid hidden defaults)
    max_output_tokens: int | None = Field(default=None, gt=0, le=8192)


class HitlResolveResponse(BaseModel):
    queue_id: int
    request_id: str
    status: Literal["approved", "declined"]
    output_text: str | None = None
