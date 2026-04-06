from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LlmProxyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sanitized_text: str = Field(min_length=1)
    max_output_tokens: int = Field(gt=0)
    system_prompt: str | None = None


class LlmProxyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    raw_text: str
    model: str
    usage: dict[str, Any] | None = None
