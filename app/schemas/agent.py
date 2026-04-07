from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Decision = Literal["allow", "block", "sanitize", "escalate"]


class ResolverAgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)
