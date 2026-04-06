from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class OutputGuardClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_safe: bool
    violations: list[str] = Field(default_factory=list)
    final_output: str = Field(min_length=1)
