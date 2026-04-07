from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AttackType(str, Enum):
    instruction_override = "instruction_override"
    role_hijack = "role_hijack"
    data_exfiltration = "data_exfiltration"
    benign = "benign"
    other = "other"


Decision = Literal["allow", "block", "sanitize", "escalate"]


class InputGuardResult(BaseModel):
    """Signals-only output from the Input Guard.

    This object intentionally does NOT include an allow/block/sanitize/escalate decision.
    Final action selection belongs to the ResolverAgent.
    """

    model_config = ConfigDict(extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    attack_type: AttackType
    sanitized_text: str | None = None
