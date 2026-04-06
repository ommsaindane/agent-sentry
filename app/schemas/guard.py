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


class InputGuardClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_malicious: bool
    attack_type: AttackType
    risk_score: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1)
    sanitized_text: str | None = None


class InputGuardResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    classification: InputGuardClassification

    policy_decision: Decision
    policy_risk_score: int = Field(ge=0)
    matched_rule_ids: list[str]

    final_text: str
