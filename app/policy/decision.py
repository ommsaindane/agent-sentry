from __future__ import annotations

from typing import Literal

from app.policy.policy_engine import PolicyResult

Decision = Literal["allow", "block", "sanitize", "escalate"]


_DECISION_PRECEDENCE: dict[str, int] = {
    "allow": 0,
    "sanitize": 1,
    "escalate": 2,
    "block": 3,
}


def policy_decision_from_signals(policy_result: PolicyResult) -> Decision:
    """Derive a deterministic policy intent from signals.

    PolicyEngine is signals-only; interpretation of those signals is centralized here.
    Precedence: block > escalate > sanitize > allow.

    Inputs:
    - policy_result.thresholds: sanitize_at/escalate_at/block_at
    - policy_result.risk_score: cumulative score
    - policy_result.matches[*].action: rule intent (if any)
    """

    thresholds = policy_result.thresholds or {}
    sanitize_at = int(thresholds.get("sanitize_at", 0))
    escalate_at = int(thresholds.get("escalate_at", 0))
    block_at = int(thresholds.get("block_at", 0))

    risk_score = int(policy_result.risk_score)

    threshold_decision: Decision = "allow"
    if block_at and risk_score >= block_at:
        threshold_decision = "block"
    elif escalate_at and risk_score >= escalate_at:
        threshold_decision = "escalate"
    elif sanitize_at and risk_score >= sanitize_at:
        threshold_decision = "sanitize"

    action_decision: Decision = "allow"
    for m in policy_result.matches:
        action = str(m.action)
        if action in _DECISION_PRECEDENCE and _DECISION_PRECEDENCE[action] > _DECISION_PRECEDENCE[action_decision]:
            action_decision = action  # type: ignore[assignment]

    if _DECISION_PRECEDENCE[threshold_decision] >= _DECISION_PRECEDENCE[action_decision]:
        return threshold_decision
    return action_decision
