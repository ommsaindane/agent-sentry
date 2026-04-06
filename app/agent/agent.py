from __future__ import annotations

from dataclasses import dataclass

from app.agent.tools import DecisionTools
from app.policy.policy_engine import PolicyResult
from app.schemas.agent import DecisionAgentOutput
from app.schemas.guard import InputGuardResult


_DECISION_PRECEDENCE: dict[str, int] = {
    "allow": 0,
    "sanitize": 1,
    "escalate": 2,
    "block": 3,
}

_POLICY_CONFIDENCE: dict[str, float] = {
    "allow": 0.4,
    "sanitize": 0.6,
    "escalate": 0.8,
    "block": 1.0,
}


@dataclass(frozen=True, slots=True)
class DecisionAgent:
    tools: DecisionTools

    def decide(
        self,
        *,
        guard_result: InputGuardResult,
        policy_result: PolicyResult | None = None,
    ) -> DecisionAgentOutput:
        # Prefer explicit policy_result if provided, else use policy fields already embedded
        # in guard_result (as produced by InputGuard).
        policy_decision = guard_result.policy_decision
        policy_risk_score = guard_result.policy_risk_score
        matched_rule_ids = guard_result.matched_rule_ids

        if policy_result is not None:
            policy_decision = policy_result.decision
            policy_risk_score = policy_result.risk_score
            matched_rule_ids = list(policy_result.matched_rule_ids)

        guard_decision = guard_result.decision
        attack_type = guard_result.classification.attack_type.value
        guard_risk = float(guard_result.classification.risk_score)

        final_decision = self._max_decision(policy_decision, guard_decision)

        # Optional deterministic nuance: exfiltration at high risk escalates.
        if (
            final_decision == "sanitize"
            and attack_type == "data_exfiltration"
            and guard_risk >= 0.7
        ):
            final_decision = "escalate"

        confidence = self._compute_confidence(
            final_decision=final_decision,
            policy_decision=policy_decision,
            guard_risk=guard_risk,
        )

        reason = (
            f"final={final_decision}; "
            f"guard={guard_decision} (attack={attack_type} risk={guard_risk:.2f}); "
            f"policy={policy_decision} (risk_score={policy_risk_score} matched={matched_rule_ids})"
        )

        return DecisionAgentOutput(
            decision=final_decision,
            confidence=confidence,
            reason=reason,
        )

    def _max_decision(self, a: str, b: str) -> str:
        return a if _DECISION_PRECEDENCE[a] >= _DECISION_PRECEDENCE[b] else b

    def _compute_confidence(self, *, final_decision: str, policy_decision: str, guard_risk: float) -> float:
        if final_decision == "block" and policy_decision == "block":
            return 1.0

        policy_conf = _POLICY_CONFIDENCE[policy_decision]
        confidence = max(guard_risk, policy_conf)

        # Clamp to [0,1] deterministically.
        if confidence < 0.0:
            return 0.0
        if confidence > 1.0:
            return 1.0
        return confidence
