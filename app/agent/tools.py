from __future__ import annotations

from dataclasses import dataclass

from app.policy.policy_engine import PolicyEngine
from app.policy.decision import policy_decision_from_signals


@dataclass(frozen=True, slots=True)
class DecisionTools:
    policy_engine: PolicyEngine

    def policy_lookup(self, rule_id: str) -> dict:
        return self.policy_engine.get_rule(rule_id)

    def risk_score(self, text: str) -> float:
        """Deterministic risk score in [0,1] derived from policy signals."""

        result = self.policy_engine.evaluate(text)

        intent = policy_decision_from_signals(result)

        if intent == "block":
            return 1.0
        if intent == "escalate":
            return 0.8
        if intent == "sanitize":
            return 0.5
        return 0.0
