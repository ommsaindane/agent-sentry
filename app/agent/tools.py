from __future__ import annotations

from dataclasses import dataclass

from app.policy.policy_engine import PolicyEngine


@dataclass(frozen=True, slots=True)
class DecisionTools:
    policy_engine: PolicyEngine

    def policy_lookup(self, rule_id: str) -> dict:
        return self.policy_engine.get_rule(rule_id)

    def risk_score(self, text: str) -> float:
        """Deterministic risk score in [0,1] derived from PolicyEngine decision."""
        result = self.policy_engine.evaluate(text)

        if result.decision == "block":
            return 1.0
        if result.decision == "escalate":
            return 0.8
        if result.decision == "sanitize":
            return 0.5
        return 0.0
