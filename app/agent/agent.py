from __future__ import annotations

from dataclasses import dataclass

from app.policy.policy_engine import PolicyResult
from app.policy.decision import policy_decision_from_signals
from app.schemas.agent import ResolverAgentOutput
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
class ResolverAgent:
    """Deterministically resolves the final action from signals.

    Inputs are signals only:
    - PolicyResult: matches + scores + thresholds
    - InputGuardResult: semantic risk + attack_type + sanitized_text suggestion
    """

    def decide(
        self,
        *,
        input_guard_result: InputGuardResult,
        policy_result: PolicyResult,
    ) -> ResolverAgentOutput:
        policy_decision = policy_decision_from_signals(policy_result)
        guard_decision = self._guard_decision_from_signals(input_guard_result)

        final_decision = self._max_decision(policy_decision, guard_decision)

        # Deterministic safety: if we decide to sanitize but no sanitized_text is available,
        # escalate for HITL rather than silently allowing.
        if final_decision == "sanitize":
            st = input_guard_result.sanitized_text
            if st is None or not str(st).strip():
                final_decision = "escalate"

        confidence = self._compute_confidence(
            final_decision=final_decision,
            policy_decision=policy_decision,
            guard_risk=float(input_guard_result.risk_score),
        )

        matched_rule_ids = list(policy_result.matched_rule_ids)
        reason = (
            f"final={final_decision}; "
            f"guard=risk={float(input_guard_result.risk_score):.2f} "
            f"attack={input_guard_result.attack_type.value} "
            f"has_sanitized={bool(input_guard_result.sanitized_text and input_guard_result.sanitized_text.strip())}; "
            f"policy={policy_decision} (risk_score={policy_result.risk_score} matched={matched_rule_ids})"
        )

        return ResolverAgentOutput(
            decision=final_decision,
            confidence=confidence,
            reason=reason,
        )

    def _max_decision(self, a: str, b: str) -> str:
        return a if _DECISION_PRECEDENCE[a] >= _DECISION_PRECEDENCE[b] else b

    def _guard_decision_from_signals(self, g: InputGuardResult) -> str:
        r = float(g.risk_score)
        if r >= 0.9:
            return "block"
        if r >= 0.7:
            return "escalate"
        if r > 0.0:
            return "sanitize"
        return "allow"

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
