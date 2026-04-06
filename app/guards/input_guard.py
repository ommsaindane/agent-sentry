from __future__ import annotations

from dataclasses import dataclass

from app.guards.prompts import INPUT_GUARD_SYSTEM_PROMPT, build_input_guard_user_prompt
from app.llm.client import LlmClient, LlmClientError
from app.policy.policy_engine import PolicyEngine
from app.schemas.guard import (
    AttackType,
    InputGuardClassification,
    InputGuardResult,
)


class InputGuardError(RuntimeError):
    pass


_DECISION_PRECEDENCE: dict[str, int] = {
    "allow": 0,
    "sanitize": 1,
    "escalate": 2,
    "block": 3,
}


@dataclass(frozen=True, slots=True)
class InputGuard:
    policy_engine: PolicyEngine
    llm_client: LlmClient

    def evaluate(self, raw_text: str) -> InputGuardResult:
        if not isinstance(raw_text, str):
            raise InputGuardError("raw_text must be a string")

        policy_result = self.policy_engine.evaluate(raw_text)

        # Deterministic hard backstop: if policy blocks, do not call LLM.
        if policy_result.decision == "block":
            classification = InputGuardClassification(
                is_malicious=True,
                attack_type=AttackType.other,
                risk_score=1.0,
                reasoning=self._policy_reasoning(policy_result.matched_rule_ids),
                sanitized_text=None,
            )
            return InputGuardResult(
                decision="block",
                classification=classification,
                policy_decision=policy_result.decision,
                policy_risk_score=policy_result.risk_score,
                matched_rule_ids=list(policy_result.matched_rule_ids),
                final_text="",
            )

        policy_context = self._build_policy_context(raw_text)
        user_prompt = build_input_guard_user_prompt(
            raw_user_prompt=raw_text,
            policy_context=policy_context,
        )

        try:
            json_obj = self.llm_client.classify_json(
                system_prompt=INPUT_GUARD_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                schema_model=InputGuardClassification,
            )
        except LlmClientError as exc:
            raise InputGuardError(f"Input guard classifier failed: {exc}") from exc

        try:
            classification = InputGuardClassification.model_validate(json_obj)
        except Exception as exc:
            raise InputGuardError(f"Classifier output failed schema validation: {exc}") from exc

        classifier_decision = self._decision_from_classification(classification)
        final_decision = self._max_decision(policy_result.decision, classifier_decision)

        final_text = raw_text
        if final_decision == "sanitize":
            if not classification.sanitized_text or not classification.sanitized_text.strip():
                raise InputGuardError(
                    "Classifier marked input as requiring sanitize, but sanitized_text is missing"
                )
            final_text = classification.sanitized_text
        elif final_decision == "block":
            final_text = ""

        return InputGuardResult(
            decision=final_decision,
            classification=classification,
            policy_decision=policy_result.decision,
            policy_risk_score=policy_result.risk_score,
            matched_rule_ids=list(policy_result.matched_rule_ids),
            final_text=final_text,
        )

    def _max_decision(self, a: str, b: str) -> str:
        return a if _DECISION_PRECEDENCE[a] >= _DECISION_PRECEDENCE[b] else b

    def _decision_from_classification(self, c: InputGuardClassification) -> str:
        if not c.is_malicious:
            return "allow"

        if c.risk_score >= 0.9:
            return "block"
        if c.risk_score >= 0.7:
            return "escalate"

        return "sanitize"

    def _build_policy_context(self, raw_text: str) -> str:
        policy_result = self.policy_engine.evaluate(raw_text)

        lines: list[str] = []
        lines.append(f"policy_decision: {policy_result.decision}")
        lines.append(f"policy_risk_score: {policy_result.risk_score}")
        if policy_result.matched_rule_ids:
            lines.append("matched_rules:")
            for rid in policy_result.matched_rule_ids:
                rule = self.policy_engine.get_rule(rid)
                desc = str(rule.get("description", "")).strip()
                action = str(rule.get("action", "")).strip()
                lines.append(f"- {rid}: action={action}; description={desc}")
        else:
            lines.append("matched_rules: none")

        return "\n".join(lines)

    def _policy_reasoning(self, matched_rule_ids: tuple[str, ...]) -> str:
        if not matched_rule_ids:
            return "Blocked by policy engine."
        return "Blocked by policy engine. Matched rules: " + ", ".join(matched_rule_ids)
