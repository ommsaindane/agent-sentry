from __future__ import annotations

from dataclasses import dataclass

from app.guards.prompts import INPUT_GUARD_SYSTEM_PROMPT, build_input_guard_user_prompt
from app.llm.client import LlmClient, LlmClientError
from app.policy.policy_engine import PolicyEngine, PolicyResult
from app.schemas.guard import (
    AttackType,
    InputGuardResult,
)


class InputGuardError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InputGuard:
    policy_engine: PolicyEngine
    llm_client: LlmClient

    def evaluate(self, raw_text: str, *, policy_result: PolicyResult) -> InputGuardResult:
        if not isinstance(raw_text, str):
            raise InputGuardError("raw_text must be a string")

        policy_context = self._build_policy_context(policy_result)
        user_prompt = build_input_guard_user_prompt(
            raw_user_prompt=raw_text,
            policy_context=policy_context,
        )

        try:
            json_obj = self.llm_client.classify_json(
                system_prompt=INPUT_GUARD_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                schema_model=InputGuardResult,
            )
        except LlmClientError as exc:
            raise InputGuardError(f"Input guard classifier failed: {exc}") from exc

        try:
            classification = InputGuardResult.model_validate(json_obj)
        except Exception as exc:
            raise InputGuardError(f"Classifier output failed schema validation: {exc}") from exc

        return classification

    def _build_policy_context(self, policy_result: PolicyResult) -> str:
        lines: list[str] = []
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
