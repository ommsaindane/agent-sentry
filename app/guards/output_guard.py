from __future__ import annotations

from dataclasses import dataclass

from app.guards.prompts import OUTPUT_GUARD_SYSTEM_PROMPT, build_output_guard_user_prompt
from app.llm.client import LlmClient, LlmClientError
from app.policy.policy_engine import PolicyEngine, PolicyResult
from app.policy.decision import policy_decision_from_signals
from app.schemas.output_guard import OutputGuardClassification


class OutputGuardError(RuntimeError):
    pass


SAFE_REPLACEMENT_MESSAGE = "I can't help with that request."


@dataclass(frozen=True, slots=True)
class OutputGuardResult:
    is_safe: bool
    violations: list[str]
    final_output: str

    policy_decision: str
    policy_risk_score: int
    matched_rule_ids: list[str]

    # Internal-only helper for deterministic log masking in the pipeline.
    # NOTE: Do not log these raw terms.
    redact_terms: list[str]


@dataclass(frozen=True, slots=True)
class OutputGuard:
    policy_engine: PolicyEngine
    llm_client: LlmClient

    def evaluate(self, raw_output_text: str) -> OutputGuardResult:
        if not isinstance(raw_output_text, str):
            raise OutputGuardError("raw_output_text must be a string")

        # One-pass flow: classify first, then enforce policy once on the classifier output.
        user_prompt = build_output_guard_user_prompt(
            raw_llm_output=raw_output_text,
            policy_context="policy_context: (not evaluated prior to classification)",
        )

        try:
            json_obj = self.llm_client.classify_json(
                system_prompt=OUTPUT_GUARD_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                schema_model=OutputGuardClassification,
            )
        except LlmClientError as exc:
            raise OutputGuardError(f"Output guard classifier failed: {exc}") from exc

        try:
            classification = OutputGuardClassification.model_validate(json_obj)
        except Exception as exc:
            raise OutputGuardError(f"Classifier output failed schema validation: {exc}") from exc

        violations = self._stable_violations(classification.violations)

        # Enforce policy once, after classification, using the classifier's output.
        policy_result = self.policy_engine.evaluate(classification.final_output)
        policy_decision = policy_decision_from_signals(policy_result)
        matched_rule_ids = list(policy_result.matched_rule_ids)

        # Deterministic masking: if policy indicates sensitive-topic matches OR classifier flags pii.
        sensitive_terms = self._sensitive_terms_from_policy(policy_result)
        redact_terms = list(sensitive_terms)
        should_mask = ("pii_leakage" in set(violations)) or bool(sensitive_terms)

        final_output = classification.final_output
        if should_mask:
            final_output = self._mask_terms_case_insensitive(final_output, sensitive_terms)

        # Classifier safety takes precedence.
        if not classification.is_safe:
            return OutputGuardResult(
                is_safe=False,
                violations=violations if violations else ["unsafe_or_disallowed_content"],
                final_output=SAFE_REPLACEMENT_MESSAGE,
                policy_decision=str(policy_decision),
                policy_risk_score=policy_result.risk_score,
                matched_rule_ids=matched_rule_ids,
                redact_terms=redact_terms,
            )

        # Policy enforcement (single pass).
        if policy_decision == "block":
            return OutputGuardResult(
                is_safe=False,
                violations=self._stable_violations(violations + ["policy_violation"] + matched_rule_ids),
                final_output=SAFE_REPLACEMENT_MESSAGE,
                policy_decision=str(policy_decision),
                policy_risk_score=policy_result.risk_score,
                matched_rule_ids=matched_rule_ids,
                redact_terms=redact_terms,
            )

        # If we only flagged PII leakage, masking makes the output safe enough to return.
        return OutputGuardResult(
            is_safe=True,
            violations=violations,
            final_output=final_output,
            policy_decision=str(policy_decision),
            policy_risk_score=policy_result.risk_score,
            matched_rule_ids=matched_rule_ids,
            redact_terms=redact_terms,
        )

    def _stable_violations(self, violations: list[str]) -> list[str]:
        # Deterministic ordering and de-dupe, ignoring falsy entries.
        cleaned = [v.strip() for v in violations if isinstance(v, str) and v.strip()]
        return sorted(set(cleaned))

    def _sensitive_terms_from_policy(self, policy_result: PolicyResult) -> list[str]:
        # Conservative: mask only matched sensitive-topic terms (exact phrases) to avoid over-masking.
        terms: list[str] = []
        for m in policy_result.matches:
            if m.policy_type == "sensitive_topic":
                terms.append(m.matched)
        # Deterministic ordering.
        return sorted(set(t for t in terms if t))

    def _mask_terms_case_insensitive(self, text: str, terms: list[str]) -> str:
        masked = text
        # Deterministic order: longer first, then lexicographic.
        ordered = sorted(set(terms), key=lambda t: (-len(t), t.casefold()))
        for term in ordered:
            masked = self._replace_case_insensitive(masked, term, "[REDACTED]")
        return masked

    def _replace_case_insensitive(self, text: str, term: str, replacement: str) -> str:
        if not term:
            return text

        term_cf = term.casefold()
        if not term_cf:
            return text

        text_cf = text.casefold()
        start = 0
        parts: list[str] = []

        while True:
            idx = text_cf.find(term_cf, start)
            if idx == -1:
                parts.append(text[start:])
                break
            parts.append(text[start:idx])
            parts.append(replacement)
            start = idx + len(term)

        return "".join(parts)
