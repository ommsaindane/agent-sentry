from __future__ import annotations

import json
import string
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal

Decision = Literal["allow", "block", "sanitize", "escalate"]
PolicyType = Literal[
    "allowed_behavior",
    "restricted_action",
    "sensitive_topic",
    "escalation_threshold",
]


class PolicyConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PolicyMatch:
    rule_id: str
    policy_type: PolicyType
    action: Decision
    matched: str
    score: int


@dataclass(frozen=True, slots=True)
class PolicyResult:
    decision: Decision
    risk_score: int
    matched_rule_ids: tuple[str, ...]
    matches: tuple[PolicyMatch, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "matched_rule_ids": list(self.matched_rule_ids),
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "policy_type": m.policy_type,
                    "action": m.action,
                    "matched": m.matched,
                    "score": m.score,
                }
                for m in self.matches
            ],
        }


@dataclass(frozen=True, slots=True)
class _Thresholds:
    sanitize_at: int
    escalate_at: int
    block_at: int


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    policy_type: PolicyType
    enabled: bool
    description: str
    action: Decision
    score: int | None
    keywords: tuple[str, ...]
    phrases: tuple[tuple[str, ...], ...]
    thresholds: _Thresholds | None


_ACTION_PRECEDENCE: dict[Decision, int] = {
    "allow": 0,
    "sanitize": 1,
    "escalate": 2,
    "block": 3,
}


class PolicyEngine:
    def __init__(self, rules_path: str | Path):
        self._rules_path = Path(rules_path)
        raw = self._load_json(self._rules_path)
        self._raw_rules_by_id: dict[str, dict[str, Any]] = {}
        self._rules_by_id: dict[str, _Rule] = {}
        self._thresholds: _Thresholds = self._parse_config(raw)

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        if rule_id not in self._raw_rules_by_id:
            raise KeyError(f"Unknown rule_id: {rule_id}")
        return dict(self._raw_rules_by_id[rule_id])

    def evaluate(self, text: str) -> PolicyResult:
        tokens = self._tokenize(text)

        matches: list[PolicyMatch] = []
        risk_score = 0

        for rule_id, rule in self._rules_by_id.items():
            if not rule.enabled:
                continue
            if rule.policy_type == "escalation_threshold":
                continue

            rule_matches = self._match_rule(rule, tokens)
            if not rule_matches:
                continue

            score = rule.score
            if score is None:
                raise PolicyConfigError(
                    f"Rule {rule_id} missing required 'score' (policy_type={rule.policy_type})"
                )

            risk_score += score * len(rule_matches)
            for matched in rule_matches:
                matches.append(
                    PolicyMatch(
                        rule_id=rule_id,
                        policy_type=rule.policy_type,
                        action=rule.action,
                        matched=matched,
                        score=score,
                    )
                )

        threshold_decision = self._decision_from_thresholds(risk_score)
        decision = threshold_decision
        for m in matches:
            if _ACTION_PRECEDENCE[m.action] > _ACTION_PRECEDENCE[decision]:
                decision = m.action

        matched_rule_ids = tuple(sorted({m.rule_id for m in matches}))
        matches_sorted = tuple(sorted(matches, key=lambda m: (m.rule_id, m.matched)))

        return PolicyResult(
            decision=decision,
            risk_score=risk_score,
            matched_rule_ids=matched_rule_ids,
            matches=matches_sorted,
        )

    def _load_json(self, path: Path) -> dict[str, Any]:
        try:
            data = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise PolicyConfigError(f"Policy config file not found: {path}") from exc

        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise PolicyConfigError(f"Invalid JSON in policy config: {path}: {exc}") from exc

        if not isinstance(parsed, dict):
            raise PolicyConfigError("Policy config must be a JSON object")
        return parsed

    def _parse_config(self, raw: dict[str, Any]) -> _Thresholds:
        version = raw.get("version")
        if not isinstance(version, int):
            raise PolicyConfigError("Policy config missing required int field: version")

        rules_obj = raw.get("rules")
        if not isinstance(rules_obj, dict) or not rules_obj:
            raise PolicyConfigError("Policy config missing required object field: rules")

        thresholds_rule_ids: list[str] = []

        for rule_id, rule_raw in rules_obj.items():
            if not isinstance(rule_id, str) or not rule_id:
                raise PolicyConfigError("Rule IDs must be non-empty strings")
            if not isinstance(rule_raw, dict):
                raise PolicyConfigError(f"Rule {rule_id} must be a JSON object")

            parsed_rule = self._parse_rule(rule_id, rule_raw)

            self._raw_rules_by_id[rule_id] = dict(rule_raw)
            self._rules_by_id[rule_id] = parsed_rule

            if parsed_rule.policy_type == "escalation_threshold" and parsed_rule.enabled:
                thresholds_rule_ids.append(rule_id)

        if len(thresholds_rule_ids) != 1:
            raise PolicyConfigError(
                "Exactly one enabled escalation_threshold rule is required; found "
                f"{len(thresholds_rule_ids)}: {thresholds_rule_ids}"
            )

        threshold_rule = self._rules_by_id[thresholds_rule_ids[0]]
        if threshold_rule.thresholds is None:
            raise PolicyConfigError("Enabled escalation_threshold rule is missing thresholds")

        return threshold_rule.thresholds

    def _parse_rule(self, rule_id: str, rule_raw: dict[str, Any]) -> _Rule:
        rid = rule_raw.get("id")
        if rid != rule_id:
            raise PolicyConfigError(f"Rule {rule_id} must include id matching its key")

        policy_type = rule_raw.get("policy_type")
        if policy_type not in (
            "allowed_behavior",
            "restricted_action",
            "sensitive_topic",
            "escalation_threshold",
        ):
            raise PolicyConfigError(f"Rule {rule_id} has invalid policy_type: {policy_type}")

        enabled = rule_raw.get("enabled")
        if not isinstance(enabled, bool):
            raise PolicyConfigError(f"Rule {rule_id} missing required bool field: enabled")

        description = rule_raw.get("description")
        if not isinstance(description, str) or not description.strip():
            raise PolicyConfigError(f"Rule {rule_id} missing required string field: description")

        action = rule_raw.get("action")
        if action not in ("allow", "block", "sanitize", "escalate"):
            raise PolicyConfigError(f"Rule {rule_id} has invalid action: {action}")

        score = rule_raw.get("score")
        if policy_type == "escalation_threshold":
            if score is not None:
                raise PolicyConfigError(f"Rule {rule_id} (escalation_threshold) must not include score")
        else:
            if not isinstance(score, int):
                raise PolicyConfigError(f"Rule {rule_id} missing required int field: score")
            if score < 0:
                raise PolicyConfigError(f"Rule {rule_id} score must be non-negative")

        keywords: tuple[str, ...] = ()
        phrases: tuple[tuple[str, ...], ...] = ()
        thresholds: _Thresholds | None = None

        if policy_type == "escalation_threshold":
            if action != "allow":
                raise PolicyConfigError(
                    f"Rule {rule_id} (escalation_threshold) action must be 'allow'"
                )
            thresholds_obj = rule_raw.get("thresholds")
            if not isinstance(thresholds_obj, dict):
                raise PolicyConfigError(f"Rule {rule_id} missing required object field: thresholds")

            sanitize_at = thresholds_obj.get("sanitize_at")
            escalate_at = thresholds_obj.get("escalate_at")
            block_at = thresholds_obj.get("block_at")

            if not all(isinstance(x, int) for x in (sanitize_at, escalate_at, block_at)):
                raise PolicyConfigError(
                    f"Rule {rule_id} thresholds must be ints: sanitize_at/escalate_at/block_at"
                )
            if sanitize_at < 0 or escalate_at < 0 or block_at < 0:
                raise PolicyConfigError(f"Rule {rule_id} thresholds must be non-negative")
            if not (sanitize_at <= escalate_at <= block_at):
                raise PolicyConfigError(
                    f"Rule {rule_id} thresholds must satisfy sanitize_at <= escalate_at <= block_at"
                )

            thresholds = _Thresholds(
                sanitize_at=sanitize_at,
                escalate_at=escalate_at,
                block_at=block_at,
            )
        else:
            match_obj = rule_raw.get("match")
            if not isinstance(match_obj, dict):
                raise PolicyConfigError(f"Rule {rule_id} missing required object field: match")

            keywords_raw = match_obj.get("keywords")
            phrases_raw = match_obj.get("phrases")

            if keywords_raw is not None:
                if not isinstance(keywords_raw, list) or not keywords_raw:
                    raise PolicyConfigError(f"Rule {rule_id} match.keywords must be a non-empty list")
                if not all(isinstance(k, str) and k.strip() for k in keywords_raw):
                    raise PolicyConfigError(f"Rule {rule_id} match.keywords must contain non-empty strings")
                keywords = tuple(self._normalize_token(k) for k in keywords_raw)

            if phrases_raw is not None:
                if not isinstance(phrases_raw, list) or not phrases_raw:
                    raise PolicyConfigError(f"Rule {rule_id} match.phrases must be a non-empty list")
                if not all(isinstance(p, str) and p.strip() for p in phrases_raw):
                    raise PolicyConfigError(f"Rule {rule_id} match.phrases must contain non-empty strings")
                phrase_tokens: list[tuple[str, ...]] = []
                for p in phrases_raw:
                    toks = tuple(self._tokenize(p))
                    if not toks:
                        raise PolicyConfigError(f"Rule {rule_id} has an empty phrase after normalization: {p!r}")
                    phrase_tokens.append(toks)
                phrases = tuple(phrase_tokens)

            if not keywords and not phrases:
                raise PolicyConfigError(
                    f"Rule {rule_id} match must include at least one of keywords or phrases"
                )

        return _Rule(
            rule_id=rule_id,
            policy_type=policy_type,
            enabled=enabled,
            description=description,
            action=action,
            score=score,
            keywords=keywords,
            phrases=phrases,
            thresholds=thresholds,
        )

    def _decision_from_thresholds(self, risk_score: int) -> Decision:
        if risk_score >= self._thresholds.block_at:
            return "block"
        if risk_score >= self._thresholds.escalate_at:
            return "escalate"
        if risk_score >= self._thresholds.sanitize_at:
            return "sanitize"
        return "allow"

    def _normalize_text(self, text: str) -> str:
        normalized = unicodedata.normalize("NFKC", text).casefold()

        # Deterministic, non-regex punctuation handling.
        punctuation_chars = set(string.punctuation)
        punctuation_chars.update({
            "“",
            "”",
            "‘",
            "’",
            "—",
            "–",
            "…",
        })
        trans = {ord(ch): " " for ch in punctuation_chars}
        return normalized.translate(trans)

    def _tokenize(self, text: str) -> list[str]:
        normalized = self._normalize_text(text)
        tokens = [t for t in normalized.split() if t]
        return tokens

    def _normalize_token(self, token: str) -> str:
        toks = self._tokenize(token)
        if len(toks) != 1:
            raise PolicyConfigError(f"Keyword must normalize to a single token: {token!r}")
        return toks[0]

    def _match_rule(self, rule: _Rule, tokens: list[str]) -> list[str]:
        matched: list[str] = []

        if rule.keywords:
            token_set = set(tokens)
            for kw in rule.keywords:
                if kw in token_set:
                    matched.append(kw)

        if rule.phrases:
            for phrase in rule.phrases:
                if self._contains_phrase(tokens, phrase):
                    matched.append(" ".join(phrase))

        return matched

    def _contains_phrase(self, tokens: list[str], phrase_tokens: tuple[str, ...]) -> bool:
        if not phrase_tokens:
            return False
        if len(phrase_tokens) > len(tokens):
            return False

        window = len(phrase_tokens)
        for start in range(0, len(tokens) - window + 1):
            if tuple(tokens[start : start + window]) == phrase_tokens:
                return True
        return False
