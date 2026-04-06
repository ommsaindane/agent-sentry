from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class TraceLogger:
    logger: logging.Logger

    def event(self, name: str, **fields: Any) -> None:
        """Emit one JSON object per line.

        Logging must never affect execution: this method is intentionally non-throwing.
        """
        try:
            payload: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": name,
            }
            for k, v in fields.items():
                payload[k] = v

            msg = _stable_json(payload)
            self.logger.info(msg)
        except Exception as exc:
            # Last-resort, must not raise.
            try:
                fallback = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "event": "trace.logging_error",
                    "original_event": str(name),
                    "error": str(exc),
                }
                self.logger.info(_stable_json(fallback))
            except Exception:
                try:
                    self.logger.info('{"event":"trace.logging_error"}')
                except Exception:
                    pass


def stable_terms(terms: list[str]) -> list[str]:
    """Deterministically clean, de-dupe (case-insensitive), and order terms.

    Ordering: longer terms first, then lexicographic by casefold.
    """
    best_by_key: dict[str, str] = {}
    for t in terms:
        if not isinstance(t, str):
            continue
        s = t.strip()
        if not s:
            continue
        key = s.casefold()
        prev = best_by_key.get(key)
        if prev is None or len(s) > len(prev):
            best_by_key[key] = s

    return sorted(best_by_key.values(), key=lambda x: (-len(x), x.casefold()))


def mask_terms_case_insensitive(text: str, terms: list[str], *, replacement: str = "[REDACTED]") -> str:
    if not isinstance(text, str) or not text:
        return text

    masked = text
    for term in stable_terms(terms):
        masked = _replace_case_insensitive(masked, term, replacement)
    return masked


def _replace_case_insensitive(text: str, term: str, replacement: str) -> str:
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


def _stable_json(obj: dict[str, Any]) -> str:
    # Deterministic, compact JSON.
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def get_trace_logger(name: str = "agentsentry") -> TraceLogger:
    logger = logging.getLogger(name)

    level_name = str(os.getenv("LOG_LEVEL") or "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)
    if not isinstance(level, int):
        level = logging.INFO
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    logger.propagate = False
    return TraceLogger(logger=logger)
