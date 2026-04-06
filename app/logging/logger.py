from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class TraceLogger:
    logger: logging.Logger

    def event(self, name: str, **fields: Any) -> None:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": name,
        }
        for k, v in fields.items():
            payload[k] = v

        # Deterministic JSON serialization.
        msg = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.logger.info(msg)


def get_trace_logger(name: str = "agentsentry") -> TraceLogger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    logger.propagate = False
    return TraceLogger(logger=logger)
