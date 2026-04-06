from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.config import Settings
from app.hitl.db import HitlDbError, SqliteConnector


class HitlServiceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HitlEnqueueResult:
    request_id: str
    queue_id: int


@dataclass(frozen=True, slots=True)
class HitlService:
    settings: Settings
    connector: SqliteConnector

    @classmethod
    def from_settings(cls, settings: Settings) -> "HitlService":
        return cls(settings=settings, connector=SqliteConnector(settings=settings))

    async def ensure_schema(self) -> None:
        table = self.settings.sqlite_table

        ddl = f"""
CREATE TABLE IF NOT EXISTS {table} (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  risk_score REAL NOT NULL,
  decision TEXT NOT NULL,
  status TEXT NOT NULL,
  input_raw TEXT NOT NULL,
  input_sanitized TEXT NOT NULL,
  guard_json TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  agent_json TEXT NOT NULL,
  review_note TEXT,
  reviewed_at TEXT
);
""".strip()

        idx = f"CREATE INDEX IF NOT EXISTS idx_{table}_status ON {table}(status);"

        try:
            conn = await self.connector.connect()
            try:
                await conn.execute(ddl)
                await conn.execute(idx)
                await conn.commit()
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise HitlServiceError(str(exc)) from exc
        except Exception as exc:
            raise HitlServiceError(f"Failed to ensure HITL schema: {exc}") from exc

    async def enqueue(
        self,
        *,
        request_id: str,
        decision: str,
        input_raw: str,
        input_sanitized: str,
        risk_score: float,
        guard_obj: dict[str, Any],
        policy_obj: dict[str, Any],
        agent_obj: dict[str, Any],
    ) -> HitlEnqueueResult:
        if not request_id or not str(request_id).strip():
            raise HitlServiceError("request_id is required")

        table = self.settings.sqlite_table

        if not isinstance(risk_score, (int, float)):
            raise HitlServiceError("risk_score must be a number")

        sql = (
            f"INSERT INTO {table} "
            "(request_id, created_at, risk_score, decision, status, input_raw, input_sanitized, guard_json, policy_json, agent_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        from datetime import datetime, timezone

        created_at = datetime.now(timezone.utc).isoformat()

        try:
            conn = await self.connector.connect()
            try:
                cur = await conn.execute(
                    sql,
                    (
                        str(request_id),
                        created_at,
                        float(risk_score),
                        str(decision),
                        "pending_review",
                        str(input_raw),
                        str(input_sanitized),
                        json.dumps(guard_obj, sort_keys=True, ensure_ascii=False),
                        json.dumps(policy_obj, sort_keys=True, ensure_ascii=False),
                        json.dumps(agent_obj, sort_keys=True, ensure_ascii=False),
                    ),
                )
                await conn.commit()

                queue_id = int(getattr(cur, "lastrowid", 0) or 0)
                if queue_id <= 0:
                    raise HitlServiceError("Failed to retrieve HITL queue id")
                return HitlEnqueueResult(request_id=str(request_id), queue_id=queue_id)
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise HitlServiceError(str(exc)) from exc
        except HitlServiceError:
            raise
        except Exception as exc:
            raise HitlServiceError(f"Failed to enqueue HITL request: {exc}") from exc
