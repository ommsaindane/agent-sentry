from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.config import Settings
from app.hitl.db import HitlDbError, MySqlConnector


class HitlServiceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HitlEnqueueResult:
    request_id: str
    queue_id: int


@dataclass(frozen=True, slots=True)
class HitlService:
    settings: Settings
    connector: MySqlConnector

    @classmethod
    def from_settings(cls, settings: Settings) -> "HitlService":
        return cls(settings=settings, connector=MySqlConnector(settings=settings))

    def ensure_schema(self) -> None:
        table = self.settings.mysql_table

        ddl = f"""
CREATE TABLE IF NOT EXISTS {table} (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  request_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decision VARCHAR(16) NOT NULL,
  input_raw TEXT NOT NULL,
  input_sanitized TEXT NOT NULL,
  guard_json LONGTEXT NOT NULL,
  policy_json LONGTEXT NOT NULL,
  agent_json LONGTEXT NOT NULL
)
""".strip()

        try:
            conn = self.connector.connect()
            try:
                cur = conn.cursor()
                cur.execute(ddl)
                conn.commit()
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise HitlServiceError(str(exc)) from exc
        except Exception as exc:
            raise HitlServiceError(f"Failed to ensure HITL schema: {exc}") from exc

    def enqueue(
        self,
        *,
        request_id: str,
        decision: str,
        input_raw: str,
        input_sanitized: str,
        guard_obj: dict[str, Any],
        policy_obj: dict[str, Any],
        agent_obj: dict[str, Any],
    ) -> HitlEnqueueResult:
        if not request_id or not str(request_id).strip():
            raise HitlServiceError("request_id is required")

        table = self.settings.mysql_table

        sql = (
            f"INSERT INTO {table} (request_id, decision, input_raw, input_sanitized, guard_json, policy_json, agent_json) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)"
        )

        try:
            conn = self.connector.connect()
            try:
                cur = conn.cursor()
                cur.execute(
                    sql,
                    (
                        str(request_id),
                        str(decision),
                        str(input_raw),
                        str(input_sanitized),
                        json.dumps(guard_obj, sort_keys=True, ensure_ascii=False),
                        json.dumps(policy_obj, sort_keys=True, ensure_ascii=False),
                        json.dumps(agent_obj, sort_keys=True, ensure_ascii=False),
                    ),
                )
                queue_id = int(getattr(cur, "lastrowid", 0) or 0)
                conn.commit()
                if queue_id <= 0:
                    raise HitlServiceError("Failed to retrieve HITL queue id")
                return HitlEnqueueResult(request_id=str(request_id), queue_id=queue_id)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise HitlServiceError(str(exc)) from exc
        except HitlServiceError:
            raise
        except Exception as exc:
            raise HitlServiceError(f"Failed to enqueue HITL request: {exc}") from exc
