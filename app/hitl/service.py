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
class HitlQueueItem:
    queue_id: int
    request_id: str
    created_at: str
    risk_score: float
    decision: str
    status: str
    input_raw: str
    input_sanitized: str
    guard_obj: dict[str, Any]
    policy_obj: dict[str, Any]
    agent_obj: dict[str, Any]
    review_note: str | None
    reviewed_at: str | None


@dataclass(frozen=True, slots=True)
class HitlQueueListItem:
    queue_id: int
    request_id: str
    created_at: str
    risk_score: float
    decision: str
    status: str


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

    async def get_item(self, *, queue_id: int) -> HitlQueueItem | None:
        if not isinstance(queue_id, int) or queue_id <= 0:
            raise HitlServiceError("queue_id must be a positive integer")

        table = self.settings.sqlite_table
        sql = (
            f"SELECT id, request_id, created_at, risk_score, decision, status, "
            "input_raw, input_sanitized, guard_json, policy_json, agent_json, review_note, reviewed_at "
            f"FROM {table} WHERE id = ?"
        )

        try:
            conn = await self.connector.connect()
            try:
                cur = await conn.execute(sql, (int(queue_id),))
                row = await cur.fetchone()
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise HitlServiceError(str(exc)) from exc
        except Exception as exc:
            raise HitlServiceError(f"Failed to fetch HITL queue item: {exc}") from exc

        if row is None:
            return None

        try:
            (
                rid,
                request_id,
                created_at,
                risk_score,
                decision,
                status,
                input_raw,
                input_sanitized,
                guard_json,
                policy_json,
                agent_json,
                review_note,
                reviewed_at,
            ) = row

            guard_obj = json.loads(str(guard_json))
            policy_obj = json.loads(str(policy_json))
            agent_obj = json.loads(str(agent_json))
            if not isinstance(guard_obj, dict) or not isinstance(policy_obj, dict) or not isinstance(agent_obj, dict):
                raise HitlServiceError("HITL stored JSON blobs must be objects")

            return HitlQueueItem(
                queue_id=int(rid),
                request_id=str(request_id),
                created_at=str(created_at),
                risk_score=float(risk_score),
                decision=str(decision),
                status=str(status),
                input_raw=str(input_raw),
                input_sanitized=str(input_sanitized),
                guard_obj=guard_obj,
                policy_obj=policy_obj,
                agent_obj=agent_obj,
                review_note=(str(review_note) if review_note is not None else None),
                reviewed_at=(str(reviewed_at) if reviewed_at is not None else None),
            )
        except HitlServiceError:
            raise
        except Exception as exc:
            raise HitlServiceError(f"Failed to parse HITL queue item: {exc}") from exc

    async def list_items(
        self,
        *,
        status: str | None,
        limit: int,
        offset: int,
    ) -> list[HitlQueueListItem]:
        if not isinstance(limit, int) or limit <= 0 or limit > 500:
            raise HitlServiceError("limit must be an integer in [1,500]")
        if not isinstance(offset, int) or offset < 0:
            raise HitlServiceError("offset must be a non-negative integer")

        table = self.settings.sqlite_table

        where_sql = ""
        args: list[Any] = []
        if isinstance(status, str) and status.strip():
            where_sql = " WHERE status = ?"
            args.append(str(status))

        sql = (
            f"SELECT id, request_id, created_at, risk_score, decision, status "
            f"FROM {table}{where_sql} "
            "ORDER BY created_at DESC "
            "LIMIT ? OFFSET ?"
        )
        args.extend([int(limit), int(offset)])

        try:
            conn = await self.connector.connect()
            try:
                cur = await conn.execute(sql, tuple(args))
                rows = await cur.fetchall()
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise HitlServiceError(str(exc)) from exc
        except Exception as exc:
            raise HitlServiceError(f"Failed to list HITL queue items: {exc}") from exc

        out: list[HitlQueueListItem] = []
        for row in rows or []:
            rid, request_id, created_at, risk_score, decision, status_v = row
            out.append(
                HitlQueueListItem(
                    queue_id=int(rid),
                    request_id=str(request_id),
                    created_at=str(created_at),
                    risk_score=float(risk_score),
                    decision=str(decision),
                    status=str(status_v),
                )
            )
        return out

    async def mark_reviewed(
        self,
        *,
        queue_id: int,
        status: str,
        review_note: str | None,
    ) -> None:
        if not isinstance(queue_id, int) or queue_id <= 0:
            raise HitlServiceError("queue_id must be a positive integer")
        if not isinstance(status, str) or not status.strip():
            raise HitlServiceError("status is required")

        table = self.settings.sqlite_table

        from datetime import datetime, timezone

        reviewed_at = datetime.now(timezone.utc).isoformat()

        sql = f"UPDATE {table} SET status = ?, review_note = ?, reviewed_at = ? WHERE id = ?"

        try:
            conn = await self.connector.connect()
            try:
                cur = await conn.execute(sql, (str(status), review_note, reviewed_at, int(queue_id)))
                await conn.commit()
                rowcount = int(getattr(cur, "rowcount", 0) or 0)
                if rowcount <= 0:
                    raise HitlServiceError("No HITL row updated (queue_id not found)")
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
            raise HitlServiceError(f"Failed to mark HITL item reviewed: {exc}") from exc
