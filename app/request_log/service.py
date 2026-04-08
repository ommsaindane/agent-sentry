from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.config import Settings
from app.hitl.db import HitlDbError, SqliteConnector


class RequestLogServiceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RequestLogListItem:
    request_id: str
    created_at: str
    decision: str
    status: str
    risk_score: float
    policy_risk_score: float
    queue_id: int | None


@dataclass(frozen=True, slots=True)
class RequestLogItem(RequestLogListItem):
    input_raw: str
    input_sanitized: str
    output_text: str | None
    guard_obj: dict[str, Any]
    policy_obj: dict[str, Any]
    agent_obj: dict[str, Any]
    output_obj: dict[str, Any] | None


@dataclass(frozen=True, slots=True)
class RequestLogService:
    settings: Settings
    connector: SqliteConnector

    @classmethod
    def from_settings(cls, settings: Settings) -> "RequestLogService":
        return cls(settings=settings, connector=SqliteConnector(settings=settings))

    async def ensure_schema(self) -> None:
        table = self.settings.request_log_table

        ddl = f"""
CREATE TABLE IF NOT EXISTS {table} (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  decision TEXT NOT NULL,
  status TEXT NOT NULL,
  risk_score REAL NOT NULL,
  policy_risk_score REAL NOT NULL,
  queue_id INTEGER,
  input_raw TEXT NOT NULL,
  input_sanitized TEXT NOT NULL,
  output_text TEXT,
  guard_json TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  agent_json TEXT NOT NULL,
  output_json TEXT
);
""".strip()

        idx1 = f"CREATE INDEX IF NOT EXISTS idx_{table}_created_at ON {table}(created_at);"
        idx2 = f"CREATE INDEX IF NOT EXISTS idx_{table}_decision ON {table}(decision);"
        idx3 = f"CREATE INDEX IF NOT EXISTS idx_{table}_status ON {table}(status);"

        try:
            conn = await self.connector.connect()
            try:
                await conn.execute(ddl)
                await conn.execute(idx1)
                await conn.execute(idx2)
                await conn.execute(idx3)
                await conn.commit()
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise RequestLogServiceError(str(exc)) from exc
        except Exception as exc:
            raise RequestLogServiceError(f"Failed to ensure request log schema: {exc}") from exc

    async def record(
        self,
        *,
        request_id: str,
        decision: str,
        status: str,
        created_at: str,
        risk_score: float,
        policy_risk_score: float,
        queue_id: int | None,
        input_raw: str,
        input_sanitized: str,
        output_text: str | None,
        guard_obj: dict[str, Any],
        policy_obj: dict[str, Any],
        agent_obj: dict[str, Any],
        output_obj: dict[str, Any] | None,
    ) -> None:
        if not request_id or not str(request_id).strip():
            raise RequestLogServiceError("request_id is required")
        if not isinstance(created_at, str) or not created_at.strip():
            raise RequestLogServiceError("created_at is required")

        table = self.settings.request_log_table

        sql = (
            f"INSERT INTO {table} "
            "(request_id, created_at, decision, status, risk_score, policy_risk_score, queue_id, "
            "input_raw, input_sanitized, output_text, guard_json, policy_json, agent_json, output_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )

        try:
            conn = await self.connector.connect()
            try:
                await conn.execute(
                    sql,
                    (
                        str(request_id),
                        str(created_at),
                        str(decision),
                        str(status),
                        float(risk_score),
                        float(policy_risk_score),
                        (int(queue_id) if queue_id is not None else None),
                        str(input_raw),
                        str(input_sanitized),
                        (str(output_text) if output_text is not None else None),
                        json.dumps(guard_obj, sort_keys=True, ensure_ascii=False),
                        json.dumps(policy_obj, sort_keys=True, ensure_ascii=False),
                        json.dumps(agent_obj, sort_keys=True, ensure_ascii=False),
                        (json.dumps(output_obj, sort_keys=True, ensure_ascii=False) if output_obj is not None else None),
                    ),
                )
                await conn.commit()
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise RequestLogServiceError(str(exc)) from exc
        except Exception as exc:
            raise RequestLogServiceError(f"Failed to record request log row: {exc}") from exc

    async def update_status_by_request_id(self, *, request_id: str, status: str) -> None:
        if not request_id or not str(request_id).strip():
            raise RequestLogServiceError("request_id is required")
        if not isinstance(status, str) or not status.strip():
            raise RequestLogServiceError("status is required")

        table = self.settings.request_log_table
        sql = f"UPDATE {table} SET status = ? WHERE request_id = ?"

        try:
            conn = await self.connector.connect()
            try:
                cur = await conn.execute(sql, (str(status), str(request_id)))
                await conn.commit()
                rowcount = int(getattr(cur, "rowcount", 0) or 0)
                if rowcount <= 0:
                    raise RequestLogServiceError("No request log row updated (request_id not found)")
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise RequestLogServiceError(str(exc)) from exc
        except RequestLogServiceError:
            raise
        except Exception as exc:
            raise RequestLogServiceError(f"Failed to update request log status: {exc}") from exc

    async def list_requests(
        self,
        *,
        limit: int,
        offset: int,
        decision: str | None = None,
        status: str | None = None,
    ) -> list[RequestLogListItem]:
        if not isinstance(limit, int) or limit <= 0 or limit > 500:
            raise RequestLogServiceError("limit must be an integer in [1,500]")
        if not isinstance(offset, int) or offset < 0:
            raise RequestLogServiceError("offset must be a non-negative integer")

        table = self.settings.request_log_table

        where = []
        args: list[Any] = []
        if isinstance(decision, str) and decision.strip():
            where.append("decision = ?")
            args.append(str(decision))
        if isinstance(status, str) and status.strip():
            where.append("status = ?")
            args.append(str(status))

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""

        sql = (
            f"SELECT request_id, created_at, decision, status, risk_score, policy_risk_score, queue_id "
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
            raise RequestLogServiceError(str(exc)) from exc
        except Exception as exc:
            raise RequestLogServiceError(f"Failed to list request log rows: {exc}") from exc

        out: list[RequestLogListItem] = []
        for row in rows or []:
            (
                request_id,
                created_at,
                decision_v,
                status_v,
                risk_score,
                policy_risk_score,
                queue_id,
            ) = row
            out.append(
                RequestLogListItem(
                    request_id=str(request_id),
                    created_at=str(created_at),
                    decision=str(decision_v),
                    status=str(status_v),
                    risk_score=float(risk_score),
                    policy_risk_score=float(policy_risk_score),
                    queue_id=(int(queue_id) if queue_id is not None else None),
                )
            )
        return out

    async def get_request(self, *, request_id: str) -> RequestLogItem | None:
        if not request_id or not str(request_id).strip():
            raise RequestLogServiceError("request_id is required")

        table = self.settings.request_log_table
        sql = (
            f"SELECT request_id, created_at, decision, status, risk_score, policy_risk_score, queue_id, "
            "input_raw, input_sanitized, output_text, guard_json, policy_json, agent_json, output_json "
            f"FROM {table} WHERE request_id = ?"
        )

        try:
            conn = await self.connector.connect()
            try:
                cur = await conn.execute(sql, (str(request_id),))
                row = await cur.fetchone()
            finally:
                try:
                    await conn.close()
                except Exception:
                    pass
        except HitlDbError as exc:
            raise RequestLogServiceError(str(exc)) from exc
        except Exception as exc:
            raise RequestLogServiceError(f"Failed to fetch request log row: {exc}") from exc

        if row is None:
            return None

        try:
            (
                request_id_v,
                created_at,
                decision_v,
                status_v,
                risk_score,
                policy_risk_score,
                queue_id,
                input_raw,
                input_sanitized,
                output_text,
                guard_json,
                policy_json,
                agent_json,
                output_json,
            ) = row

            guard_obj = json.loads(str(guard_json))
            policy_obj = json.loads(str(policy_json))
            agent_obj = json.loads(str(agent_json))
            output_obj = json.loads(str(output_json)) if output_json is not None else None

            if not isinstance(guard_obj, dict) or not isinstance(policy_obj, dict) or not isinstance(agent_obj, dict):
                raise RequestLogServiceError("Stored JSON blobs must be objects")
            if output_obj is not None and not isinstance(output_obj, dict):
                raise RequestLogServiceError("output_json must be an object when present")

            return RequestLogItem(
                request_id=str(request_id_v),
                created_at=str(created_at),
                decision=str(decision_v),
                status=str(status_v),
                risk_score=float(risk_score),
                policy_risk_score=float(policy_risk_score),
                queue_id=(int(queue_id) if queue_id is not None else None),
                input_raw=str(input_raw),
                input_sanitized=str(input_sanitized),
                output_text=(str(output_text) if output_text is not None else None),
                guard_obj=guard_obj,
                policy_obj=policy_obj,
                agent_obj=agent_obj,
                output_obj=output_obj,
            )
        except RequestLogServiceError:
            raise
        except Exception as exc:
            raise RequestLogServiceError(f"Failed to parse request log row: {exc}") from exc
