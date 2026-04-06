from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings


class HitlDbError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SqliteConnector:
    settings: Settings

    async def connect(self):
        try:
            import aiosqlite  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise HitlDbError("SQLite driver is required. Install `aiosqlite`.") from exc

        if not self.settings.sqlite_path or not str(self.settings.sqlite_path).strip():
            raise HitlDbError("Missing SQLite path for HITL (HITL_SQLITE_PATH)")

        try:
            return await aiosqlite.connect(self.settings.sqlite_path)
        except Exception as exc:
            raise HitlDbError(f"Failed to connect to SQLite: {exc}") from exc
