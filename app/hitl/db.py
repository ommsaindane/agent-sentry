from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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

        sqlite_path = str(self.settings.sqlite_path).strip()
        if sqlite_path != ":memory:":
            try:
                p = Path(sqlite_path)
                parent = p.parent
                if parent and parent != Path("."):
                    parent.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                raise HitlDbError(f"Failed to create SQLite directory: {exc}") from exc

        try:
            return await aiosqlite.connect(sqlite_path)
        except Exception as exc:
            raise HitlDbError(f"Failed to connect to SQLite: {exc}") from exc
