from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import Settings


class HitlDbError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class MySqlConnector:
    settings: Settings

    def connect(self) -> Any:
        try:
            import mysql.connector  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise HitlDbError(
                "MySQL driver is required. Install `mysql-connector-python`."
            ) from exc

        try:
            return mysql.connector.connect(
                host=self.settings.mysql_host,
                port=self.settings.mysql_port,
                user=self.settings.mysql_user,
                password=self.settings.mysql_password,
                database=self.settings.mysql_database,
                autocommit=False,
            )
        except Exception as exc:
            raise HitlDbError(f"Failed to connect to MySQL: {exc}") from exc
