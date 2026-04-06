from __future__ import annotations

import os
from dataclasses import dataclass


class SettingsError(RuntimeError):
    pass


def _require_env(name: str) -> str:
    val = os.getenv(name)
    if val is None or not str(val).strip():
        raise SettingsError(f"Missing required env var: {name}")
    return str(val)


def _get_env_int(name: str, *, default: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        if default is None:
            raise SettingsError(f"Missing required env var: {name}")
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception as exc:
        raise SettingsError(f"Env var {name} must be an integer") from exc


def _get_env_bool(name: str, *, default: bool | None = None) -> bool:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        if default is None:
            raise SettingsError(f"Missing required env var: {name}")
        return bool(default)

    v = str(raw).strip().casefold()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False

    raise SettingsError(f"Env var {name} must be a boolean (true/false)")


@dataclass(frozen=True, slots=True)
class Settings:
    # LLM settings
    openai_api_key: str
    openai_model: str

    # HITL settings
    enable_hitl: bool
    mysql_host: str
    mysql_port: int
    mysql_user: str
    mysql_password: str
    mysql_database: str
    mysql_table: str

    @classmethod
    def from_env(cls) -> "Settings":
        # Fail fast: these are non-negotiable per project rules.
        openai_api_key = _require_env("OPENAI_API_KEY")
        openai_model = _require_env("OPENAI_MODEL")

        enable_hitl = _get_env_bool("ENABLE_HITL", default=True)

        # HITL is optional, but if enabled it must be fully configured.
        if enable_hitl:
            mysql_host = _require_env("MYSQL_HOST")
            mysql_port = _get_env_int("MYSQL_PORT", default=3306)
            mysql_user = _require_env("MYSQL_USER")
            mysql_password = _require_env("MYSQL_PASSWORD")
            mysql_database = _require_env("MYSQL_DATABASE")
        else:
            mysql_host = ""
            mysql_port = _get_env_int("MYSQL_PORT", default=3306)
            mysql_user = ""
            mysql_password = ""
            mysql_database = ""
        mysql_table = os.getenv("MYSQL_HITL_TABLE")
        if mysql_table is None or not str(mysql_table).strip():
            mysql_table = "hitl_queue"

        return cls(
            openai_api_key=openai_api_key,
            openai_model=openai_model,
            enable_hitl=enable_hitl,
            mysql_host=mysql_host,
            mysql_port=mysql_port,
            mysql_user=mysql_user,
            mysql_password=mysql_password,
            mysql_database=mysql_database,
            mysql_table=str(mysql_table),
        )
