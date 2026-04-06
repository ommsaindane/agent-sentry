from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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


def _get_env_float(name: str, *, default: float | None = None) -> float:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        if default is None:
            raise SettingsError(f"Missing required env var: {name}")
        return float(default)
    try:
        return float(str(raw).strip())
    except Exception as exc:
        raise SettingsError(f"Env var {name} must be a float") from exc


@dataclass(frozen=True, slots=True)
class Settings:
    # LLM settings
    openai_api_key: str
    openai_model: str

    # HITL settings
    enable_hitl: bool
    risk_threshold: float
    sqlite_path: str
    sqlite_table: str

    @classmethod
    def from_env(cls) -> "Settings":
        # Fail fast: these are non-negotiable per project rules.
        openai_api_key = _require_env("OPENAI_API_KEY")
        openai_model = _require_env("OPENAI_MODEL")

        enable_hitl = _get_env_bool("ENABLE_HITL", default=True)

        # HITL is optional, but if enabled it must be fully configured.
        if enable_hitl:
            sqlite_path = _require_env("HITL_SQLITE_PATH")
            _validate_hitl_sqlite_path(sqlite_path)
            risk_threshold = _get_env_float("RISK_THRESHOLD")
            if risk_threshold < 0.0 or risk_threshold > 1.0:
                raise SettingsError("RISK_THRESHOLD must be in [0,1]")
        else:
            sqlite_path = os.getenv("HITL_SQLITE_PATH") or ""
            # Risk threshold unused when HITL disabled; keep deterministic value.
            risk_threshold = _get_env_float("RISK_THRESHOLD", default=1.0)

        sqlite_table = os.getenv("HITL_SQLITE_TABLE")
        if sqlite_table is None or not str(sqlite_table).strip():
            sqlite_table = "hitl_queue"

        return cls(
            openai_api_key=openai_api_key,
            openai_model=openai_model,
            enable_hitl=enable_hitl,
            risk_threshold=float(risk_threshold),
            sqlite_path=str(sqlite_path),
            sqlite_table=str(sqlite_table),
        )


def _validate_hitl_sqlite_path(sqlite_path: str) -> None:
    """Require HITL SQLite files to live in a dedicated folder (not repo root).

    This avoids creating `hitl*.db` in the project root by accident.
    """

    p = str(sqlite_path or "").strip()
    if not p:
        raise SettingsError("HITL_SQLITE_PATH is required")

    # Allow in-memory databases explicitly.
    if p == ":memory:":
        return

    path = Path(p)

    # Absolute paths are allowed (caller controls location).
    if path.is_absolute():
        return

    # For relative paths, enforce a directory component.
    # Examples that should FAIL: "hitl.db", "./hitl.db"
    # Examples that should PASS: "data/hitl.db", "./data/hitl.db"
    if path.parent == Path("."):
        raise SettingsError(
            "HITL_SQLITE_PATH must include a directory (not project root). "
            "Example: ./data/hitl.db"
        )
