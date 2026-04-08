from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx
from dotenv import load_dotenv


class ApiError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ApiConfig:
    base_url: str
    review_key: str

    @classmethod
    def from_env(cls) -> "ApiConfig":
        load_dotenv(override=False)

        base_url = os.getenv("AGENTSENTRY_API_URL")
        if base_url is None or not str(base_url).strip():
            raise ApiError("Missing required env var: AGENTSENTRY_API_URL")

        review_key = os.getenv("HITL_REVIEW_API_KEY")
        if review_key is None or not str(review_key).strip():
            raise ApiError("Missing required env var: HITL_REVIEW_API_KEY")

        return cls(base_url=str(base_url).rstrip("/"), review_key=str(review_key))


def _client(cfg: ApiConfig) -> httpx.Client:
    return httpx.Client(
        base_url=cfg.base_url,
        timeout=httpx.Timeout(10.0, connect=5.0),
        headers={"X-HITL-REVIEW-KEY": cfg.review_key},
    )


def _client_no_auth(cfg: ApiConfig) -> httpx.Client:
    return httpx.Client(
        base_url=cfg.base_url,
        timeout=httpx.Timeout(30.0, connect=5.0),
    )


def send_chat(*, cfg: ApiConfig, message: str, max_output_tokens: int) -> dict[str, Any]:
    payload = {"message": str(message), "max_output_tokens": int(max_output_tokens)}

    with _client_no_auth(cfg) as c:
        r = c.post("/chat", json=payload)
        if r.status_code not in {200, 202, 403}:
            raise ApiError(f"POST /chat failed: {r.status_code} {r.text}")
        data = r.json()
        if not isinstance(data, dict):
            raise ApiError("POST /chat returned invalid payload")
        return {"status_code": int(r.status_code), "body": data}


def list_requests(*, cfg: ApiConfig, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    with _client(cfg) as c:
        r = c.get("/requests", params={"limit": int(limit), "offset": int(offset)})
        if r.status_code != 200:
            raise ApiError(f"GET /requests failed: {r.status_code} {r.text}")
        data = r.json()
        items = data.get("items")
        if not isinstance(items, list):
            raise ApiError("GET /requests returned invalid payload")
        return items


def get_request(*, cfg: ApiConfig, request_id: str) -> dict[str, Any]:
    with _client(cfg) as c:
        r = c.get(f"/requests/{request_id}")
        if r.status_code == 404:
            raise ApiError("Request not found")
        if r.status_code != 200:
            raise ApiError(f"GET /requests/{{id}} failed: {r.status_code} {r.text}")
        data = r.json()
        if not isinstance(data, dict):
            raise ApiError("GET /requests/{id} returned invalid payload")
        return data


def list_hitl_queue(
    *,
    cfg: ApiConfig,
    status: str = "pending_review",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    with _client(cfg) as c:
        r = c.get(
            "/hitl/queue",
            params={"status": str(status), "limit": int(limit), "offset": int(offset)},
        )
        if r.status_code != 200:
            raise ApiError(f"GET /hitl/queue failed: {r.status_code} {r.text}")
        data = r.json()
        items = data.get("items")
        if not isinstance(items, list):
            raise ApiError("GET /hitl/queue returned invalid payload")
        return items


def get_hitl_item(*, cfg: ApiConfig, queue_id: int) -> dict[str, Any]:
    with _client(cfg) as c:
        r = c.get(f"/hitl/queue/{int(queue_id)}")
        if r.status_code == 404:
            raise ApiError("Queue item not found")
        if r.status_code != 200:
            raise ApiError(f"GET /hitl/queue/{{id}} failed: {r.status_code} {r.text}")
        data = r.json()
        if not isinstance(data, dict):
            raise ApiError("GET /hitl/queue/{id} returned invalid payload")
        return data


def resolve_hitl(
    *,
    cfg: ApiConfig,
    queue_id: int,
    action: str,
    note: str | None,
    max_output_tokens: int | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"queue_id": int(queue_id), "action": str(action)}
    if isinstance(note, str) and note.strip():
        payload["note"] = str(note)
    if max_output_tokens is not None:
        payload["max_output_tokens"] = int(max_output_tokens)

    with _client(cfg) as c:
        r = c.post("/hitl/resolve", json=payload)
        if r.status_code != 200:
            raise ApiError(f"POST /hitl/resolve failed: {r.status_code} {r.text}")
        data = r.json()
        if not isinstance(data, dict):
            raise ApiError("POST /hitl/resolve returned invalid payload")
        return data
