from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel


class LlmClientError(RuntimeError):
    pass


class LlmClient(Protocol):
    def classify_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema_model: type[BaseModel],
    ) -> dict[str, Any]:
        """Return a JSON object that should validate against schema_model."""


@dataclass(frozen=True, slots=True)
class OpenAIClient(LlmClient):
    api_key: str
    model: str

    @classmethod
    def from_env(cls) -> "OpenAIClient":
        api_key = os.getenv("OPENAI_API_KEY")
        model = os.getenv("OPENAI_MODEL")

        if not api_key:
            raise LlmClientError("Missing required env var: OPENAI_API_KEY")
        if not model:
            raise LlmClientError("Missing required env var: OPENAI_MODEL")

        return cls(api_key=api_key, model=model)

    def classify_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema_model: type[BaseModel],
    ) -> dict[str, Any]:
        try:
            from openai import OpenAI  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise LlmClientError(
                "OpenAI python package is required. Install `openai`."
            ) from exc

        client = OpenAI(api_key=self.api_key)

        try:
            response = client.responses.parse(
                model=self.model,
                temperature=0,
                input=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                text_format=schema_model,
            )
        except Exception as exc:
            raise LlmClientError(f"OpenAI request failed: {exc}") from exc

        parsed = getattr(response, "output_parsed", None)
        if parsed is None:
            raise LlmClientError("OpenAI response missing parsed structured output")

        if not isinstance(parsed, BaseModel):
            raise LlmClientError("OpenAI parsed output did not match expected schema")

        return parsed.model_dump()
