from __future__ import annotations

import json
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

        # Pydantic v2 schema. The OpenAI API expects a JSON Schema object.
        json_schema = schema_model.model_json_schema()

        try:
            response = client.responses.create(
                model=self.model,
                temperature=0,
                input=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": schema_model.__name__,
                        "schema": json_schema,
                        "strict": True,
                    },
                },
            )
        except Exception as exc:
            raise LlmClientError(f"OpenAI request failed: {exc}") from exc

        # The OpenAI SDK returns structured output text; enforce strict JSON parse.
        try:
            output_text = response.output_text
        except Exception as exc:
            raise LlmClientError("OpenAI response missing output_text") from exc

        try:
            parsed = json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise LlmClientError(f"Model did not return valid JSON: {exc}") from exc

        if not isinstance(parsed, dict):
            raise LlmClientError("Model JSON output must be an object")

        return parsed
