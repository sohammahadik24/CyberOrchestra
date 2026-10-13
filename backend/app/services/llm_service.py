"""Reusable, configurable service for an OpenAI-compatible cloud LLM endpoint."""

import json
import time
from typing import Any, Dict, Optional, Type

import httpx
from pydantic import BaseModel

from app.core.config import settings


class LLMServiceError(Exception):
    """Base error for LLM configuration, transport, or response failures."""


class LLMConfigurationError(LLMServiceError):
    pass


class LLMConnectionError(LLMServiceError):
    pass


class LLMResponseError(LLMServiceError):
    pass


class LLMService:
    """Small synchronous adapter; provider/model/key are supplied by environment config."""

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.provider = provider if provider is not None else settings.LLM_PROVIDER
        self.model = model if model is not None else settings.LLM_MODEL
        self.api_key = api_key if api_key is not None else settings.LLM_API_KEY
        self.base_url = base_url if base_url is not None else settings.LLM_BASE_URL
        self.timeout = timeout if timeout is not None else settings.LLM_TIMEOUT_SECONDS
        self.transport = transport

    @staticmethod
    def _make_groq_schema_strict(schema: Dict[str, Any]) -> None:
        """Normalize Pydantic JSON Schema for Groq strict structured outputs."""
        def normalize(node: Any) -> None:
            if not isinstance(node, dict):
                return
            properties = node.get("properties")
            if isinstance(properties, dict):
                node["additionalProperties"] = False
                node["required"] = list(properties)
                for child in properties.values():
                    normalize(child)
            for key in ("items", "additionalItems"):
                normalize(node.get(key))
            for key in ("$defs", "definitions"):
                definitions = node.get(key)
                if isinstance(definitions, dict):
                    for child in definitions.values():
                        normalize(child)
            for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
                variants = node.get(key)
                if isinstance(variants, list):
                    for child in variants:
                        normalize(child)
        normalize(schema)

    def generate(
        self,
        system_prompt: str,
        structured_input: Dict[str, Any],
        response_model: Type[BaseModel],
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> str:
        """Send structured JSON context and request a strict JSON-schema response."""
        active_provider = provider or self.provider
        active_model = model or self.model
        active_api_key = api_key or self.api_key
        active_base_url = base_url or self.base_url
        if not all((active_provider, active_model, active_api_key, active_base_url)):
            raise LLMConfigurationError(
                "LLM provider, model, API key, and base URL must be configured in environment settings."
            )
        # This protocol is deliberately isolated so other provider adapters can be added later.
        if active_provider.lower() not in {"openai_compatible", "openai-compatible", "groq"}:
            raise LLMConfigurationError(f"Unsupported configured LLM provider: {active_provider}")

        schema = response_model.model_json_schema()
        if active_provider.lower() == "groq":
            self._make_groq_schema_strict(schema)
        url = active_base_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url += "/chat/completions"
        body = {
            "model": active_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(structured_input, ensure_ascii=False)},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "threat_assessment", "strict": True, "schema": schema},
            },
        }
        max_retries = 5
        response = None
        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                    response = client.post(
                        url,
                        headers={"Authorization": f"Bearer {active_api_key}", "Content-Type": "application/json"},
                        json=body,
                    )
            except httpx.RequestError as err:
                if attempt == max_retries - 1:
                    raise LLMConnectionError(f"LLM request failed: {err}") from err
                time.sleep(1.0)
                continue

            if response.status_code == 429 and attempt < max_retries - 1:
                reset_str = response.headers.get("retry-after") or response.headers.get("x-ratelimit-reset-tokens")
                retry_wait = (attempt + 1) * 3.0
                if reset_str:
                    try:
                        clean_str = reset_str.rstrip("s").strip()
                        retry_wait = float(clean_str) + 0.5
                    except (ValueError, TypeError):
                        pass
                time.sleep(min(max(retry_wait, 2.0), 15.0))
                continue
            break

        if response is None:
            raise LLMConnectionError("LLM request produced no response.")
        if response.status_code < 200 or response.status_code >= 300:
            raise LLMResponseError(f"LLM endpoint returned HTTP {response.status_code}: {response.text}")
        try:
            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as err:
            raise LLMResponseError("LLM endpoint returned a malformed chat completion.") from err
        if not isinstance(content, str):
            raise LLMResponseError("LLM endpoint did not return a JSON string response.")
        return content


llm_service = LLMService()
