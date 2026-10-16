"""Minimal OpenAI-compatible chat-completions client (ADR-0008). Works with OpenRouter.

Configured only by environment: LLM_BASE_URL, LLM_API_KEY, LLM_MODEL. No vendor SDK.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
RETRY_STATUSES = {408, 429, 500, 502, 503, 504}


class ConfigError(Exception):
    pass


class LLMError(Exception):
    pass


@dataclass(frozen=True)
class LLMConfig:
    api_key: str = field(repr=False)  # never shows up in logs or reprs
    model: str
    base_url: str = DEFAULT_BASE_URL

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> LLMConfig:
        e = os.environ if env is None else env
        key, model = e.get("LLM_API_KEY"), e.get("LLM_MODEL")
        if not key:
            raise ConfigError("LLM_API_KEY is not set")
        if not model:
            raise ConfigError("LLM_MODEL is not set")
        return cls(api_key=key, model=model, base_url=e.get("LLM_BASE_URL") or DEFAULT_BASE_URL)


@dataclass(frozen=True)
class ChatResponse:
    message: dict[str, Any]
    tokens_in: int
    tokens_out: int
    cost_usd: float  # from usage.cost when the provider reports it (OpenRouter), else 0


class ChatClient:
    def __init__(
        self,
        config: LLMConfig,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 4,
        timeout_s: float = 120.0,
    ) -> None:
        self._config = config
        self._http = httpx.Client(transport=transport, timeout=timeout_s)
        self._sleep = sleep
        self._max_attempts = max_attempts

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ChatResponse:
        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": messages,
            "tools": tools,
            "usage": {"include": True},  # OpenRouter: report cost; ignored elsewhere
        }
        headers = {"Authorization": f"Bearer {self._config.api_key}"}
        url = self._config.base_url.rstrip("/") + "/chat/completions"
        last = "no attempt made"
        for attempt in range(self._max_attempts):
            try:
                res = self._http.post(url, json=body, headers=headers)
            except httpx.TransportError as exc:
                last = f"transport error: {type(exc).__name__}"
            else:
                if res.status_code in RETRY_STATUSES:
                    last = f"HTTP {res.status_code}"
                elif res.status_code != 200:
                    raise LLMError(f"HTTP {res.status_code}: {res.text[:200]}")
                else:
                    return _parse(res.json())
            self._sleep(min(2.0**attempt, 30.0))
        raise LLMError(f"gave up after {self._max_attempts} attempts: {last}")


def _parse(data: dict[str, Any]) -> ChatResponse:
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("malformed completion response") from exc
    usage = data.get("usage") or {}
    return ChatResponse(
        message=message,
        tokens_in=int(usage.get("prompt_tokens", 0)),
        tokens_out=int(usage.get("completion_tokens", 0)),
        cost_usd=float(usage.get("cost", 0.0)),
    )
