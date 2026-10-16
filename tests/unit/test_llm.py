from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from dabao.llm import ChatClient, ConfigError, LLMConfig, LLMError

CFG = LLMConfig(api_key="sk-secret", model="some/model", base_url="https://llm.test/v1")


def ok(content: str = "hi", usage: dict[str, Any] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": usage if usage is not None else {},
        },
    )


def client(handler: Any, sleeps: list[float] | None = None) -> ChatClient:
    return ChatClient(
        CFG,
        transport=httpx.MockTransport(handler),
        sleep=(sleeps if sleeps is not None else []).append,
    )


def test_config_from_env_requires_key_and_model_and_defaults_to_openrouter() -> None:
    with pytest.raises(ConfigError):
        LLMConfig.from_env({"LLM_MODEL": "m"})
    with pytest.raises(ConfigError):
        LLMConfig.from_env({"LLM_API_KEY": "k"})
    cfg = LLMConfig.from_env({"LLM_API_KEY": "k", "LLM_MODEL": "m"})
    assert cfg.base_url == "https://openrouter.ai/api/v1"


def test_api_key_is_not_in_repr() -> None:
    assert "sk-secret" not in repr(CFG)


def test_request_shape_auth_and_usage_parsing() -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"], seen["auth"], seen["body"] = (
            str(req.url),
            req.headers["authorization"],
            req.read(),
        )
        return ok(usage={"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.002})

    resp = client(handler).complete([{"role": "user", "content": "x"}], [])
    assert seen["url"] == "https://llm.test/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-secret"
    body = json.loads(seen["body"])
    assert body["model"] == "some/model" and body["usage"] == {"include": True}
    assert (resp.tokens_in, resp.tokens_out, resp.cost_usd) == (10, 5, 0.002)


def test_retries_rate_limits_with_backoff_then_succeeds() -> None:
    calls = iter([httpx.Response(429), httpx.Response(503), ok()])
    sleeps: list[float] = []
    resp = client(lambda _r: next(calls), sleeps).complete([], [])
    assert resp.message["content"] == "hi"
    assert sleeps == [1.0, 2.0]


def test_gives_up_after_max_attempts() -> None:
    with pytest.raises(LLMError, match="gave up after 4 attempts: HTTP 500"):
        client(lambda _r: httpx.Response(500)).complete([], [])


def test_client_errors_are_not_retried() -> None:
    n = 0

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal n
        n += 1
        return httpx.Response(401, text="bad key")

    with pytest.raises(LLMError, match="HTTP 401"):
        client(handler).complete([], [])
    assert n == 1


def test_malformed_response_is_an_error() -> None:
    with pytest.raises(LLMError, match="malformed"):
        client(lambda _r: httpx.Response(200, json={"choices": []})).complete([], [])
