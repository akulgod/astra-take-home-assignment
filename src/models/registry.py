"""Build LLMClients from config and wrap them with caching + retry.

The registry is the only place that knows the provider -> adapter mapping, so
adding a provider touches exactly one dict here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from .anthropic_client import AnthropicClient
from .base import LLMClient, ModelConfig
from .fake_client import FakeClient
from .openai_compat import OpenAICompatClient

# provider id -> adapter class. The one place to register a new provider.
_PROVIDERS: dict[str, type[LLMClient]] = {
    "anthropic": AnthropicClient,
    "openai_compat": OpenAICompatClient,
    "fake": FakeClient,  # offline test double, no network/keys
}


class CachedClient(LLMClient):
    """Decorator: disk cache keyed by hash(model, system, user) + retry/backoff.
    Caching makes repeated runs cheap and deterministic for the recall eval."""

    def __init__(self, inner: LLMClient, cache_dir: Optional[str]):
        self.inner = inner
        self.cfg = inner.cfg
        self._cache = Path(cache_dir) if cache_dir else None
        if self._cache:
            self._cache.mkdir(parents=True, exist_ok=True)

    def _key(self, system: str, user: str, salt: str) -> str:
        h = hashlib.sha256()
        for part in (self.cfg.model, str(self.cfg.temperature), str(self.cfg.max_tokens),
                     salt, system, user):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()

    def complete(self, system: str, user: str, salt: str = "") -> str:
        if self._cache:
            path = self._cache / f"{self._key(system, user, salt)}.json"
            if path.exists():
                return json.loads(path.read_text())["completion"]

        text = self._call_with_retry(system, user)

        if self._cache:
            path.write_text(json.dumps({"model": self.cfg.model, "completion": text}))
        return text

    def _call_with_retry(self, system: str, user: str) -> str:
        from tenacity import (
            retry,
            retry_if_exception_type,
            stop_after_attempt,
            wait_exponential,
        )

        @retry(
            stop=stop_after_attempt(5),
            wait=wait_exponential(multiplier=1, min=2, max=30),
            retry=retry_if_exception_type(Exception),  # TODO: narrow to rate-limit/transient
            reraise=True,
        )
        def _go() -> str:
            return self.inner.complete(system, user)

        return _go()


def build_client(cfg: ModelConfig, cache_dir: Optional[str] = None) -> LLMClient:
    adapter = _PROVIDERS.get(cfg.provider)
    if adapter is None:
        raise ValueError(
            f"Unknown provider '{cfg.provider}'. Registered: {list(_PROVIDERS)}"
        )
    return CachedClient(adapter(cfg), cache_dir)


def model_config_from_dict(name: str, d: dict) -> ModelConfig:
    return ModelConfig(
        name=name,
        provider=d["provider"],
        model=d["model"],
        api_key_env=d.get("api_key_env", ""),
        base_url=d.get("base_url"),
        max_tokens=d.get("max_tokens", 4096),
        tokens_param=d.get("tokens_param", "max_tokens"),
        temperature=d.get("temperature", 0.0),
    )
