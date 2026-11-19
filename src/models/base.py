"""The single interface every model speaks.

Adding a new provider = implementing this ABC once and registering it. Adding a
new *model* of an existing provider = a YAML entry, no code. That split is the
extensibility story the assignment asks for.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional


@dataclass
class ModelConfig:
    name: str                       # registry key, e.g. "claude-sonnet"
    provider: str                   # "anthropic" | "openai_compat" | "fake"
    model: str                      # provider model id
    api_key_env: str = ""           # empty for providers that need no key (fake)
    base_url: Optional[str] = None  # openai_compat only
    max_tokens: int = 4096
    # newer OpenAI models renamed this kwarg; Groq/older still use "max_tokens"
    tokens_param: str = "max_tokens"
    # None => don't send temperature (some reasoning models only allow default)
    temperature: Optional[float] = 0.0


class LLMClient(abc.ABC):
    """Minimal surface: one text-in/text-out call. JSON-schema shaping is done
    by the caller via the prompt (keeps the interface provider-agnostic)."""

    def __init__(self, cfg: ModelConfig):
        self.cfg = cfg

    @abc.abstractmethod
    def complete(self, system: str, user: str, salt: str = "") -> str:
        """Return the model's raw text completion. `salt` only affects the cache
        key (it lets repeated runs of the same prompt produce distinct cache
        entries); concrete adapters ignore it. Retries/backoff and caching are
        layered around this by the registry, not reimplemented per client."""
        raise NotImplementedError
