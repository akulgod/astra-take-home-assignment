"""Anthropic (Claude) adapter. SDK imported lazily so the package is only
required when this provider is actually selected."""
from __future__ import annotations

import os

from .base import LLMClient, ModelConfig


class AnthropicClient(LLMClient):
    def __init__(self, cfg: ModelConfig):
        super().__init__(cfg)
        import anthropic  # lazy

        key = os.environ.get(cfg.api_key_env)
        if not key:
            raise RuntimeError(f"Missing API key env var: {cfg.api_key_env}")
        self._client = anthropic.Anthropic(api_key=key)

    def complete(self, system: str, user: str, salt: str = "") -> str:
        resp = self._client.messages.create(
            model=self.cfg.model,
            max_tokens=self.cfg.max_tokens,
            temperature=self.cfg.temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        # Concatenate text blocks.
        return "".join(
            block.text for block in resp.content if getattr(block, "type", None) == "text"
        )
