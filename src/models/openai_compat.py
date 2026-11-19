"""One adapter for every OpenAI-compatible endpoint: OpenAI itself, Groq, and
Gemini's OpenAI-compatible API. The only difference between them is `base_url`
and which API-key env var to read — both come from config. This is why adding
Groq or Gemini is a YAML change, not new code."""
from __future__ import annotations

import os

from .base import LLMClient, ModelConfig


class OpenAICompatClient(LLMClient):
    def __init__(self, cfg: ModelConfig):
        super().__init__(cfg)
        from openai import OpenAI  # lazy

        key = os.environ.get(cfg.api_key_env)
        if not key:
            raise RuntimeError(f"Missing API key env var: {cfg.api_key_env}")
        self._client = OpenAI(api_key=key, base_url=cfg.base_url)

    def complete(self, system: str, user: str, salt: str = "") -> str:
        # Token-limit kwarg name varies by provider/model (max_tokens vs
        # max_completion_tokens) — driven by config.tokens_param.
        kwargs = {
            "model": self.cfg.model,
            self.cfg.tokens_param: self.cfg.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self.cfg.temperature is not None:  # some reasoning models reject it
            kwargs["temperature"] = self.cfg.temperature
        resp = self._client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""
