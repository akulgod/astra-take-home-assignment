"""Load config.yaml + .env into typed access. Thin on purpose."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class Config:
    def __init__(self, data: dict[str, Any]):
        self._d = data

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        # Load .env if present so API-key env vars are available.
        try:
            from dotenv import load_dotenv

            load_dotenv()
        except ImportError:
            pass
        data = yaml.safe_load(Path(path).read_text())
        return cls(data)

    # convenience accessors ------------------------------------------------
    @property
    def models(self) -> dict[str, dict]:
        return self._d["models"]

    @property
    def roles(self) -> dict[str, str]:
        return self._d["roles"]

    def model_for_role(self, role: str) -> dict:
        name = self.roles[role]
        return {"name": name, **self.models[name]}

    @property
    def app(self) -> dict:
        return self._d["app"]

    @property
    def eval(self) -> dict:
        return self._d["eval"]

    @property
    def run(self) -> dict:
        return self._d.get("run", {})
