"""Offline test double. Returns canned JSON so the full pipeline (schema,
scan parsing, lessons, matcher, eval) can run with no API keys or network.

Selected via `provider: fake` in config. The canned responses are keyed by a
marker in the system prompt so scan vs. lesson-generation get the right shape.
"""
from __future__ import annotations

import json

from .base import LLMClient, ModelConfig

# A couple of plausible findings + one off-vocabulary type to exercise
# normalization, and one bad-cased severity.
_FAKE_FINDINGS = json.dumps([
    {"type": "webview_misconfig", "severity": "High",
     "location": {"file": "com/insecureshop/WebViewActivity.java",
                  "component": "WebViewActivity", "method": "onCreate"},
     "evidence": "settings.setJavaScriptEnabled(true)", "rationale": "JS enabled on untrusted content"},
    {"type": "insecure_storage", "severity": "medium",
     "location": {"component": "Prefs"},
     "evidence": "SharedPreferences stores password in cleartext", "rationale": "no encryption"},
    {"type": "totally_made_up_type", "severity": "low",
     "location": {"component": "Foo"}, "evidence": "x", "rationale": "y"},
])

_FAKE_LESSONS = json.dumps([
    {"category": "webview_misconfig",
     "rule": "Do not enable JavaScript or file access on a WebView that can load untrusted content.",
     "detection_hint": "Look for setJavaScriptEnabled(true) alongside loadUrl of external input."},
    {"category": "insecure_storage",
     "rule": "Never store credentials in plaintext local storage.",
     "detection_hint": "SharedPreferences or files holding passwords/tokens without encryption."},
])


class FakeClient(LLMClient):
    def __init__(self, cfg: ModelConfig):
        super().__init__(cfg)

    def complete(self, system: str, user: str, salt: str = "") -> str:
        if "general" in system.lower() and "lesson" in system.lower():
            return _FAKE_LESSONS
        return _FAKE_FINDINGS
