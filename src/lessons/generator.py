"""Teacher turns its findings into general lessons in a SINGLE pass (per the
assignment), then the deterministic validator strips any that leaked
app-specific identifiers."""
from __future__ import annotations

import json

from ..ingest.loader import AppBundle
from ..models.base import LLMClient
from ..schema import Finding, Lesson
from ..scan import prompts
from .validator import validate


def _parse_lessons(raw: str) -> list[Lesson]:
    text = raw.strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        return []
    try:
        items = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return []
    out = []
    for item in items:
        try:
            out.append(Lesson.model_validate(item))
        except Exception:
            continue
    return out


def generate_lessons(
    findings: list[Finding], client: LLMClient, bundle: AppBundle
) -> tuple[list[Lesson], list[dict]]:
    """Return (accepted_lessons, rejected_lessons_with_reason)."""
    findings_json = json.dumps(
        [f.model_dump(mode="json", exclude={"source", "id"}) for f in findings],
        indent=2,
    )
    # Drive coverage from the categories actually present, so the single pass
    # can't skew toward a few classes and leave the biggest bucket un-lessoned.
    cats = sorted({f.type.value for f in findings} - {"other"})
    categories = "\n".join(f"  - {c}" for c in cats)
    user = prompts.LESSON_GEN_USER_TEMPLATE.format(
        findings_json=findings_json, categories=categories)
    raw = client.complete(prompts.LESSON_GEN_SYSTEM, user)
    lessons = _parse_lessons(raw)
    return validate(lessons, bundle)
