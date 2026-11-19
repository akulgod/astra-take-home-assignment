"""Deterministic generality validator.

The assignment forbids instance-specific lessons. This makes "general" verifiable
instead of aspirational: reject any lesson whose text contains an identifier
drawn from the scanned app (class/file/package names, string literals, line
numbers). Runs with NO model call.
"""
from __future__ import annotations

import re

from ..ingest.loader import AppBundle
from ..schema import Lesson

_LINE_RE = re.compile(r"\bline\s+\d+\b", re.IGNORECASE)


def _app_identifiers(bundle: AppBundle) -> set[str]:
    ids: set[str] = set()
    pkg = bundle.manifest.package
    if pkg:
        ids.add(pkg)
        ids.update(pkg.split("."))
    for sf in bundle.sources:
        stem = sf.rel_path.rsplit("/", 1)[-1].removesuffix(".java")
        if len(stem) > 3:               # skip tiny names like "R"
            ids.add(stem)
    for c in bundle.manifest.exported_components:
        name = c["name"].rsplit(".", 1)[-1]
        if len(name) > 3:
            ids.add(name)
    # drop very common words that would over-reject (case-insensitive)
    _generic = {"util", "utils", "main", "base", "app", "data", "item", "view"}
    return {i for i in ids if len(i) > 3 and i.lower() not in _generic}


def validate(lessons: list[Lesson], bundle: AppBundle) -> tuple[list[Lesson], list[dict]]:
    """Return (accepted, rejected_with_reason)."""
    idents = _app_identifiers(bundle)
    accepted: list[Lesson] = []
    rejected: list[dict] = []
    for lesson in lessons:
        text = f"{lesson.rule} {lesson.detection_hint}"
        hit = next((i for i in idents if re.search(rf"\b{re.escape(i)}\b", text)), None)
        if hit:
            rejected.append({"lesson": lesson.rule, "reason": f"mentions app identifier '{hit}'"})
        elif _LINE_RE.search(text):
            rejected.append({"lesson": lesson.rule, "reason": "mentions a specific line number"})
        else:
            accepted.append(lesson)
    return accepted, rejected
