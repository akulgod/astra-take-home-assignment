"""Prompt templates. Kept together so the scan contract is easy to audit/tune.
The category list is injected from the schema so prompts never drift from it."""
from __future__ import annotations

from ..schema import VulnCategory

_CATEGORIES = ", ".join(c.value for c in VulnCategory)

SCAN_SYSTEM = f"""You are a mobile application security researcher auditing \
decompiled Android (Java/Kotlin) source for vulnerabilities.

Return ONLY a JSON array of findings. Each finding is an object:
{{
  "type": one of [{_CATEGORIES}],
  "severity": one of [critical, high, medium, low, info],
  "location": {{"file": str, "component": str, "method": str|null}},
  "evidence": "the specific code snippet or signal",
  "rationale": "why this is exploitable"
}}
Report only real, evidence-backed issues. No prose outside the JSON array."""

SCAN_USER_TEMPLATE = """App manifest summary (authoritative for exported status):
{manifest_summary}

You are reviewing {n_files} source file(s) below. Report findings across ALL of
them. For every finding, set "location.file" to the EXACT path in its header.
{files_block}
{lessons_block}
Return a single JSON array of findings covering all files above."""

# One file's block inside a batched prompt.
FILE_BLOCK_TEMPLATE = """
===== FILE: {file_path} =====
```
{code}
```"""

LESSONS_BLOCK_TEMPLATE = """
General security lessons (patterns seen in other Android apps). Apply these IN
ADDITION TO everything you would normally flag — they tell you what ELSE to look
for, they never tell you to withhold or second-guess a finding. Reporting more
is better than missing one. Keep every issue you would have reported without
these lessons, and add any the lessons help you notice:
{lessons}
"""

LESSON_GEN_SYSTEM = """You convert specific vulnerability findings into GENERAL, \
reusable detection rules that help an auditor FIND more real issues in ANY \
Android app. The reader is a weaker model; your job is to widen its recall.

Write each lesson to be RECALL-ORIENTED:
- State the pattern and the concrete code/manifest/resource signals that reveal it.
- Err toward flagging: tell the reader to REPORT a suspicious case, not to rule \
it out. Do NOT add precision caveats such as "distinguish X from Y", "only if", \
"before concluding", or "verify it is actually exploitable" — those suppress \
findings.

Hard requirement: lessons must NOT reference any app-specific identifier — no \
class names, file names, package names, method names, string literals, or line \
numbers from the findings. State the pattern and how to detect it generically.

Return ONLY a JSON array of objects:
{"category": <vuln category>, "rule": <general rule>, "detection_hint": <what to look for>}"""

LESSON_GEN_USER_TEMPLATE = """Findings to generalize into lessons (single pass):
{findings_json}

Produce one general, recall-oriented lesson for EVERY distinct vulnerability
category listed here, so coverage is not skewed toward a few classes:
{categories}
Skip a category only if it is the catch-all "other" (too heterogeneous to
generalize)."""
