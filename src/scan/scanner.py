"""Scan an AppBundle with a given model and return deduped Findings.

Per-file chunking with the manifest summary prepended to every chunk. Optional
`lessons` are injected into the student rescan — the SAME scanner runs the
baseline (lessons=None) and the post-lessons pass, so the only variable is the
lessons text. That keeps the recall comparison honest.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ..ingest.loader import AppBundle
from ..models.base import LLMClient
from ..schema import Finding, Lesson, Severity, VulnCategory
from . import prompts

_VALID_TYPES = {c.value for c in VulnCategory}
_VALID_SEV = {s.value for s in Severity}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    dropped: int = 0   # findings a model emitted that failed validation


def _normalize(item: dict) -> dict:
    """Lowercase + coerce enum fields so a casing or off-vocabulary label does
    not silently drop a real finding (which would bias the baseline and fake
    part of the post-lessons lift)."""
    if not isinstance(item, dict):
        return item
    t = str(item.get("type", "")).strip().lower()
    item["type"] = t if t in _VALID_TYPES else VulnCategory.other.value
    sev = str(item.get("severity", "")).strip().lower()
    item["severity"] = sev if sev in _VALID_SEV else Severity.medium.value
    return item


def _parse_findings(raw: str) -> tuple[list[Finding], int]:
    """Tolerant JSON extraction: models sometimes wrap the array in prose or
    ```json fences. Returns (findings, dropped_count)."""
    text = raw.strip()
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return [], 0
    try:
        items = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return [], 0
    out: list[Finding] = []
    dropped = 0
    for item in items:
        try:
            out.append(Finding.model_validate(_normalize(item)))
        except Exception:
            dropped += 1  # count drops instead of hiding them
    return out, dropped


def _lessons_block(lessons: Optional[list[Lesson]]) -> str:
    if not lessons:
        return ""
    body = "\n".join(f"- [{l.category.value}] {l.rule} ({l.detection_hint})" for l in lessons)
    return prompts.LESSONS_BLOCK_TEMPLATE.format(lessons=body)


def _chunk_files(sources, max_chars: int, max_files: int = 1):
    """Greedily pack whole files into batches, bounded by BOTH a char budget
    and a file-count cap. max_files=1 => one file per call (best recall for a
    weak student); raise it to batch files and cut per-call overhead when
    scaling to a large codebase. A file over the char budget gets its own
    (truncated) batch."""
    batches, cur, cur_len = [], [], 0
    for sf in sources:
        n = len(sf.text)
        if cur and (cur_len + n > max_chars or len(cur) >= max_files):
            batches.append(cur)
            cur, cur_len = [], 0
        cur.append(sf)
        cur_len += n
    if cur:
        batches.append(cur)
    return batches


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.type.value, (f.location.component or f.location.file or "").lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan(
    bundle: AppBundle,
    client: LLMClient,
    source_label: str,
    lessons: Optional[list[Lesson]] = None,
    max_chunk_chars: int = 12000,
    max_files_per_batch: int = 1,
    cache_salt: str = "",
) -> ScanResult:
    """`cache_salt` must differ between repeated runs of the same model/prompt,
    otherwise the disk cache replays run 1 and `repeats` become fake (stdev 0).
    max_files_per_batch=1 is per-file scanning (best recall); >1 batches."""
    manifest_summary = bundle.manifest_summary()
    lessons_block = _lessons_block(lessons)

    all_findings: list[Finding] = []
    total_dropped = 0
    batches = _chunk_files(bundle.sources, max_chunk_chars, max_files_per_batch)
    for bi, batch in enumerate(batches):
        file_blocks = []
        for sf in batch:
            code = sf.text[:max_chunk_chars]
            if len(sf.text) > max_chunk_chars:
                print(f"[scan] WARNING truncated {sf.rel_path}: "
                      f"{len(sf.text)} -> {max_chunk_chars} chars")
            file_blocks.append(
                prompts.FILE_BLOCK_TEMPLATE.format(file_path=sf.rel_path, code=code)
            )
        user = prompts.SCAN_USER_TEMPLATE.format(
            manifest_summary=manifest_summary,
            n_files=len(batch),
            files_block="\n".join(file_blocks),
            lessons_block=lessons_block,
        )
        raw = client.complete(prompts.SCAN_SYSTEM, user, salt=f"{cache_salt}#b{bi}")
        findings, dropped = _parse_findings(raw)
        total_dropped += dropped
        batch_paths = {sf.rel_path for sf in batch}
        for f in findings:
            f.source = source_label
            # if the model omitted/garbled the file and the batch is a single
            # file, attribute it; otherwise leave as-is.
            if f.location.file not in batch_paths and len(batch) == 1:
                f.location.file = batch[0].rel_path
            all_findings.append(f)

    # TODO: also scan manifest + resources as their own chunks (several of the
    # 19 vulns live there, e.g. FileProvider paths, cleartext config).
    return ScanResult(findings=_dedupe(all_findings), dropped=total_dropped)
