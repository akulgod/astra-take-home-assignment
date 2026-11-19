"""Build the reference set (ground-truth file OR teacher findings) and compute
recall. Supports repeated student runs so the before/after lift is reported as
mean +/- spread rather than a single noisy pair (19 items => ~5 pts/flip)."""
from __future__ import annotations

from pathlib import Path
from statistics import mean, pstdev

import yaml

from ..schema import Finding, RecallReport
from ..matching.matcher import ReferenceItem, match


def references_from_ground_truth(path: str | Path) -> list[ReferenceItem]:
    data = yaml.safe_load(Path(path).read_text())
    return [
        ReferenceItem(id=v["id"], category=v["category"],
                      component=v.get("component", ""), description=v.get("description", ""))
        for v in data["vulnerabilities"]
    ]


def references_from_findings(findings: list[Finding]) -> list[ReferenceItem]:
    """For an unseen APK with no ground truth: the teacher's findings are the
    reference the student is measured against."""
    refs = []
    for i, f in enumerate(findings):
        refs.append(ReferenceItem(
            id=f.id or f"T-{i:02d}",
            category=f.type.value,
            component=f.location.component or f.location.file or "",
            description=f.rationale,
        ))
    return refs


def recall_for(references, findings, reference_label, **match_kw) -> RecallReport:
    report = match(references, findings, **match_kw)
    report.reference = reference_label
    return report


def summarize_repeats(recalls: list[float]) -> dict:
    return {
        "mean": round(mean(recalls), 4) if recalls else 0.0,
        "stdev": round(pstdev(recalls), 4) if len(recalls) > 1 else 0.0,
        "runs": recalls,
    }
