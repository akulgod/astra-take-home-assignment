"""Match model findings against a reference set (ground-truth entries OR the
teacher's findings). One-to-one assignment: each reference can be claimed by at
most one finding, and each finding satisfies at most one reference — so five
duplicate findings cannot inflate recall.

Rule: deterministic match — location overlap (shared class name) AND category
agreement. Category agreement is exact, with ONE escape hatch: the `other`
bucket is the schema's explicit "couldn't categorize" label, so a location match
where either side is `other` counts. That recovers findings a model located
correctly but filed under the catch-all, without aliasing two *specific*
categories to each other (which would hide a genuine disagreement). Exact
matches are always claimed first, so an `other` finding never steals a slot a
specific match needs. No LLM involved, so the recall number is reproducible.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..schema import Finding, MatchPair, RecallReport


@dataclass
class ReferenceItem:
    id: str
    category: str
    component: str
    description: str = ""


def _class_names(s: str) -> set[str]:
    """Extract CamelCase class-like identifiers (WebViewActivity, Prefs, Util...).

    A class name has an uppercase letter and isn't an all-caps constant. This
    rule alone excludes lowercase package segments (com, insecureshop, the
    `util` *package*) while keeping a class literally named `Util` — which a
    generic stop-list would wrongly drop, costing a real match (e.g. GT-01's
    hardcoded creds in Util)."""
    out = set()
    for raw in re.split(r"[^A-Za-z0-9]+", s or ""):
        if not raw:
            continue
        if re.search(r"[A-Z]", raw) and not raw.isupper():
            out.add(raw.lower())
    return out


def _location_overlap(ref: ReferenceItem, f: Finding, allow_wildcard: bool = True) -> bool:
    ref_toks = _class_names(ref.component)
    loc = f.location
    fin_toks = _class_names(loc.component) | _class_names(loc.file) | _class_names(loc.method)
    if not ref_toks:
        # package-level reference (no class in it, e.g. "logcat"): location is a
        # wildcard, so the match rests entirely on category. That is safe when
        # the category is EXACT (pass 1), but combined with the `other`-bucket
        # category waiver (pass 2) it would let a wildcard ref claim any stray
        # `other` finding anywhere in the app — a free match. So pass 2 sets
        # allow_wildcard=False: the `other` waiver requires real class overlap.
        return allow_wildcard
    return bool(ref_toks & fin_toks)


_OTHER = "other"


def _category_ok(ref_cat: str, fin_cat: str, require_same_category: bool, allow_other: bool) -> bool:
    if not require_same_category:
        return True
    if fin_cat == ref_cat:
        return True
    return allow_other and (fin_cat == _OTHER or ref_cat == _OTHER)


def match(
    references: list[ReferenceItem],
    findings: list[Finding],
    require_same_category: bool = True,
) -> RecallReport:
    used_findings: set[int] = set()
    result: dict[str, MatchPair] = {}

    # Specific (class-bearing) references claim findings before package-level
    # wildcard references, so a wildcard can't steal a finding a specific ref
    # needs. Original order is preserved in the output via the id lookup below.
    ordered = sorted(references, key=lambda r: 0 if _class_names(r.component) else 1)

    def _claim(allow_other: bool, allow_wildcard: bool, method: str) -> None:
        for ref in ordered:
            if ref.id in result:
                continue  # already matched in an earlier (stricter) pass
            for i, f in enumerate(findings):
                if i in used_findings:
                    continue
                if not _category_ok(ref.category, f.type.value, require_same_category, allow_other):
                    continue
                if _location_overlap(ref, f, allow_wildcard=allow_wildcard):
                    used_findings.add(i)
                    result[ref.id] = MatchPair(reference_id=ref.id, finding_index=i,
                                               matched=True, method=method)
                    break

    # Pass 1: exact category + location (a package-level ref may match on
    # category alone, since the category is exact).
    _claim(allow_other=False, allow_wildcard=True, method="category+location")
    # Pass 2: the `other` escape hatch, for refs still unmatched — but it
    # requires REAL class-name overlap, so the category waiver can't combine
    # with a location wildcard to produce a free match.
    _claim(allow_other=True, allow_wildcard=False, method="location+other-bucket")

    pairs = [result.get(ref.id, MatchPair(reference_id=ref.id, matched=False))
             for ref in references]

    matched = sum(1 for p in pairs if p.matched)
    total = len(references)
    return RecallReport(
        reference="",  # filled by caller
        total_reference=total,
        matched=matched,
        recall=(matched / total if total else 0.0),
        pairs=pairs,
    )

