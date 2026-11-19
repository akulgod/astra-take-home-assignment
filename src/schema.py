"""Core data contracts shared across ingest, scan, lessons, matching, eval.

These are the stable interfaces. Everything else depends on this module, so
keep it free of app- or model-specific logic.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class VulnCategory(str, Enum):
    """Generic Android vulnerability taxonomy.

    Deliberately NOT InsecureShop-specific — these are reusable classes that an
    unseen app would also map onto. `other` is the escape hatch so a model is
    never forced to mislabel. The matcher keys on this field.
    """
    hardcoded_credentials = "hardcoded_credentials"
    insecure_storage = "insecure_storage"
    insecure_logging = "insecure_logging"
    webview_url_validation = "webview_url_validation"
    webview_host_validation = "webview_host_validation"
    webview_misconfig = "webview_misconfig"
    ssl_validation = "ssl_validation"
    arbitrary_code_execution = "arbitrary_code_execution"
    intent_redirection = "intent_redirection"
    implicit_intent_leak = "implicit_intent_leak"
    insecure_broadcast = "insecure_broadcast"
    insecure_content_provider = "insecure_content_provider"
    fileprovider_misconfig = "fileprovider_misconfig"
    insecure_setresult = "insecure_setresult"
    file_theft = "file_theft"
    exported_component = "exported_component"
    cloud_misconfig = "cloud_misconfig"
    vulnerable_dependency = "vulnerable_dependency"
    other = "other"


class Location(BaseModel):
    """Where a finding lives. Line numbers are intentionally optional and are
    NOT used by the matcher — jadx line numbers are not stable across runs."""
    file: Optional[str] = None            # e.g. com/insecureshop/WebViewActivity.java
    component: Optional[str] = None       # class or manifest component name
    method: Optional[str] = None
    line: Optional[int] = None            # advisory only, never matched on


class Finding(BaseModel):
    """One vulnerability a model (or ground truth) asserts."""
    type: VulnCategory
    severity: Severity = Severity.medium
    location: Location = Field(default_factory=Location)
    evidence: str = ""                    # the code snippet / concrete signal
    rationale: str = ""                   # why this is a vulnerability
    # bookkeeping (not model-provided)
    source: Optional[str] = None          # "teacher" | "student" | "student+lessons"
    id: Optional[str] = None


class Lesson(BaseModel):
    """A GENERAL rule distilled by the teacher. Must not name app-specific
    identifiers — enforced by lessons.validator."""
    category: VulnCategory
    rule: str                             # the general guidance
    detection_hint: str = ""              # what to look for, generically


class MatchPair(BaseModel):
    """One matched (reference, finding) pair in the eval table."""
    reference_id: str                     # GT id or teacher-finding id
    finding_index: Optional[int] = None   # index into the model findings list
    matched: bool
    method: str = ""                      # how it matched, e.g. "category+location"
    note: str = ""


class RecallReport(BaseModel):
    reference: str                        # "ground_truth_file" | "teacher_findings"
    total_reference: int
    matched: int
    recall: float
    pairs: list[MatchPair] = Field(default_factory=list)
