"""End-to-end orchestration: ingest -> teacher scan -> student baseline ->
lessons -> student rescan -> recall. Writes every artifact to runs/<timestamp>/.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .config import Config
from .eval.recall import (
    recall_for,
    references_from_findings,
    references_from_ground_truth,
    summarize_repeats,
)
from .ingest.loader import load_app
from .lessons.generator import generate_lessons
from .models.registry import build_client, model_config_from_dict
from .scan.scanner import scan


def _client(cfg: Config, role: str):
    mc = model_config_from_dict(cfg.roles[role], cfg.models[cfg.roles[role]])
    return build_client(mc, cfg.run.get("cache_dir"))


def _dump(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str))


def run(config_path: str) -> dict:
    cfg = Config.load(config_path)
    out_dir = Path(cfg.run.get("output_dir", "./runs")) / datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    chunk = cfg.run.get("max_chunk_chars", 12000)
    mfpb = cfg.run.get("max_files_per_batch", 1)

    # 1. Ingest
    bundle = load_app(cfg.app)
    _dump(out_dir / "manifest_summary.txt", bundle.manifest_summary())

    teacher = _client(cfg, "teacher")
    student = _client(cfg, "student")

    # 2. Frontier (teacher) scan
    teacher_result = scan(bundle, teacher, "teacher",
                          max_chunk_chars=chunk, max_files_per_batch=mfpb)
    teacher_findings = teacher_result.findings
    _dump(out_dir / "teacher_findings.json",
          [f.model_dump(mode="json") for f in teacher_findings])

    repeats = cfg.eval.get("repeats", 1)

    # Reference set: GT file, or teacher findings for an unseen APK.
    if cfg.eval["reference"] == "ground_truth_file":
        references = references_from_ground_truth(cfg.eval["ground_truth_file"])
    else:
        references = references_from_findings(teacher_findings)
    ref_label = cfg.eval["reference"]
    match_kw = {"require_same_category": cfg.eval["match"].get("require_same_category", True)}

    # Teacher recall vs references = the ceiling the student is chasing
    # (only meaningful when references are independent ground truth).
    teacher_recall = None
    if ref_label == "ground_truth_file":
        tr = recall_for(references, teacher_findings, ref_label, **match_kw)
        teacher_recall = tr.recall
        _dump(out_dir / "teacher_match.json", tr.model_dump(mode="json"))

    def _run_phase(label: str, lessons=None):
        recalls, counts, drops, precisions = [], [], [], []
        for i in range(repeats):
            res = scan(bundle, student, label, lessons=lessons,
                       max_chunk_chars=chunk, max_files_per_batch=mfpb,
                       cache_salt=f"{label}-{i}")
            r = recall_for(references, res.findings, ref_label, **match_kw)
            recalls.append(r.recall)
            counts.append(len(res.findings))
            drops.append(res.dropped)
            # precision: matched findings / total emitted. Guards against a
            # recall "gain" that is really just the student emitting more.
            precisions.append(r.matched / len(res.findings) if res.findings else 0.0)
            _dump(out_dir / f"{label}_run{i}_match.json", r.model_dump(mode="json"))
            # Persist the student's actual findings too — the match file only
            # holds indices into this list, so without it a lost/relabelled
            # finding can't be diagnosed after the run.
            _dump(out_dir / f"{label}_run{i}_findings.json",
                  [f.model_dump(mode="json") for f in res.findings])
        return recalls, counts, drops, precisions

    # 3a. Student baseline (repeats to average out noise)
    baseline_recalls, baseline_counts, baseline_drops, baseline_prec = _run_phase("student")

    # 3b. Lessons from teacher findings (single pass) + generality validation
    lessons, rejected = generate_lessons(teacher_findings, teacher, bundle)
    _dump(out_dir / "lessons.json",
          {"accepted": [l.model_dump(mode="json") for l in lessons], "rejected": rejected})

    # 3c. Student rescan WITH lessons (same scanner; only variable = lessons)
    post_recalls, post_counts, post_drops, post_prec = _run_phase("student+lessons", lessons=lessons)

    # 4. Report — strict deterministic recall, plus the context to assess the lift.
    base = summarize_repeats(baseline_recalls)
    post = summarize_repeats(post_recalls)
    summary = {
        "reference": ref_label,
        "total_reference": len(references),
        "teacher_recall_ceiling": teacher_recall,
        "teacher_findings": len(teacher_findings),
        "baseline": {**base, "avg_findings": _avg(baseline_counts),
                     "avg_dropped": _avg(baseline_drops),
                     "avg_precision": _avg(baseline_prec)},
        "with_lessons": {**post, "avg_findings": _avg(post_counts),
                         "avg_dropped": _avg(post_drops),
                         "avg_precision": _avg(post_prec)},
        "lift": round(post["mean"] - base["mean"], 4),
        "precision_delta": round(_avg(post_prec) - _avg(baseline_prec), 4),
        "num_lessons": len(lessons),
        "num_rejected_lessons": len(rejected),
    }
    _dump(out_dir / "summary.json", summary)
    return summary


def _avg(xs: list[int]) -> float:
    return round(sum(xs) / len(xs), 2) if xs else 0.0
