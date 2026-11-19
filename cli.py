"""Entry point. Usage:

    python cli.py run   --config config/config.yaml
    python cli.py ingest --config config/config.yaml   # ingest-only smoke test (no API keys)
"""
from __future__ import annotations

import argparse
import json
import sys

from src.config import Config
from src.ingest.loader import load_app
from src.pipeline import run


def _cmd_ingest(args):
    cfg = Config.load(args.config)
    bundle = load_app(cfg.app)
    print(bundle.manifest_summary())
    print(f"\n[ingest] package={bundle.manifest.package} "
          f"sources={len(bundle.sources)} resources={len(bundle.resources)}")
    for sf in bundle.sources:
        print(f"  - {sf.rel_path} ({len(sf.text)} chars)")


def _cmd_run(args):
    print(json.dumps(run(args.config), indent=2))


def _cmd_scan(args):
    """Frontier-scan-only: ingest the app and run ONE scan with a role's model.
    Prints findings as JSON. Useful for a quick frontier pass on a new APK."""
    from src.models.registry import build_client, model_config_from_dict
    from src.scan.scanner import scan

    cfg = Config.load(args.config)
    bundle = load_app(cfg.app)
    name = cfg.roles[args.role]
    mc = model_config_from_dict(name, cfg.models[name])
    client = build_client(mc, cfg.run.get("cache_dir"))
    res = scan(bundle, client, args.role,
               max_chunk_chars=cfg.run.get("max_chunk_chars", 12000),
               max_files_per_batch=cfg.run.get("max_files_per_batch", 1))
    print(json.dumps([f.model_dump(mode="json") for f in res.findings], indent=2))
    print(f"[scan] {args.role}={name} -> {len(res.findings)} findings, "
          f"{res.dropped} dropped", file=sys.stderr)


def _cmd_check(args):
    """Cheap connectivity + model-id validation: one trivial call per role."""
    from src.models.registry import build_client, model_config_from_dict

    cfg = Config.load(args.config)
    ok = True
    for role in ("teacher", "student"):
        name = cfg.roles[role]
        mc = model_config_from_dict(name, cfg.models[name])
        try:
            client = build_client(mc, cache_dir=None)  # no cache, force a real call
            reply = client.complete("Reply with exactly: OK", "ping", salt="check")
            print(f"[check] {role:8} {name:14} ({mc.model}) -> OK  ({reply.strip()[:40]!r})")
        except Exception as e:
            ok = False
            print(f"[check] {role:8} {name:14} ({mc.model}) -> FAIL: {type(e).__name__}: {e}")
    print("[check] all good" if ok else "[check] FIX THE ABOVE before running")


def main():
    p = argparse.ArgumentParser(description="Teacher->student Android vuln-scan pipeline")
    sub = p.add_subparsers(required=True)

    pi = sub.add_parser("ingest", help="load the app and print what was ingested")
    pi.add_argument("--config", default="config/config.yaml")
    pi.set_defaults(func=_cmd_ingest)

    pc = sub.add_parser("check", help="one cheap call per role to validate keys + model ids")
    pc.add_argument("--config", default="config/config.yaml")
    pc.set_defaults(func=_cmd_check)

    ps = sub.add_parser("scan", help="frontier-scan-only: one scan pass with a role's model")
    ps.add_argument("--config", default="config/config.yaml")
    ps.add_argument("--role", default="teacher", choices=["teacher", "student"])
    ps.set_defaults(func=_cmd_scan)

    pr = sub.add_parser("run", help="full pipeline (requires API keys)")
    pr.add_argument("--config", default="config/config.yaml")
    pr.set_defaults(func=_cmd_run)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
