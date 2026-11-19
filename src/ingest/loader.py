"""Load a decompiled Android app into a normalized AppBundle: manifest facts,
app source files, and security-relevant resources.

Works on any app. The only app-specific inputs are the path and the
exclude lists, both from config. If given an .apk it shells out to jadx first.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_METADATA_RE = re.compile(r"^\s*@Metadata\(.*?\)\s*$", re.MULTILINE)


@dataclass
class SourceFile:
    rel_path: str      # e.g. com/insecureshop/WebViewActivity.java
    text: str


@dataclass
class ManifestFacts:
    package: str = ""
    permissions: list[str] = field(default_factory=list)
    exported_components: list[dict] = field(default_factory=list)  # {name,type,intent_filters,...}
    providers: list[dict] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext_traffic: bool = False
    raw_xml: str = ""


@dataclass
class AppBundle:
    manifest: ManifestFacts
    sources: list[SourceFile]
    resources: dict[str, str]  # rel_path -> text (strings.xml, res/xml/*, network config)

    def manifest_summary(self) -> str:
        """Compact manifest digest to prepend to every scan chunk — exported
        status is what turns a code pattern into a real vulnerability."""
        m = self.manifest
        lines = [f"package: {m.package}",
                 f"debuggable: {m.debuggable}  allowBackup: {m.allow_backup}  "
                 f"cleartextTraffic: {m.uses_cleartext_traffic}",
                 f"permissions: {', '.join(m.permissions) or '(none)'}",
                 "exported components:"]
        for c in m.exported_components:
            filt = c.get("intent_filters", "")
            lines.append(f"  - [{c['type']}] {c['name']} {filt}")
        for p in m.providers:
            lines.append(f"  - [provider] {p['name']} authorities={p.get('authorities','')} "
                         f"exported={p.get('exported')}")
        return "\n".join(lines)


# --- decompile-if-needed --------------------------------------------------

def _ensure_decompiled(path: Path) -> Path:
    """If path is an .apk, decompile with jadx into a sibling dir and return it."""
    if path.is_dir():
        return path
    if path.suffix.lower() == ".apk":
        out = path.with_name(path.stem + "-src")
        if not out.exists():
            if not shutil.which("jadx"):
                raise RuntimeError("jadx not found on PATH; install it or pass a decompiled dir")
            subprocess.run(["jadx", "-d", str(out), str(path)], check=False)
        return out
    raise ValueError(f"app.path must be a decompiled dir or an .apk: {path}")


# --- manifest parsing -----------------------------------------------------

def _parse_manifest(manifest_path: Path) -> ManifestFacts:
    facts = ManifestFacts()
    if not manifest_path.exists():
        return facts
    facts.raw_xml = manifest_path.read_text(errors="replace")
    root = ET.fromstring(facts.raw_xml)
    facts.package = root.get("package", "")

    for perm in root.findall("uses-permission"):
        name = perm.get(ANDROID_NS + "name")
        if name:
            facts.permissions.append(name)

    app = root.find("application")
    if app is not None:
        facts.debuggable = app.get(ANDROID_NS + "debuggable") == "true"
        facts.allow_backup = app.get(ANDROID_NS + "allowBackup") == "true"
        facts.uses_cleartext_traffic = app.get(ANDROID_NS + "usesCleartextTraffic") == "true"

        for tag in ("activity", "activity-alias", "service", "receiver"):
            for comp in app.findall(tag):
                name = comp.get(ANDROID_NS + "name", "")
                exported_attr = comp.get(ANDROID_NS + "exported")
                has_filter = comp.find("intent-filter") is not None
                # exported defaults to true if it has an intent-filter and no explicit flag
                exported = exported_attr == "true" or (exported_attr is None and has_filter)
                if exported:
                    filters = []
                    for f in comp.findall("intent-filter"):
                        for action in f.findall("action"):
                            filters.append("action=" + action.get(ANDROID_NS + "name", ""))
                        for data in f.findall("data"):
                            sch = data.get(ANDROID_NS + "scheme")
                            if sch:
                                filters.append("scheme=" + sch)
                    facts.exported_components.append(
                        {"name": name, "type": tag, "intent_filters": " ".join(filters)}
                    )

        for prov in app.findall("provider"):
            facts.providers.append({
                "name": prov.get(ANDROID_NS + "name", ""),
                "authorities": prov.get(ANDROID_NS + "authorities", ""),
                "exported": prov.get(ANDROID_NS + "exported"),
            })
    return facts


# --- source + resource collection ----------------------------------------

def _collect_sources(root: Path, package: str, exclude_prefixes: list[str],
                     exclude_patterns: list[str]) -> list[SourceFile]:
    sources_dir = root / "sources"
    base = sources_dir if sources_dir.exists() else root
    pkg_path = package.replace(".", "/")

    out: list[SourceFile] = []
    for f in base.rglob("*.java"):
        rel = f.relative_to(base).as_posix()
        # keep only the app's own package tree
        if pkg_path and pkg_path not in rel:
            continue
        if any(rel.replace("/", ".").startswith(p) for p in exclude_prefixes):
            continue
        if any(pat in rel for pat in exclude_patterns):
            continue
        text = _METADATA_RE.sub("", f.read_text(errors="replace"))
        out.append(SourceFile(rel_path=rel, text=text))
    return out


def _collect_resources(root: Path) -> dict[str, str]:
    base = root / "resources" if (root / "resources").exists() else root
    res: dict[str, str] = {}
    candidates = [base / "res" / "values" / "strings.xml"]
    xml_dir = base / "res" / "xml"
    if xml_dir.exists():
        candidates += list(xml_dir.glob("*.xml"))
    for c in candidates:
        if c.exists():
            res[c.relative_to(base).as_posix()] = c.read_text(errors="replace")
    return res


def load_app(app_cfg: dict) -> AppBundle:
    root = _ensure_decompiled(Path(app_cfg["path"]))
    manifest_path = (root / "resources" / "AndroidManifest.xml")
    if not manifest_path.exists():
        manifest_path = root / "AndroidManifest.xml"

    manifest = _parse_manifest(manifest_path)
    sources = _collect_sources(
        root,
        manifest.package,
        app_cfg.get("exclude_package_prefixes", []),
        app_cfg.get("exclude_file_patterns", []),
    )
    resources = _collect_resources(root)
    return AppBundle(manifest=manifest, sources=sources, resources=resources)
