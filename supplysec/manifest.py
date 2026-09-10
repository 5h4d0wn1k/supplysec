"""Manifest parser — parses requirements.txt, package.json, go.mod, pom.xml, Gemfile.lock."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    source_file: str
    purl: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.purl:
            self.purl = f"pkg:{self.ecosystem}/{self.name}@{self.version}"


def _normalise_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, [-_.]+ → -."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def parse_requirements_txt(path: Path) -> list[Dependency]:
    """Parse a pip requirements.txt (pinned lines only)."""
    deps: list[Dependency] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-.]+)\s*==\s*(.+)$", line)
        if m:
            deps.append(Dependency(
                name=_normalise_name(m.group(1)),
                version=m.group(2).strip(),
                ecosystem="pypi",
                source_file=str(path),
            ))
    return deps


def parse_package_json(path: Path) -> list[Dependency]:
    """Parse a Node package.json (dependencies + devDependencies)."""
    import json
    data = json.loads(path.read_text())
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            ver_clean = ver.lstrip("^~>=<!")
            deps.append(Dependency(
                name=name,
                version=ver_clean,
                ecosystem="npm",
                source_file=str(path),
            ))
    return deps


def parse_go_mod(path: Path) -> list[Dependency]:
    """Parse a go.mod (require block lines)."""
    deps: list[Dependency] = []
    in_require = False
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")":
            in_require = False
            continue
        if in_require:
            parts = stripped.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                deps.append(Dependency(
                    name=parts[0],
                    version=parts[1].lstrip("v"),
                    ecosystem="golang",
                    source_file=str(path),
                ))
        elif stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 3:
                deps.append(Dependency(
                    name=parts[1],
                    version=parts[2].lstrip("v"),
                    ecosystem="golang",
                    source_file=str(path),
                ))
    return deps


def parse_pom_xml(path: Path) -> list[Dependency]:
    """Parse a Maven pom.xml <dependencies> block."""
    tree = ET.parse(path)
    root = tree.getroot()
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    deps: list[Dependency] = []
    for dep_el in root.iter(f"{ns}dependency"):
        gid = dep_el.findtext(f"{ns}groupId", "").strip()
        aid = dep_el.findtext(f"{ns}artifactId", "").strip()
        ver = dep_el.findtext(f"{ns}version", "").strip()
        if aid and ver:
            name = f"{gid}/{aid}" if gid else aid
            deps.append(Dependency(
                name=name,
                version=ver,
                ecosystem="maven",
                source_file=str(path),
            ))
    return deps


def parse_gemfile_lock(path: Path) -> list[Dependency]:
    """Parse a Gemfile.lock (specs: blocks)."""
    deps: list[Dependency] = []
    in_specs = False
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs:
            if not stripped or stripped.startswith("(") or stripped.startswith(")") or not line.startswith("    "):
                in_specs = False
                if not stripped:
                    continue
            m = re.match(r"^\s{4}(\S+)\s+\((.+)\)", line)
            if m:
                deps.append(Dependency(
                    name=m.group(1).lower(),
                    version=m.group(2).strip(),
                    ecosystem="gem",
                    source_file=str(path),
                ))
    return deps


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
    "pom.xml": parse_pom_xml,
    "Gemfile.lock": parse_gemfile_lock,
}


def parse_manifest(path: str | Path) -> list[Dependency]:
    """Auto-detect format and parse manifest file."""
    p = Path(path)
    parser = PARSERS.get(p.name)
    if parser is None:
        raise ValueError(f"Unsupported manifest: {p.name}")
    return parser(p)
