"""Advisory matcher — offline advisory DB, CVE matching with version-range + fixed-in logic."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _version_tuple(v: str) -> tuple:
    """Convert version string to comparable tuple."""
    parts: list = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(p)
    return tuple(parts)


def _version_in_range(ver: str, introduced: str, fixed: str) -> bool:
    """Check if ver is in range [introduced, fixed)."""
    vt = _version_tuple(ver)
    try:
        it = _version_tuple(introduced)
        ft = _version_tuple(fixed)
        return it <= vt < ft
    except Exception:
        return False


@dataclass
class Advisory:
    cve_id: str
    package: str
    severity: str
    introduced: str
    fixed: str
    advisory_url: str = ""
    description: str = ""
    patch_state: str = "available"

    @property
    def fixed_versions(self) -> list[str]:
        return [self.fixed] if self.fixed else []


@dataclass
class Finding:
    advisory: Advisory
    affected_version: str
    is_fixed: bool = False


def load_advisory_db(path: str | Path) -> list[Advisory]:
    """Load advisory database from JSON fixture."""
    data = json.loads(Path(path).read_text())
    advisories: list[Advisory] = []
    for entry in data.get("advisories", data if isinstance(data, list) else []):
        advisories.append(Advisory(
            cve_id=entry["cve_id"],
            package=entry["package"],
            severity=entry.get("severity", "unknown"),
            introduced=entry.get("introduced", "0"),
            fixed=entry.get("fixed", ""),
            advisory_url=entry.get("advisory_url", ""),
            description=entry.get("description", ""),
            patch_state=entry.get("patch_state", "available"),
        ))
    return advisories


def match_advisories(
    deps: list,
    advisories: list[Advisory],
) -> list[Finding]:
    """Match dependency list against advisory DB. Returns findings."""
    findings: list[Finding] = []
    dep_map = {}
    for d in deps:
        key = d.name.lower()
        if key not in dep_map:
            dep_map[key] = []
        dep_map[key].append(d)

    for adv in advisories:
        pkg_key = adv.package.lower()
        for dep in dep_map.get(pkg_key, []):
            if _version_in_range(dep.version, adv.introduced, adv.fixed):
                is_fixed = False
                if adv.fixed:
                    try:
                        if _version_tuple(dep.version) >= _version_tuple(adv.fixed):
                            is_fixed = True
                    except Exception:
                        pass
                if not is_fixed:
                    findings.append(Finding(
                        advisory=adv,
                        affected_version=dep.version,
                        is_fixed=is_fixed,
                    ))
    return findings
