"""License scanner — wraps fixture license texts, policy allow/deny gate."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class LicenseInfo:
    package: str
    detected_license: str
    source_file: str


@dataclass
class LicenseCheck:
    package: str
    detected_license: str
    allowed: bool
    reason: str = ""


LICENSE_DB_PATH = None


def load_license_db(path: str | Path) -> dict[str, str]:
    """Load license mapping {package_name: license_id}."""
    data = json.loads(Path(path).read_text())
    return data.get("licenses", data) if isinstance(data, dict) else {}


def scan_licenses(deps: list, license_db: dict[str, str]) -> list[LicenseInfo]:
    """Scan dependencies against license database."""
    results: list[LicenseInfo] = []
    for dep in deps:
        lic = license_db.get(dep.name.lower(), license_db.get(dep.name, "unknown"))
        results.append(LicenseInfo(
            package=dep.name,
            detected_license=lic,
            source_file=dep.source_file,
        ))
    return results


def check_license_policy(
    license_infos: list[LicenseInfo],
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
    strict_mode: bool = False,
) -> list[LicenseCheck]:
    """Check licenses against allow/deny policy. Returns check results."""
    denied_set = set(d.lower() for d in (denied or []))
    allowed_set = set(a.lower() for a in (allowed or []))
    results: list[LicenseCheck] = []

    for li in license_infos:
        lic_lower = li.detected_license.lower()
        allowed = True
        reason = ""

        if lic_lower in denied_set:
            allowed = False
            reason = f"License '{li.detected_license}' is in deny list"
        elif strict_mode and lic_lower == "unknown":
            allowed = False
            reason = "Unknown license denied in strict mode"
        elif allowed_set and lic_lower not in allowed_set:
            allowed = False
            reason = f"License '{li.detected_license}' not in allow list"

        results.append(LicenseCheck(
            package=li.package,
            detected_license=li.detected_license,
            allowed=allowed,
            reason=reason,
        ))
    return results
