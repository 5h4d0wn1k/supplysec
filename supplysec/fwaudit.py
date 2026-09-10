"""Firmware audit — entropy analysis, embedded strings, hash advisory match."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class FirmwareReport:
    filename: str
    size_bytes: int
    entropy: float
    strings_found: list[str]
    embedded_versions: list[dict]
    hash_matches: list[dict]
    findings: list[dict]

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    strings: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def _find_versions(strings: list[str]) -> list[dict]:
    """Extract version-like strings."""
    import re
    versions: list[dict] = []
    version_patterns = [
        re.compile(r"v?(\d+\.\d+\.\d+)"),
        re.compile(r"version[=: ]+(\d+\.\d+\.\d+)"),
        re.compile(r"([\w.-]+)-(\d+\.\d+\.\d+)"),
    ]
    seen = set()
    for s in strings:
        for pat in version_patterns:
            m = pat.search(s)
            if m:
                ver = m.group(m.lastindex or 1)
                if ver not in seen:
                    seen.add(ver)
                    versions.append({"string": s.strip(), "version": ver})
                break
    return versions


def _hash_data(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def audit_firmware(
    firmware_path: str | Path,
    advisory_db_path: str | Path | None = None,
    version_hints: list[dict] | None = None,
) -> FirmwareReport:
    """Audit a firmware binary fixture."""
    fw_path = Path(firmware_path)
    data = fw_path.read_bytes()
    entropy = _calculate_entropy(data)
    strings = _extract_strings(data)
    versions = _find_versions(strings)
    hashes = _hash_data(data)

    findings: list[dict] = []

    if entropy > 7.5:
        findings.append({
            "type": "high_entropy",
            "severity": "warning",
            "message": f"High entropy ({entropy}) — possible encrypted/packed section",
        })
    elif entropy > 7.0:
        findings.append({
            "type": "moderate_entropy",
            "severity": "info",
            "message": f"Moderate entropy ({entropy}) — may contain compressed data",
        })

    for v in versions:
        findings.append({
            "type": "embedded_version",
            "severity": "info",
            "version": v["version"],
            "string": v["string"],
            "message": f"Embedded version string: {v['version']}",
        })

    hash_matches: list[dict] = []
    if advisory_db_path:
        adv_db = json.loads(Path(advisory_db_path).read_text())
        fw_advisories = adv_db.get("firmware_advisories", [])
        for fw_adv in fw_advisories:
            if hashes.get("sha256") == fw_adv.get("sha256"):
                hash_matches.append(fw_adv)
                findings.append({
                    "type": "hash_match",
                    "severity": fw_adv.get("severity", "critical"),
                    "cve": fw_adv.get("cve_id", ""),
                    "message": f"Hash match: {fw_adv.get('cve_id', 'unknown')} ({fw_adv.get('description', '')})",
                })

    return FirmwareReport(
        filename=fw_path.name,
        size_bytes=len(data),
        entropy=entropy,
        strings_found=strings[:50],
        embedded_versions=versions,
        hash_matches=hash_matches,
        findings=findings,
    )
