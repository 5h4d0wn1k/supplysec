"""PQC scanner — detect small RSA keys, DSA, SHA-1, report PQC migration needs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PQCFindings:
    issues: list[dict]

    @property
    def has_issues(self) -> bool:
        return len(self.issues) > 0


def _check_rsa_key(key_data: dict) -> list[dict]:
    """Check RSA key for quantum-vulnerable sizes."""
    issues = []
    key_size = key_data.get("key_size_bits", 0)
    kid = key_data.get("id", "unknown")
    if key_size and key_size < 2048:
        issues.append({
            "type": "rsa_weak_key",
            "key_id": kid,
            "key_size_bits": key_size,
            "severity": "critical",
            "message": f"RSA-{key_size} is quantum-broken; migrate to ML-KEM/RSA-4096+",
            "recommendation": "Replace with ML-KEM-768 or RSA-4096 minimum",
        })
    elif key_size and key_size < 4096:
        issues.append({
            "type": "rsa_classical",
            "key_id": kid,
            "key_size_bits": key_size,
            "severity": "info",
            "message": f"RSA-{key_size} safe classically; plan PQC migration",
        })
    return issues


def _check_dsa_key(key_data: dict) -> list[dict]:
    """Flag DSA keys as quantum-vulnerable."""
    issues = []
    kid = key_data.get("id", "unknown")
    size = key_data.get("key_size_bits", 0)
    issues.append({
        "type": "dsa_vulnerable",
        "key_id": kid,
        "key_size_bits": size,
        "severity": "critical",
        "message": f"DSA-{size} broken by Shor's algorithm; migrate to Ed25519/ML-DSA",
        "recommendation": "Replace with ML-DSA-65 or Ed25519",
    })
    return issues


def _check_ecdsa_key(key_data: dict) -> list[dict]:
    """Flag small ECDSA keys."""
    issues = []
    kid = key_data.get("id", "unknown")
    curve = key_data.get("curve", "")
    size = key_data.get("key_size_bits", 0)
    if size and size < 256:
        issues.append({
            "type": "ecdsa_weak_curve",
            "key_id": kid,
            "curve": curve,
            "severity": "critical",
            "message": f"ECDSA {curve} ({size}-bit) too small; use P-384+ or ML-DSA",
            "recommendation": "Migrate to ML-DSA-65 or P-384 minimum",
        })
    elif size and size < 384:
        issues.append({
            "type": "ecdsa_small",
            "key_id": kid,
            "curve": curve,
            "severity": "warning",
            "message": f"ECDSA {curve} ({size}-bit) acceptable; plan PQC migration",
        })
    return issues


def _check_signature_algorithm(sig_alg: str, kid: str = "") -> list[dict]:
    """Check for SHA-1 usage."""
    issues = []
    if sig_alg and "sha1" in sig_alg.lower():
        issues.append({
            "type": "sha1_collision",
            "key_id": kid,
            "algorithm": sig_alg,
            "severity": "critical",
            "message": f"SHA-1 ({sig_alg}) collision-prone; migrate to SHA-384/SHA-512",
            "recommendation": "Use SHA-384 or SHA-512 minimum",
        })
    return issues


def scan_pqc(data_path: str | Path) -> PQCFindings:
    """Scan key/cert fixture for PQC issues."""
    data = json.loads(Path(data_path).read_text())
    all_issues: list[dict] = []

    for key in data.get("keys", []):
        ktype = key.get("type", "").lower()
        kid = key.get("id", "unknown")

        if ktype == "rsa":
            all_issues.extend(_check_rsa_key(key))
        elif ktype == "dsa":
            all_issues.extend(_check_dsa_key(key))
        elif ktype == "ecdsa":
            all_issues.extend(_check_ecdsa_key(key))

        sig_alg = key.get("signature_algorithm", "")
        if sig_alg:
            all_issues.extend(_check_signature_algorithm(sig_alg, kid))

    for cert in data.get("certificates", []):
        sig_alg = cert.get("signature_algorithm", "")
        kid = cert.get("id", "unknown")
        if sig_alg:
            all_issues.extend(_check_signature_algorithm(sig_alg, kid))

    return PQCFindings(issues=all_issues)
