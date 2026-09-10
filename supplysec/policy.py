"""Policy gate — CVE severity deny, license deny list, version pinning, unknown deny. CI exit codes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


EXIT_PASS = 0
EXIT_FAIL_DENIED = 1
EXIT_FAIL_POLICY = 2


@dataclass
class PolicyRule:
    cve_critical_deny: bool = True
    cve_high_warn: bool = True
    cve_medium_warn: bool = False
    license_deny: list[str] = field(default_factory=list)
    version_pinning_require: bool = True
    package_version_unknown_deny: bool = True


@dataclass
class GateResult:
    passed: bool
    exit_code: int
    violations: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    summary: str = ""


def load_policy(path: str | Path) -> PolicyRule:
    """Load policy config from JSON/YAML file."""
    p = Path(path)
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(text)
        except ImportError:
            data = json.loads(text) if text.strip().startswith("{") else {}
    else:
        data = json.loads(text)
    return PolicyRule(
        cve_critical_deny=data.get("cve_critical_deny", True),
        cve_high_warn=data.get("cve_high_warn", True),
        cve_medium_warn=data.get("cve_medium_warn", False),
        license_deny=data.get("license_deny", []),
        version_pinning_require=data.get("version_pinning_require", True),
        package_version_unknown_deny=data.get("package_version_unknown_deny", True),
    )


def evaluate_gate(
    findings: list,
    license_checks: list,
    policy: PolicyRule,
    deps: list | None = None,
) -> GateResult:
    """Evaluate policy gate against findings and license checks."""
    violations: list[dict] = []
    warnings: list[dict] = []

    for f in findings:
        sev = f.advisory.severity.lower()
        if sev == "critical" and policy.cve_critical_deny:
            violations.append({
                "type": "cve_deny",
                "severity": sev,
                "cve": f.advisory.cve_id,
                "package": f.advisory.package,
                "version": f.affected_version,
                "message": f"Critical CVE {f.advisory.cve_id} → DENY",
            })
        elif sev == "high" and policy.cve_high_warn:
            warnings.append({
                "type": "cve_warn",
                "severity": sev,
                "cve": f.advisory.cve_id,
                "package": f.advisory.package,
                "message": f"High CVE {f.advisory.cve_id} → WARNING",
            })
        elif sev == "medium" and policy.cve_medium_warn:
            warnings.append({
                "type": "cve_warn",
                "severity": sev,
                "cve": f.advisory.cve_id,
                "package": f.advisory.package,
                "message": f"Medium CVE {f.advisory.cve_id} → WARNING",
            })

    for lc in license_checks:
        if not lc.allowed:
            violations.append({
                "type": "license_deny",
                "package": lc.package,
                "license": lc.detected_license,
                "message": lc.reason or f"License {lc.detected_license} denied",
            })

    if deps and policy.version_pinning_require:
        for dep in deps:
            if not dep.version or dep.version == "*":
                violations.append({
                    "type": "version_unpinned",
                    "package": dep.name,
                    "message": f"Unpinned version for {dep.name}",
                })

    if deps and policy.package_version_unknown_deny:
        for dep in deps:
            if not dep.version or dep.version in ("", "unknown", "*"):
                violations.append({
                    "type": "version_unknown",
                    "package": dep.name,
                    "message": f"Unknown version for {dep.name}",
                })

    if violations:
        exit_code = EXIT_FAIL_DENIED
        summary = f"FAIL: {len(violations)} violation(s), {len(warnings)} warning(s)"
    elif warnings:
        exit_code = EXIT_PASS
        summary = f"PASS with {len(warnings)} warning(s)"
    else:
        exit_code = EXIT_PASS
        summary = "PASS: no violations"

    return GateResult(
        passed=(exit_code == EXIT_PASS),
        exit_code=exit_code,
        violations=violations,
        warnings=warnings,
        summary=summary,
    )
