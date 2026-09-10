"""Policy gate tests — exit codes 0/1/2 rules."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.advisory import Advisory  # noqa: E402
from supplysec.license import LicenseCheck  # noqa: E402
from supplysec.manifest import Dependency  # noqa: E402
from supplysec.policy import (  # noqa: E402
    PolicyRule,
    evaluate_gate,
    EXIT_PASS,
    EXIT_FAIL_DENIED,
    EXIT_FAIL_POLICY,
    load_policy,
)


def make_finding(severity, cve="CVE-X", pkg="urllib3", ver="1.0.0"):
    adv = Advisory(cve_id=cve, package=pkg, severity=severity,
                   introduced="0", fixed="9.9.9")
    return type("F", (), {"advisory": adv, "affected_version": ver})()


class TestGate(unittest.TestCase):
    def test_clean_pass_exit_0(self):
        gate = evaluate_gate([], [], PolicyRule())
        self.assertTrue(gate.passed)
        self.assertEqual(gate.exit_code, EXIT_PASS)

    def test_critical_deny_exit_1(self):
        gate = evaluate_gate([make_finding("critical")], [], PolicyRule())
        self.assertFalse(gate.passed)
        self.assertEqual(gate.exit_code, EXIT_FAIL_DENIED)

    def test_critical_disabled_allows(self):
        gate = evaluate_gate([make_finding("critical")], [],
                             PolicyRule(cve_critical_deny=False))
        self.assertEqual(gate.exit_code, EXIT_PASS)

    def test_high_warn_exit_0(self):
        gate = evaluate_gate([make_finding("high")], [], PolicyRule())
        self.assertEqual(gate.exit_code, EXIT_PASS)
        self.assertGreaterEqual(len(gate.warnings), 1)

    def test_medium_warn_only_when_enabled(self):
        gate = evaluate_gate([make_finding("medium", cve="CVE-M")], [],
                             PolicyRule(cve_medium_warn=True))
        self.assertEqual(gate.exit_code, EXIT_PASS)
        self.assertIn("CVE-M", gate.warnings[0]["cve"])
        gate2 = evaluate_gate([make_finding("medium", cve="CVE-M")], [], PolicyRule())
        self.assertEqual(len(gate2.warnings), 0)

    def test_license_deny_exit_1(self):
        checks = [LicenseCheck("scapy", "GPL-3.0", allowed=False, reason="deny list")]
        gate = evaluate_gate([], checks, PolicyRule())
        self.assertEqual(gate.exit_code, EXIT_FAIL_DENIED)

    def test_unpinned_version_violation(self):
        deps = [Dependency("requests", "2.32.3", "pypi", "f"),
                Dependency("flask", "", "pypi", "f")]
        gate = evaluate_gate([], [], PolicyRule(), deps=deps)
        self.assertEqual(gate.exit_code, EXIT_FAIL_DENIED)
        types = {v["type"] for v in gate.violations}
        self.assertIn("version_unpinned", types)

    def test_unknown_version_deny(self):
        deps = [Dependency("x", "unknown", "pypi", "f")]
        gate = evaluate_gate([], [], PolicyRule(), deps=deps)
        types = {v["type"] for v in gate.violations}
        self.assertIn("version_unknown", types)

    def test_violation_count(self):
        findings = [make_finding("critical", cve="CVE-1"),
                    make_finding("critical", cve="CVE-2")]
        gate = evaluate_gate(findings, [], PolicyRule())
        self.assertEqual(len(gate.violations), 2)


class TestPolicyLoad(unittest.TestCase):
    def test_load_json(self):
        path = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "policy.json"
        policy = load_policy(path)
        self.assertTrue(policy.cve_critical_deny)
        self.assertTrue(policy.cve_high_warn)
        self.assertIn("GPL-3.0", policy.license_deny)

    def test_load_strict(self):
        path = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "policy-strict.json"
        policy = load_policy(path)
        self.assertTrue(policy.cve_medium_warn)
        self.assertIn("unknown", policy.license_deny)


if __name__ == "__main__":
    unittest.main()