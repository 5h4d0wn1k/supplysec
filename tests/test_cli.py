"""CLI integration tests — exit codes for subcommands + demo."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "supplysec" / "fixtures"
CLEAN = FIXTURES / "manifests" / "clean"
VULN = FIXTURES / "manifests" / "vuln"


def run_cli(*args, cwd=None):
    proc = subprocess.run(
        [sys.executable, "-m", "supplysec", *args],
        cwd=cwd or str(REPO),
        capture_output=True,
        text=True,
    )
    return proc


class TestDemo(unittest.TestCase):
    def test_demo_pass_exit_0(self):
        proc = run_cli("demo", "-o", "/tmp/reports_demo_pass")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_demo_fail_cve_exit_1(self):
        proc = run_cli("demo", "--mode", "fail-cve", "-o", "/tmp/reports_demo_fail")
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_demo_fail_report_shows_deny(self):
        out = Path("/tmp/reports_demo_fail")
        report = json.loads((out / "report.json").read_text())
        self.assertFalse(report["gate"]["passed"])
        self.assertEqual(report["gate"]["exit_code"], 1)

    def test_demo_pass_report_clean(self):
        out = Path("/tmp/reports_demo_pass")
        report = json.loads((out / "report.json").read_text())
        self.assertTrue(report["gate"]["passed"])
        self.assertEqual(report["gate"]["exit_code"], 0)


class TestSubcommands(unittest.TestCase):
    def test_manifest_exit_0(self):
        proc = run_cli("manifest", str(CLEAN / "requirements.txt"), "-o", "/tmp/r_manifest")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        deps = json.loads((Path("/tmp/r_manifest") / "manifest_deps.json").read_text())
        self.assertGreater(len(deps), 0)

    def test_manifest_missing_error(self):
        proc = run_cli("manifest", "/nonexistent/req.txt")
        self.assertEqual(proc.returncode, 1)

    def test_sbom_writes_files(self):
        proc = run_cli("sbom", str(CLEAN / "requirements.txt"), "-o", "/tmp/r_sbom")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((Path("/tmp/r_sbom") / "bom-cyclonedx.json").exists())
        self.assertTrue((Path("/tmp/r_sbom") / "sbom-spdx.json").exists())

    def test_advisory_clean_exit_0(self):
        proc = run_cli("advisory", str(CLEAN / "requirements.txt"),
                       "--advisory-db", str(FIXTURES / "advisory_db.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_advisory_vuln_exit_1(self):
        proc = run_cli("advisory", str(VULN / "requirements.txt"),
                       "--advisory-db", str(FIXTURES / "advisory_db.json"))
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_policy_clean_exit_0(self):
        proc = run_cli("policy", str(CLEAN / "requirements.txt"), str(CLEAN / "package.json"))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_policy_vuln_exit_1(self):
        proc = run_cli("policy", str(VULN / "requirements.txt"), str(VULN / "package.json"))
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_report_gate_written(self):
        proc = run_cli("report", str(CLEAN / "requirements.txt"), "-o", "/tmp/r_report")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((Path("/tmp/r_report") / "report.json").exists())
        self.assertTrue((Path("/tmp/r_report") / "report.md").exists())

    def test_pqc_flags_fixture(self):
        proc = run_cli("pqc", "--data", str(FIXTURES / "keys" / "sample_keys.json"))
        self.assertEqual(proc.returncode, 1, proc.stdout)

    def test_fwaudit_flags_fixture(self):
        proc = run_cli("fwaudit", "--firmware", str(FIXTURES / "firmware" / "sample_fw.bin"))
        self.assertEqual(proc.returncode, 1, proc.stdout)

    def test_version_flag(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()