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

class TestFailClosedOnMissingInputs(unittest.TestCase):
    """#13: a gate that answers PASS over inputs it never read is worse than no gate."""

    def test_advisory_missing_manifest_fails_closed(self):
        proc = run_cli("advisory", "/nonexistent-manifest.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("ERROR: manifest not found: /nonexistent-manifest.txt", proc.stderr)

    def test_license_missing_manifest_fails_closed(self):
        proc = run_cli("license", "/nonexistent-manifest.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("ERROR: manifest not found: /nonexistent-manifest.txt", proc.stderr)

    def test_policy_missing_manifest_fails_closed(self):
        proc = run_cli("policy", "/nonexistent-manifest.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("ERROR: manifest not found: /nonexistent-manifest.txt", proc.stderr)
        self.assertNotIn("PASS", proc.stdout)

    def test_sbom_missing_manifest_fails_closed(self):
        proc = run_cli("sbom", "/nonexistent-manifest.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("ERROR: manifest not found: /nonexistent-manifest.txt", proc.stderr)

    def test_report_missing_manifest_writes_nothing(self):
        out = Path("/tmp/reports_missing_manifest")
        if out.exists():
            import shutil
            shutil.rmtree(out)  # a previous run's artifact must not answer this test
        proc = run_cli("report", "/nonexistent-manifest.txt", "-o", str(out))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("ERROR: manifest not found: /nonexistent-manifest.txt", proc.stderr)
        self.assertFalse(out.exists(), "a PASS report artifact must not be written for an unread input")

    def test_one_missing_manifest_among_real_ones_fails_closed(self):
        real = str(CLEAN / "requirements.txt")
        proc = run_cli("policy", real, "/nonexistent-manifest.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("ERROR: manifest not found: /nonexistent-manifest.txt", proc.stderr)

    def test_an_empty_manifest_fails_closed_too(self):
        # The parsers are keyed by manifest name, so the empty file must be
        # a real requirements.txt.
        empty_dir = Path("/tmp/ss_empty_manifest")
        empty_dir.mkdir(parents=True, exist_ok=True)
        (empty_dir / "requirements.txt").write_text("# no dependencies here\n")
        empty = str(empty_dir / "requirements.txt")
        for sub in ("advisory", "license", "policy"):
            proc = run_cli(sub, empty)
            self.assertEqual(proc.returncode, 1, f"{sub}: {proc.stdout}{proc.stderr}")
            self.assertIn("ERROR: no dependencies found", proc.stderr)
