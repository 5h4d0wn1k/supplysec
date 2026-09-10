"""Advisory matching tests — vulnerable flagged, fixed versions NOT flagged."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.advisory import (  # noqa: E402
    Advisory,
    load_advisory_db,
    match_advisories,
)
from supplysec.manifest import Dependency  # noqa: E402

ADV_CHAIN = [
    Advisory(cve_id="CVE-2024-37891", package="urllib3", severity="critical",
             introduced="1.0.0", fixed="2.2.2"),
    Advisory(cve_id="CVE-2024-21667", package="urllib3", severity="high",
             introduced="1.0.0", fixed="2.0.7"),
]


class TestMatch(unittest.TestCase):
    def test_flags_vulnerable(self):
        deps = [Dependency("urllib3", "2.1.0", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        self.assertTrue(any(f.advisory.cve_id == "CVE-2024-37891" for f in findings))

    def test_does_not_flag_fixed(self):
        deps = [Dependency("urllib3", "2.2.3", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        self.assertEqual(len(findings), 0)

    def test_looks_like_fixed_not_flagged(self):
        """Version exactly equal to fixed version must NOT be flagged."""
        deps = [Dependency("urllib3", "2.2.2", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        self.assertEqual(len(findings), 0)

    def test_range_elusive_mid(self):
        """Version between introduced and fixed IS flagged."""
        deps = [Dependency("urllib3", "1.26.0", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        self.assertTrue(any(f.advisory.cve_id == "CVE-2024-37891" for f in findings))

    def test_introduced_inclusive(self):
        """Version equal to introduced version IS flagged."""
        adv = [Advisory(cve_id="CVE-X", package="foo", severity="high",
                        introduced="1.0.0", fixed="2.0.0")]
        deps = [Dependency("foo", "1.0.0", "pypi", "requirements.txt")]
        findings = match_advisories(deps, adv)
        self.assertEqual(len(findings), 1)

    def test_unrelated_package_not_flagged(self):
        deps = [Dependency("requests", "2.32.0", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        self.assertEqual(len(findings), 0)

    def test_severity_captured(self):
        deps = [Dependency("urllib3", "1.26.0", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        sevs = {f.advisory.severity for f in findings}
        self.assertIn("critical", sevs)
        self.assertIn("high", sevs)

    def test_multiple_findings_same_package(self):
        deps = [Dependency("urllib3", "1.26.0", "pypi", "requirements.txt")]
        findings = match_advisories(deps, ADV_CHAIN)
        self.assertEqual(len(findings), 2)


class TestAdvisoryDBFixture(unittest.TestCase):
    def test_load(self):
        db_path = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "advisory_db.json"
        advisories = load_advisory_db(db_path)
        self.assertGreater(len(advisories), 5)
        self.assertTrue(all(a.cve_id for a in advisories))

    def test_fixture_vuln_set_flag(self):
        db_path = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "advisory_db.json"
        vuln_dir = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "manifests" / "vuln"
        advisories = load_advisory_db(db_path)
        deps = []
        for m in (vuln_dir / "requirements.txt", vuln_dir / "package.json",
                  vuln_dir / "go.mod", vuln_dir / "pom.xml"):
            from supplysec.manifest import parse_manifest
            deps.extend(parse_manifest(m))
        findings = match_advisories(deps, advisories)
        flagged = {f.advisory.cve_id for f in findings}
        self.assertIn("CVE-2024-37891", flagged)
        self.assertIn("CVE-2025-0001", flagged)
        self.assertIn("CVE-2025-0002", flagged)

    def test_fixture_clean_set_clear(self):
        db_path = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "advisory_db.json"
        clean_dir = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "manifests" / "clean"
        advisories = load_advisory_db(db_path)
        from supplysec.manifest import parse_manifest
        deps = []
        for m in (clean_dir / "requirements.txt", clean_dir / "package.json",
                  clean_dir / "go.mod", clean_dir / "pom.xml"):
            deps.extend(parse_manifest(m))
        findings = match_advisories(deps, advisories)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()