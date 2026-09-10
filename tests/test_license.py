"""License scan tests — detection, allow/deny, strict gate."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.license import (  # noqa: E402
    LicenseInfo,
    load_license_db,
    scan_licenses,
    check_license_policy,
)
from supplysec.manifest import Dependency  # noqa: E402


class TestDetection(unittest.TestCase):
    def test_detect_mit(self):
        lic_db = {"urllib3": "MIT"}
        deps = [Dependency("urllib3", "2.2.3", "pypi", "requirements.txt")]
        infos = scan_licenses(deps, lic_db)
        self.assertEqual(infos[0].detected_license, "MIT")

    def test_detect_unknown(self):
        lic_db = {"urllib3": "MIT"}
        deps = [Dependency("unknownpkg", "1.0.0", "pypi", "requirements.txt")]
        infos = scan_licenses(deps, lic_db)
        self.assertEqual(infos[0].detected_license, "unknown")

    def test_full_fixture_scan(self):
        db_path = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "licenses.json"
        lic_db = load_license_db(db_path)
        deps = [Dependency("urllib3", "2.2.3", "pypi", "requirements.txt"),
                Dependency("express", "4.19.2", "npm", "package.json")]
        infos = scan_licenses(deps, lic_db)
        self.assertEqual({i.detected_license for i in infos}, {"MIT"})


class TestPolicy(unittest.TestCase):
    def test_deny_gpl_fails(self):
        infos = [LicenseInfo("scapy", "GPL-3.0", "requirements.txt")]
        checks = check_license_policy(infos, denied=["GPL-3.0", "AGPL-3.0"])
        self.assertFalse(checks[0].allowed)

    def test_allowlist(self):
        infos = [LicenseInfo("a", "MIT", "f"), LicenseInfo("b", "GPL-3.0", "f")]
        checks = check_license_policy(infos, allowed=["MIT"])
        self.assertTrue(checks[0].allowed)
        self.assertFalse(checks[1].allowed)

    def test_strict_unknown_fails(self):
        infos = [LicenseInfo("mystery", "unknown", "f")]
        checks = check_license_policy(infos, strict_mode=True)
        self.assertFalse(checks[0].allowed)

    def test_non_strict_unknown_passes(self):
        infos = [LicenseInfo("mystery", "unknown", "f")]
        checks = check_license_policy(infos, strict_mode=False)
        self.assertTrue(checks[0].allowed)

    def test_mit_allowed_default(self):
        infos = [LicenseInfo("k", "MIT", "f")]
        checks = check_license_policy(infos)
        self.assertTrue(checks[0].allowed)

    def test_deny_flag_reason(self):
        infos = [LicenseInfo("scapy", "GPL-3.0", "f")]
        checks = check_license_policy(infos, denied=["GPL-3.0"])
        self.assertIn("deny", checks[0].reason.lower())


if __name__ == "__main__":
    unittest.main()