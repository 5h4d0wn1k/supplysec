"""Firmware audit tests — entropy, strings, versions, advisory hash match."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.fwaudit import (  # noqa: E402
    audit_firmware,
    _calculate_entropy,
    _extract_strings,
)

FW = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "firmware" / "sample_fw.bin"
ADV_DB = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "advisory_db.json"


class TestFunctions(unittest.TestCase):
    def test_entropy_zero_for_constant(self):
        self.assertAlmostEqual(_calculate_entropy(b"\x00" * 100), 0.0)

    def test_entropy_one_for_uniform(self):
        data = bytes(range(256)) * 4
        self.assertAlmostEqual(_calculate_entropy(data), 8.0, places=2)

    def test_strings_extracted(self):
        data = b"secureboot v2\0hello world\0binary\xff\xfe junk"
        strings = _extract_strings(data)
        self.assertIn("hello world", strings)


class TestFixtures(unittest.TestCase):
    def test_fixture_flagged(self):
        report = audit_firmware(FW, ADV_DB)
        self.assertTrue(report.has_findings)
        self.assertGreater(len(report.findings), 0)

    def test_hash_match_advisory(self):
        report = audit_firmware(FW, ADV_DB)
        self.assertEqual(len(report.hash_matches), 1)
        self.assertEqual(report.hash_matches[0]["cve_id"], "FW-2024-001")

    def test_version_strings(self):
        report = audit_firmware(FW, ADV_DB)
        versions = [v["version"] for v in report.embedded_versions]
        self.assertIn("1.2.3", versions)

    def test_size_and_entropy(self):
        report = audit_firmware(FW, ADV_DB)
        self.assertEqual(report.size_bytes, len(FW.read_bytes()))
        self.assertGreater(report.entropy, 0.0)

    def test_strings_mined(self):
        report = audit_firmware(FW, ADV_DB)
        self.assertGreater(len(report.strings_found), 3)

    def test_no_hash_db_still_analyses(self):
        report = audit_firmware(FW, None)
        self.assertEqual(len(report.hash_matches), 0)
        self.assertGreater(len(report.embedded_versions), 0)


if __name__ == "__main__":
    unittest.main()