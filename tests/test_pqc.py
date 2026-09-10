"""PQC scanner tests — 512-bit RSA flagged, 2048 not, SHA-1 flagged."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.pqc import (  # noqa: E402
    scan_pqc,
    _check_rsa_key,
    _check_signature_algorithm,
)

KEYS = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "keys" / "sample_keys.json"


class TestRSA(unittest.TestCase):
    def test_512_flagged(self):
        result = _check_rsa_key({"id": "k", "key_size_bits": 512})
        self.assertTrue(any(i["type"] == "rsa_weak_key" for i in result))
        self.assertEqual(result[0]["severity"], "critical")

    def test_2048_not_weak(self):
        result = _check_rsa_key({"id": "k", "key_size_bits": 2048})
        types = [i["type"] for i in result]
        self.assertNotIn("rsa_weak_key", types)
        self.assertIn("rsa_classical", types)

    def test_4096_no_issue(self):
        result = _check_rsa_key({"id": "k", "key_size_bits": 4096})
        self.assertEqual(result, [])


class TestSHA1(unittest.TestCase):
    def test_sha1_flagged(self):
        result = _check_signature_algorithm("sha1WithRSAEncryption", "cert1")
        self.assertTrue(result)
        self.assertEqual(result[0]["severity"], "critical")

    def test_sha256_ok(self):
        result = _check_signature_algorithm("sha256WithRSAEncryption", "cert1")
        self.assertEqual(result, [])


class TestFixtureScan(unittest.TestCase):
    def test_full_scan_flags_fixture(self):
        result = scan_pqc(KEYS)
        self.assertTrue(result.has_issues)

    def test_fixture_512_key_flagged(self):
        result = scan_pqc(KEYS)
        weak = [i for i in result.issues if i["type"] == "rsa_weak_key"]
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0]["key_size_bits"], 512)
        self.assertEqual(weak[0]["key_id"], "old-root-rsa-512")

    def test_fixture_2048_not_weak(self):
        result = scan_pqc(KEYS)
        enough = [i for i in result.issues if i["key_id"] == "server-rsa-2048"]
        self.assertEqual(len(enough), 1)
        self.assertEqual(enough[0]["type"], "rsa_classical")

    def test_fixture_dsa_flagged(self):
        result = scan_pqc(KEYS)
        dsa = [i for i in result.issues if i["type"] == "dsa_vulnerable"]
        self.assertTrue(dsa)
        self.assertEqual(dsa[0]["key_id"], "legacy-dsa-1024")

    def test_fixture_ecdsa_not_small(self):
        result = scan_pqc(KEYS)
        p521 = [i for i in result.issues if i["key_id"] == "ecdsa-p521"]
        self.assertEqual(p521, [])

    def test_fixture_sha1_cert_flagged(self):
        result = scan_pqc(KEYS)
        sha1 = [i for i in result.issues if i.get("key_id") == "legacy-web-cert"]
        self.assertTrue(any(i["type"] == "sha1_collision" for i in sha1))


if __name__ == "__main__":
    unittest.main()