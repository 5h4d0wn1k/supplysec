"""Shared test helpers."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "supplysec" / "fixtures"

CLEAN_DIR = FIXTURES / "manifests" / "clean"
VULN_DIR = FIXTURES / "manifests" / "vuln"

ADVISORY_DB = FIXTURES / "advisory_db.json"
LICENSE_DB = FIXTURES / "licenses.json"
POLICY = FIXTURES / "policy.json"
POLICY_STRICT = FIXTURES / "policy-strict.json"
KEYS = FIXTURES / "keys" / "sample_keys.json"
FIRMWARE = FIXTURES / "firmware" / "sample_fw.bin"