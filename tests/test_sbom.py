"""SBOM tests — CycloneDX/SPDX structure + round-trip parse."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.manifest import parse_manifest, Dependency  # noqa: E402
from supplysec.sbom import to_cyclonedx, to_spdx, write_sbom  # noqa: E402

CLEAN = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "manifests" / "clean"

SAMPLE_DEPS = [Dependency("urllib3", "2.2.3", "pypi", "requirements.txt"),
               Dependency("express", "4.19.2", "npm", "package.json"),
               Dependency("github.com/spf13/cobra", "1.8.0", "golang", "go.mod")]


def minimal_cdx_parse(doc):
    """Minimal CycloneDX parser: validate spec + return components."""
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] in ("1.4", "1.5")
    for c in doc["components"]:
        assert c["type"] == "library"
        assert c["name"]
        assert c["version"]
        assert c["bom-ref"]
        assert c["purl"].startswith("pkg:")
        if c["hashes"]:
            assert c["hashes"][0]["alg"] == "SHA-256"
            assert len(c["hashes"][0]["content"]) == 64
    return doc


class TestCycloneDX(unittest.TestCase):
    def test_spec_1_5(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        self.assertEqual(doc["specVersion"], "1.5")
        self.assertEqual(doc["bomFormat"], "CycloneDX")

    def test_spec_1_4(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.4")
        self.assertEqual(doc["specVersion"], "1.4")

    def test_round_trip(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        parsed = minimal_cdx_parse(doc)
        self.assertEqual(len(parsed["components"]), len(SAMPLE_DEPS))
        names = [c["name"] for c in parsed["components"]]
        self.assertIn("urllib3", names)

    def test_bom_ref_unique(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        refs = [c["bom-ref"] for c in doc["components"]]
        self.assertEqual(len(refs), len(set(refs)))

    def test_purl(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        urllib3 = [c for c in doc["components"] if c["name"] == "urllib3"][0]
        self.assertEqual(urllib3["purl"], "pkg:pypi/urllib3@2.2.3")

    def test_hashes(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        for c in doc["components"]:
            self.assertEqual(len(c["hashes"]), 1)
            self.assertEqual(c["hashes"][0]["alg"], "SHA-256")
            self.assertEqual(len(c["hashes"][0]["content"]), 64)

    def test_component_graph(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        props = doc["components"][0]["properties"]
        kinds = [p["name"] for p in props]
        self.assertIn("supplysec:ecosystem", kinds)
        self.assertIn("supplysec:source", kinds)

    def test_metadata_tooling(self):
        doc = to_cyclonedx(SAMPLE_DEPS, "1.5")
        tools = doc["metadata"]["tools"]
        self.assertEqual(tools[0]["name"], "supplysec")


class TestSPDX(unittest.TestCase):
    def test_spdx_version(self):
        doc = to_spdx(SAMPLE_DEPS, "2.3")
        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")

    def test_packages(self):
        doc = to_spdx(SAMPLE_DEPS, "2.3")
        self.assertEqual(len(doc["packages"]), len(SAMPLE_DEPS))
        urllib3 = [p for p in doc["packages"] if p["name"] == "urllib3"][0]
        self.assertEqual(urllib3["versionInfo"], "2.2.3")

    def test_relationships(self):
        doc = to_spdx(SAMPLE_DEPS, "2.3")
        rel_types = {r["relationshipType"] for r in doc["relationships"]}
        self.assertIn("CONTAINS", rel_types)
        self.assertEqual(len(doc["relationships"]), len(SAMPLE_DEPS))

    def test_external_refs_purl(self):
        doc = to_spdx(SAMPLE_DEPS, "2.3")
        urllib3 = [p for p in doc["packages"] if p["name"] == "urllib3"][0]
        refs = urllib3["externalRefs"]
        self.assertTrue(any(r["referenceLocator"].startswith("pkg:") for r in refs))

    def test_checksums(self):
        doc = to_spdx(SAMPLE_DEPS, "2.3")
        for p in doc["packages"]:
            self.assertEqual(p["checksums"][0]["algorithm"], "SHA256")


class TestWriteSBOM(unittest.TestCase):
    def test_writes_both(self):
        out = Path("/tmp/sbom_out_test")
        paths = write_sbom(SAMPLE_DEPS, out, "1.5", "2.3")
        self.assertTrue(paths["cyclonedx"].exists())
        self.assertTrue(paths["spdx"].exists())
        cdx = minimal_cdx_parse(__import__("json").loads(paths["cyclonedx"].read_text()))
        self.assertTrue(isinstance(cdx, dict))

    def test_reports_match_manifest(self):
        deps = parse_manifest(CLEAN / "requirements.txt")
        doc = to_cyclonedx(deps, "1.5")
        doc_names = sorted(c["name"] for c in doc["components"])
        manifest_names = sorted(d.name for d in deps)
        self.assertEqual(doc_names, manifest_names)


if __name__ == "__main__":
    unittest.main()