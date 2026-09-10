"""Manifest parser tests — each supported format."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.manifest import (  # noqa: E402
    parse_requirements_txt,
    parse_package_json,
    parse_go_mod,
    parse_pom_xml,
    parse_gemfile_lock,
    parse_manifest,
)

CLEAN = Path(__file__).resolve().parents[1] / "supplysec" / "fixtures" / "manifests" / "clean"


class TestRequirementsTxt(unittest.TestCase):
    def setUp(self):
        self.deps = parse_requirements_txt(CLEAN / "requirements.txt")

    def test_basic(self):
        names = [d.name for d in self.deps]
        self.assertIn("urllib3", names)
        self.assertIn("jinja2", names)
        self.assertIn("django", names)

    def test_version(self):
        urllib3 = [d for d in self.deps if d.name == "urllib3"][0]
        self.assertEqual(urllib3.version, "2.2.3")

    def test_ecosystem(self):
        for d in self.deps:
            self.assertEqual(d.ecosystem, "pypi")

    def test_ignores_comments(self):
        tmp = Path("/tmp/req_with_comments.txt")
        tmp.write_text("# comment\nurllib3==2.0.0\n-j base.txt\nrequests==2.32.0\n")
        deps = parse_requirements_txt(tmp)
        names = [d.name for d in deps]
        self.assertNotIn("# comment", names)
        self.assertEqual(names, ["urllib3", "requests"])

    def test_pep503_normalisation(self):
        tmp = Path("/tmp/req_dash.txt")
        tmp.write_text("backports_ssl-match-hostname==3.7.0\n")
        deps = parse_requirements_txt(tmp)
        self.assertEqual(deps[0].name, "backports-ssl-match-hostname")


class TestPackageJson(unittest.TestCase):
    def setUp(self):
        self.deps = parse_package_json(CLEAN / "package.json")

    def test_dependencies_and_dev(self):
        names = [d.name for d in self.deps]
        self.assertIn("express", names)
        self.assertIn("axios", names)
        self.assertIn("lodash", names)

    def test_version(self):
        express = [d for d in self.deps if d.name == "express"][0]
        self.assertEqual(express.version, "4.19.2")

    def test_caret_stripped(self):
        axios = [d for d in self.deps if d.name == "axios"][0]
        self.assertEqual(axios.version, "1.7.2")


class TestGoMod(unittest.TestCase):
    def setUp(self):
        self.deps = parse_go_mod(CLEAN / "go.mod")

    def test_require_block(self):
        names = [d.name for d in self.deps]
        self.assertIn("github.com/spf13/cobra", names)

    def test_v_prefix_stripped(self):
        cobra = [d for d in self.deps if d.name == "github.com/spf13/cobra"][0]
        self.assertEqual(cobra.version, "1.8.0")

    def test_ecosystem(self):
        for d in self.deps:
            self.assertEqual(d.ecosystem, "golang")

    def test_single_line_require(self):
        tmp = Path("/tmp/single_go.mod")
        tmp.write_text("module lab\n\nrequire gopkg.in/yaml.v3 v3.0.2\n")
        deps = parse_go_mod(tmp)
        self.assertEqual([d.version for d in deps], ["3.0.2"])


class TestPomXml(unittest.TestCase):
    def setUp(self):
        self.deps = parse_pom_xml(CLEAN / "pom.xml")

    def test_gav(self):
        names = [d.name for d in self.deps]
        self.assertIn("com.fasterxml.jackson.core/jackson-databind", names)

    def test_version(self):
        jackson = [d for d in self.deps if d.name == "com.fasterxml.jackson.core/jackson-databind"][0]
        self.assertEqual(jackson.version, "2.17.0")

    def test_ecosystem(self):
        for d in self.deps:
            self.assertEqual(d.ecosystem, "maven")


class TestGemfileLock(unittest.TestCase):
    def setUp(self):
        self.deps = parse_gemfile_lock(CLEAN / "Gemfile.lock")

    def test_specs(self):
        names = [d.name for d in self.deps]
        self.assertIn("actionpack", names)

    def test_version(self):
        actionpack = [d for d in self.deps if d.name == "actionpack"][0]
        self.assertEqual(actionpack.version, "7.1.3")


class TestAutoDetect(unittest.TestCase):
    def test_unsupported(self):
        tmp = Path("/tmp/unknown.manifest")
        tmp.write_text("whatever")
        with self.assertRaises(ValueError):
            parse_manifest(tmp)

    def test_pyproject_unsupported(self):
        tmp = Path("/tmp/pyproject.toml")
        tmp.write_text("[project]")
        with self.assertRaises(ValueError):
            parse_manifest(tmp)

    def test_auto(self):
        deps = parse_manifest(CLEAN / "requirements.txt")
        self.assertGreater(len(deps), 0)


if __name__ == "__main__":
    unittest.main()