"""Report tests — JSON + Markdown with gate decision."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from supplysec.report import (  # noqa: E402
    generate_json_report,
    generate_markdown_report,
    write_report,
)
from supplysec.sbom import to_cyclonedx  # noqa: E402
from supplysec.manifest import Dependency  # noqa: E402

DEPS = [Dependency("urllib3", "2.2.3", "pypi", "requirements.txt")]


class TestJSONReport(unittest.TestCase):
    def test_structure(self):
        r = generate_json_report(
            sbom_cdx=to_cyclonedx(DEPS),
            findings=[{"severity": "critical", "cve": "CVE-2024-37891",
                       "package": "urllib3", "version": "2.1.0", "message": "x"}],
            gate_result={"passed": False, "exit_code": 1, "summary": "FAIL"},
        )
        self.assertEqual(gate := r["gate"], {"passed": False, "exit_code": 1, "summary": "FAIL"})
        self.assertEqual(r["sbom"]["cyclonedx"]["specVersion"], "1.5")
        self.assertEqual(len(r["advisory_findings"]), 1)

    def test_writrept_outcomes(self):
        r = write_report("/tmp/report_out_test",
                         gate_result={"passed": True, "exit_code": 0, "summary": "PASS"})
        self.assertTrue(r["json"].exists())
        self.assertTrue(r["markdown"].exists())
        data = json.loads(r["json"].read_text())
        self.assertEqual(data["gate"]["exit_code"], 0)


class TestMarkdownReport(unittest.TestCase):
    def test_gate_status(self):
        out = Path("/tmp/report_md_test.md")
        r = generate_json_report(gate_result={"passed": False, "exit_code": 1,
                                              "summary": "FAIL: 1 violation"})
        generate_markdown_report(r, out)
        text = out.read_text()
        self.assertIn("FAIL (exit 1)", text)

    def test_pass_status(self):
        out = Path("/tmp/report_md_pass.md")
        r = generate_json_report(gate_result={"passed": True, "exit_code": 0,
                                              "summary": "PASS"})
        generate_markdown_report(r, out)
        self.assertIn("PASS (exit 0)", out.read_text())

    def test_findings_table(self):
        out = Path("/tmp/report_md_find.md")
        r = generate_json_report(
            findings=[{"severity": "critical", "cve": "CVE-2024-37891",
                       "package": "urllib3", "version": "2.1.0", "message": "m"}],
            gate_result={"passed": False, "exit_code": 1, "summary": "FAIL"},
        )
        generate_markdown_report(r, out)
        text = out.read_text()
        self.assertIn("CVE-2024-37891", text)
        self.assertIn("urllib3", text)


if __name__ == "__main__":
    unittest.main()