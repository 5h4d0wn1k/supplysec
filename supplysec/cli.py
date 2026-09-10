"""CLI — argparse subcommands for supplysec: manifest, sbom, advisory, license, policy, pqc, fwaudit, report, demo."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__

FIXTURES_DIR = Path(__file__).parent / "fixtures"
DEFAULT_OUTPUT = Path("reports")


def _out_dir(args) -> Path:
    return Path(args.output) if hasattr(args, "output") and args.output else DEFAULT_OUTPUT


def cmd_manifest(args):
    """Parse dependency manifests."""
    from .manifest import parse_manifest
    all_deps = []
    for m in args.manifests:
        p = Path(m)
        if not p.exists():
            print(f"ERROR: manifest not found: {m}", file=sys.stderr)
            return 1
        deps = parse_manifest(p)
        all_deps.extend(deps)
        print(f"Parsed {len(deps)} dependencies from {m}")
    out = _out_dir(args)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest_deps.json").write_text(json.dumps([
        {"name": d.name, "version": d.version, "ecosystem": d.ecosystem,
         "purl": d.purl, "source_file": d.source_file}
        for d in all_deps
    ], indent=2))
    print(f"Total: {len(all_deps)} dependencies → {out / 'manifest_deps.json'}")
    return 0


def cmd_sbom(args):
    """Generate SBOM from manifest."""
    from .manifest import parse_manifest
    from .sbom import write_sbom
    deps = []
    for m in args.manifests:
        p = Path(m)
        if p.exists():
            deps.extend(parse_manifest(p))
    if not deps:
        print("ERROR: no dependencies found", file=sys.stderr)
        return 1
    out = _out_dir(args)
    paths = write_sbom(deps, out, args.cdx_version, args.spdx_version)
    print(f"SBOM written: CycloneDX → {paths['cyclonedx']}, SPDX → {paths['spdx']}")
    return 0


def cmd_advisory(args):
    """Match dependencies against offline advisory DB."""
    from .manifest import parse_manifest
    from .advisory import load_advisory_db, match_advisories
    db_path = args.advisory_db or str(FIXTURES_DIR / "advisory_db.json")
    advisories = load_advisory_db(db_path)
    deps = []
    for m in args.manifests:
        p = Path(m)
        if p.exists():
            deps.extend(parse_manifest(p))
    findings = match_advisories(deps, advisories)
    print(f"Advisory DB: {len(advisories)} entries, {len(findings)} finding(s)")
    for f in findings:
        sev = f.advisory.severity.upper()
        print(f"  [{sev}] {f.advisory.cve_id} — {f.advisory.package} {f.affected_version}")
    if findings:
        return 1
    return 0


def cmd_license(args):
    """Scan licenses against policy."""
    from .manifest import parse_manifest
    from .license import load_license_db, scan_licenses, check_license_policy
    lic_db_path = args.license_db or str(FIXTURES_DIR / "licenses.json")
    license_db = load_license_db(lic_db_path)
    deps = []
    for m in args.manifests:
        p = Path(m)
        if p.exists():
            deps.extend(parse_manifest(p))
    lic_infos = scan_licenses(deps, license_db)
    checks = check_license_policy(lic_infos, strict_mode=args.strict)
    denied = [c for c in checks if not c.allowed]
    print(f"License scan: {len(checks)} packages, {len(denied)} denied")
    for c in denied:
        print(f"  DENIED: {c.package} → {c.detected_license} ({c.reason})")
    if denied:
        return 1
    return 0


def cmd_policy(args):
    """Evaluate full policy gate."""
    from .manifest import parse_manifest
    from .advisory import load_advisory_db, match_advisories
    from .license import load_license_db, scan_licenses, check_license_policy
    from .policy import load_policy, evaluate_gate
    policy_path = args.policy or str(FIXTURES_DIR / "policy.json")
    policy = load_policy(policy_path)
    db_path = str(FIXTURES_DIR / "advisory_db.json")
    advisories = load_advisory_db(db_path)
    lic_db_path = str(FIXTURES_DIR / "licenses.json")
    license_db = load_license_db(lic_db_path)

    deps = []
    for m in args.manifests:
        p = Path(m)
        if p.exists():
            deps.extend(parse_manifest(p))

    findings = match_advisories(deps, advisories)
    lic_infos = scan_licenses(deps, license_db)
    lic_checks = check_license_policy(lic_infos, strict_mode=args.strict)
    gate = evaluate_gate(findings, lic_checks, policy, deps)

    print(f"Gate: {gate.summary}")
    for v in gate.violations:
        print(f"  VIOLATION: {v['message']}")
    for w in gate.warnings:
        print(f"  WARNING: {w['message']}")
    return gate.exit_code


def cmd_pqc(args):
    """Scan for PQC vulnerabilities in key/cert fixtures."""
    from .pqc import scan_pqc
    data_path = args.data or str(FIXTURES_DIR / "keys" / "sample_keys.json")
    result = scan_pqc(data_path)
    print(f"PQC scan: {len(result.issues)} issue(s)")
    for issue in result.issues:
        sev = issue["severity"].upper()
        print(f"  [{sev}] {issue['message']}")
    return 1 if result.has_issues else 0


def cmd_fwaudit(args):
    """Audit firmware fixture."""
    from .fwaudit import audit_firmware
    fw_path = args.firmware or str(FIXTURES_DIR / "firmware" / "sample_fw.bin")
    adv_db = str(FIXTURES_DIR / "advisory_db.json")
    report = audit_firmware(fw_path, adv_db)
    print(f"Firmware: {report.filename}, {report.size_bytes} bytes, entropy={report.entropy}")
    print(f"  Strings: {len(report.strings_found)}, Versions: {len(report.embedded_versions)}")
    print(f"  Hash matches: {len(report.hash_matches)}, Findings: {len(report.findings)}")
    for f in report.findings:
        print(f"    [{f['severity'].upper()}] {f['message']}")
    return 1 if report.has_findings else 0


def cmd_report(args):
    """Generate full report with gate decision."""
    from .manifest import parse_manifest
    from .sbom import to_cyclonedx, to_spdx
    from .advisory import load_advisory_db, match_advisories
    from .license import load_license_db, scan_licenses, check_license_policy
    from .pqc import scan_pqc
    from .fwaudit import audit_firmware
    from .policy import load_policy, evaluate_gate
    from .report import write_report

    policy_path = args.policy or str(FIXTURES_DIR / "policy.json")
    policy = load_policy(policy_path)
    db_path = str(FIXTURES_DIR / "advisory_db.json")
    advisories = load_advisory_db(db_path)
    lic_db_path = str(FIXTURES_DIR / "licenses.json")
    license_db = load_license_db(lic_db_path)
    pqc_path = str(FIXTURES_DIR / "keys" / "sample_keys.json")
    fw_path = str(FIXTURES_DIR / "firmware" / "sample_fw.bin")

    deps = []
    for m in args.manifests:
        p = Path(m)
        if p.exists():
            deps.extend(parse_manifest(p))

    findings = match_advisories(deps, advisories)
    lic_infos = scan_licenses(deps, license_db)
    lic_checks = check_license_policy(lic_infos, strict_mode=args.strict)
    gate = evaluate_gate(findings, lic_checks, policy, deps)
    pqc = scan_pqc(pqc_path)
    fw = audit_firmware(fw_path, db_path)

    out = _out_dir(args)
    paths = write_report(
        out,
        sbom_cdx=to_cyclonedx(deps) if deps else None,
        sbom_spdx=to_spdx(deps) if deps else None,
        findings=[{"severity": f.advisory.severity, "cve": f.advisory.cve_id,
                    "package": f.advisory.package, "version": f.affected_version,
                    "message": f"{f.advisory.cve_id} {f.advisory.package} {f.affected_version}"}
                   for f in findings],
        license_checks=[{"package": lc.package, "detected_license": lc.detected_license,
                          "allowed": lc.allowed, "reason": lc.reason} for lc in lic_checks],
        pqc_findings=pqc.issues,
        fw_report={"filename": fw.filename, "size_bytes": fw.size_bytes,
                    "entropy": fw.entropy, "findings": fw.findings},
        gate_result={"passed": gate.passed, "exit_code": gate.exit_code,
                      "summary": gate.summary,
                      "violations": gate.violations, "warnings": gate.warnings},
        policy_file=policy_path,
    )
    print(f"Report written: JSON → {paths['json']}, Markdown → {paths['markdown']}")
    print(f"Gate: {gate.summary}")
    return gate.exit_code


def cmd_demo(args):
    """Run demo with fixture data. Exit 0 if gate passes, 1 if deny."""
    from .manifest import parse_manifest
    from .sbom import to_cyclonedx, to_spdx
    from .advisory import load_advisory_db, match_advisories
    from .license import load_license_db, scan_licenses, check_license_policy
    from .pqc import scan_pqc
    from .fwaudit import audit_firmware
    from .policy import load_policy, evaluate_gate
    from .report import write_report

    print("=== supplysec demo ===")
    print()

    demo_mode = getattr(args, "mode", "pass")

    if demo_mode == "fail-cve":
        manifest_dir = FIXTURES_DIR / "manifests" / "vuln"
    else:
        manifest_dir = FIXTURES_DIR / "manifests" / "clean"

    manifests = [
        str(manifest_dir / "requirements.txt"),
        str(manifest_dir / "package.json"),
        str(manifest_dir / "go.mod"),
        str(manifest_dir / "pom.xml"),
        str(manifest_dir / "Gemfile.lock"),
    ]
    print(f"  [manifests] {manifest_dir}")

    deps = []
    for m in manifests:
        p = Path(m)
        if p.exists():
            d = parse_manifest(p)
            deps.extend(d)
            print(f"  [manifest] {p.name}: {len(d)} deps")
    print(f"  Total deps: {len(deps)}")
    print()

    db_path = str(FIXTURES_DIR / "advisory_db.json")
    advisories = load_advisory_db(db_path)
    findings = match_advisories(deps, advisories)
    print(f"  [advisory] {len(advisories)} DB entries, {len(findings)} finding(s)")
    for f in findings:
        print(f"    [{f.advisory.severity.upper()}] {f.advisory.cve_id} — {f.advisory.package} {f.affected_version}")
    print()

    lic_db_path = str(FIXTURES_DIR / "licenses.json")
    license_db = load_license_db(lic_db_path)
    lic_infos = scan_licenses(deps, license_db)
    strict = demo_mode == "fail-license"
    lic_checks = check_license_policy(lic_infos, strict_mode=strict)
    denied_lic = [c for c in lic_checks if not c.allowed]
    print(f"  [license] {len(lic_checks)} packages scanned, {len(denied_lic)} denied")
    for c in denied_lic:
        print(f"    DENIED: {c.package} → {c.detected_license}")
    print()

    pqc_path = str(FIXTURES_DIR / "keys" / "sample_keys.json")
    pqc = scan_pqc(pqc_path)
    print(f"  [pqc] {len(pqc.issues)} issue(s)")
    for i in pqc.issues:
        print(f"    [{i['severity'].upper()}] {i['message']}")
    print()

    fw_path = str(FIXTURES_DIR / "firmware" / "sample_fw.bin")
    fw = audit_firmware(fw_path, db_path)
    print(f"  [fwaudit] {fw.filename}: {fw.size_bytes} bytes, entropy={fw.entropy}")
    for ff in fw.findings:
        print(f"    [{ff['severity'].upper()}] {ff['message']}")
    print()

    policy_path = str(FIXTURES_DIR / "policy.json")
    if demo_mode == "fail-cve":
        policy_path = str(FIXTURES_DIR / "policy-strict.json")
    policy = load_policy(policy_path)
    gate = evaluate_gate(findings, lic_checks, policy, deps)
    print(f"  [gate] {gate.summary}")
    for v in gate.violations:
        print(f"    VIOLATION: {v['message']}")
    for w in gate.warnings:
        print(f"    WARNING: {w['message']}")
    print()

    out = _out_dir(args)
    paths = write_report(
        out,
        sbom_cdx=to_cyclonedx(deps) if deps else None,
        sbom_spdx=to_spdx(deps) if deps else None,
        findings=[{"severity": f.advisory.severity, "cve": f.advisory.cve_id,
                    "package": f.advisory.package, "version": f.affected_version,
                    "message": f"{f.advisory.cve_id} {f.advisory.package} {f.affected_version}"}
                   for f in findings],
        license_checks=[{"package": lc.package, "detected_license": lc.detected_license,
                          "allowed": lc.allowed, "reason": lc.reason} for lc in lic_checks],
        pqc_findings=pqc.issues,
        fw_report={"filename": fw.filename, "size_bytes": fw.size_bytes,
                    "entropy": fw.entropy, "findings": fw.findings},
        gate_result={"passed": gate.passed, "exit_code": gate.exit_code,
                      "summary": gate.summary,
                      "violations": gate.violations, "warnings": gate.warnings},
        policy_file=policy_path,
    )
    print(f"  [report] JSON → {paths['json']}")
    print(f"  [report] MD   → {paths['markdown']}")
    print()
    print(f"=== Demo complete. Exit code: {gate.exit_code} ({gate.summary}) ===")
    return gate.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supplysec",
        description="Supply-chain security gate: SBOM, advisory, license, PQC, firmware audit, CI-ready",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # manifest
    p_manifest = sub.add_parser("manifest", help="Parse dependency manifests")
    p_manifest.add_argument("manifests", nargs="+", help="Manifest file(s)")
    p_manifest.add_argument("-o", "--output", default=None, help="Output directory")
    p_manifest.set_defaults(func=cmd_manifest)

    # sbom
    p_sbom = sub.add_parser("sbom", help="Generate SBOM")
    p_sbom.add_argument("manifests", nargs="+", help="Manifest file(s)")
    p_sbom.add_argument("--cdx-version", default="1.5", help="CycloneDX version")
    p_sbom.add_argument("--spdx-version", default="2.3", help="SPDX version")
    p_sbom.add_argument("-o", "--output", default=None, help="Output directory")
    p_sbom.set_defaults(func=cmd_sbom)

    # advisory
    p_adv = sub.add_parser("advisory", help="Match against advisory DB")
    p_adv.add_argument("manifests", nargs="+", help="Manifest file(s)")
    p_adv.add_argument("--advisory-db", default=None, help="Advisory DB JSON")
    p_adv.set_defaults(func=cmd_advisory)

    # license
    p_lic = sub.add_parser("license", help="Scan licenses")
    p_lic.add_argument("manifests", nargs="+", help="Manifest file(s)")
    p_lic.add_argument("--license-db", default=None, help="License DB JSON")
    p_lic.add_argument("--strict", action="store_true", help="Strict mode (deny unknown)")
    p_lic.set_defaults(func=cmd_license)

    # policy
    p_pol = sub.add_parser("policy", help="Evaluate policy gate")
    p_pol.add_argument("manifests", nargs="+", help="Manifest file(s)")
    p_pol.add_argument("--policy", default=None, help="Policy config JSON")
    p_pol.add_argument("--strict", action="store_true", help="Strict mode")
    p_pol.set_defaults(func=cmd_policy)

    # pqc
    p_pqc = sub.add_parser("pqc", help="PQC vulnerability scan")
    p_pqc.add_argument("--data", default=None, help="Keys/certs JSON")
    p_pqc.set_defaults(func=cmd_pqc)

    # fwaudit
    p_fw = sub.add_parser("fwaudit", help="Audit firmware binary")
    p_fw.add_argument("--firmware", default=None, help="Firmware binary path")
    p_fw.set_defaults(func=cmd_fwaudit)

    # report
    p_rep = sub.add_parser("report", help="Generate full report")
    p_rep.add_argument("manifests", nargs="+", help="Manifest file(s)")
    p_rep.add_argument("--policy", default=None, help="Policy config JSON")
    p_rep.add_argument("--strict", action="store_true", help="Strict mode")
    p_rep.add_argument("-o", "--output", default=None, help="Output directory")
    p_rep.set_defaults(func=cmd_report)

    # demo
    p_demo = sub.add_parser("demo", help="Run demo with fixtures")
    p_demo.add_argument("--mode", default="pass", choices=["pass", "fail-cve", "fail-license"],
                         help="Demo mode")
    p_demo.add_argument("-o", "--output", default=None, help="Output directory")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rc = args.func(args)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
