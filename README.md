# supplysec
![tests](https://github.com/5h4d0wn1k/supplysec/actions/workflows/ci.yml/badge.svg) ![MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Supply-chain security gate — dependency manifest parsing, SBOM generation
(CycloneDX 1.4/1.5 + SPDX 2.3), offline advisory matching, license/policy gate,
post-quantum (PQC) scanner, firmware audit, CI-ready JSON+Markdown reports.

A Wave 4 "BLUE" flagship in a 24-tool portfolio. References:
dependency-check, SBOM tooling (CycloneDX / SPDX specs), Pinpoint, SLSA.
Operates fully **offline** on fixtures — no network, no exfiltration.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

```bash
python3 -m pip install -e .
supplysec --demo                # offline, gate PASS, exit 0
supplysec --demo --mode fail-cve  # demonstrates DENY, exit 1
python3 -m unittest discover -s tests
```

## Subcommands

| Command    | Purpose                                             | Exit |
|------------|-----------------------------------------------------|------|
| `manifest` | Parse requirements.txt / package.json / go.mod / pom.xml / Gemfile.lock | 0/1 |
| `sbom`     | Emit CycloneDX (1.4/1.5) + SPDX (2.3) JSON, component graph, purl, hashes | 0/1 |
| `advisory` | Match deps against offline advisory DB (ranges + fixed-in) | 0/1 |
| `license`  | Wrap-license scan, allow/deny list, strict unknown deny | 0/1 |
| `policy`   | Full gate: {critical deny, high warn, license deny, pinning, unknown deny} | 0/1/2 |
| `pqc`      | RSA<2048 / DSA / small ECDSA / SHA-1 → ML-KEM/ML-DSA migration notes | 0/1 |
| `fwaudit`  | Entropy, embedded strings/versions, firmware hash vs advisory | 0/1 |
| `report`   | SBOM + findings + gate decision as JSON + Markdown | gate |

### CI gate exit codes

- `0` — PASS
- `1` — FAIL: denied (critical CVE, denied license, unpinned/unknown version)
- `2` — FAIL: policy configuration error

## Usage examples

```bash
supplysec manifest supplysec/fixtures/manifests/clean/requirements.txt
supplysec sbom     supplysec/fixtures/manifests/clean/package.json -o reports
supplysec advisory supplysec/fixtures/manifests/vuln/requirements.txt --advisory-db supplysec/fixtures/advisory_db.json
supplysec policy   supplysec/fixtures/manifests/vuln/requirements.txt
supplysec license  supplysec/fixtures/manifests/clean/requirements.txt --strict
supplysec pqc      --data supplysec/fixtures/keys/sample_keys.json
supplysec fwaudit  --firmware supplysec/fixtures/firmware/sample_fw.bin
supplysec report   supplysec/fixtures/manifests/vuln/requirements.txt -o reports
```

Reports are written under `reports/` (overridable with `-o`): `report.json`,
`report.md`, `bom-cyclonedx.json`, `sbom-spdx.json`, `manifest_deps.json`.

## Live Lab Test Plan

Run on your own lab only. Expected proof output:

```bash
# 1. Clean fixture set must pass the gate (exit 0)
supplysec demo -o /tmp/lab_pass; echo "exit=$?"        # expect PASS, exit=0
grep "Gate: PASS" /tmp/lab_pass/report.md

# 2. Vulnerable set must fail with critical CVE (exit 1)
supplysec demo --mode fail-cve -o /tmp/lab_fail; echo "exit=$?"   # expect exit=1
grep "CVE-2024-37891" /tmp/lab_fail/report.md                      # 1 critical CVE → DENY

# 3. SBOM round-trips (own minimal parser in tests/test_sbom.py)
python3 -m unittest tests.test_sbom -v

# 4. Fixed version NOT flagged (false-positive avoidance)
python3 -m unittest tests.test_advisory -v

# 5. Full suite
python3 -m unittest discover -s tests
```

## Metrics
(as measured — see METRICS.md for the continuously-updated numbers.)

## License

MIT — see LICENSE. Authorized use only; see the legal block above.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).
