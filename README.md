> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# supplysec — Supply-Chain Security Gate

A CI-ready **supply-chain security** gate: parse dependency manifests, generate
**SBOMs (CycloneDX & SPDX)**, match advisories offline, enforce license and
policy gates, scan for **post-quantum (PQC)** weaknesses, and audit firmware —
all in one Python CLI.

[![CI](https://github.com/5h4d0wn1k/supplysec/actions/workflows/ci.yml/badge.svg)](https://github.com/5h4d0wn1k/supplysec/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/supplysec)](https://github.com/5h4d0wn1k/supplysec)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/supplysec)](https://github.com/5h4d0wn1k/supplysec)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/supplysec)](https://github.com/5h4d0wn1k/supplysec)

## Why supplysec

Modern attacks ride in through dependencies: a pinned-but-vulnerable library,
a denied license, or a weak key in the signing chain. supplysec is a
**DevSecOps** gate that runs fully offline — no network, no exfiltration —
against CI fixtures. It parses requirements.txt, package.json, go.mod, pom.xml
and Gemfile.lock, emits CycloneDX 1.5 + SPDX 2.3 SBOMs, matches an offline
advisory DB, enforces license/policy rules, flags RSA<2048 / DSA / small-ECDSA /
SHA-1 keys for ML-KEM/ML-DSA migration, and audits firmware entropy and
embedded versions. Designed for **authorized security testing** of your own
build pipeline.

## Features

- **Manifest parsing** — `requirements.txt`, `package.json`, `go.mod`, `pom.xml`, `Gemfile.lock`
- **SBOM generation** — CycloneDX 1.5 and SPDX 2.3 with purl + hashes
- **Offline advisory matching** — version-range + fixed-in detection against a local DB
- **License gate** — allow/deny lists, strict unknown-license denial
- **Policy gate** — critical deny, high warn, pinning, and unknown-version rules (exit 0/1/2)
- **Post-quantum scan** — weak RSA/DSA/ECDSA and SHA-1 signatures → migration notes
- **Firmware audit** — entropy, embedded strings/versions, hash-vs-advisory check
- **Reports** — JSON + Markdown for CI logs and artifacts
- **Demo modes** — `pass` and `fail-cve` fixtures to prove gate behavior

## Quickstart

```bash
pip install -e .

supplysec --demo                 # gate PASS, exit 0
supplysec --demo --mode fail-cve # demonstrates DENY, exit 1
python3 -m unittest discover -s tests
```

| Command | Purpose |
|---|---|
| `supplysec manifest <file...>` | Parse manifests to JSON |
| `supplysec sbom <file...> -o reports` | Emit CycloneDX + SPDX SBOMs |
| `supplysec advisory <file...> --advisory-db db.json` | Match offline advisories |
| `supplysec license <file...> --strict` | License allow/deny gate |
| `supplysec policy <file...> --policy policy.json` | Full gate decision |
| `supplysec pqc --data keys.json` | Post-quantum key scan |
| `supplysec fwaudit --firmware fw.bin` | Firmware entropy/version audit |
| `supplysec report <file...> -o reports` | Combined JSON + Markdown report |

### CI exit codes

- `0` — PASS
- `1` — FAIL (critical CVE, denied license, unpinned/unknown version)
- `2` — FAIL (policy configuration error)

## Examples

- `supplysec/fixtures/manifests/{clean,vuln}/` — clean and CVE-poisoned manifests (requirements.txt, package.json, go.mod, pom.xml, Gemfile.lock)
- `supplysec/fixtures/advisory_db.json`, `licenses.json`, `policy*.json`, `keys/sample_keys.json`, `firmware/sample_fw.bin`

## Project structure

- `supplysec/` — package: `cli.py`, `manifest.py`, `sbom.py`, `advisory.py`, `license.py`, `policy.py`, `pqc.py`, `fwaudit.py`, `report.py`
- `supplysec/fixtures/` — demo data for every mode
- `tests/` — coverage for every subcommand and parser

## Documentation

- [METRICS.md](METRICS.md) — continuously-updated measured numbers (tests, accuracy demonstrations)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)