# Metrics

Measured on Python 3.13.5 (CPython 3.13.5, Linux), commit HEAD after the 1.0.0 build runs.

## Test suite (aim >= 35 — actual)

| Metric | Value |
|--------|-------|
| Tests | **106**, all green |
| Test files | 8 |
| Suite wall time | ~20 s (`python -m unittest discover -s tests`) |
| Parser coverage | 5/5 manifest formats |

## Accuracy / correctness demonstrations

| Check | Result | Proof |
|-------|--------|-------|
| Advisory flags vulnerable version | urllib3 2.1.0 → CVE-2024-37891 (critical) | demo fail-cve, tests.test_advisory |
| Fixed version NOT flagged (FP-avoidance) | urllib3 2.2.3 → 0 findings | tests.test_advisory::test_does_not_flag_fixed |
| Version == fixed-in not flagged | urllib3 2.2.2 → 0 findings | tests.test_advisory::test_looks_like_fixed_not_flagged |
| License deny fails gate | GPL-3.0 → deny | tests.test_license |
| Strict unknown license fails | unknown → deny | tests.test_license |
| Policy exit codes | 0 pass / 1 deny / 2 config-error | tests.test_policy |
| PQC flags 512-bit RSA, not 2048 | RSA-512 critical, RSA-2048 info-only | tests.test_pqc |
| FWAudit flags fixture firmware | FW-2024-001 hash match, entropy 7.94 | tests.test_fwaudit |
| SBOM round-trip | CycloneDX 1.4/1.5 + SPDX 2.3 parse back | tests.test_sbom |
| Manifest formats | requirements / package.json / go.mod / pom.xml / Gemfile.lock | tests.test_manifest |

## Demo runs (exit codes)

| Run | Exit | Gate result |
|-----|------|-------------|
| `supplysec demo` (clean fixtures) | 0 | PASS: no violations |
| `supplysec demo --mode fail-cve` (vuln fixtures) | 1 | FAIL: 1 CVE critical → DENY |

## Timings (single-shot CLI, ms)

| Subcommand | Exit | Time |
|------------|------|------|
| manifest | 0 | ~0.9 s |
| sbom | 0 | ~1.9 s |
| advisory (vuln) | 1 | ~2.0 s |
| license --strict (clean) | 0 | ~0.9 s |
| policy (vuln) | 1 | ~2.4 s |
| pqc | 1 | ~0.7 s |
| fwaudit | 1 | ~1.0 s |
| report | gate | ~2 s |
| demo (pass) | 0 | ~2.0 s |

(All includes Python 3.13 interpreter startup; steady-state per-run cost is small since the
pipeline is offline/localhost and fixture-sized.)

## Advisory DB (offline fixture)

- 19 advisory entries: urllib3, jinja2, django, express, rails, packaging,
  golang.org/x/text, jackson-databind (fixed-in version ranges honored)
- 1 firmware hash advisory (FW-2024-001) matched by real SHA-256 of the fixture binary
- 0 network calls — fully offline

## Codebase

| Area | Lines |
|------|-------|
| supplysec/ (8 modules + CLI) | ~1450 |
| tests/ | ~884 |

## Policy gate exit-code contract (CI)

- `0` PASS · `1` FAIL-denied (critical CVE, license deny, unpinned/unknown) · `2` FAIL-policy config