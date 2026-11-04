# Prufyx Community v0.1.0-beta.1

This prerelease is for testing. A passing
claim covers only the rules and declared inputs evaluated; it does not establish
that a whole upgrade is safe.

## Changes

- Declared-state plans can bind authored reference artifacts to scoped checks.
- The MariaDB Operator project check can select a verified local knowledge store for the existing supported rule.
- A policy-bound forward-compatible knowledge format can defer unsupported rules while retaining independently verified blockers.

## Known limitations

- Results depend on the selected knowledge, its validity, and the completeness
  of the supplied inputs. Missing evidence remains unknown.
- Declared-state plans describe caller-supplied reference states. They do not
  establish that an upgrade or remediation was executed.
- Application ordering and runtime behavior require separate evidence.
- The MariaDB Operator project check uses embedded knowledge by default. An
  explicit local knowledge store may be selected for supported rules.

## What changed in this release

<!-- release-notes:begin -->

Changes from `v0.1.0-beta.0` (70f67cac4a3b) to `v0.1.0-beta.1` (2bb6adac1720), computed by `prufyx-maintainer release-notes` from the data files of the two trees. No figure or list below is typed by hand.

### Summary

| Measure | v0.1.0-beta.0 | v0.1.0-beta.1 | Change |
| --- | --- | --- | --- |
| Projects catalogued with retained public sources | 58 | 58 | 0 |
|   of them source-only, no check | 11 | 11 | 0 |
| Projects with at least one executable check | 67 | 67 | 0 |
| CNCF source rules, active | 252 | 252 | 0 |
| CNCF projects with a rule | 53 | 53 | 0 |
| Rules for non-CNCF projects | 42 | 42 | 0 |
| Non-CNCF projects with a rule | 10 | 10 | 0 |
| Line attestations | 104 | 104 | 0 |
| Kubernetes minors with a line attestation | 18 | 18 | 0 |
| Projects with a release-line snapshot (README coverage block) | 78 | 78 | 0 |
| Upgrades between consecutive release lines | 390 | 390 | 0 |
| Decided for the whole release-line pair (A+B) | 46 | 46 | 0 |
| Rule for one exact version pair only (S) | 40 | 40 | 0 |
| Gap, no valid rule (G) | 304 | 304 | 0 |

The release-line figures are the README coverage block, generated on 2026-10-31 (v0.1.0-beta.0) and 2026-10-31 (v0.1.0-beta.1) by `scripts/readme-coverage.sh`; the block comes from `prufyx-maintainer coverage report`.

### Projects added to the support inventory (0)

No project was added.

### Catalogued projects that gained their first executable check (0)

None.

### Onboarding batches (0 approved, 0 project entries)

No onboarding batch was added.

### Projects with custom-resource version checks (87)

No project was added or removed.

### Rules by project (0 added, 0 removed)

No rule was added or removed.

### Rules newly withdrawn (0)

None.

### Line attestations by project (0)

No line attestation was added or removed.

### Kubernetes minors

Lines with a line attestation (18): 1.20, 1.21, 1.22, 1.23, 1.24, 1.25, 1.26, 1.27, 1.28, 1.29, 1.30, 1.31, 1.32, 1.33, 1.34, 1.35, 1.36, 1.37. New since `v0.1.0-beta.0`: none.

### How to read these figures

A catalogued project is not tested coverage: a catalogue entry says Prufyx holds retained public sources for the project, and only an executable check can block an upgrade. Decided means a valid rule or attestation covers every version of both release lines, so the answer is BLOCKED or UNKNOWN, never a whole-upgrade PASS; decided is not safe. An exact-pair rule decides only the versions it names. A line attestation says which rules were derived for a release line, not that an upgrade into it is safe. The metrics are defined in `cli/docs/coverage-report.md`.

<!-- release-notes:end -->
