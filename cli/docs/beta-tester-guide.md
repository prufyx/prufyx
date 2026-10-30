# Beta tester guide

This guide is for people trying the Prufyx v0.1.0-beta.0 pre-release. Prufyx
checks a planned upgrade of Kubernetes or a CNCF project against reviewed,
source-cited rules. It runs locally, offline, and uploads nothing.

A beta result is a scoped finding. `PASS` never means a whole upgrade is safe,
and a wrong `PASS` is the worst bug this project can have. Reports of a wrong
answer are the most useful thing you can send.

What this build covers is stated in the
[release notes](release-notes-v0.1.0-beta.0.md) (generated figures at the end)
and the generated [support inventory](community-support-inventory.md). This
guide types no coverage figure on purpose.

## 1. Install

Download from the GitHub release page and verify before you run anything. The
full procedure, and what each step proves, is in [releasing](releasing.md#verifying-a-release).
In short:

```sh
TAG=v0.1.0-beta.0
ARCHIVE="prufyx_${TAG}_linux_amd64.tar.gz"   # linux or darwin, amd64 or arm64
BASE="https://github.com/prufyx/prufyx/releases/download/$TAG"
curl -fsSLO "$BASE/SHA256SUMS" && curl -fsSLO "$BASE/$ARCHIVE"

# 1. Checksum: detects changed bytes only, says nothing about who built it.
grep " $ARCHIVE\$" SHA256SUMS | sha256sum -c -     # macOS: shasum -a 256 -c -

# 2. Attestation: the archive was built by this repository's release workflow.
gh attestation verify "$ARCHIVE" \
  --repo prufyx/prufyx \
  --signer-workflow prufyx/prufyx/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" \
  --deny-self-hosted-runners

# 3. Unpack and compare the self-reported build identity.
tar -xzf "$ARCHIVE"
"./prufyx_${TAG}_linux_amd64/prufyx" version
```

Step 2 needs the `gh` CLI and network access. `version` reports
`"candidateOnly": true` and `"trustRootDigest": "UNPINNED"`: this is a candidate
build, not maintainer-signed. No Windows archive is published. You can also
build from source (see the [README](../../README.md)).

Put the binary on your `PATH`, then `prufyx` prints a command overview and
`prufyx <command> help` prints one command's details. Check flags against that
help for your build; it is the reference.

## 2. Scan rendered manifests

`scan` reads rendered Kubernetes manifests and reports API versions that a
release on the way to your target stops serving. It covers Kubernetes only.

```sh
helm template my-release ./chart > rendered.yaml     # or: kustomize build
chmod 600 rendered.yaml
prufyx scan rendered.yaml --from kubernetes=1.24.0 --to kubernetes=1.25.0
```

Without declarations the answer is usually `UNKNOWN` with a `NOT CHECKED` list:
three entries ask for facts only you can state. State them only if they are
true:

```sh
prufyx scan rendered.yaml --from kubernetes=1.24.0 --to kubernetes=1.25.0 \
  --distribution official_upstream \
  --resource-scope-complete \
  --target-api-apply-required
```

Never add a declaration flag that is not true. See [declarations](declarations.md),
[scan](scan.md) and [scan config](scan-config.md) (`prufyx.yaml`). Useful flags
(from `prufyx scan help`): `--format human|json|sarif|markdown|csv`,
`--show-passes`, `--verbose` (cited sources), `--redact`, `--fail-on
blocked|unknown|none`. Pass `-` as the path to read standard input.

## 3. Check one CNCF project

`check cncf` evaluates one project's rules against minimized declarations you
supply (not whole manifests).

```sh
prufyx catalog cncf                              # list projects
prufyx catalog checks --project SLUG --from X --to Y   # rules, command and input each reads
prufyx check cncf --project SLUG --help          # that project's input flags
prufyx check cncf --project SLUG --input input.json --from X --to Y --now 2026-10-18T00:00:00Z
```

Notes from the help text:

- `--now RFC3339` selects the embedded knowledge at that instant; `--knowledge-db
  DIR` selects a local store instead. Without either, `check cncf` and `scan`
  use a verified default store if one exists, else the embedded knowledge (see
  [knowledge updates](knowledge-updates.md#automatic-use-of-the-local-database)).
  A rule past its expiry answers `UNKNOWN`, so use the real current time.
- Input flags differ per project; `--project SLUG --help` names them.
  Input files must be regular, owner-only files (`chmod 600`), not symlinks.
- Add `--strict-exit` in CI: a scoped `PASS` then exits `14`, not `0`.
- `prufyx prepare cncf --project SLUG --input FILE --from X --to Y` builds a
  check input from the project's own configuration file; `--format input` writes
  the prepared input. Non-CNCF projects (grafana, kibana, loki, fluent-bit,
  ceph) use `prepare project` and `check project`.
- Several checks in one go: `prufyx check batch --plan plan.json --root DIR
  --now RFC3339`. The plan file format is in [batch checks](batch-checks.md).
  The batch plan file is not the same thing as `prufyx plan` (section 4).

A config example (cert-manager Helm values, owner-only file):

```sh
echo '{"prometheus":{"servicemonitor":{"path":"/custom"}}}' > values.json
chmod 600 values.json
prufyx check cert-manager-values --from 1.20.3 --to 1.21.1 --values values.json
```

This one exits `10` (`BLOCKED`). Pick real projects and real versions of your
own for testing; try ones where you already know the answer from the upstream
release notes, and compare.

## 4. Plan a multi-hop upgrade

`prufyx plan` takes the inputs and flags of `scan` and prints the route as
ordered stages, one per hop, with each stage's blockers, gaps and the reason it
is not `PASS`. Full reference: [plan](plan.md).

```sh
prufyx plan rendered.yaml --from kubernetes=1.29.15 --to kubernetes=1.33.0 \
  --distribution official_upstream --resource-scope-complete \
  --target-api-apply-required
```

What it does and does not do in this build:

- It runs one `scan` and places the hops in stages; it evaluates no rule of its
  own. Kubernetes hops follow the reviewed `sequential_minor` path policy;
  other components follow, with an order marked `inferred`.
- **No stage is `PASS` yet.** Hop actions (for example stored-version
  migrations) are not checked and node rolls are not planned, so a covered hop
  shows as `UNKNOWN` with `HOP_ACTIONS_NOT_CHECKED` (and
  `NODE_ROLLS_NOT_PLANNED` for Kubernetes). A `BLOCKED` stage is decided.
- A component whose path `scan` cannot plan, for example an app with no
  reviewed path policy, is listed under "Not planned" with the scan's gap
  (`NO_REVIEWED_PATH_POLICY` when the upgrade skips release lines).
- `--to kubernetes=newest-covered` picks the `.0` release of the newest line
  whose reviewed served-API list is current. It is not "latest", and the plan
  prints a note saying so. Details: [plan](plan.md#newest-covered).
- `--to COMPONENT=latest` is not resolved: no signed release-line snapshot
  ships. The component is reported `LATEST_NOT_RESOLVED` and not planned. Give an
  explicit version.
- `--fail-on` is refused (usage error, exit `2`). The exit code is the plan
  verdict: `0` PASS, `10` BLOCKED, `11` otherwise. Since no stage is `PASS`
  yet, expect `10` or `11`.
- `--format human|markdown|json`.

## 5. Read the answer

| Answer | Exit | Meaning |
| --- | --- | --- |
| `PASS` (`check`) | `0`, or `14` with `--strict-exit` | The rules this check evaluated, for that exact pair, passed. Nothing more. |
| `PASS FOR THE DECLARED SCOPE` (`scan`) | `0` | Every hop is covered by reviewed records and nothing is missing, for what you declared. Not a whole-upgrade certificate. |
| `BLOCKED` | `10` | A reviewed rule matched your input. The output names the file, object and fix, and cites the upstream source. |
| `UNKNOWN`, `NOT CHECKED` | `11` | The evidence did not decide. Not a pass. |
| invalid input | `2` | Command line or an input was not accepted. |
| integrity failure | `3` | Knowledge or an input failed verification, or the default local knowledge store is invalid or expired. |

`plan` uses `0`, `10` and `11` only (never `14`).

`UNKNOWN` is the common answer in a beta: a version pair with no rule, an
expired rule, a missing declaration. Read the reason lines. Full tables:
[verdicts](verdicts.md), [exit codes](exit-codes.md).

## 6. Knowledge database

- A binary carries embedded knowledge. It works offline with no setup.
- Embedded rules are time-limited. After a rule expires, the answer for it is
  `UNKNOWN` by design.
- `prufyx db update` downloads a complete signed package and verifies it with
  TUF. With no arguments it targets the official `cncf-projects` feed and
  needs the trust root pinned in the build. This build pins the official
  root, so a no-argument `db update` fetches the signed package from the
  official feed and refuses anything not signed from that root. The manual path is `prufyx db update --profile cncf --source URL
  --package-out FILE --db-root DIR --bootstrap-root root.json
  --bootstrap-root-digest sha256:...`: you need a package source you operate
  and a root you verified independently.
- `prufyx db verify FILE` checks a package offline; `db import` installs a
  package you carried over; `db status` shows the selected store.
- Offline behaviour: checks never touch the network. With no store they use the
  embedded knowledge. If a default local store exists but is invalid, expired,
  rolled back or not private, the command stops with exit `3` and does not fall
  back silently; repair it with `db update`, remove the store, or pass
  `--knowledge=embedded`.
- `scan` and `check cncf` never refresh anything on their own. Details and
  exact flags: [knowledge updates](knowledge-updates.md).

## 7. Limits

- `scan` does not read a live cluster, custom resources, stored versions,
  admission or component configuration, or node version skew (unless you
  declare kubelet versions).
- Apps with no reviewed path policy are planned as one hop; an upgrade that
  skips release lines then stays unchecked (`NO_REVIEWED_PATH_POLICY`).
- Many projects have rules for exact version pairs only. A pair with no rule is
  `UNKNOWN`. A catalogued project is not tested coverage.
- Patch-only upgrades within one release line are not evaluated for removals.
- Prufyx never infers what you did not declare, and does not prove migration
  completion, runtime compatibility, availability, data safety or security.
- Only `assess` touches a cluster, and only if you run it, read-only through
  kubectl. Nothing else needs a cluster.

## Report a wrong answer

A wrong answer is: `PASS` when upstream says the upgrade breaks, `BLOCKED` with
a wrong or missing fix, or `UNKNOWN` where reviewed upstream evidence clearly
decides. Send:

1. the command line and `prufyx version`;
2. the verdict, exit code and the reason lines;
3. the upstream document or source line that shows the right answer;
4. a **minimized, anonymised** input (only the keys involved).

Never include customer configuration, cluster snapshots, secrets or credentials.
Open an issue at https://github.com/prufyx/prufyx/issues using the template
"Beta wrong answer". For evidence about a rule use "Propose a project or
transition" or "Upstream evidence contribution"; for a missing project use
"Suggest a public project source". Report security issues privately, as described in [SECURITY.md](../../SECURITY.md).
To propose a rule yourself, see the [rule contribution guide](contributing-rules.md)
and [CONTRIBUTING.md](../../CONTRIBUTING.md).
