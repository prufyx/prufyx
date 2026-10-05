# GitHub Action

The repository root holds a composite GitHub Action (`action.yml`) that runs
[`prufyx scan`](scan.md) in a workflow. Like the command, it works offline once
the binary is installed: it reads the manifests you name and sends nothing
anywhere.

> **No release has been published yet.** The action can install a release
> binary, but until a release exists that path stops with a clear message.
> Use `version: source` to build the binary from the ref the action was
> loaded from.

## Example

This workflow scans on pull requests, writes the report to the job summary and
uploads SARIF to code scanning. Replace `<full commit SHA>` with the full
commit SHA of the Prufyx ref you have reviewed, and pin the other actions the
same way.

```yaml
name: Upgrade check
on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  prufyx:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write # only to upload SARIF
      # actions: read        # also needed to upload SARIF in a private repository
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - name: Scan
        id: prufyx
        uses: prufyx/prufyx@<full commit SHA>
        with:
          version: source
          paths: |
            manifests/
          from: kubernetes=1.24.17
          to: kubernetes=1.25.3
          distribution: official_upstream
          resource-scope-complete: "true"
          target-api-apply-required: "true"
          format: sarif

      - name: Upload SARIF
        if: ${{ !cancelled() && steps.prufyx.outputs.report-file != '' && github.event.pull_request.head.repo.full_name == github.repository }}
        uses: github/codeql-action/upload-sarif@1190a975f95ce23525efb6a3fc21ea29567c1b52 # v3.38.2
        with:
          sarif_file: ${{ steps.prufyx.outputs.report-file }}
```

The upload step is not part of the action, so you choose whether to use it. It
needs `security-events: write`. A pull request from a fork gets a read-only
token, so the upload would fail there; the `if:` condition above skips it for
forks. Run the workflow on `pull_request`. The action is
written for code that has been checked out with read-only permissions and is
not documented for `pull_request_target`.

## Inputs

| Input | Required | Meaning |
| --- | --- | --- |
| `version` | yes | A release tag such as `v0.1.0`, or `source`. `latest` is refused. |
| `verify-attestation` | no | `auto` (default), `true` or `false`. When on, `gh attestation verify` checks that the archive was built by the release workflow for that tag. The install fails if the check fails or `gh` is not on the runner. `auto` is on for a release and off for `source`; `true` with `source` is refused. |
| `archive-sha256` | no | The SHA-256 of the release archive for the runner's platform. When given, the archive must match it in addition to the release's `SHA256SUMS`. Not valid with `source`. |
| `paths` | yes | Manifest files or directories, one per line. A line must not start with `-`. |
| `to` | yes, unless `config` sets targets | `COMPONENT=VERSION`, one per line. |
| `from` | no | `COMPONENT=VERSION` in use now, one per line. |
| `config` | no | A [`prufyx.yaml`](scan-config.md). |
| `distribution` | no | `official_upstream` or `custom_build`. |
| `resource-scope-complete` | no | `true` or `false`. Empty leaves it to `prufyx.yaml`. |
| `target-api-apply-required` | no | `true` or `false`. Empty leaves it to `prufyx.yaml`. |
| `format` | no | The report file format: `json` (default), `sarif` or `markdown`. |
| `redact` | no | `true` replaces paths and object names with digests in the report and the summary. Default `false`. |
| `require-basis` | no | Comma separated evidence bases, as for `--require-basis`. |
| `knowledge-db` | no | A verified [knowledge database](scan.md#knowledge-database) directory. |
| `fail-on` | no | When the step fails: `none`, `blocked` (default), or `unknown`, which means "unknown or worse" and also fails on BLOCKED (`blocked,unknown` is the same). |

`blocked` is exit code `10` and `unknown` is exit code `11`, "no blockers found
in covered checks". Under the default, exit `11` leaves the step green and adds a
warning annotation that not every area was checked (see [answers and exit codes](scan.md#answers-and-exit-codes)).
Invalid input (exit `2`) and a knowledge integrity failure (exit `3`) always
fail the step, whatever `fail-on` says. Because `scan` rarely answers PASS
today, `blocked` is the sensible default.

An input that is not valid is refused before `prufyx` runs, with a message that
names the input and not its value.

## Outputs

| Output | Meaning |
| --- | --- |
| `exit-code` | The exit code of `prufyx scan`. |
| `verdict` | `pass`, `blocked`, `unknown`, `invalid-input`, `integrity-failure` or `error`. |
| `report-file` | The report in the requested format. Empty when nothing was written. |

Use `if: ${{ !cancelled() }}` on steps that read the report, so they run when
the scan step failed because of a blocker. When an input is refused, or `prufyx`
does not run, no output is set and `exit-code` is empty. Each use of the action
writes its report to its own directory, so two uses in one job keep both
reports. Container jobs are not tested.

## Job summary

When the scan completes with `0`, `10` or `11`, the action appends the Markdown
report to the job summary. The Markdown output escapes text from manifests and
rules, so a `|` or a backtick cannot break a table (see
[Markdown](scan.md#markdown)). With a `format` other than `markdown` the action
runs the scan a second time to produce it. A summary over 900 KB is replaced by
a short note. With `redact: "true"` the summary has digests, not paths.

## How the binary is installed

- **Release tag.** The action downloads `prufyx_<tag>_<os>_<arch>.tar.gz` and
  `SHA256SUMS` from that release over HTTPS, requires exactly one matching line
  in `SHA256SUMS`, compares the archive digest, and only then extracts the one
  expected file. Any missing file, mismatch or unexpected archive layout stops
  the job; no binary is installed. The runner must be Linux or macOS, x64 or
  arm64.
  `SHA256SUMS` comes from the same release as the archive, so it detects a
  damaged or swapped file but not a release that was published with the wrong
  contents. The build attestation closes that gap: with `verify-attestation`
  on, `gh attestation verify` requires the archive to match the provenance of
  the release workflow run for the tag. Offline alternative: verify the archive
  once yourself with `gh attestation verify`, then set `archive-sha256` to its
  digest and `verify-attestation: "false"`. The archive may hold only the
  package directory and one regular file, `prufyx`, with no repeated names or
  links; anything else stops the job.
- **`source`.** The action sets up Go from `cli/go.mod` and builds
  `cmd/prufyx-community` from the vendored sources at the ref the action was
  loaded from, with `GOWORK=off`, `GOTOOLCHAIN=local` and `GOENV=off`. Nothing
  is downloaded except the Go toolchain.

## How inputs are handled

Inputs reach the scripts as environment variables, never inside a shell
command line. Each one is checked against a fixed pattern, then added to an
argument list and passed to `prufyx` without a shell, so a quote, `$(...)`, a
backtick, a semicolon or a newline in a value is treated as text. Text printed
by `prufyx` can contain file names from your repository, so it is printed inside
a `stop-commands` block with a random token and cannot create workflow
annotations. Values that
could be read as a flag (a path or database starting with `-`) are refused. The
tests in `scripts/action/test.sh` feed such values to the scripts; run them
with `bash scripts/action/test.sh`.
