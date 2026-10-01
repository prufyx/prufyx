# Prufyx Community v0.0.1-alpha.1

This is the first alpha of Prufyx Community: a deterministic, offline
Kubernetes/CNCF upgrade-safety checker. It evaluates an upgrade against
human-reviewed, source-pinned rules and returns one of three verdicts —
**PASS**, **BLOCKED**, or **UNKNOWN** — with a citation into the upstream
source that backs each rule. It does not guess.

This is an alpha: expect gaps, and read the limitations below before relying
on a verdict.

## What works

- 194 native check routes, verified against the compiled route catalog.
- Kubernetes API-removal checks for the removal releases 1.22, 1.25, 1.26,
  1.27, 1.29, and 1.32. These apply to any patch version that crosses the
  removal release, for example `1.24.17 -> 1.25.3`.
- The quickstart at `cli/docs/quickstart.md` takes a clean clone to a real
  **BLOCKED** verdict, with a citation into upstream Kubernetes source, in
  under five minutes.
- The community rule validator, `prufyx-maintainer rule validate`, checks a
  candidate rule file before it is proposed.

## What does not work

- Most checks need operator-declared inputs (an effective config, a
  kubeconfig-derived snapshot, or similar); Prufyx does not infer them.
- Collector observation (`prufyx-collector`) covers only a few components
  today; most component facts still have to be declared by the operator.
- There is no Windows build of `prufyx`: the `observation` package uses Unix
  syscalls and does not build on Windows.
- The embedded rules start expiring on 2026-12-07. After a rule expires, its
  verdict turns UNKNOWN by design, until the rule is re-reviewed and
  republished. This is intentional: Prufyx never keeps citing a source it
  has stopped checking against.
- A multi-minor jump (for example `1.24 -> 1.27`) or a patch-only upgrade
  (for example `1.25.1 -> 1.25.4`) returns UNKNOWN for the API-removal
  checks; only a crossing of exactly one reviewed minor line is evaluated.
- Input files must be regular files, mode `0600`, and not symlinks. A
  symlinked path is refused rather than followed.

## Verifying a download

Every archive is listed in `SHA256SUMS` and covered by a keyless build
provenance attestation.

```sh
sha256sum -c SHA256SUMS
gh attestation verify <file> -R prufyx/prufyx
```

## Feedback

Please file issues using the repository's issue templates.
