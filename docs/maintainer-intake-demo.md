# Maintainer intake demo

This walkthrough shows the public maintainer form and a separate local
compatibility example. It uses fictional form values and the checked-in
MariaDB Operator example; it does not submit an issue or demonstrate that a
submission enters a live analysis queue.

## 1. Inspect the public onboarding request form

The documented observation request is the
[onboarding request form](https://github.com/prufyx/prufyx/issues/new?template=onboarding-request.yml).
It requires a repository URL, license declaration, and consent checkbox. Slug,
release count, tag prefix, and changelog paths are optional. The resulting
issue is public, so do not enter private links, credentials, customer data,
cluster data, or email addresses.

Example values for the form only:

- Repository URL: `https://github.com/example/example-operator`
- License declaration: `NOT_REVIEWED`
- Consent: confirm the repository is public and no private or personal data
  was included
- Release count: `5`

These values are illustrative. Do not file the example as a real submission.
The separate `maintainer-project.yml` form asks different questions and does
not match the currently tested onboarding-request body normalizer. Do not use
it as evidence that the staged adapter accepts the submitted issue.

The onboarding-request form describes a reviewer building and validating a
request before syncing a bounded public-source snapshot. The adapter's tested
`PENDING_ANALYSIS` disposition means a validated request was durably recorded
and is awaiting a separate analysis consumer. It does not mean analysis ran,
that the submitter receives a status, that a compatibility claim was added, or
that the project is covered. The complete issue-to-analysis route and
maintainer-visible status are not demonstrated as live; this page does not
submit an issue or claim a live queue result.

## 2. Inspect an existing local compatibility example

The repository includes a reproducible offline MariaDB Operator example at
[`cli/examples/projects/mariadb-operator/README.md`](../cli/examples/projects/mariadb-operator/README.md).
It evaluates checked-in synthetic resource files for the exact 26.3.0 to
26.6.0 pair. Its documented outcomes are a scoped blocker, a scoped passing
claim for a corrected intermediate input, and an unknown result. The overall
assessment remains `UNKNOWN`; the example does not apply an upgrade or prove
runtime readiness or whole-upgrade safety.

This existing example demonstrates one already verified product workflow. It
does not establish new project coverage, and it is independent of any
maintainer issue submission or staged `PENDING_ANALYSIS` disposition.

## What this demo does not show

- A live issue submission, queue item, or returned maintainer status.
- A completed analysis or coverage decision.
- Any new rule, signed publication, runtime test, or full upgrade result.

Until a live submission and its durable identity and returned disposition are
verified, describe the intake lifecycle as unverified.
