# For project maintainers

Prufyx checks Kubernetes upgrades against facts taken from the upstream
projects themselves: for example CRD changes between two versions. If you
maintain a public project, you can tell us where those facts live.

## Send information

If you can supply the files, the preferred route is an
[onboarding bundle pull request](../contrib/onboard-bundles/README.md). A
bundle contains hints for one public project; passing validation establishes
that it is well-formed, not that its contents are compatible or correct.

To collect a bounded public-source snapshot for your own review, follow the
[project onboarding guide](../cli/docs/project-onboarding.md). After building
the runner as described there, set `PRIVATE` outside the checkout and shared
directories, then create a private corpus directory, request and snapshot:

```sh
umask 077
mkdir -m 700 -p "$PRIVATE/corpus"
prufyx-maintainer project init \
  --repository https://github.com/OWNER/REPOSITORY \
  --release-limit 5 \
  --output "$PRIVATE/project-request.json"
prufyx-maintainer project sync \
  --manifest "$PRIVATE/project-request.json" \
  --output-parent "$PRIVATE/corpus"
```

The request and snapshot stay private; `init` leaves the project unreviewed
and not admitted. Prepare the bundle separately using the documented layout,
and submit only public material you can redistribute. CI validates changed
bundles using the validator built from the pull request's base branch; it does
not establish the truth of the hints or add a compatibility claim.

If you prefer to send a project observation request as an issue, use the
[onboarding request form](https://github.com/prufyx/prufyx/issues/new?template=onboarding-request.yml).
It asks for a public repository URL, a license declaration, and consent that
the repository is public and contains no private or personal data. Optional
fields provide a slug, release count, tag prefix, and changelog paths. The
issue is public.

The separate [maintainer project form](https://github.com/prufyx/prufyx/issues/new?template=maintainer-project.yml)
collects different fields and is not the form represented by the current
onboarding-request adapter. It asks for project name, repository, relation,
release and CRD pointers, chart and Kubernetes-version details, notes,
deprecations, exclusions, and contact preference. Use the onboarding request
form above for the documented observation request; do not treat the separate
maintainer form as accepted by the staged adapter. Do not put email addresses,
customer data, cluster data, credentials, or private links in either public
issue.

The [maintainer intake demo](maintainer-intake-demo.md) uses fictional form
values and checked-in example files. It does not submit an issue or show a
live intake status. The issue-to-analysis route and a returned maintainer
status are not demonstrated as live; a form submission alone does not mean
the project was analyzed or covered.

## Steps, and what you will see afterwards

You need no access to anything except this public repository.

1. Build the maintainer tool from a checkout (`cd cli && go build ./cmd/prufyx-maintainer`).
2. Optional: run `project init` (and `project sync` if you want a private
   snapshot) as shown above. Both stay on your machine.
3. Either prepare a bundle and validate it offline:

   ```sh
   cd cli
   go run ./cmd/prufyx-maintainer onboard-bundle validate --dir-is-slug ../contrib/onboard-bundles/<slug>
   ```

   then open a pull request, or open the
   [onboarding request form](https://github.com/prufyx/prufyx/issues/new?template=onboarding-request.yml)
   as an issue. The validator reads only the bundle directory, runs nothing
   from it and needs no network. It checks structure and refuses, among other
   things, secret-shaped values, owner-environment names, unknown files and a
   licence identifier outside its allowlist (see the bundle
   [licence rules](../contrib/onboard-bundles/README.md#licence-and-cla)).

What happens next, today:

- Pull request route (implemented): CI validates the changed bundle with the
  validator from the base branch and reports pass or findings on the pull
  request. Maintainers review the diff by hand. A merge does not publish a
  rule or claim.
- Issue route (partly implemented): the issue is public and maintainers read
  it. The issue adapter is not accepted as live intake, see above.

Planned, not live today: automatic status comments, and an automatic import of
accepted submissions into the build pipeline. When they exist, you will be told
the stages in this order: received, validated, imported, then classified as in
scope, blocked with a reason, or out of scope (for example a project with no
CRDs), draft target proposed, included in a batch pull request, merged, and
release pairs decided (n of m). Until then, any stage after validation is
handled by maintainers by hand and is reported, if at all, as a comment from a
maintainer. No time frame is given for any stage.

Review: maintainers review every submission and every batch. Nothing is
published without that review and the project owner's signature on the
knowledge bundle. Passing validation, a merge of your bundle, or a status of
"validated" is not a compatibility claim.

Licence and consent: submit only public projects whose licence lets us
redistribute the facts. BUSL, ELv2, SSPL and proprietary or unlicensed
projects are not accepted. Pull request authors sign the
[CLA](../CLA.md); the issue form requires a consent checkbox that the
repository is public and no private or personal data is included.

Never collected: secrets, credentials, cluster data or any customer data. The
tools above read public repositories only; do not put such data in a bundle,
an issue or a comment.

## How the information is used

What you send is a hint. It tells us where to look and what to ask. It is
never published as fact on its own.

- Every claim is checked against the project's own sources (tags, files,
  changelogs) before publication.
- A claim that cannot be verified is not published as fact. We may ask you for
  a pointer or leave the item out.
- A link that shows you maintain the project (a MAINTAINERS, CODEOWNERS or
  OWNERS line) helps us weigh the hint. Without it the hint has lower
  confidence. It does not replace the checks above.

## What is published and where

Verified results become part of Prufyx knowledge in this repository: rules,
CRD version targets and the coverage listed in the README. They cite your
repository's files. They are published under the data license of this
repository, [CC BY-SA 4.0](../DATA-LICENSE.md). Source code is under the
license in [LICENSE](../LICENSE).

Prufyx covers public, open-source projects; other projects may be declined.
Submitting the form does not guarantee that the project is covered, and this
page gives no date for coverage.

## Update later

Comment on your original issue, or open a new one with the same form and link
the old issue. Pull requests are also accepted; see
[CONTRIBUTING.md](../CONTRIBUTING.md). If a published fact is wrong, say so
in an issue and cite the file that shows the correct value.

## Opt out

Comment on your issue, or open a new one, asking for removal. We remove the
project from the current knowledge set and stop covering it in later releases.
Earlier releases, git history, and copies others made under CC BY-SA 4.0
remain.

## Other routes

- [Project source form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml):
  for anyone, not only maintainers; the repository URL is enough.
- [Onboarding bundles](../contrib/onboard-bundles/README.md): a pull request
  for people who can supply the bundle files.
