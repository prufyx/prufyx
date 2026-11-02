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

If you prefer to send a suggestion as an issue, use the existing form:

Open the
[maintainer form](https://github.com/prufyx/prufyx/issues/new?template=maintainer-project.yml).
Required: project name, repository URL, your relation to the project, and a
consent checkbox. Everything else is optional: release tag pattern, CRD
locations, Helm chart location, supported Kubernetes versions per release
line, upgrade notes and breaking changes, deprecations, versions to exclude,
and how you want to be contacted.

The issue is public. Do not put email addresses, customer data, cluster data
or credentials in it.

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
