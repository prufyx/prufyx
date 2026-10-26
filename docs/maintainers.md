# For project maintainers

Prufyx checks Kubernetes upgrades against facts taken from the upstream
projects themselves: for example CRD changes between two versions. If you
maintain a public project, you can tell us where those facts live.

## Send information

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

Projects under source-available or proprietary licenses are not accepted.
Submitting the form does not guarantee that the project is covered, and this
page gives no date for coverage.

## Update later

Comment on your original issue, or open a new one with the same form and link
the old issue. Pull requests are also accepted; see
[CONTRIBUTING.md](../CONTRIBUTING.md). If a published fact is wrong, say so
in an issue and cite the file that shows the correct value.

## Opt out

Comment on your issue, or open a new one, asking for removal. We remove the
project's published knowledge and stop covering it. We cannot recall copies
that others already made under the license.

## Other routes

- [Project source form](https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml):
  for anyone, not only maintainers; the repository URL is enough.
- [Onboarding bundles](../contrib/onboard-bundles/README.md): a pull request
  for people who can supply the bundle files.
