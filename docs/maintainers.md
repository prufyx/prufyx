# For project maintainers

Prufyx checks Kubernetes upgrades against facts taken from the upstream
projects themselves: for example CRD changes between two versions. If you
maintain a public project, you can tell us where those facts live.

## Start here: which route

1. Check first whether your project is already bundled: look for a directory
   named after it in [`contrib/onboard-bundles/`](../contrib/onboard-bundles/)
   (for example `ls contrib/onboard-bundles/` in a checkout). A project that
   already has a bundle, or is already onboarded, is refused in review.
2. Only an invited maintainer of the project can submit a bundle. To get an
   invite, open the
   [maintainer project form](https://github.com/prufyx/prufyx/issues/new?template=maintainer-project.yml)
   (see [Intake is for invited maintainers only](#intake-is-for-invited-maintainers-only)).
   The form only asks for an invite and imports nothing. After you open it, a
   Prufyx maintainer checks your public link and, if it holds, records the
   invite and tells you in a comment on that issue. No response time is
   promised yet.
3. Which form for what: invite request -> maintainer project form;
   observation request (a public repository to look at, no bundle) ->
   [onboarding request form](https://github.com/prufyx/prufyx/issues/new?template=onboarding-request.yml);
   bundle -> a pull request from your own fork, neither form.
4. Not automated yet: building the bundle files. There is no command that
   writes the bundle from your snapshot or its receipt digests; see the
   [bundle README](../contrib/onboard-bundles/README.md). Until then, ask for
   the invite first and say so in the issue.

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
  --slug SHORT-NAME \
  --release-limit 5 \
  --output "$PRIVATE/project-request.json"
prufyx-maintainer project sync \
  --manifest "$PRIVATE/project-request.json" \
  --output-parent "$PRIVATE/corpus"
```

Pass `--slug` with the short project name (for example `jobset`). Without it
the slug is `<owner>-<name>-<hash>`, which will not match a bundle directory.
`prufyx-maintainer` must be on your `PATH`: the build block in the guide does
that with `export PATH="$PRIVATE/bin:$PATH"`. Without that build, use
`cd cli && go run ./cmd/prufyx-maintainer ...` instead of the bare command.

The request and snapshot stay private; `init` leaves the project unreviewed
and not admitted. The bundle is prepared separately using the documented layout; that step is
not automated yet (see above). Submit only public material you can redistribute. CI validates changed
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

1. Build the maintainer tool from a checkout (`cd cli && go build ./cmd/prufyx-maintainer`;
   the binary lands in `cli/`, so add that directory to `PATH` or use `go run`).
   It needs Go 1.26 (any 1.26.x); the first build can take a while.
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

Planned, not live today: automatic status comments. Until they exist, any stage
after validation is reported, if at all, as a comment from a maintainer, and no
time frame is given for any stage. When status comments exist, you will be told
the stages in this order: received, validated, imported, then classified as in
scope, blocked with a reason, or out of scope (for example a project with no
CRDs), draft target proposed, included in a batch pull request, merged, and
release pairs decided (n of m).

Review: maintainers review every submission and every batch. Nothing is
published without that review and the Prufyx maintainers' signature on the
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

## Intake is for invited maintainers only

Prufyx takes new projects only from people who maintain them. A bundle is
imported into the build pipeline only when the account that opened the pull
request holds an active invite for that exact repository. A bundle from an
account without an invite is refused and is not imported, even if it is
well-formed and merged. Refusal is not a judgement of the project.

### Invite steps

1. Ask for an invite. Open the
   [maintainer project form](https://github.com/prufyx/prufyx/issues/new?template=maintainer-project.yml)
   with the repository, your relation to it, and a public link that names your
   GitHub account (a MAINTAINERS, CODEOWNERS or OWNERS line, or an
   organisation page). There is no automatic invite and no way to invite
   yourself.
2. A Prufyx maintainer checks that link and, if it holds, records an invite
   for your GitHub login and the repository (up to five repositories per
   invite). An invite is limited in time (at most 180 days), can be revoked,
   and is counted against weekly and lifetime limits, with one submission in
   flight per invite. You are told by a comment on your issue.
3. Prepare the bundle as described above and validate it offline.
4. Open the bundle pull request from your own fork, with your own account.
   The pull request is the submission; the issue forms do not import anything.

### The accepted merge path

The import accepts exactly one path, and checks it again by itself instead of
trusting the pull request page:

- The bundle is a new directory `contrib/onboard-bundles/<slug>/` (lower-case
  letters, digits and hyphens) and arrives on `main` through a pull request
  merged with a merge commit by a Prufyx maintainer. Squash, rebase,
  fast-forward and direct commits are refused: they leave no merge commit and
  no pull-request number to attribute the bundle to. You do not merge your own
  pull request.
- The merge commit subject is the standard
  `Merge pull request #<n> from <your-login>/<branch>`. Your login is read from
  that subject. A pull request from a branch inside the Prufyx repository itself
  names the repository owner, not a contributor, and is refused. Open it from a
  fork.
- The merge commit must have two parents, be on `main`, and change nothing
  outside that one bundle directory.
- The bundle directory in the merge commit must be the same content that was
  read and validated: same tree, same digest, and still valid under the pinned
  validator. Symlinks, submodules, files over the size limit and unlisted files
  refuse it. If a later change by someone else touches the directory, the
  bundle is attributed to that later change and refused as not provably yours.
- GitHub must report that pull request as merged into `main`, with that merge
  commit, opened by the same login that holds the invite, and the invite must
  still be active, unexpired, and for the same repository.

Anything else is parked with a reason, not imported. An import that cannot
prove the merge refuses rather than guesses. Provenance is not signed:
the check is the merge commit, the pull request and the invite together.

### Who does what

You submit the pull request. CI validates the bundle and the history is checked
for merge commits and a branch from `main`. A Prufyx maintainer reviews the diff
and merges. Import into the build pipeline runs by itself within about an hour
after the merge and is then verified as above. Everything after import is
reviewed by maintainers, and a signed knowledge bundle is still required before
anything is published.

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
