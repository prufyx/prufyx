# Knowledge gate

`prufyx-maintainer gate export|classify|limits|daily-count|verify` checks a proposed change to
the published knowledge — the rule packs, their corpus attestations, the
generated support inventory and the reattestation records — before it can
merge. The `Knowledge gate` workflow (`.github/workflows/knowledge-gate.yml`)
runs it on every pull request to `main` and once a day on `main`.

The gate compares two trees of the repository: the **base** the change is
proposed against and the proposed **head**. It is built from the base and only
reads the head's files; nothing from the proposed change is executed. A change
therefore cannot weaken the gate that checks it. In the workflow both trees are
written by `gate export` from git objects, never checked out, so the change's
own `.gitattributes` (keyword expansion, line-ending or encoding conversion,
filters) cannot make the files the gate checks differ from the blobs that
merge.

Every head file is read without following symbolic links, without blocking (a
FIFO or device is refused, never opened for reading) and up to a size bound. A
symbolic link or special file anywhere under `cli/` in the head fails the
`tree` check.

## Tightening and loosening

Every rule that differs between the base and the head is classified from the
pack diff. Nothing the change declares about itself is used.

| Class | What qualifies | What the gate requires |
| --- | --- | --- |
| Tightening | withdrawing an active rule (`evidence.state` `active` → `withdrawn`); moving `evidence.validUntil` earlier; adding a rule that is already withdrawn. Every other byte of the rule must stay the same. | the pack checks below |
| Loosening | anything else: a new rule, a renewal (later `reviewedAt`, `derivedAt` or `validUntil`), a re-pin (changed `evidence.sources`), reactivation, any change to `range`, any text change, a basis change, and removing a rule | a proof, checked by the gate itself, plus the pack checks |

A tightening change can only turn a `PASS` or `BLOCKED` answer into `UNKNOWN`.
A new rule is loosening even when it only adds `BLOCKED`, because a rule also
makes a scope-complete `PASS` reachable for inputs it does not match.
Narrowing a range is loosening too: when another rule's reviewed pair equals
the transition, a range-matched `BLOCKED` can become a scope-complete `PASS`.
Removing a rule is never admitted; withdraw it instead.

The comparison is on canonical JSON (keys sorted), so re-formatting a pack
file is not a change. The list of changed files compares content and the
executable bit, so a mode-only change is a change. Each entry is compared as the engine reads it: the gate
decodes the pack with the engine's own types and compares the re-encoded
entries. A pack in which any object holds a repeated member, or two members
whose names differ only in letter case (`"rule"` and `"Rule"`), is refused
outright, by the gate and by the engine, because different JSON readers would
read it differently. Top-level member names must be spelled exactly.

Only `entries` has classification rules. A change to any other top-level pack
member (`schema`, `revision`, the policy and digest members,
`lineAttestations`, or a new member) is a loosening change that this version
of the gate never admits. A reattestation statement must therefore keep the
pack's `revision`.

### Proofs for loosening changes

| Evidence basis | Admitted when |
| --- | --- |
| `mechanical` | the extractor named in `evidence.extractor`, as compiled into the gate, re-derives the rule from upstream bytes pinned by commit SHA and fetched by the gate itself, and the re-derived entry is byte-identical (canonical JSON) to the proposed one. The rule's own `derivedAt` and lease (`validUntil` − `derivedAt`) are reused, so a renewal is a re-derivation at a later time. `derivedAt` must lie between 24 hours before and 5 minutes after the gate's clock, so a rule cannot be derived ahead of time to become current later. The extractor id, version and code digest must equal the gate's. |
| `reviewed` (or absent) | either the change appends one signed reattestation statement to the pack's statement chain and that statement passes every `evidence reattest verify` invariant, including the comparison with a worklist the gate's job produced with its own `evidence repin` run; or the change carries an owner approval for exactly that entry (see below) |
| `consensus` | never as loosening. Consensus evidence may only block; while the engine cannot evaluate a consensus rule as block-only, any active consensus rule fails the gate |
| `empirical`, any other | not admitted by this version |

With `--source github` the gate reads upstream repositories directly from
GitHub: directory listings from the git trees API (walking tree objects from
the commit's root tree), file bytes from `raw.githubusercontent.com` by
commit SHA, and tags with `git ls-remote --tags` (an annotated tag resolves to
the commit it points at). Every file is checked against the git blob id its
commit records. It never reads the factory mirror. A `GITHUB_TOKEN` or
`GH_TOKEN` in the environment is used for API requests (rate limit only).

## Pack checks

Run on every pack of the head, whatever the change:

| Check | Fails when |
| --- | --- |
| `admit/<pack>` | the pack (with its landscape, priority list or project registry) is not admitted exactly as shipped knowledge is: registry, policy, identities, review windows, engine parse (string and size limits included) |
| `rulecheck/<pack>` | `rule validate` finds anything in any entry |
| `registry/<pack>` | the compiled fact registry exceeds its cap |
| `size/<pack>` | the published target exceeds its size cap, or is at or above 80 percent of it and the change loosens and grows the pack. At or above 80 percent an alarm is reported |
| `targets/cncf` | the CNCF pack, split into the per-project targets and the index it is published as, has a target over the per-target cap or a total over the package bound (the limits of `knowledge-targets check-size`), or a target or the total is at or above its alarm and the change loosens and grows the pack. Alarms are reported. The single-target size above is still checked, because the publisher still produces that layout |
| `stagger/<pack>` | a loosening change moves a lease into an ISO week that then holds more than 15% of the pack's rules (at least one) |
| `attestation/<pack>` | the committed corpus attestation differs from a regeneration from the head's pack |
| `generated/…` | the committed support inventory differs from a regeneration from the head's files |
| `block-only/<pack>` | an active rule has basis `consensus` (see above) |
| `reattestation/<pack>` | the statement chain changed and the appended statement does not verify |
| `tree` | the head holds a symbolic link or a special file under `cli/` |
| `file-modes` | a knowledge file the automation may change has, or changes, an executable bit |
| `trust-material` | the change touches trust material (see below) and is not a person's change matching the pinned digest |
| `knowledge-records` | an approval file, worklist or review record changed without the rule change or statement it belongs to (see below) |
| `limits` | the change holds more loosening changes than the cap (default 200) |
| `kill-switch` | the file `factory/PAUSE` exists in the base or the head and the change holds any loosening change |

The kill switch blocks every loosening change and lets tightening through. A
change that adds `factory/PAUSE` pauses itself; a change that deletes it is
still paused, because the base has it.

## Circuit breakers, daily limit, shadow mode

These checks only ever make the gate stricter: a tripped breaker or limit
fails the run, shadow mode makes a change ineligible for automatic merging, and
none of them can make a failing change pass.

**Withdrawal breaker.** Withdrawing a rule is tightening, so without a limit one
change could switch off a whole pack's checks. A change fails, with an alarm, when
it withdraws more than `--max-withdraw-percent` percent (default 5) of a pack's
active rules in the base, or more than `--max-withdraw-project` rules (default 20)
of one project. Exactly the limit passes. Only an `active` to `withdrawn` change
counts: expiring a lease or adding a rule that is already withdrawn does not. The
checks are `breaker/withdrawals/<pack>` and `breaker/withdrawals-project`.
Raise the limits with the repository variables below for a deliberate large
withdrawal.

**Daily limit.** The loosening changes the automation merged in the last 24
hours, plus this change's, may not exceed `--max-daily-loosening` (default
400); this is in addition to the per-change cap. Counting needs the history of
`main`, so the caller counts and passes the number as `--daily-loosening-count`.
`gate daily-count` does the counting: for each commit of `main` from the last
day that the automation authored (or whose author GitHub does not know), it
classifies the commit against its first parent with the same code a pull
request is checked with and adds up the loosening changes; commits by other
people do not count. A change that loosens nothing is never held back by the
daily limit. When the count is not supplied, the change is never eligible for
automatic merging; the workflow supplies it only when the GitHub API call and
the count both succeed, so any failure fails closed (the gate still checks the
change normally). A missing count is never read as zero.

**Shadow mode.** With `--shadow` (the workflow sets it from the repository
variable `KNOWLEDGE_GATE_SHADOW=true` or a pull request label `shadow`) the
report is computed exactly as usual, `mode` is `shadow`, and `autoMerge.eligible`
is always false. Labelling or unlabelling a pull request runs the gate again,
and the run counts as triggered by the person who changed the label.

## Metrics and alarm files

`gate verify` can write two files per run; the workflow uploads both with the
report.

`--metrics FILE` writes `gate-metrics.json` (`prufyx.io/knowledge-gate-metrics/v1`):
`mode`, `result`, `paused`, `totals`, `classes` (changes per class and kind; a
change with two kinds counts under each), `projects` (tightening and loosening
changes per project; at most 500 projects, the rest under `(other)`), `renewals`,
`withdrawals`, `rederivations` (changed rules admitted by re-derivation),
`rederivedUnchanged` (rules a `--rederive-all` run re-derived), `failures`
(failed changes, failed checks and their names), `limits`, `breakers` (every
breaker with what it observed and whether it tripped), `alarms`,
`autoMergeEligible` and `durationMs`. Keys are sorted at every depth and the
file is a function of the report, so identical runs give identical bytes except
`durationMs`. It holds only statistics about knowledge changes; every string
is at most 256 bytes.

`--alarms FILE` writes `gate-alarms.json` (`prufyx.io/knowledge-gate-alarms/v1`):
a list of `{kind, detail}` records, one per alarm. Kinds: `loosening-cap`,
`daily-limit`, `withdrawal-breaker-pack`, `withdrawal-breaker-project`, `size`.
Details are made safe to print and cut to 256 bytes. `--alarms-markdown FILE`
writes the same list as Markdown.

If the repository variable `OPS_ISSUES_REPO` (owner/name of a separate, private
repository) and the secret `OPS_ISSUES_TOKEN` (a token that can write issues in
that repository only, stored as a secret of the `knowledge-alarms`
environment) exist, the `Gate alarms` job opens an issue titled
`Knowledge gate alarms: pull request N` (or `scheduled run`), or comments on the
open one. It runs only when the gate raised alarms, for pull requests only for
the automation's own, holds no repository permission and runs no code of the
change. Without the variable and secret it does nothing; the gate does not
need either.

## Automatic merge eligibility

The gate reports, and never acts on, whether a change would be eligible for
automatic merging, and for which head commit (`headSha` in the report, the
job output `head-sha`). It is eligible only when:

- every check passes and the change contains at least one knowledge change;
- the pull request's author (`--author`) and the account whose action
  triggered the run (`--sender`) are the automation account (`--bot-login`);
- every commit between the base and the head is authored and committed by the
  automation account and carries a signature GitHub verified (`--commits`,
  GitHub's compare API for `base...head`), the list is complete and ends at
  `--head-sha`;
- the daily count was supplied (`--daily-loosening-count`) and shadow mode is
  off;
- it touches only these files:
  - `cli/internal/cncfcheck/data/rules.json`, `cli/internal/cncfcheck/data/corpus-attestation.json`
  - `cli/internal/projectcheck/data/rules.json`, `cli/internal/projectcheck/data/corpus-attestation.json`
  - `cli/docs/generated/community-support-inventory.json`, `cli/docs/generated/community-support-inventory.md`
  - anything under `cli/knowledge/approvals/`
  - anything under `cli/knowledge/reattestation/<pack>/chain/`, `…/worklists/` and `…/review-records/`

Trust material is never on that list. A consumer that merges automatically
must merge exactly the commit in `head-sha` (for example with the expected
head commit of the merge request), and only when the gate job succeeded, not
on the eligibility output alone.

## Trust material

Trust material is everything under `cli/knowledge/trust/`, the reattestation
trust root `cli/knowledge/reattestation/trust-root.json`, and any file named
`trust-root*` or `*approval-keys*` anywhere. The gate reads it from the base
only. A change that touches it fails the `trust-material` check unless all of
these hold: the author is a person (not the automation account, and the run
was not triggered by it), and the changed file is the trust root or the
approval key file and matches the digest pinned in a repository variable
(`REATTEST_TRUST_ROOT_DIGEST`, `WEB_APPROVAL_KEYS_DIGEST`: `sha256:` and the
hex sha256 of the file without its final newline). Update the variable first,
then merge the file. Other files under `cli/knowledge/trust/` cannot pass the
gate. `CODEOWNERS` requires the owner's review for these paths.

## Records that belong to a change

- `cli/knowledge/approvals/<pack>/<rule id>.json` may be added or changed only
  together with a change to that rule that the approval admitted; it may be
  removed only together with an admitted change to that rule.
- `cli/knowledge/reattestation/<pack>/worklists/<stem>.worklist.json` may only
  be added, and only for the statement `<stem>` the same change appends and the
  gate verifies.
- `cli/knowledge/reattestation/<pack>/review-records/<rule id>.json` may be
  added or changed (never removed) only for rules that statement renews.
- Any other file under these directories fails the `knowledge-records` check.

## File layout

| Path | Read from | Holds |
| --- | --- | --- |
| `factory/PAUSE` | base and head | kill switch (any content) |
| `cli/knowledge/reattestation/<pack>/chain/` | base and head | the pack's signed statement chain: `<stem>.statement.json` and `<stem>.statement.sig.json` pairs |
| `cli/knowledge/reattestation/<pack>/worklists/<stem>.worklist.json` | head | the worklist the statement `<stem>` was prepared from |
| `cli/knowledge/reattestation/<pack>/review-records/<rule id>.json` | head | individual review records, when a human statement uses them |
| `cli/knowledge/reattestation/trust-root.json` | base only | the reattestation trust root; its digest is passed separately (`--trust-root-digest`) |
| `cli/knowledge/approvals/<pack>/<rule id>.json` | head | owner approvals |
| `cli/knowledge/trust/web-approval-keys.json` | base only | the pinned owner-approval keys; their digest is passed separately (`--approval-keys-digest`) |

`<pack>` is `cncf` or `community`. A reattestation worklist names each pack by
its repository path (`cli/internal/cncfcheck/data/rules.json`,
`cli/internal/projectcheck/data/rules.json`); run `evidence repin` from the
repository root with those `--rules` paths.

## Owner approvals

An owner approval admits one exact reviewed entry in place of one exact base
state. The committed file is:

```json
{
  "schema": "prufyx.io/knowledge-approval/v2",
  "record": {
    "baseDigest": "absent",
    "candidateDigest": "sha256:…",
    "candidateId": "…",
    "decidedAt": "2026-10-03T12:00:00Z",
    "decision": "approve",
    "identity": "owner-login",
    "pack": "cncf",
    "ruleId": "…"
  },
  "keyId": "sha256:…",
  "signature": "…"
}
```

- `candidateDigest` is `sha256:` and the hex sha256 of the proposed entry's
  canonical JSON: the entry object (`project`, `description`,
  `requiredFacts`, `rule`) as the engine reads it, with object keys sorted,
  two-space indentation, no HTML escaping and one final newline.
- `baseDigest` is the same digest of the entry with that rule id in the base,
  or `absent` when the base has no such rule. An approval therefore cannot be
  replayed after the rule changed, for example to re-activate it after it was
  withdrawn.
- `signature` is the standard base64 Ed25519 signature over the bytes
  `prufyx.io/knowledge-approval/v2`, one NUL byte, then the record as compact
  JSON with its keys in the order shown. Every record field is plain ASCII
  from a restricted alphabet, so any JSON encoder produces the same bytes.
- `keyId` is `sha256:` and the hex sha256 of the raw 32-byte public key.

Version 1 approvals (without `baseDigest`) are refused.

The gate accepts an approval only if the base's `web-approval-keys.json`
matches `--approval-keys-digest`, the key is pinned in it
(`"role": "web-approval"`) and not past its
`notAfter`, the signature verifies, the decision is `approve`, the identity is
one of the pinned `owners`, the pack and rule id match, the decision time is
not in the future (five minutes of clock skew allowed) and at most 14 days
old, the candidate digest matches the proposed entry and the base digest
matches the base. Changing anything in the entry after approval invalidates
it. Approvals never admit a mechanical rule.

```json
{
  "schema": "prufyx.io/web-approval-keys/v1",
  "role": "web-approval",
  "owners": ["owner-login"],
  "keys": [{"keyId": "sha256:…", "publicKey": "<64 hex>", "notAfter": "2027-10-01T00:00:00Z"}]
}
```

No approval key is pinned in this repository yet, so no approval is accepted.
`candidateId` is not checked for reuse; within its 14 days an approval is
bounded by the base digest instead.

## Commands

`classify`, `limits` and `verify` take `--base DIR` and `--head DIR`
(repository roots). Exit codes: `0` the gate passes (for `classify`: always,
when the input can be read), `1` it fails, `2` rejected input or an error.
Strings taken from the proposed change are printed with line breaks, other
control characters, `%` and `::` escaped and their length capped, so they can
never form a CI log command.

### `gate export`

Writes the tree of one commit into a new directory with the exact bytes of
every blob, read with `git cat-file` from the object store (no checkout, no
attributes, no filters). Symbolic links are written as links; a submodule, a
path component `.`, `..` or `.git`, or a tree over the size bounds fails.

| Flag | Meaning |
| --- | --- |
| `--git-dir DIR` | repository (usually bare) holding the commit |
| `--commit SHA` | full 40-hex commit id |
| `--out DIR` | directory to create; it must not exist |

### `gate classify`

Prints every changed rule with its class, kinds and basis, the packs whose
statement chain changed, and whether the kill switch is set.

| Flag | Meaning |
| --- | --- |
| `--json` | print JSON instead (`changes`, `totals`, `chainsChanged`, `paused`) |

Change kinds: `withdraw`, `expire`, `add-withdrawn` (tightening); `new`,
`remove`, `reactivate`, `renew`, `repin`, `widen`, `narrow`, `range-change`,
`basis-change`, `modify`, `pack-member` (loosening). A `pack-member` change
names the member (`member`) instead of a rule id.

### `gate limits`

Only the loosening cap, the withdrawal breakers, the daily limit and the kill
switch.

| Flag | Meaning |
| --- | --- |
| `--max-loosening N` | cap on loosening changes (default 200) |
| `--max-withdraw-percent N` | breaker: percent of a pack's active rules one change may withdraw, 1–100 (default 5) |
| `--max-withdraw-project N` | breaker: rules of one project one change may withdraw (default 20) |
| `--daily-loosening-count N` | loosening changes the automation merged in the last day (default: unknown) |
| `--max-daily-loosening N` | cap on that count plus this change (default 400) |
| `--json` | print the report as JSON |

### `gate daily-count`

Prints the number of loosening changes in the listed commits of `main`
that the automation authored (or whose author is unknown).

| Flag | Meaning |
| --- | --- |
| `--git-dir DIR` | repository holding the commits and their parents |
| `--commits FILE` | JSON list of `{sha, parent, author}` (the first parent, and the author's login or null), at most 300 commits |
| `--bot-login LOGIN` | the automation account (default `prufyx-factory[bot]`) |

A commit that cannot be compared with its first parent, or a list over 300
commits, is an error (exit 2), never a smaller count.

### `gate verify`

The whole gate.

| Flag | Meaning |
| --- | --- |
| `--source github` | fetch pinned upstream bytes from GitHub for re-derivation |
| `--source fixture:DIR` | read them from a fixture tree instead (`<host>/<owner>/<name>/tags.json` and `commits/<sha>/…`, the layout `extract run --fixture` reads) |
| `--author LOGIN` | the change's author, for automatic-merge eligibility and trust material |
| `--sender LOGIN` | the account whose action triggered the run |
| `--bot-login LOGIN` | the automation account (default `prufyx-factory[bot]`) |
| `--head-sha SHA` | the head commit being checked; reported as `headSha` |
| `--commits FILE` | the change's commits as GitHub's compare API returns them (`status`, `ahead_by`, `behind_by`, `total_commits`, and per commit `sha`, `author.login`, `committer.login`, `commit.verification.verified`) |
| `--approval-keys-digest sha256:…` | pinned digest of the base's owner-approval key file; without it no approval is accepted |
| `--max-loosening N` | cap on loosening changes (default 200) |
| `--max-withdraw-percent N`, `--max-withdraw-project N` | the withdrawal breakers (defaults 5 and 20), see above |
| `--daily-loosening-count N`, `--max-daily-loosening N` | the daily limit (default cap 400); without a count the change is not eligible |
| `--shadow` | shadow mode: never eligible for automatic merging |
| `--metrics FILE`, `--alarms FILE`, `--alarms-markdown FILE` | write the metrics and alarm files |
| `--trust-root-digest sha256:…` | pinned digest of the base's reattestation trust root; without it no statement is accepted |
| `--rerun-worklist FILE` | worklist from this job's own `evidence repin` run; without it no statement is accepted |
| `--rederive-all` | also re-derive every active mechanical rule, changed or not |
| `--concurrency N` | concurrent upstream reads during re-derivation (0–64) |
| `--now RFC3339` | the gate's clock, UTC (default: now); for reproducing a past run |
| `--report FILE` | write the JSON report |
| `--summary FILE` | append a Markdown summary (the workflow passes `$GITHUB_STEP_SUMMARY`) |
| `--json` | print the report as JSON |

Without `--source`, every mechanical loosening change fails.

The report (`prufyx.io/knowledge-gate-report/v1`) lists `result` (`pass` or
`fail`), `changes` (each with `class`, `kinds`, `basis`, `proof`, `ok` and
`detail`), `checks`, `alarms`, `limits`, `daily`, `breakers`, `mode` (`enforce` or `shadow`), `changedPaths`, `chainsChanged`,
`autoMerge` (`eligible` and the reasons it is not), `author`, `sender` and
`headSha`.

## Example

Comparing a checkout with itself passes and is not eligible for automatic
merging (no knowledge change):

```sh
cd cli
go run ./cmd/prufyx-maintainer gate verify --base .. --head ..
```

```text
ok   check tree: 0 links or special files under cli/
ok   check admit/cncf: 191 entries admitted
ok   check registry/cncf: 160 of 256 facts
…
ok   check trust-material: 0 trust files changed
ok   check knowledge-records: 0 record files changed
ok   check limits: 0 loosening changes, cap 200
ok   check limits/daily: the number of loosening changes merged in the last day was not supplied; the change is not eligible for automatic merging
ok   check breaker/withdrawals/cncf: 0 of 190 active rules withdrawn, breaker above 5 percent
ok   check breaker/withdrawals/community: 0 of 34 active rules withdrawn, breaker above 5 percent
ok   check breaker/withdrawals-project: 0 projects with withdrawals, breaker above 20 rules of one project
gate: PASS (0 tightening, 0 loosening; kill switch not set; mode enforce)
auto-merge: not eligible (author "" is not the automation account "prufyx-factory[bot]"; the run was triggered by "", not the automation account; the change's commit list was not supplied; the change holds no knowledge change; the number of loosening changes merged by the automation in the last day is unknown)
```

## The workflow

`Knowledge gate` runs on `pull_request_target` so that its definition and
the gate code always come from the base branch. For a pull request it resolves
the tip of `main` at run time and fails when the pull request's base is not
that tip (the branch must be up to date). It checks out only the base, without
stored credentials, and builds the gate from it with module caching off. It
fetches the base and head commits into a bare repository, requires the head to
contain the base, and exports both trees with `gate export`. It lists the
change's commits with GitHub's compare API, then runs `gate classify` and
`gate verify --source github` with the author, the event sender, the head
commit and the commit list; gate output is printed with workflow commands
stopped. When a statement chain changed it first runs `evidence repin` itself
and passes the result as `--rerun-worklist`. For a pull request it also counts
the loosening changes the automation merged in the last day (`gate daily-count`
over the history of `main`) and passes the number. The token is read-only and
the gate job uses no secrets; the only secret in the workflow belongs to the
separate `Gate alarms` job. On the daily run it adds `--rederive-all`.

It does not run for a merge queue: a `merge_group` run would use the workflow
definition of the queued commit. Pull requests must instead be up to date with
`main` before they merge (branch protection "require branches to be up to
date"), so the merged tree is the tree the gate checked.

Repository variables: `REATTEST_TRUST_ROOT_DIGEST` (the pinned trust root
digest; unset means no statement is accepted), `WEB_APPROVAL_KEYS_DIGEST` (the
pinned owner-approval key file digest; unset means no approval is accepted),
`KNOWLEDGE_BOT_LOGIN` (default `prufyx-factory[bot]`), `KNOWLEDGE_MAX_LOOSENING`
(default 200), `KNOWLEDGE_MAX_DAILY_LOOSENING` (default 400),
`KNOWLEDGE_MAX_WITHDRAW_PERCENT` (default 5), `KNOWLEDGE_MAX_WITHDRAW_PROJECT`
(default 20), `KNOWLEDGE_GATE_SHADOW` (`true` for shadow mode) and, for alarm
issues, `OPS_ISSUES_REPO`.

The job's outputs `result`, `auto-merge-eligible`, `head-sha` and `alarm-count` and the
uploaded `knowledge-gate-report` artifact carry the result. The workflow never
merges. The factory must open its pull requests with its GitHub App token
(pull requests opened with the workflow token start no workflows) and create
its commits as the App, so they are authored, committed and signed by it.
