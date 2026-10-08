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
Removing a rule is not admitted; withdraw it instead. The one exception is a
reviewed rule replaced by a re-derived mechanical one: see [Superseding a
reviewed rule](#superseding-a-reviewed-rule).

The comparison is on canonical JSON (keys sorted), so re-formatting a pack
file is not a change. The list of changed files compares content and the
executable bit, so a mode-only change is a change. Each entry is compared as the engine reads it: the gate
decodes the pack with the engine's own types and compares the re-encoded
entries. A pack in which any object holds a repeated member, or two members
whose names differ only in letter case (`"rule"` and `"Rule"`), is refused
outright, by the gate and by the engine, because different JSON readers would
read it differently. Top-level member names must be spelled exactly.

Only `entries` and, in the CNCF pack, the line attestations
(`lineAttestations`) and upgrade-path policies (`pathPolicies`) have
classification rules (see [Line attestations and path
policies](#line-attestations-and-path-policies)). A change to any other
top-level pack member (`schema`, `revision`, the policy and digest members, or
a new member) is a loosening change that this version of the gate never
admits. A reattestation statement must therefore keep the pack's `revision`,
and adding the first record of a section, or removing the last one, changes
the pack's `schema` and is not admitted either. In the community pack the
record sections have no classification rules.

### Proofs for loosening changes

| Evidence basis | Admitted when |
| --- | --- |
| `mechanical` | the extractor named in `evidence.extractor`, as compiled into the gate, re-derives the rule from upstream bytes pinned by commit SHA and fetched by the gate itself, and the re-derived entry is byte-identical (canonical JSON) to the proposed one. The rule's own `derivedAt` and lease (`validUntil` − `derivedAt`) are reused, so a renewal is a re-derivation at a later time. `derivedAt` must lie between 24 hours before and 5 minutes after the gate's clock, so a rule cannot be derived ahead of time to become current later. The extractor id, version and code digest must equal the gate's. |
| `reviewed` (or absent) | either the change appends one signed reattestation statement to the pack's statement chain and that statement passes every `evidence reattest verify` invariant, including the comparison with a worklist the gate's job produced with its own `evidence repin` run; or the change carries an owner approval for exactly that entry (see below) |
| `consensus` | never as loosening: the engine evaluates consensus as block-only, but this gate has no consensus verifier |
| `empirical` | not admitted by this version: empirical evidence may pass, and the gate cannot yet check its reproduction |
| `lead` | never: a lead is not published through this gate |
| any other | not admitted |

### Superseding a reviewed rule

A reviewed rule R can turn a `BLOCKED` answer into a scope-complete `PASS`
when it is deleted, so a removal is refused unless the same change adds a
mechanical rule M that replaces it. The gate pairs the two from the pack diff
alone. A removal is paired with an addition when all of these hold:

- R is a removed rule whose basis is `reviewed` (or absent), in any state;
  M is a new rule with basis `mechanical` and state `active`;
- M and R are in the same project and the same subject component and have an
  **equal constraint key**: the operator and the constrained fact (side,
  component and fact id; for a dependency rule side and component). The key is
  computed by `constraintengine.ConstraintKey`, the function the engine's
  overlap lint uses, so the gate cannot drift from it;
- the rest of the predicate is identical: the condition's values, `appliesWhen`,
  the dependency's comparison and version, `intermediate` and `severity`.
  Only `id`, `evidence`, `reasonCode`, `nextAction` and `range` may differ;
- M's match region contains R's region on both sides (an exact anchor counts as
  a single version, a range as `[gte, lt)`; a version that is not a release
  version covers nothing), and for a set rule M's forbidden members include all
  of R's.

The pairing is one to one: a removal that several additions could replace, or
an addition that could replace several removals, stays a plain removal and is
refused. A pair is **admitted** only when

1. M is itself admitted by re-derivation (the extractor re-derives it from the
   pinned upstream bytes, byte for byte), checked after the re-derivation step;
2. the change's author (`--author`) **and** the account that triggered the run
   (`--sender`) are the repository owner (`--owner-login`, default `airstand`,
   the CODEOWNERS entry), and the owner is not the automation account;
3. the commit list (`--commits`, `--head-sha`) is supplied, complete, strictly
   ahead of the base and ends at the head, and **every commit is authored and
   committed by the owner** (a foreign commit pushed to the owner's branch
   refuses the pair). Unlike the automation's commits, no signature is required.

R then has kinds `remove, supersede`, proof `superseded` and `supersededBy`
naming M; M carries `supersedes`. A supersede is never eligible for automatic
merging (a reason is added to `autoMerge`), even though the pack checks still
apply and the engine must admit the head pack (its overlap lint would refuse
M next to R, which is why R must go in the same change).

Consequences to know:

- A rule that is already `withdrawn` may be superseded too; only its reviewed
  basis matters.
- The superseded rule's lease is replaced by M's mechanical lease: at expiry
  the answer is `UNKNOWN`, never `PASS`.
- Users who run `--trust-policy reviewed` lose the rule (the assessment is
  `UNKNOWN`), because M is mechanical, not reviewed.
- Pairing is 1:1: one M replacing two reviewed rules is refused; make it two
  changes.
- The entry's `description` and `requiredFacts` are not compared; only the rule
  object decides a verdict.
- A rule whose canonical form cannot be computed is never paired (fail closed).

Counting: a pair is **one** loosening for the cap, the daily limit and the
totals (counted on M). Neither half is a withdrawal for the circuit breakers.
The report lists the pairs under `supersedes` (`pack`, `old`, `new`, `ok`,
`detail`), the log prints `supersede <pack>: R -> M` and the Markdown summary
has a table. Any refusal leaves R's change failed with the reason.

## Line attestations and path policies

The CNCF pack's line attestations and upgrade-path policies are compared
record by record. Each record is keyed by its record ID, the same ID `evidence
repin` and `evidence reattest` use (`line-attestation.` or `path-policy.`
followed by 24 hex digits, derived from the record's scope), never by its
position in the section. Both sections are read strictly, exactly as the
engine reads them; a pack whose records cannot be read is refused.

| Class | What qualifies |
| --- | --- |
| Tightening | removing a line attestation (its line becomes a gap again); withdrawing a path policy (`evidence.state` `active` → `withdrawn`); moving a record's `evidence.validUntil` earlier. Every other byte of the record must stay the same. |
| Loosening | anything else: a new record (also a path policy that is already withdrawn), a renewal, any change to a record's content, and removing a path policy (without a record a path is planned as one direct hop; withdraw it instead) |

A loosening record change is admitted only with one of these proofs:

| Record | Admitted when |
| --- | --- |
| reviewed line attestation or path policy, renewed | the change appends one signed statement to the pack's statement chain that verifies (as for rules, including the comparison with the gate's own worklist), the statement is an automated one (`signerRole` `automation`), it renews this record, and the record differs from the base only in a later `evidence.reviewedAt` and a later `evidence.validUntil`, set exactly to the statement's `attestedAt` and the `validUntil` the statement gives the record. The gate checks the dates itself; it does not infer them from the statement verifying. |
| reviewed line attestation, added or changed otherwise | an owner approval for exactly that record (see [Owner approvals](#owner-approvals)), and the cross-check below |
| reviewed path policy, changed otherwise | never |
| mechanical line attestation | the extractor named in `evidence.extractor`, as compiled into the gate, derives exactly this attestation (canonical JSON) from upstream bytes pinned by commit SHA, with the record's own `derivedAt` and lease, under the same 24-hour derivation-time bound as a mechanical rule. A statement or an approval never admits one. |
| mechanical path policy | never: no extractor derives path policies |

**Cross-check of a reviewed line attestation.** A line attestation states that
the rules it lists are all the pack's rules for one line and fact family. The
pack checks prove the list matches the pack; they cannot prove that upstream
removed nothing else on that line. So the gate also runs the extractor that
attests the attestation's fact family over pinned upstream bytes, at its own
clock, and requires:

- for a line before the first line the extractor is built to derive (1.20 for
  `k8s.served-api-removal`): nothing more (the approval alone decides);
- for any other line: the extractor derives and attests that line in this run,
  and for every rule it derives for the line the attestation lists a rule with
  the same operator and the identical condition (side, component, fact and
  value) that is neither a one-way notice nor a lead.

An attestation of a line the extractor does not derive (for example a line
that has no release yet, or whose release could not be resolved), one that
leaves out a removal upstream makes, or one that covers it only with a rule
reading the fact differently, is refused even with an approval. Without an
upstream source (`--source`) the cross-check fails.

Record changes count like rule changes: toward the loosening cap, the daily
limit and the kill switch, and switching records off counts toward the record
breaker (see below). A record change appears in the report with `section`
(`lineAttestations` or `pathPolicies`) and the record ID as `ruleId`.

The CNCF knowledge is published as one target per project, and that split
does not carry records yet: a CNCF pack holding any record still fails the
`targets/cncf` check, so no such change can merge through the gate until the
split supports them.

With `--source github` the gate reads upstream repositories directly from
GitHub: directory listings from the git trees API (walking tree objects from
the commit's root tree), file bytes from `raw.githubusercontent.com` by
commit SHA, and tags with `git ls-remote --tags` (an annotated tag resolves to
the commit it points at). Every file is checked against the git blob id its
commit records. It never reads the factory mirror. A `GITHUB_TOKEN` or
`GH_TOKEN` in the environment is used for API requests (rate limit only).

**Request budget.** A full re-derivation of the CRD wave costs about a thousand
REST requests, as much as the workflow token's hourly limit. A pull request
re-derives only the rules it changes. The scheduled run re-derives one shard a
day (`--shard day/7`), so every project is fully re-derived at least weekly. Git
trees are cached by id within a run (and between runs with `--cache-dir`);
git objects never change, so a cache hit replaces a conditional request. Every
run reports its REST requests (report `upstream`, metrics `restRequests`, the
step summary). If the budget runs out (`--rest-budget`, or GitHub refuses or
reports too few requests left) the run fails with a `rest-budget` check
"could not run", `couldNotRun` set, and exit status 3: a starved run is never a
pass, and nothing it did compute counts as one. It also raises a
`could-not-run` alarm, so the alarm channel hears about it (a red cron run alone
is easy to miss). The budget is one counter: the citation verifier's
api.github.com calls (changed rules only) draw on it too, and `rest-budget` is
evaluated after the citation check, so starvation during citations is
`couldNotRun` as well. The raw file host is not counted. Calls made by other
steps of the job (`evidence repin`, `gh api`) and by concurrent runs on the same
token are not counted; the 25-request reserve is for them.

**Weekly guarantee, and its limits.** "Every project is re-derived at least
weekly" holds only if every scheduled run happens and finishes. GitHub can drop
a scheduled run, and a manual dispatch cancels a running nightly one (they share
a concurrency group), so a missed shard can wait 7 days or more for its next
turn. A shard that cannot finish (its extractors need more than the budget)
starves every time its day comes round. Two tools make this visible and
recoverable: `--shard-state FILE` records, per shard, the last attempt, the last
passing run and the last result (`prufyx.io/knowledge-gate-shards/v1`), and with
it a shard attempted before but without a pass within its cycle plus a day
raises a `shard-stale` alarm (a shard never recorded is unknown, not stale);
`--shard least/n` re-derives the shard whose last pass is oldest (never passed
counts as oldest), so a missed night is caught up. The workflow does not persist
such a file yet (that needs a cache or the previous run's artifact, a decision
for the owner), so today the nightly run uses `day/7` and neither feature acts;
until then watch the `could-not-run` alarms.

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
| `stagger/<pack>/records` | (a pack holding records) a loosening change of a rule or a record moves a lease into an ISO week that then holds more than 15% of the pack's rules and records together (at least one), as a reattestation statement's own check counts them |
| `rulecheck/<pack>/lineAttestations` | (a pack holding line attestations) an attestation does not list exactly the pack's rules for its line and fact family, or lists a rule that does not match every transition into the line; for example, a rule was added to an attested line without the attestation being updated |
| `attestation/<pack>` | the committed corpus attestation differs from a regeneration from the head's pack |
| `generated/…` | the committed support inventory differs from a regeneration from the head's files |
| `block-only/<pack>` | an active rule has an unknown basis, or the engine does not evaluate its basis safely: consensus must be block-only and a lead verdict-neutral |
| `reattestation/<pack>` | the statement chain changed and the appended statement does not verify |
| `tree` | the head holds a symbolic link or a special file under `cli/` |
| `file-modes` | a knowledge file the automation may change has, or changes, an executable bit |
| `trust-material` | the change touches trust material (see below) and is not a person's change matching the pinned digest |
| `knowledge-records` | an approval file, worklist or review record changed without the rule change or statement it belongs to (see below) |
| `limits` | the change holds more loosening changes than the cap (default 200) |
| `kill-switch` | the file `factory/PAUSE` exists in the base or the head and the change holds any loosening change |

Run on the changed items only:

| Check | Fails when |
| --- | --- |
| `citations` | an added or changed rule, path policy or line attestation (a new item, a renewal, a reactivation or a re-pin) cites a source whose revision is not a commit object (an annotated tag object is refused, with the peeled commit named); whose commit is neither the commit of a tag of the cited repository nor in the history of its default branch (GitHub also serves commits that exist only in a fork through the upstream URL, so a commit object that resolves is not proof of upstream provenance; the check lists the repository's tags, up to 1000, and asks the compare API, once per commit); whose whole-file sha256 at that commit differs from `contentDigest`; whose lines are not inside the file (`startLine` must be a real line, `endLine` may be the empty position after the final newline); or that has no source at all; or any of this cannot be established (no `--source`, a network or rate-limit failure, a run past `--citations-timeout`). `--source fixture:DIR` is the explicit offline mode: it verifies nothing, so when the change cites a source the check fails with "not verified (offline fixture)" and the change is not eligible for automatic merge (a change that cites nothing has nothing to verify); the workflows use `--source github`. A change that touches no rule or record, a withdrawal and an earlier validUntil are not checked. The same checks run over the whole pack nightly (`rule verify-citations`, workflow `citations-nightly`) |

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
For a pack holding records, `breaker/withdrawals/<pack>/records` also fails
when a change switches off (removes a line attestation, withdraws a path
policy) more records than the same percent of the pack's active rules and
active records together; those records count toward the project breaker
under the projects `line-attestations` and `path-policies`. The rule breaker
counts rules only, as before.
Raise the limits with the repository variables below for a deliberate large
withdrawal.

**Daily limit.** The loosening changes the automation merged in the last 24
hours, plus this change's, may not exceed `--max-daily-loosening` (default
50); this is in addition to the per-change cap. Because the daily total
includes the change itself, no single change can loosen more than 50 rules
unless the limit is raised. A deliberate large renewal wave needs the
repository variable below to be raised first, and lowered again afterwards. Counting needs the history of
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
`rederivedUnchanged` (rules and line attestations a `--rederive-all` run re-derived), `shard`, `restRequests` (api.github.com requests; -1 when not counted), `couldNotRun`, `failures`
(failed changes, failed checks and their names), `limits`, `breakers` (every
breaker with what it observed and whether it tripped), `alarms`,
`autoMergeEligible` and `durationMs`. Keys are sorted at every depth and the
file is a function of the report, so identical runs give identical bytes except
`durationMs`. It holds only statistics about knowledge changes; every string
is at most 256 bytes.

`--alarms FILE` writes `gate-alarms.json` (`prufyx.io/knowledge-gate-alarms/v1`):
a list of `{kind, detail}` records, one per alarm. Kinds: `loosening-cap`,
`daily-limit`, `withdrawal-breaker-pack`, `withdrawal-breaker-project`, `size`,
`could-not-run`, `shard-stale`.
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

## Owner baseline choices

`cli/knowledge/repin-baselines.json` (see [evidence-repin.md](evidence-repin.md))
holds the owner's choice of the tag a repository's citations are compared with
when its latest release is ambiguous. It is not a rule pack and not trust
material, but a change to it is not routine either, so the gate admits it only
with an owner approval per entry and the check `repin-baselines`:

- An entry that is new or differs from the base needs an owner approval for
  exactly that entry: `cli/knowledge/approvals/repin-baselines/<owner>--<repo>.json`
  (names lower-cased; an owner login has no `--`, so the first `--` splits it),
  approval v2 with `subject: "repinBaseline"`, `pack: "repin-baselines"`,
  `ruleId: "<owner>--<repo>"` and `scope: "<owner>/<repo>"`. Its
  `candidateDigest` is the digest of the proposed entry's canonical JSON, its
  `baseDigest` that of the base entry (`absent` for a new one). The entry's
  `approval` must equal the approval's `candidateId`, the entry may not be
  decided after the approval, and a changed entry must be decided strictly after
  the entry it replaces.
- The approval is single-use and forward-only like a record approval: an approval
  already in the base admits nothing, a base approval for the same repository
  decided at the same time or later refuses it, and a live approval may not be
  deleted or replaced by a not strictly later one (`knowledge-records`).
- Removing an entry needs no approval (the repository returns to pending). The
  automation account may not change the file. A change to it is never eligible
  for automatic merging (the file is outside the automatic-merge paths) and is
  owned by the owner in CODEOWNERS.
- The file is read as the gate reads every owner input: the base for what is
  trusted. The independent re-run of `evidence repin` and the statement checks
  (V9, V12) use the **base** file, so a statement can rely on an entry only after
  the change that adds the entry has merged.
- It does not count in the loosening totals or limits: it supplies a baseline, it
  changes no rule.

Sign it with `prufyx-maintainer approval sign --subject repinBaseline`, see
[Signing and checking approvals](#signing-and-checking-approvals).

## Records that belong to a change

- `cli/knowledge/approvals/<pack>/<rule id>.json` may be added or changed only
  together with a change to that rule that the approval admitted; it may be
  removed only together with an admitted change to that rule. The same holds
  for `cli/knowledge/approvals/<pack>/<record id>.json` and a line attestation.
- `cli/knowledge/reattestation/<pack>/worklists/<stem>.worklist.json` may only
  be added, and only for the statement `<stem>` the same change appends and the
  gate verifies.
- `cli/knowledge/reattestation/<pack>/review-records/<rule id>.json` may be
  added or changed (never removed) only for rules that statement renews. A
  review record named for a line attestation or path policy record ID is
  refused: no tool produces or verifies one yet.
- `cli/knowledge/approvals/repin-baselines/<owner>--<repo>.json` may be added or
  changed only together with the baseline entry it admitted, and removed only
  when it can no longer verify.
- Any other file under these directories fails the `knowledge-records` check.

## File layout

| Path | Read from | Holds |
| --- | --- | --- |
| `factory/PAUSE` | base and head | kill switch (any content) |
| `cli/knowledge/reattestation/<pack>/chain/` | base and head | the pack's signed statement chain: `<stem>.statement.json` and `<stem>.statement.sig.json` pairs |
| `cli/knowledge/reattestation/<pack>/worklists/<stem>.worklist.json` | head | the worklist the statement `<stem>` was prepared from |
| `cli/knowledge/reattestation/<pack>/review-records/<rule id>.json` | head | individual review records, when a human statement uses them |
| `cli/knowledge/reattestation/trust-root.json` | base only | the reattestation trust root; its digest is passed separately (`--trust-root-digest`) |
| `cli/knowledge/approvals/<pack>/<rule id>.json` | head | owner approvals (`<record id>.json` for a line attestation) |
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

An approval for a line attestation has the same form, with two more members
at the end of `record`, in this order:

```json
    "ruleId": "line-attestation.…",
    "scope": "pkg:github/kubernetes/kubernetes kubernetes.removed_served_gvk 1.33",
    "subject": "lineAttestation"
```

`ruleId` is the attestation's record ID and `scope` is its component, fact
family and line separated by single spaces. `candidateDigest` and
`baseDigest` are taken over the attestation record (its object in the
`lineAttestations` section, in the same canonical JSON), and `baseDigest` is
`absent` when the base has no attestation for that scope. A rule approval
has neither member, so a rule approval never verifies for an attestation, and
the reverse. Approvals for path policies are not accepted.

An attestation can be removed (tightening) and added again later, so the base
state alone does not stop an approval from being used twice. A record
approval therefore admits only the change that adds it:

- the gate decodes every approval file in the base's approval directories
  (every pack) and refuses a record approval when any of them holds the same
  signed record or the same signature, whatever its encoding or file name;
- decisions about one record only move forward: a record approval is refused
  when the base holds a record approval for the same record ID, at any path
  and in any pack, decided at the same time or later, so an approval the
  owner superseded cannot be put back;
- a record approval in the base that could still verify (decided less than
  14 days before the gate's clock, or at a time that cannot be read) may not
  be deleted, and may be overwritten only by a record approval decided
  strictly later (the `knowledge-records` check).

If any entry of the base's approval directories cannot be read (for example
a file over the size bound, a subdirectory or a link), every record approval
is refused until the entry is fixed: the gate fails closed rather than
admit an approval it could not compare. A file that is not a valid approval
is skipped, because it can never verify. Rule approvals are not affected by
these checks.

The gate accepts an approval only if the base's `web-approval-keys.json`
matches `--approval-keys-digest`, the key is pinned in it
(`"role": "web-approval"`) and not past its
`notAfter`, the signature verifies, the decision is `approve`, the identity is
one of the pinned `owners`, the pack and rule id match, the decision time is
not in the future (five minutes of clock skew allowed) and at most 14 days
old, the candidate digest matches the proposed entry and the base digest
matches the base. Changing anything in the entry after approval invalidates
it. Approvals never admit a mechanical rule or a mechanical line attestation.

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

### Signing and checking approvals

For an owner baseline entry (see [Owner baseline choices](#owner-baseline-choices)),
`--subject repinBaseline` replaces the pack flags:

```sh
prufyx-maintainer approval sign --subject repinBaseline \
  --repository owner/repo --head-baselines cli/knowledge/repin-baselines.json \
  --base-baselines "$T/base-baselines.json" \
  --keys "$T/base-keys.json" --keys-digest "$(gh variable get WEB_APPROVAL_KEYS_DIGEST)" \
  --identity airstand --candidate-id pr-15 --key-stdin \
  --output cli/knowledge/approvals/repin-baselines/owner--repo.json
```

`--base-baselines` is omitted when the base has no file. `--repository` must be
spelled as the entry spells it, and `--candidate-id` must equal the entry's
`approval`. `approval verify` takes the same subject flags plus `--base-root DIR` (the base
checkout; see below).

`prufyx-maintainer approval` signs and checks approval files offline. It reads
both packs exactly as the gate does, signs the bytes the gate checks, and runs
the gate's own approval check on the result before it writes anything, so a
file it writes is accepted for that base and head until it is 14 days old (or
the key's `notAfter`, if earlier).

The web-approval key is an Ed25519 private key in PKCS #8 PEM form. Keep it
outside any checkout, for example in a password manager. Creating one needs
OpenSSL 3.x (`openssl version` prints `OpenSSL 3.…`). On macOS,
`/usr/bin/openssl` is LibreSSL, which cannot generate Ed25519 keys
("Algorithm ed25519 not found"); use OpenSSL 3 from Homebrew
(`brew install openssl@3`, then `"$(brew --prefix openssl@3)/bin/openssl"` in
place of `openssl` below), or any Linux system with OpenSSL 3. To create one:

```sh
umask 077
openssl version   # must print OpenSSL 3.x
openssl genpkey -algorithm ed25519 -out "$HOME/web-approval-key.pem"
prufyx-maintainer approval public-key --key "$HOME/web-approval-key.pem"
# {"keyId":"sha256:…","publicKey":"…"}
```

Add the printed `keyId` and `publicKey`, with a `notAfter`, to
`cli/knowledge/trust/web-approval-keys.json` (format above), then print the
digest to pin in `WEB_APPROVAL_KEYS_DIGEST`:

```sh
prufyx-maintainer approval keys-digest --keys cli/knowledge/trust/web-approval-keys.json
```

To approve one rule of a change, give the pack file as it is on the base
branch and as the change proposes it:

```sh
git show origin/main:cli/internal/cncfcheck/data/rules.json > /path/to/base-rules.json
git show origin/main:cli/knowledge/trust/web-approval-keys.json > /path/to/base-keys.json
prufyx-maintainer approval sign \
  --pack cncf --rule RULE_ID \
  --base-pack /path/to/base-rules.json \
  --head-pack cli/internal/cncfcheck/data/rules.json \
  --keys /path/to/base-keys.json --keys-digest sha256:… \
  --identity OWNER_LOGIN --candidate-id pr-123 \
  --key "$HOME/web-approval-key.pem" \
  --output cli/knowledge/approvals/cncf/RULE_ID.json
```

| Option | Meaning |
| --- | --- |
| `--pack` | `cncf` or `community` |
| `--rule` | the rule id; the proposed pack must hold it exactly once with evidence basis `reviewed`, and the change to it must be one the gate classifies as loosening (a change that only withdraws the rule or moves its `validUntil` earlier needs no approval and is refused) |
| `--base-pack`, `--head-pack` | the pack file on the base branch and as proposed; a rule the base does not hold gets `baseDigest` `absent` |
| `--keys`, `--keys-digest` | the base branch's `web-approval-keys.json` and the digest pinned for it; the file must match the digest |
| `--identity` | the owner's login; it must be one of the key file's `owners` |
| `--candidate-id` | a reference for the change, such as its pull request (letters, digits, `.`, `_`, `:`, `-`) |
| `--key FILE` | the private key file: a regular file owned by you with no group or other permission (mode `0600` or `0400`), not a symbolic link, with no symbolic link in its path and only one hard link |
| `--key-stdin` | read the private key from standard input instead; standard input must be a pipe (a terminal, another device or a redirected file is refused; give a file with `--key`) |
| `--output` | the approval file to create; its path must end in `<pack>/<rule id>.json` (the gate reads `cli/knowledge/approvals/<pack>/<rule id>.json`); an existing file or link there is never replaced, no directory in the path may be a symbolic link, missing directories are created, and the file gets mode `0644` |
| `--subject` | what the approval is for: `rule` (the default), `lineAttestation` or `repinBaseline` |
| `--record` | with `--subject lineAttestation`, in place of `--rule`: the line attestation's record ID; the proposed pack must hold it with evidence basis `reviewed`, it must differ from the base record, the base record must not be mechanical, and the change must loosen (a change that only shortens `validUntil` is refused) |

A line attestation approval names `"subject": "lineAttestation"` and the
record's `scope`, and its digests are those of the base and proposed record.
Path policies and mechanical attestations cannot be approved. The gate uses a
record approval once and only forward: it refuses an approval file already in
the base, and one decided at or before an approval the base holds for the same
record, so write a new one for each change (`decidedAt` is the current time).
The signer reads no base approvals, so it cannot warn about either rule;
`approval verify --base-root DIR` applies both before it prints `approval OK`.

```sh
prufyx-maintainer approval sign --subject lineAttestation --pack cncf \
  --record <record id> --base-pack "$T/base-cncf.json" --head-pack cli/internal/cncfcheck/data/rules.json \
  --keys "$T/base-keys.json" --keys-digest "$(gh variable get WEB_APPROVAL_KEYS_DIGEST)" \
  --identity airstand --candidate-id pr-15 --key-stdin \
  --output cli/knowledge/approvals/cncf/<record id>.json
```

`decidedAt` is the current time. The key may end with line breaks and nothing
else; any other text before or after the PEM block is refused. The command
never prints key material, and its messages never include the key file's
content. To read the key from a password manager without writing it to disk,
pipe it in, for example `op read "op://…/web-approval-key" | prufyx-maintainer
approval sign … --key-stdin`.

`approval verify` runs the gate's approval check for one file:

```sh
prufyx-maintainer approval verify \
  --approval cli/knowledge/approvals/cncf/RULE_ID.json \
  --pack cncf --rule RULE_ID \
  --base-pack /path/to/base-rules.json \
  --head-pack cli/internal/cncfcheck/data/rules.json \
  --keys /path/to/base-keys.json --keys-digest sha256:…
```

For a line attestation or a repin baseline, `approval verify` also needs
`--base-root DIR`, the base checkout. It then applies the gate's checks of the
base's approvals before it prints `approval OK`: an approval the base already
holds, and an approval for the same record that the base superseded with a
decision made at the same time or later, are refused. `--base-root` must be a
base checkout: it has to hold the layout's pack file(s), and the file it holds
must equal `--base-pack` (or `--base-baselines`, when given; a base checkout that
holds a baseline file needs `--base-baselines` too); an empty or other directory
is an error, never `approval OK`. `--base-root` is refused
for a rule approval. The baseline flags (`--repository`, `--base-baselines`,
`--head-baselines`) belong to `--subject repinBaseline` and are refused for the
other subjects.

`--now RFC3339` (UTC, `Z`) checks at another time. `--help` on `approval` or
any of its commands prints the usage and exits `0`. Exit codes for `approval`:
`0` signed, or the approval is accepted; `1` (`verify` only) the approval is
refused, with the reason; `2` rejected input or a refused signing. Nothing
uses the network.

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
`basis-change`, `modify`, `pack-member` (loosening). A removal that is half of a supersede pair also has the kind `supersede`. A `pack-member` change
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
| `--max-daily-loosening N` | cap on that count plus this change (default 50) |
| `--json` | print the report as JSON |

### `gate daily-count`

Prints the number of loosening changes in the listed commits of `main`
that the automation authored (or whose author is unknown).

| Flag | Meaning |
| --- | --- |
| `--git-dir DIR` | repository holding the commits and their parents |
| `--commits FILE` | JSON list of `{sha, parent, author}` (the first parent, and the author's login or null), at most 300 commits |
| `--bot-login LOGIN` | the automation account (default `prufyx-factory[bot]`) |
| `--owner-login LOGIN` | the repository owner (default `airstand`); only the owner's own change (author and sender) may supersede a reviewed rule |

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
| `--daily-loosening-count N`, `--max-daily-loosening N` | the daily limit (default cap 50); without a count the change is not eligible |
| `--shadow` | shadow mode: never eligible for automatic merging |
| `--metrics FILE`, `--alarms FILE`, `--alarms-markdown FILE` | write the metrics and alarm files |
| `--trust-root-digest sha256:…` | pinned digest of the base's reattestation trust root; without it no statement is accepted |
| `--rerun-worklist FILE` | worklist from this job's own `evidence repin` run; without it no statement is accepted |
| `--rederive-all` | also re-derive every active mechanical rule and every mechanical line attestation, changed or not |
| `--shard all\|i/n\|day/n\|least/n` | with `--rederive-all`: re-derive one deterministic slice of the extractors. An extractor belongs to the shard chosen by a hash of its id (stable when others are added); `day/n` uses the UTC day number mod n, so a daily run covers every extractor every n days. `least/n` picks the shard with the oldest last pass in `--shard-state`. The scheduled run uses `day/7` |
| `--shard-state FILE` | with a `--shard`: file recording each shard's last attempt and last pass; read before the run, rewritten after it. Needed for `least/n`; enables the `shard-stale` alarm |
| `--rest-budget N` | cap on api.github.com requests (0: only GitHub's own limit). The gate also keeps 25 of GitHub's reported remaining requests for the rest of the job and treats a rate-limit refusal as exhausted |
| `--cache-dir DIR` | keep git trees and small blobs on disk between runs; an entry is used only if it hashes to its own object id, with the exact canonical mode and the type that mode implies (a tree entry cannot be reclassified); the cache is never written through a symlinked directory and never read through a symlink |
| `--concurrency N` | concurrent upstream reads during re-derivation (0–64) |
| `--citations-timeout D` | overall deadline of the citation verification (default 20m); a run that does not finish in time fails the `citations` check |
| `--now RFC3339` | the gate's clock, UTC (default: now); for reproducing a past run |
| `--report FILE` | write the JSON report |
| `--summary FILE` | append a Markdown summary (the workflow passes `$GITHUB_STEP_SUMMARY`) |
| `--json` | print the report as JSON |

Without `--source`, every mechanical loosening change fails, and so does every
change that adds or changes a rule or record with cited sources (the
`citations` check): a citation that cannot be checked is not a pass. With
`--source fixture:DIR` (offline, for tests and local runs) citations are not
verified, so a change that cites sources fails the `citations` check and is
never eligible for automatic merge.

The citation check makes a bounded number of GitHub REST calls (one commit
lookup and at most one compare per distinct commit, a tag listing (one request
per 100 tags, up to 10) and one repository lookup per repository, plus raw file
reads). A very large renewal change can exhaust the
API rate limit of the workflow token (about 1000 requests per hour per
repository); the check then fails closed, and the run is repeated later.

The report (`prufyx.io/knowledge-gate-report/v1`) lists `result` (`pass` or
`fail`), `changes` (each with `class`, `kinds`, `basis`, `proof`, `ok` and
`detail`, and `supersededBy` or `supersedes` on a supersede pair), `supersedes` (the pairs), `checks`, `alarms`, `limits`, `daily`, `breakers`, `mode` (`enforce` or `shadow`), `changedPaths`, `chainsChanged`,
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
(default 200), `KNOWLEDGE_MAX_DAILY_LOOSENING` (default 50),
`KNOWLEDGE_MAX_WITHDRAW_PERCENT` (default 5), `KNOWLEDGE_MAX_WITHDRAW_PROJECT`
(default 20), `KNOWLEDGE_GATE_SHADOW` (`true` for shadow mode) and, for alarm
issues, `OPS_ISSUES_REPO`.

The job's outputs `result`, `auto-merge-eligible`, `head-sha` and `alarm-count` and the
uploaded `knowledge-gate-report` artifact carry the result. The workflow never
merges. The factory must open its pull requests with its GitHub App token
(pull requests opened with the workflow token start no workflows) and create
its commits as the App, so they are authored, committed and signed by it.
