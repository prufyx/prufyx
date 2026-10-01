# Batch evidence re-attestation

`prufyx-maintainer evidence reattest prepare|sign|verify` renews the review
lease on a batch of rules in one signed statement, when a fresh `evidence
repin` run has mechanically confirmed that every one of their cited
upstream spans is unchanged. A human maintainer signs a human-mode batch at
a terminal; an automation key signs an automated-mode batch unattended (see
[Modes and signer roles](#modes-and-signer-roles)). It renews exactly two
fields per rule, `evidence.reviewedAt` and `evidence.validUntil`; it never
re-derives, edits, or authors a compatibility claim, and it never decides
that a rule's evidence is unchanged on its own — that decision is always
computed from a retained `evidence repin` worklist, never declared by a
caller, and never trusted from the statement itself: `verify` reruns the
whole computation from scratch and requires an exact byte match.

This tool is separate from, and does not replace, individual rule review
(`review-record`). A rule whose citations show any real drift (a moved,
changed, or gone span, or a corpus-integrity mismatch) is never eligible for
batch renewal; it goes to individual review.

## Modes and signer roles

`prepare` has two modes, and every statement records the role of the key
that must sign it (`signerRole`):

| | Human mode (`--mode human`, the default) | Automated mode (`--mode automated`) |
|---|---|---|
| Signer role | `human` | `automation` |
| Who signs | a maintainer, at a terminal | an unattended job (for example CI) |
| What it renews | reviewed rules whose citations are all mechanically unchanged (E1–E7) | the same, with each latest-release baseline additionally re-proven against the worklist's own repository record |
| Sample | `ceil(10%)` of the batch must be individually reviewed before signing | none |
| Schedule | one wave slot for the whole batch (`--wave 1..7`) | each rule scheduled into its own week (see [Automated mode](#automated-mode)) |
| Consecutive-cycle cap | 2 | 2, shared with human renewals |
| Mechanical rules | never renewed | never renewed |

The binding is enforced in both directions and at every step: `sign`
refuses a statement prepared for the other role, and refuses a key whose
role in the trust root is not the one it signs as; a signature verifies a
statement only when its key holds the statement's role
(`VerifySignature`, which `verify` and the chain derivation both use); and
`verify` recomputes the statement in the mode its role names and checks the
role's policy independently (V8). An automation key can therefore only ever
produce a statement that renews what the automated policy computes as
eligible, and a human statement always carries the wave and the reviewed
sample the human path requires.

## Pipeline

Every path argument must be absolute (the commands reject relative paths),
so the examples below use `"$PWD/..."`.

- `$REPIN_RULES_PATH` is the rule pack path exactly as `evidence repin`
  recorded it in the worklist (`scope.rulePacks` and each citation's
  `rulePack`): the `--rules` value repin was given, or by default the
  absolute path of the shipped pack in the checkout repin ran from.
  Citations are matched to the pack by that exact string, so
  `--rules-worklist-path` is needed whenever it differs from the
  `--rules`/`--prior-pack` path being read; it may be omitted when the two
  are identical.
- `$ROOT_DIGEST` is the trust root's pinned digest (see
  [Signing](#signing) for how it is computed and why it must not be
  derived from the file at hand).

```sh
# 0. One statement chain directory per pack, kept in version control.
#    Each statement gets the next zero-padded sequence number as its stem,
#    so a new entry never overwrites an earlier one.
mkdir -p "$PWD/chain/cncf"
SEQ=$(printf '%04d' $(( $(find "$PWD/chain/cncf" -name '*.statement.json' | wc -l) + 1 )))

# 1. (existing; unchanged)
prufyx-maintainer evidence repin --state "$PWD/fresh-state" --output "$PWD/worklist.json"

# 2. Build the statement and the candidate next pack.
prufyx-maintainer evidence reattest prepare \
  --worklist "$PWD/worklist.json" --pack cncf --rules "$PWD/current-rules.json" \
  --rules-worklist-path "$REPIN_RULES_PATH" \
  --statement-chain-dir "$PWD/chain/cncf" \
  --trust-root "$PWD/evidence-reattest-trust-root.json" --trust-root-digest "$ROOT_DIGEST" \
  --review-record-dir "$PWD/reviews" \
  --next-revision <rev> --wave <1..7> --output-dir "$PWD/out/$SEQ"
#   → out/$SEQ/statement.json  (canonical JSON, sorted keys)
#   → out/$SEQ/rules.next.json (candidate next pack: only reviewedAt/validUntil changed)
#   → out/$SEQ/summary.txt     (what a human reads before signing)

#    (Automated mode: --mode automated instead of --wave; see below.)

# 3. A human, at a terminal, reads out/$SEQ/summary.txt, individually
#    reviews every rule it lists as sampled, adds each review record to
#    reviews/ as <ruleId>.json, reruns step 2, and then signs. Records
#    already recorded in the chain may stay in reviews/; they are skipped.
prufyx-maintainer evidence reattest sign \
  --statement "$PWD/out/$SEQ/statement.json" \
  --trust-root "$PWD/evidence-reattest-trust-root.json" --trust-root-digest "$ROOT_DIGEST" \
  --key "$PWD/evidence-reattest.key.pem" \
  --output "$PWD/out/$SEQ/statement.sig.json"

# 4. Append the signed statement to the pack's chain, and apply the next
#    pack, in the same change.
cp "$PWD/out/$SEQ/statement.json"     "$PWD/chain/cncf/$SEQ.statement.json"
cp "$PWD/out/$SEQ/statement.sig.json" "$PWD/chain/cncf/$SEQ.statement.sig.json"
cp "$PWD/out/$SEQ/rules.next.json"    "$PWD/current-rules.json"

# 5. Deterministic, CI-usable gate; non-zero exit on any violation. CI runs
#    it on the change, with the base branch's chain directory and rule pack
#    checked out separately (see "The base branch's chain" below).
prufyx-maintainer evidence reattest verify \
  --statement "$PWD/chain/cncf/$SEQ.statement.json" --prior-pack "$BASE/current-rules.json" \
  --next-pack "$PWD/current-rules.json" --worklist "$PWD/worklist.json" --pack cncf \
  --rules-worklist-path "$REPIN_RULES_PATH" \
  --statement-chain-dir "$PWD/chain/cncf" --base-statement-chain-dir "$BASE/chain/cncf" \
  --review-record-dir "$PWD/reviews" \
  --envelope "$PWD/chain/cncf/$SEQ.statement.sig.json" \
  --trust-root "$PWD/evidence-reattest-trust-root.json" --trust-root-digest "$ROOT_DIGEST"
```

`$BASE` is a separate, read-only checkout of the base branch the change is
proposed against, for example:

```sh
BASE=$(mktemp -d)/base
git worktree add --detach "$BASE" "origin/main"
mkdir -p "$BASE/chain/cncf"   # stays empty when the base branch has no chain yet
# ... run verify ...
git worktree remove "$BASE"
```

or, without a worktree, by exporting just the two inputs `verify` needs
from the base branch:

```sh
BASE=$(mktemp -d)
mkdir -p "$BASE/chain/cncf"
git show origin/main:current-rules.json > "$BASE/current-rules.json"
for f in $(git ls-tree --name-only origin/main chain/cncf/); do
  git show "origin/main:$f" > "$BASE/$f"
done
```

Either way, when the base branch has no chain directory yet,
`$BASE/chain/cncf` is an empty directory. The retained worklist and the
review records are read from the change itself.

`--trust-root`/`--trust-root-digest` may be omitted from `prepare` only
while the pack's chain directory is still empty; as soon as it holds a
statement, both commands need the pin to verify it. `--review-record-dir`
is optional, but without it every sampled rule is reported as `MISSING
REVIEW RECORD` and `sign` and `verify` refuse the statement.

`--attested-at` defaults to the current time and may never be later than
it: `prepare` rejects a future `--attested-at`, `sign` refuses to sign a
statement whose `attestedAt` is later than the signer's clock, and
`prepare` and `verify` reject a chain holding an entry attested later than
their own clock.

In automated mode, steps 2 and 3 become:

```sh
prufyx-maintainer evidence reattest prepare --mode automated \
  --worklist "$PWD/worklist.json" --pack cncf --rules "$PWD/current-rules.json" \
  --rules-worklist-path "$REPIN_RULES_PATH" \
  --statement-chain-dir "$PWD/chain/cncf" \
  --trust-root "$PWD/evidence-reattest-trust-root.json" --trust-root-digest "$ROOT_DIGEST" \
  --review-record-dir "$PWD/reviews" \
  --next-revision <rev> --output-dir "$PWD/out/$SEQ"

prufyx-maintainer evidence reattest sign --role automation \
  --statement "$PWD/out/$SEQ/statement.json" \
  --trust-root "$PWD/evidence-reattest-trust-root.json" --trust-root-digest "$ROOT_DIGEST" \
  --key-env REATTEST_AUTOMATION_KEY --passphrase-env REATTEST_AUTOMATION_PASSPHRASE \
  --output "$PWD/out/$SEQ/statement.sig.json"
```

Steps 4 and 5 are unchanged: an automated statement is appended to the same
chain, and `verify` takes the same arguments.

`prepare` and `verify` never wire a statement into the runtime pack loader
or the embedded rule pack. Publishing a re-attested pack (running
`corpus-attestation` and `export-knowledge` on the changed rule pack) is a
separate step, exactly as it is for any other rule pack change; this tool
does not perform it.

## Eligibility: computed, never declared

`prepare` recomputes, for every rule in the pack, whether it qualifies for
batch renewal (conditions E1–E7 below), directly from the worklist's
citations — never from any rolled-up verdict the worklist itself might
also carry. A rule that fails any one of them is listed in `notExtended`
with the worst reason found, and is left for individual review. `sign` and
`verify` never trust a caller's claim about eligibility either: `verify`
reruns `prepare`'s exact computation from the same worklist and pack and
requires the result to reproduce the supplied statement, and the supplied
next pack, byte-for-byte.

| # | Condition | What it means |
|---|---|---|
| E1 | The rule's citations, matched one-for-one against `evidence.sources[].id`, each classify `NO_NEW_RELEASE`, `FILE_IDENTICAL`, or `SPAN_IDENTICAL`, are not stale, were not resolved through the GitHub tags fallback, and each cite the exact commit their source pins; a citation compared against a release line (`baseline: release_line`, see [evidence-repin.md](evidence-repin.md)) must additionally have a consistent pinned tag, line and compared tag and be backed by a fresh, resolved line record in the worklist naming that exact tag and commit | A source with no citation, an extra citation with no source, a duplicate citation, or one bad citation excludes the whole rule, never just that citation. A citation classified `NO_RELEASE_BASELINE` (its repository has no releases and no tags, see [evidence-repin.md](evidence-repin.md)) is one of those bad citations: the rule is listed in `notExtended` with reason `NO_RELEASE_BASELINE` and goes to individual review or expires |
| E2 | Across the whole worklist, no citation for this pack classifies `PENDING`, and the worklist's scope has no `--project`/`--limit` filter | A partial or still-resolving worklist disqualifies the entire batch, not just the rules it touches. `NO_RELEASE_BASELINE` is not `PENDING`: it is a settled finding about one repository, so it excludes only the rules citing it and does not disqualify the rest of the pack. This is computed by counting the citations themselves, never read from a self-reported summary field a caller could hand-edit |
| E3 | (folded into E1) No citation's repository was resolved through the GitHub tags fallback | A tag-fallback baseline is weaker evidence and goes to individual review |
| E4 | The worklist is within 72 hours of the attestation instant, and every cited repository's own resolution is too (and, for a release-line citation, so is its line record) | A stale worklist is never treated as current |
| E5 | The rule carries no `range` | Ranged rules are excluded from batch renewal entirely |
| E6 | The rule's consecutive batch-renewal count, derived from the pack's verified statement chain (see [The statement chain](#the-statement-chain-v5)), does not exceed 2 | A rule renewed by batch twice since its last recorded individual review must go through an individual review next |
| E7 | The rule's evidence state is `active`, and no citation anywhere in the rule's project classified `CORPUS_DIGEST_MISMATCH` | A withdrawn rule, or a project with an unresolved corpus-integrity finding, is excluded project-wide |

A rule that passes E1–E7 is renewed only if the renewal moves its
`validUntil` later and its lease is close to its end:

- the batch's slot date must be strictly later than the rule's current
  `validUntil`; otherwise the rule is listed in `notExtended` as
  `NOT_LATER_THAN_CURRENT`. A renewal never moves a rule's `validUntil`
  earlier or leaves it unchanged.
- the rule's current `validUntil` must be no more than 21 days (three
  weekly waves) after `attestedAt`; otherwise it is listed as
  `NOT_YET_DUE`. A rule renewed recently is therefore not picked again
  while most of its lease is left, which would spend its two-cycle
  budget (E6) within days.

The remaining rules are then capped by the stagger rule (V7 below):
`prepare` orders them by how soon they expire relative to the slot date
(earliest current `validUntil` first), then by rule ID, and renews as many
as fit in the slot week. The rest are listed in `notExtended` with the
reason `STAGGER_DEFERRED`; they are left for a later wave, not for
individual review.

Among the rules renewed after that cap, `prepare` samples `ceil(10%)` of
them, seeded by `sha256(worklistDigest ‖ ruleId)`, and lists them in
`sampledForFullReview`. Each one needs a full individual review before
`sign` — or `verify` — will accept the statement: a review record for it
must be supplied in `--review-record-dir`, and it must be a new individual
review (see [The statement chain](#the-statement-chain-v5)). The seed is
a function of inputs nobody controls after the worklist is generated, so the
sample cannot be predicted or chosen.

## Automated mode

`prepare --mode automated` computes eligibility exactly as above (E1–E7,
including the mechanical-rule exclusion, `NOT_YET_DUE` and
`NOT_LATER_THAN_CURRENT`), with these differences:

- **Latest-release baselines are re-proven.** A citation compared with its
  repository's latest release must name, as its compared commit, exactly
  the commit the worklist's own record for that repository resolved to,
  and that record must be `RESOLVED` through Releases, never the tags
  fallback. Otherwise the rule is listed as `LATEST_BASELINE_UNVERIFIED`.
  (A release-line citation is already required to be backed by a matching
  line record; see E1.) A v1 worklist, which predates baseline records, is
  rejected.
- **No sample.** `sampledForFullReview` is always empty, and must be: a
  human statement that renews rules without a reviewed sample, or an
  automated statement carrying a sample, is rejected.
- **The consecutive-cycle cap still applies**, and it counts human and
  automated renewals together: a rule renewed twice since its last
  recorded individual review, by either kind of statement, is not renewed
  again (`CONSECUTIVE_BATCH_CYCLE_CAP`). With no individual review, its
  lease then runs out and it evaluates as `UNKNOWN`.
- **Review records are counted only when the pack requires them.** A
  review record is a maintainer's declaration; in a human statement the
  signing maintainer vouches for it, but nobody signs an automated
  statement. So an automated statement counts a supplied record as a new
  individual review (resetting the rule's cycle count) only for a rule
  whose `reviewedAt` in the prior pack is later than the chain head's
  `attestedAt` — a rule whose dates were already moved on the base branch
  by an individual review merged outside the chain, which the next
  statement must record anyway (see "A truncated chain is detected"
  below). Every other supplied record is ignored, so supplying records can
  never reset a rule's count in automated mode. V6 likewise accepts only
  the statement's own rules, never a review record, as accounting for a
  changed date in an automated statement's pack.
- **Per-rule schedule instead of waves.** There is no `--wave`. The
  candidate dates are the weekly Monday 12:00 UTC instants that are more
  than 42 days (twice the renewal window) and at most 90 days after
  `attestedAt` — six or seven of them, each in its own ISO week. Due rules
  are placed one at a time, soonest-expiring first, then by rule ID. Each
  rule starts at its own preferred date — `sha256` of a fixed domain string
  and the rule ID, modulo the number of candidate dates — and takes the
  first date, moving later and wrapping around to the earliest, whose ISO
  week stays within the V7 cap, counting every rule's `validUntil` as it
  will be in the next pack. A rule no date accepts is `STAGGER_DEFERRED`
  and is picked up by a later run. Each renewed rule's own date is recorded
  as `rules[].validUntil`; the statement's `validUntil` is the latest
  candidate date. The schedule depends only on the pack's rules, the
  eligible set and `attestedAt` — not on pack order — so `verify`
  recomputes it identically. Because every candidate date is more than 42
  days out and a rule is due only within 21 days of its lease end, an
  automated renewal always moves `validUntil` later, and a renewed rule is
  not due again for at least 21 days.

Automated runs are meant to be frequent (for example daily): each run renews
whatever has become due since the last one, spread over the coming weeks.

`notExtended` reasons are either the worst citation class found (E1), or
one of: `WORKLIST_SCOPE_INCOMPLETE` (E2), `TAG_FALLBACK_BASELINE` (E3),
`STALE_BASELINE` (E4, or a stale citation), `RELEASE_LINE_BASELINE_UNVERIFIED` (E1, a release-line citation whose pinned tag, line, compared tag or line record is missing or inconsistent), `RANGED_RULE_EXCLUDED` (E5),
`CONSECUTIVE_BATCH_CYCLE_CAP` (E6), `EVIDENCE_NOT_ACTIVE` and
`CORPUS_DIGEST_MISMATCH_IN_PROJECT` (E7), `SOURCE_WITHOUT_CITATION`,
`CITATION_WITHOUT_SOURCE`, `DUPLICATE_CITATION_FOR_SOURCE`,
`CITATION_COMMIT_DOES_NOT_MATCH_PINNED_SOURCE` (E1),
`NOT_LATER_THAN_CURRENT` and `NOT_YET_DUE` (renewal timing, see above),
`STAGGER_DEFERRED` (V7 cap), `MECHANICAL_RULE_EXCLUDED`, and, in automated
mode only, `LATEST_BASELINE_UNVERIFIED`.

## What `verify` checks (V1–V8)

`verify` is deterministic and side-effect-free. It takes the statement, the
prior and next rule pack bytes, the retained worklist, the pack's statement
chain directory as it is in the change and as it is on the base branch,
and the review record directory, and fails closed with a non-zero exit on
the first violation it finds:

- **V1/V3** — `verify` reruns `prepare` with exactly the inputs the
  statement claims (mode from its `signerRole`, worklist, prior pack, wave, attestedAt, next revision,
  engine capability digest, review records) over the chain state it derived
  itself, and requires the result to reproduce both the supplied statement
  and the supplied next pack byte-for-byte. This is what makes V1 ("only
  `reviewedAt`/`validUntil` may change, nothing else, in no other rule, and
  no entry may be added, removed, or reordered") and V3 ("eligibility is
  never a caller claim") hold at once: any difference anywhere in either
  document breaks the byte match.
- **V2** — the lease (`validUntil − attestedAt`) is positive and never
  exceeds the 90-day cap. For a human statement, its `validUntil` equals
  the wave's slot date computed from `attestedAt`, and every renewed rule's
  next `reviewedAt`/`validUntil` equal the statement's (enforced by V1).
  For an automated statement, its `validUntil` is the latest automated
  candidate date for `attestedAt`, and every renewed rule's own
  `validUntil` is one of those candidate dates, each within the 90-day cap.
- **V4** — the statement's declared prior/next pack digests, revisions, and
  rule-set digests are rebound to the actual supplied pack bytes.
- **V5** — the statement chain; see [The statement chain](#the-statement-chain-v5).
- **V6** — a CI gate over the pack diff, independent of V1/V3: every rule
  whose `reviewedAt`/`validUntil` changed between the prior and next pack
  must be covered either by this statement or by a new individual review
  record (`--review-record-dir`), and every rule present in one pack must
  be present in the other. It does not re-verify a review record against
  its packet, corpus, vectors and target, which stays `review-record`'s
  job.
- **Mechanical rules** — a rule whose `evidence.basis` is `mechanical` is
  derived from source rather than reviewed, so there is no review for a
  reattestation to extend. `prepare` never renews one: it lists the rule under
  `notExtended` with `MECHANICAL_RULE_EXCLUDED`, whatever its citations say, and
  leaves its bytes untouched. `verify` rejects (under V6) any change to a
  mechanical rule's `reviewedAt`/`validUntil`, even one covered by an
  individual review record, and any change to a rule's `evidence.basis`. A pack
  whose rule carries a malformed basis (an unknown value, or a mechanical rule
  without its extractor) is rejected on load.
- **V7** — the stagger cap. The cap is `floor(15% × the number of rules in
  the pack)`, and never less than 1. For every ISO week this statement
  renews at least one rule into, the number of next-pack rules whose
  `validUntil` falls in that week must not exceed the cap. Weeks this
  statement renews nothing into are not checked: a cluster that already
  exists elsewhere in the pack does not fail an unrelated batch, and a
  batch that moves rules out of a crowded week is allowed. `prepare` caps
  its own batch the same way (see `STAGGER_DEFERRED` above), so it never
  emits a statement V7 rejects.

- **V8** — the role policy, from the statement and the prior pack alone,
  independent of V1/V3: every renewed rule exists in the prior pack, is a
  reviewed (not mechanical), active rule with no `range`, and is listed
  with exactly one citation per evidence source, each pinned to the
  source's own revision and classified `NO_NEW_RELEASE`, `FILE_IDENTICAL`
  or `SPAN_IDENTICAL` against the latest release or its release line; its
  `consecutiveBatchCycles` is between 1 and 2; a human statement has a
  wave, no per-rule `validUntil`, and a sample whenever it renews anything;
  an automated statement has no wave, no sample, and a `validUntil` on
  every rule.

`verify` also requires a valid signature under a pinned trust root whenever
the statement renews at least one rule (`--envelope` together with
`--trust-root` and `--trust-root-digest`). `--trust-root` and
`--trust-root-digest` always come as a pair; `--envelope` without them, or
one of them without the other, is a usage error (exit 2). Pass
`--structural-only` to run only the checks above, deliberately without
checking the statement's own signature; that mode always exits non-zero
(exit 1), however the structural checks came out, so it can never be
mistaken for a passing publish gate. It exists for early checks — for
example, right after `prepare`, before anyone has signed anything. It still
needs `--trust-root`/`--trust-root-digest` when the pack's chain is not
empty, because the chain's own signatures are always verified; it rejects
`--envelope`.

Exit codes: `0` — every check passed and, when anything was renewed, the
signature verified; `1` — an invariant or the signature failed, a
signature was required but not supplied, or `--structural-only` was used;
`2` — a usage error (including a missing `--base-statement-chain-dir`) or
an unreadable or malformed input file (including a bad chain or review
record directory).

## The statement chain (V5)

Each pack has a statement chain directory: a signed, append-only log of
every statement produced for that pack. It holds only regular files named
`<stem>.statement.json` and `<stem>.statement.sig.json`, one pair per
statement, exactly as `prepare` and `sign` wrote them. Any other file, a
statement without its signature (or the reverse), a symlink, or a
subdirectory rejects the command. The stem is free-form; nothing depends on
it or on the order of file names.

Both `prepare` and `verify` derive the chain the same way (one shared
function), and treat it as authoritative:

- Every entry must parse, belong to the same pack (`--pack`), and carry a
  valid signature under the same pinned trust root the command is given
  (`--trust-root` and `--trust-root-digest`). An unsigned or badly signed
  entry rejects the whole chain; it is never skipped.
- Entries are ordered by their `previousAttestationDigest` links, from
  exactly one genesis entry (`previousAttestationDigest: null`) to exactly
  one head. A fork (two entries naming the same previous), a gap (an entry
  whose previous is missing), a second genesis entry, or a duplicate entry
  rejects the chain.
- `verify` also requires the chain directory in the change
  (`--statement-chain-dir`) to equal the base branch's chain directory
  (`--base-statement-chain-dir`) entry for entry, byte for byte, plus at
  most one added entry, which must be the statement under verification.
  Removing, replacing, re-signing, or adding any other entry rejects the
  statement (V5), and so does an emptied chain directory over a non-empty
  base, or a statement the base chain already records. See
  [The base branch's chain](#the-base-branchs-chain).
- The statement being prepared or verified must name the head as its
  `previousAttestationDigest` (`null` only when the chain is empty), and
  its `attestedAt` must be later than the head's. A statement that is
  already the chain's head (verified after it was appended) is checked
  against the chain before it; one recorded anywhere else in the chain is
  rejected.
- Every rule's `consecutiveBatchCycles` is derived from the chain, never
  from a caller-supplied value, and every entry's own recorded counts must
  match that derivation: a rule's count is the number of statements in the
  chain that renewed it since the most recent statement that recorded an
  individual review for it, plus one for the statement at hand. A count
  below 1 anywhere is rejected, and a count above 2 means the rule is not
  renewed (`CONSECUTIVE_BATCH_CYCLE_CAP`). A rule that was simply not
  renewed in some cycle keeps its count: only a recorded individual review
  resets it.
- **What counts as an individual review.** A review record in
  `--review-record-dir` — one file per rule, named `<ruleId>.json` (the
  rule ID is the file name with exactly the `.json` extension removed, so
  dotted rule IDs work; a file with any other name rejects the command) —
  whose digest (the SHA-256 of its exact bytes) the chain has not already
  recorded for that rule. Such a record must be a structurally valid
  `review-record` record (`prufyx.io/declared-knowledge-review-record/v1`,
  with that format's fixed decision, authority and scope) whose
  `subject.ruleId` and `subject.project` are the rule's own, whose
  `bindings.ruleDigest` is the digest of the rule exactly as it is in the
  prior pack (the same canonical scheme `review-record` uses), and whose
  `decision.decidedAt` is later than the rule's last individual review
  recorded in the chain and not later than `attestedAt`. A record for a
  rule not in the pack, or one failing any of these checks, rejects the
  statement (V5); it is never silently ignored. So a record copied under
  another rule's name, an already counted record with a byte changed, or
  a record made against an earlier version of the rule never counts as a
  new review, whether or not the statement renews anything. `prepare`
  lists every new review in the statement's `individualReviews`, so once
  the statement is signed and appended, the review is part of the signed
  log; a later statement that supplies the same record again skips it
  and does not reset the rule a second time. A sampled rule's review is
  recorded the same way. A chain entry that lists an individual review
  for a rule in neither its `rules` nor its `notExtended` is rejected. As
  everywhere else in this tool, the record is not checked against its
  packet, corpus, vectors and target here (see
  [Known scope limits](#known-scope-limits)); its digest is bound into the
  signed statement, and the signer vouches for it.
- **Editing the pack between cycles does not reset anything.** The chain
  head is found by linkage, not by matching pack digests, so an unrelated
  rule change merged between cycles leaves every count intact.
- **A truncated chain is detected.** Every batch renewal sets the renewed
  rules' `reviewedAt` to the statement's `attestedAt`, and every renewal is
  a chain entry. So when the prior pack holds a rule whose `reviewedAt` is
  later than the head's `attestedAt`, either a statement is missing from
  the chain or the rule was reviewed individually since. `prepare` and
  `verify` both reject the statement (V5) unless a new review record is
  supplied for that rule.
- **Dates cannot drift away from the chain.** A prior-pack rule whose
  `reviewedAt` equals some chain entry's `attestedAt` must be one that
  entry renewed, still carrying the `validUntil` that entry set, or one
  that entry recorded an individual review for, unless a new review
  record is supplied for it.

`--previous-statement` has been removed from both commands: the chain
directory alone determines the previous statement.

### The base branch's chain

The chain directory only protects anything if it can never be rewritten
by the change being verified. `verify` therefore needs
`--base-statement-chain-dir`: the same pack's chain directory exactly as
it is on the base branch the change is proposed against, checked out by
CI from the base branch itself (see the `git worktree add` and `git show`
examples under [Pipeline](#pipeline)), never taken from the change. It
must be an absolute path; pass an empty directory when the base branch has
no chain for the pack yet. Supplying the change's own chain directory
here defeats the check.

The chain directories must also be protected on the base branch: changes
to them must go through the same review and required `verify` status
check as rule pack changes (for example with branch protection and a
code-owners rule on the chain directories), so nothing lands on the base
branch that removes or rewrites an entry. A change that deletes or
rewrites the chain is rejected by `verify` against the base branch; a
direct push to the base branch that bypasses `verify` is not something
this tool can see.

## Signing

`sign --role human` (the default) refuses to run off a terminal: it reads
the passphrase the same way every other signer in this repository does
(`term.ReadPassword` on `os.Stdin`, no flag, environment variable, file,
default, or redirected input), so an unattended or agent-driven shell can
never reach a human key with a usable passphrase; it rejects
`--key-env`, `--passphrase-file` and `--passphrase-env`. It additionally
refuses a statement whose sampled rules are missing a recorded individual
review (`sampledForFullReview[].reviewRecordDigest` empty): the maintainer
must show they actually reviewed the seeded sample before their signature
can cover the batch.

`sign --role automation` is the unattended path, for automated statements
only. It reads the encrypted key from `--key` (an absolute path to a file
of mode `0600` owned by the current user) or from the environment variable
named by `--key-env`, and its passphrase from `--passphrase-file` (same
file rules; one trailing newline is ignored) or from the environment
variable named by `--passphrase-env` — exactly one source of each. Both
roles refuse, before any secret is read, a statement whose `signerRole` is
not the role given, and `sign` refuses a key whose role in the trust root
is not that role. In CI, the key and the passphrase are two secrets
exposed only to the job that signs, for example:

```yaml
- name: Sign the automated statement
  env:
    REATTEST_AUTOMATION_KEY: ${{ secrets.REATTEST_AUTOMATION_KEY }}
    REATTEST_AUTOMATION_PASSPHRASE: ${{ secrets.REATTEST_AUTOMATION_PASSPHRASE }}
  run: |
    prufyx-maintainer evidence reattest sign --role automation \
      --statement "$PWD/out/statement.json" \
      --trust-root "$PWD/evidence-reattest-trust-root.json" --trust-root-digest "$ROOT_DIGEST" \
      --key-env REATTEST_AUTOMATION_KEY --passphrase-env REATTEST_AUTOMATION_PASSPHRASE \
      --output "$PWD/out/statement.sig.json"
```

Run `verify` on the prepared statement before signing it, and sign only in
a job that cannot be triggered by an untrusted change (for example only on
the protected default branch, in an environment whose secrets are
restricted to it). Even a stolen automation key can renew only what the
automated policy computes as eligible from the retained worklist: `verify`
recomputes every automated statement, and the key can never sign a human
statement.

```sh
prufyx-maintainer evidence reattest sign \
  --statement "$PWD/out/statement.json" \
  --trust-root /absolute/operator-private/evidence-reattest-trust-root.json \
  --trust-root-digest sha256:<independently-known-root-digest> \
  --key /absolute/operator-private/evidence-reattest.key.pem \
  --output "$PWD/out/statement.sig.json"
```

`--trust-root-digest` must come from somewhere other than the `--trust-root`
file itself — a value the maintainer already holds, not one computed from
the bytes being checked. `sign` and `VerifySignature` both refuse to run
without it and refuse when it does not match; computing it from the same
file would accept any self-consistent root an attacker hands in, which is
not pinning at all.

The digest is `sha256:` followed by the lowercase hex SHA-256 of the trust
root's canonical JSON bytes, which is the file's content **without** its
single trailing newline (the commands strip exactly one trailing newline
before checking). Canonical JSON contains no raw newline, so whoever
creates the root and publishes its pin can compute it with:

```sh
echo "sha256:$(tr -d '\n' < evidence-reattest-trust-root.json | shasum -a 256 | cut -d' ' -f1)"
```

The signed bytes are the exact canonical statement; the statement's own
`statement` field is a fixed text (never free-form), stating what was run,
what was found, and what the signature does and does not mean — restated
verbatim in `cli/internal/maintainer/evidencereattest/evidencereattest.go`'s
`FixedStatementText` (human) and `AutomatedStatementText` (automated; it
states that no person reviewed the statement).

## Trust roots and roles

A trust root (`prufyx.io/evidence-reattestation-trust-root/v2`) lists every
key that may sign a statement for a pack, each with a `role`: `human` or
`automation`. The threshold applies within one role — a statement is
signed by keys of its own role only — so every role a root lists must have
at least `threshold` keys. A key of the other role in an envelope is
treated exactly like an unknown key.

Earlier formats stay valid:

- A v1 trust root (`.../trust-root/v1`, no `role` fields) is still accepted;
  every key in it is a `human` key. It cannot sign or verify an automated
  statement.
- A v1 statement (`prufyx.io/evidence-reattestation/v1`, no `signerRole`)
  is a human statement. Chains that begin with v1 statements stay
  verifiable; new statements are always v2 and record their role.

`trust-root migrate` derives a v2 root from a v1 or v2 root, reading only
public keys:

```sh
prufyx-maintainer evidence reattest trust-root migrate \
  --from "$PWD/evidence-reattest-trust-root.json" --from-digest "$ROOT_DIGEST" \
  --add-automation-key <64 hex characters: the automation key's Ed25519 public key> \
  --output "$PWD/evidence-reattest-trust-root.v2.json"
```

Every key it keeps keeps its role (a v1 root's keys become `human` keys);
it can add `automation` keys (`--add-automation-key`, repeatable) and
remove keys (`--remove-key <keyId>`, repeatable, for rotation), never adds a
`human` key, keeps the threshold, and keeps the expiry unless `--expires`
is given. It prints the new root's digest, which becomes the new pinned
`--trust-root-digest`. Because the same human key is in the new root, a
chain signed under the old root verifies unchanged under the new one; only
the pin changes, and it must change in the same place for `prepare`,
`sign` and `verify`.

## Key custody

The re-attestation signing key is a separate purpose (`rule-evidence-
reattestation`) from both community-release signing and the TUF roles: a
signature made for one purpose can never verify against another
(`evidencereattest.Purpose`/`Audience`, checked on every parse). No
production trust root is configured anywhere in this repository.
`evidencereattest.ProductionTrustRootPath` is deliberately left as an unset
constant; every function that needs a trust root takes it, and its expected
digest, as explicit caller-supplied inputs instead, and no production path
is ever read implicitly. Tests in this package generate their own
throwaway keys with `ed25519.GenerateKey`; no real key or trust root is
committed anywhere in this repository. Where the production key and its
trust root are stored (hardware token vs. passphrase-encrypted offline key,
single vs. multi-maintainer signature threshold) is a deployment decision
this tool does not make; callers supply both explicitly on every call.
Keep the human and automation keys apart: the human key stays with the
maintainer and is only ever unlocked at a terminal; the automation key and
its passphrase are held as secrets of the one job that signs automated
statements, never on the machine that prepares them.

## Known scope limits

- **Rule-digest scheme.** `priorRuleDigest`/`nextRuleDigest` use
  `sourcecorpus.Canonical`/`SHA` over the generically decoded rule — the
  same scheme `maintainer/reviewrecord` uses for its own `ruleDigest`
  binding. This is deliberately **not** byte-identical to the engine's
  internal `claims[].ruleDigest` (`constraintengine`'s `digestJSON`, which
  marshals an unexported typed struct in Go field-declaration order, not
  sorted-key canonical order). The mismatch never affects a check this
  package makes, because every comparison this package performs uses its
  own scheme consistently on both sides.
- **`ruleSetDigest`.** A digest over just the pack's rule array in
  canonical form, for this package's own prior/next binding (V4). It is not
  claimed to equal `constraintengine.RuleSet.Digest()`, which is unexported
  and tied to the compiled, embedded pack rather than an arbitrary on-disk
  file.
- **`engineCapabilityDigest` for the community pack.** The CNCF pack uses
  `cncfcheck.ExternalCapabilityDigest()`. The community pack has no
  equivalent external capability surface (no external profile exists for it
  at all), so its statements instead carry
  `constraintengine.EngineContractDigest()`, the generic engine contract
  digest. This is a known, narrower binding, not a silent substitution.
- **`upstreamReleasesSincePrior`.** `evidence repin` resolves only each
  repository's single most recent release, not a full release history
  since the prior attestation. This field therefore lists the latest
  resolved tag per cited repository (the compared tag of each citation, which
  for a release-line citation is the newest release on its line), not a
  complete errata list. Not
  implemented: fetching and acknowledging the full release list for each
  cited repository.
- **`toolIdentityDigest`.** A fixed, documented placeholder
  (`evidencereattest.ToolIdentity`, hashed), not a reproducible
  build-provenance attestation; no such system exists in this repository.
- **Wave assignment.** `prepare`/`verify` compute a wave's slot date from
  `attestedAt` (`evidencereattest.SlotDate`), but do not assign projects to
  waves; the wave number is a caller-supplied input. Not implemented:
  deterministic bin-packing of projects into waves by citation count.
- **`--statement-chain-dir` contents.** `prepare` and `verify` read this
  directory to derive the chain (see [The statement chain](#the-statement-chain-v5));
  neither writes to it, and nothing in this tool appends a statement to it
  after signing. Appending each signed statement and its signature under
  a new stem is the caller's responsibility; `verify` enforces that the
  change only appends, against `--base-statement-chain-dir`.
- **Trust root rotation.** Every chain entry is verified under the one
  trust root the command is given, so a new trust root must keep every key
  that signed an existing chain entry, in the same role, for as long as
  that chain is in use. `trust-root migrate` never changes a kept key's
  role, but it does not stop the operator removing a key that signed an
  existing entry; `prepare` and `verify` then reject the chain.
- **Key generation.** This tool does not generate the automation key. Any
  Ed25519 key in the encrypted PEM format the other signers in this
  repository use works; its public key is added with
  `trust-root migrate --add-automation-key`.
- **Review record content.** `--review-record-dir` records are checked
  structurally and bound to the rule, its project, its exact prior-pack
  version, and the chain's review history (see
  [The statement chain](#the-statement-chain-v5)), but not against the
  rule's evidence packet, source corpus, vectors and target (see
  `review-record`), which this tool does not take. The record's declared
  `decidedAt` is not authenticated.
