# Contributing a rule

This is the path for proposing one deterministic compatibility rule — a
single, source-pinned claim like "upgrading component X from version A to
version B breaks under condition Y" — for review. It is separate from the
[public project onboarding workflow](project-onboarding.md), which proposes
that a whole new project be tracked at all.

Nothing you submit here is published automatically. A validator catches
malformed submissions before a human ever looks at them; a maintainer still
reviews and, if the rule is correct, folds it into the published pack by
hand. The validator itself never writes to a `rules.json` file, and it never
asserts a compatibility claim on its own.

## What a rule is

A rule lives in `internal/cncfcheck/data/rules.json` (the CNCF pack) or
`internal/projectcheck/data/rules.json` (the community-project pack). Both
files hold the same shape: a top-level `entries` array, where each entry is:

```json
{
  "project": "argo-workflows",
  "description": "one sentence explaining what this entry checks and why",
  "requiredFacts": [ /* the facts the rule's condition needs the caller to declare */ ],
  "rule": {
    "id": "argo-workflows.server-basehref.3-4-18-to-4-1-3",
    "operator": "forbid_predicate_value",
    "subject": { "component": "pkg:github/argoproj/argo-workflows", "from": "3.4.18", "to": "4.1.3" },
    "condition": { "side": "proposed", "component": "...", "factId": "...", "boolValue": true },
    "evidence": { "state": "active", "reviewedAt": "...", "validUntil": "...", "sources": [ /* pinned sources */ ] },
    "reasonCode": "REVIEWED_SOURCE_CONSTRAINT",
    "nextAction": "one sentence telling the operator what to do about it"
  }
}
```

`operator` is one of `forbid_predicate_value`, `require_component_version`,
`require_intermediate_version`, `forbid_target_version`,
`forbid_set_member` (see [Set-valued facts](#set-valued-facts-and-forbid_set_member)
below), or `notice_one_way` (see [One-way notices](#one-way-notices-and-notice_one_way)
below) — see `internal/constraintengine/parse.go` for exactly what each one
checks.
`requiredFacts` may be empty for an operator that carries no fact condition
(for example `require_component_version`, which only compares a declared
dependency version).

A candidate file is a JSON array of one or more entries in exactly this
schema — nothing more, nothing less. See the worked example below, and
either `rules.json` file, for real entries to model a new one on.

## Set-valued facts and `forbid_set_member`

Some removals are naturally a list: the feature gates a component sets, or
the command-line options it is given. Instead of one `bool` fact per removed
name, such a rule reads one **set fact** per component and kind, and the
`forbid_set_member` operator names the members it forbids.

A set fact is declared in `requiredFacts` with `"type": "set"` and
`"enumTokens": null`. In a prepared input a declared set fact carries
`"setValue": { "members": [...], "complete": true|false }`:

- `members` is strictly ascending (byte order) with no duplicates, at most 256
  entries, each 1-128 bytes of `[A-Za-z0-9._/-]` starting with a letter or
  digit;
- `complete` is the preparer's statement that no other member exists. It is
  `true` only when every source the set is read from was supplied, declared
  complete and fully understood.

A `forbid_set_member` rule carries a `setCondition` instead of a `condition`:

```json
"operator": "forbid_set_member",
"setCondition": {
  "side": "proposed",
  "component": "pkg:github/kubernetes/kubernetes",
  "factId": "component.kubernetes.kubelet_feature_gates_set",
  "members": ["ExampleRemovedGate"]
}
```

`members` names 1-64 forbidden members under the same rules (sorted, no
duplicates, same character set and length). The rule decides:

| Declared set | Verdict |
| --- | --- |
| holds a forbidden member (complete or not) | `BLOCKED`; the claim lists the members found in `matchedMembers` |
| declared complete, no forbidden member | `PASS` |
| not complete, no forbidden member | `UNKNOWN` (`RULE_SET_FACT_INCOMPLETE`) |
| missing, unsupported, conflicting or not declared | `UNKNOWN` (`RULE_FACT_UNAVAILABLE`) |

Absence is never inferred from an incomplete set. `matchedMembers` appears only
on a `BLOCKED` `forbid_set_member` claim, and human output adds one line
`forbidden members present: <members>` before the evidence basis; other claims
keep their exact bytes. Matching is exact and case-sensitive.

Set facts are valid only with `forbid_set_member`: they cannot appear in
`appliesWhen` or in a `forbid_predicate_value` condition, and a `setCondition`
on any other operator is rejected. Unknown fields anywhere in a set value or
set condition are rejected.

A rule document or pack that contains a `forbid_set_member` rule carries its
own schema — rules `prufyx.io/deterministic-constraint-rules/v1alpha3`, CNCF
pack `prufyx.io/cncf-source-rule-pack/v1alpha3` — and its reports carry a
separate engine contract digest. The schema may also hold reviewed ranges.
Binaries that predate set facts reject such a document outright, and every
document without the operator keeps its previous schema, digests and report
bytes. Two set rules on the same fact whose reviewed ranges overlap may not
forbid a common member.

## One-way notices and `notice_one_way`

Some upgrades cannot be rolled back: a stored format or version changes and
the older release cannot read it again. A `notice_one_way` rule says so for
one reviewed transition. It is a notice, not a verdict.

```json
"operator": "notice_one_way",
"subject": { "component": "...", "from": "1.29.0", "to": "1.30.0" },
"evidence": { "state": "active", "reviewedAt": "...", "validUntil": "...", "sources": [ /* pinned sources */ ] },
"reasonCode": "ONE_WAY_TRANSITION",
"nextAction": "take an etcd snapshot and verify that it restores before upgrading"
```

- `reasonCode` must be `ONE_WAY_TRANSITION`.
- The rule carries no `condition`, `setCondition`, `dependency` or
  `intermediate`. `appliesWhen` and a reviewed `range` are allowed.
- `nextAction` is the reviewed "before you upgrade" text: what the operator
  must do first (a backup, a snapshot, a verified restore), written from the
  cited source, at most 256 bytes. It must not contain the word "safe" in any
  form; describe the precaution, never the outcome.
- `requiredFacts` lists only the facts `appliesWhen` reads, and is empty when
  there are none.

When the transition matches, the evidence is current and every `appliesWhen`
condition holds, the claim status is `NOTICE`. Otherwise the claim is
`UNKNOWN` with the usual reason (stale or withdrawn evidence, a transition the
rule does not review, an applicability fact that is missing or does not
match). Either way the claim never decides anything: a notice is left out of
the exit code and of every aggregate, a project whose only rules are notices
still has no evaluated rule, and a notice cannot support a completeness
attestation. Human output prints a matching notice as
`cannot be rolled back: <rule id>` followed by
`before you upgrade: <nextAction>`; a notice for another transition prints
nothing, because the absence of a notice says nothing about rolling back.

A rule document or pack that contains a `notice_one_way` rule carries its own
schema — rules `prufyx.io/deterministic-constraint-rules/v1alpha4`, CNCF pack
`prufyx.io/cncf-source-rule-pack/v1alpha6` — and its reports carry a separate
engine contract digest. The schema may also hold reviewed ranges and
`forbid_set_member` rules. Binaries that predate notices reject such a
document outright, and every document without the operator keeps its previous
schema, digests and report bytes. Community project packs do not accept
notices.

## Evidence basis

A rule's `evidence` block may say how the rule was produced. The fields are
optional and never change a verdict; they are parsed strictly and shown next to
every finding.

| Field | Meaning |
| --- | --- |
| `basis` | `"reviewed"` (interpreted by a maintainer) or `"mechanical"` (derived from pinned upstream source by a versioned extractor). Absent means `reviewed`. Any other value is rejected. |
| `extractor` | `{ "id", "version", "codeDigest" }`: the extractor id, a strict `major.minor.patch` version and the `sha256:<64 lowercase hex>` digest of the extractor's source. Required when `basis` is `mechanical`, and rejected otherwise. |
| `derivedAt` | RFC 3339 UTC time the extractor produced this rule. Required when `basis` is `mechanical`, rejected otherwise, and earlier than `validUntil`. |

Community contributions are reviewed rules: a candidate that declares
`basis: "mechanical"` is rejected by `prufyx-maintainer rule validate`. A
mechanical rule is never renewed by `evidence reattest`; see
[evidence-reattestation.md](evidence-reattestation.md).

A rule may also be named by a **line attestation**, a statement that a minor
line's rules for one fact family are complete. If a pack attests the line
your rule's target version falls in, the attestation must list your rule, or
the pack is rejected; see [line-attestations.md](line-attestations.md).

A rule decides one hop of an upgrade. How an upgrade is split into hops (for
example, one hop per Kubernetes minor line) is a separate reviewed record, an
**upgrade-path policy**, with the same evidence as a rule. On an intermediate
hop a rule counts only if its reviewed range covers the whole minor line on
that side; a rule without a range never does. A component without a policy
is never assumed to allow skipping lines. See
[upgrade-paths.md](upgrade-paths.md).

Every human finding prints one line before the pinned sources, either
`evidence basis: reviewed by maintainer` or
`evidence basis: derived from source by <extractor id> v<version>`. In JSON
output a finding that comes from a mechanical rule carries `evidenceBasis`,
`evidenceExtractor` (`id`, `version`, `codeDigest`) and `evidenceDerivedAt` on
its claim. These fields are omitted for rules with no declared basis, so
existing reports keep their exact bytes; an absent `evidenceBasis` means the
rule was reviewed by a maintainer. Neither form changes the exit code.

## Evidence discipline

Every rule cites the exact upstream text it rests on, and the citation
discipline is not negotiable:

- **Cite a pinned commit, never a branch.** `revision` is a 40-character
  lowercase hex commit SHA, and `url` must embed that same commit — either
  `https://github.com/<owner>/<repo>/blob/<revision>/<path>` or
  `https://raw.githubusercontent.com/<owner>/<repo>/<revision>/<path>`. A URL
  pointing at `main`, a tag that can move, or a release branch is rejected:
  the whole point of pinning is that the cited text cannot change under the
  rule after it is reviewed.
- **Never write a claim the cited text does not state.** If you cannot point
  at the exact lines that support the claim, the claim does not belong in a
  rule yet. `startLine`/`endLine` must bound the passage you actually read
  and relied on, not a whole file "for context."
- **Absence of evidence is `UNKNOWN`, never `PASS`.** A rule may only ever
  produce `BLOCKED` (via `forbid_predicate_value` / `forbid_target_version`)
  or force an intermediate/dependency step. There is no operator, and no
  rule shape, that asserts something is safe because no problem was found.
  If you were hoping to write "this is fine because nothing broke it," that
  is not a rule this pack can express, and it should not be one: the absence
  of a rule already means `UNKNOWN` for that transition.

### `contentDigest` is the whole file, not the cited span

This is the single most common mistake, so it gets its own section.
`contentDigest` is `sha256:` followed by the hex digest of the **entire
file** at that revision — not a digest of the `startLine`–`endLine` span you
cited. There is no separate span digest anywhere in a rule record; the line
range and the digest are two independent statements ("here is the file this
came from, unmodified since this commit" and "here is where in that file the
relevant text is").

To compute it for a source you are about to cite:

```sh
curl -sSL "https://raw.githubusercontent.com/argoproj/argo-workflows/c2b9dc6dbc7b209eadf122238a9a9b2082ac8266/version.go" \
  | shasum -a 256
```

```
9cc3ff02c95774cefbc306c5be72cbc4f9922f956359bf25fdc1685b20d9456e  -
```

Prefix the digest with `sha256:` in the rule. This value is real — it is the
digest of the first evidence source in the published
`argo-workflows.server-basehref.3-4-18-to-4-1-3` rule (see the worked example
below), recomputed and confirmed to match while writing this doc.

## Running the validator

`prufyx-maintainer rule validate` checks a candidate file against the same
structural, pattern, and evidence rules the compiled engine
(`internal/constraintengine`) applies to a published entry, plus a few checks
specific to the contribution schema itself (rule ID collisions, fact
cross-references). It never writes anything.

Offline (default — no network access, run this first and always):

```sh
cd cli
go run ./cmd/prufyx-maintainer rule validate --file contrib/rules/your-candidate.json
```

This checks, without touching the network:

- the JSON schema is closed (no unknown fields anywhere in the candidate);
- `rule.id` matches the engine's ID pattern, and does not collide with a
  rule ID already published in either `rules.json`, or with another entry in
  the same candidate file;
- every source's `revision` is 40 lowercase hex characters;
- every source's `url` is a pinned GitHub blob or raw URL whose embedded
  commit equals `revision`;
- `startLine <= endLine` for every source;
- `rule.nextAction` is 1–256 bytes with no control characters (the engine's
  own limit), and `description` fields are non-empty with no control
  characters;
- `rule.subject.from` and `rule.subject.to` are strict semver and differ;
- every fact ID a `condition` or `appliesWhen` entry references appears in
  `requiredFacts` under the same side and component;
- `rule.evidence.state` is `active`;
- the candidate is then re-parsed by `constraintengine.ParseRuleSet` itself,
  as a final authoritative gate.

Online, opt in explicitly with `--fetch` (downloads each cited blob from
`raw.githubusercontent.com`):

```sh
go run ./cmd/prufyx-maintainer rule validate --file contrib/rules/your-candidate.json --fetch
```

This additionally verifies that the fetched file's whole-file SHA-256 equals
`contentDigest`, and that `endLine` does not exceed the file's line count.

To read the cited lines yourself before or after fetching:

```sh
go run ./cmd/prufyx-maintainer rule validate --file contrib/rules/your-candidate.json --print-span --fetch
```

Without `--fetch`, `--print-span` still lists every cited source and its
line range, just without the text (there is nothing to print offline).

The command exits `0` when the candidate validates cleanly, `1` when it is
well-formed JSON but has one or more findings, and `2` for a usage error or a
file that does not even decode as the pack entry schema. Findings are
printed to stderr, one per line, each naming the entry, rule ID, the specific
check that failed, and what is wrong — for example:

```
FAIL entry 0 rule="smoke.bad-revision.1-0-0-to-2-0-0" [revision]: rule.evidence.sources[0].revision "deadbeef" is not 40 lowercase hex characters
FAIL entry 0 rule="argo-workflows.server-basehref.3-4-18-to-4-1-3" [rule-id-collision]: rule id "argo-workflows.server-basehref.3-4-18-to-4-1-3" already exists in a published pack; choose a new, unique rule id
```

## Where to put the file

Put your candidate file under `contrib/rules/` (see
[`contrib/rules/README.md`](../contrib/rules/README.md)), named
`<project>-<short-description>.json`. CI runs the same validator over every
`*.json` file in that directory on every pull request; when the directory is
empty, that step exits `0`.

## Worked example

This walks through the real, published rule
`argo-workflows.server-basehref.3-4-18-to-4-1-3` end to end, as a template
for a new one.

1. **The claim.** Argo Workflows v4.1.3 kept the `--base-href` flag spelling
   that replaced the older `--basehref`; a `argo-server` Deployment whose
   argv still uses `--basehref` will fail after the upgrade.

2. **The evidence.** Four pinned sources: the target revision's identity
   (`version.go`), the commit that introduced the new flag spelling
   (`server.go` at the 3.5.15 revision), and two spans from the 4.1.3
   revision itself (`Dockerfile`, `server.go`) showing the old spelling is
   gone. Each source is a `https://github.com/argoproj/argo-workflows/blob/<40-hex>/<path>`
   URL with its own `startLine`/`endLine` and its own whole-file
   `contentDigest`, computed exactly as shown above for each file.

3. **The fact.** `requiredFacts` declares one fact,
   `component.argo-workflows.server_legacy_basehref_flag_present`, of type
   `bool`, on the `proposed` side. `rule.condition` references that exact
   `id`/`side`/`component` triple with `boolValue: true`.

4. **The rule.** `operator: forbid_predicate_value` — this operator only
   ever blocks; it cannot assert a pass. `subject` pins the exact
   `from`/`to` transition. `reasonCode` is `REVIEWED_SOURCE_CONSTRAINT`, and
   `nextAction` tells the operator exactly what to do: replace the flag and
   review other workloads separately (evidence never claims to cover more
   than it cites).

5. **Validate it.** Copying this entry into a candidate file (with a new
   `rule.id`, since the real one already exists) and running:

   ```sh
   go run ./cmd/prufyx-maintainer rule validate --file /tmp/candidate.json --fetch
   ```

   produces:

   ```json
   {
     "schema": "prufyx.io/community-rule-candidate-validation/v1alpha1",
     "valid": true,
     "entryCount": 1,
     "findings": null
   }
   ```

   confirming every cited digest and line range against the live repository,
   with exit code `0`.

## Review and publication

A maintainer reviews every candidate: reading the cited spans, confirming
the claim, checking the fact and operator choice, and deciding whether it
belongs in the CNCF pack or the community-project pack. Only a maintainer
folds an accepted candidate into the published `rules.json` and re-runs the
maintainer corpus-attestation tooling; this validator never does either.
