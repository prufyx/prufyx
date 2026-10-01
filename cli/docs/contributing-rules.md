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
`require_intermediate_version`, or `forbid_target_version` — see
`internal/constraintengine/parse.go` for exactly what each one checks.
`requiredFacts` may be empty for an operator that carries no fact condition
(for example `require_component_version`, which only compares a declared
dependency version).

A candidate file is a JSON array of one or more entries in exactly this
schema — nothing more, nothing less. See the worked example below, and
either `rules.json` file, for real entries to model a new one on.

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
