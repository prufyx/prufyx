# Extractor tooling for automation

Maintainer-only commands around `prufyx-maintainer extract run`. All of them
are deterministic and offline: they read the local mirror or a fixture tree
and the files named on the command line, make no network request and involve
no model. The commands are meant to be run from a program, so every result is
in the exit code and in files, never only in prose.

Exit codes of the `extract` subcommands:

| Code | Meaning |
| --- | --- |
| 0 | success (`verify`: byte-identical; `apply`: merged, or nothing to do) |
| 1 | `verify` or `oracle` found differences |
| 2 | rejected input, or a failed run, merge or refusal |
| 3 | `supersede`: refused, nothing written (see below); `run --wants-out`: files or commits the mirror does not hold are needed; `inventory`: the commit cannot be established completely; `apply --withdraw`: the run does not supersede a rule it would withdraw |

## `extract apply`

```
prufyx-maintainer extract apply --out DIR --pack FILE [--withdraw | --rules-only]
```

`--out DIR` is the directory of an `extract run`; `--pack FILE` is a rule pack
(`cli/internal/cncfcheck/data/rules.json` or the community pack), edited in
place. Run it with the working directory inside the repository tree whose
packs the new rules must not collide with, as `extract run` is.

**Without `--withdraw`** the run's rules (`candidates.json`) and line
attestations (`attestations.json`, when the extractor attests lines) are
merged into the pack:

- The run directory must be intact: the manifest's digests must match
  `candidates.json`, `vectors.json` and `attestations.json`, every candidate
  must be an active mechanical rule of the manifest's extractor, and the
  candidates' ids must be exactly the ids the manifest's derived pairs list.
- A rule whose id is already in the pack with identical content is left alone.
  A rule whose id is in the pack with different content refuses the whole
  merge, whoever wrote the other rule (a later derivation of the same rule is
  a renewal, which `extract apply` does not do). The same holds for an
  attestation with the same component, line and fact family.
- The result is rendered with the pack's members in their fixed order, entries
  sorted by project and rule id, two-space indentation and a final newline.
  An entry the run did not touch keeps its bytes, so merging a run that adds
  nothing reproduces the pack exactly. Entries a run adds are canonical JSON
  (keys in byte order).
- The result must pass `rule validate` (the checks `extract run` applies,
  including id collisions with the packs given to the command), the
  attestation exact-set check, and the engine loader of the pack's family: the
  CNCF pack is admitted with `landscape-projects.json` and
  `priority-portfolio.json`, the community pack with `projects.json`, read
  from the directory of the pack file. A pack carries exactly the schema of the
  highest-level feature it uses, so the schema is moved to the first level the
  loader admits (never lower, at most 12 levels up).
- Last, the result is compared with the base: every base rule must be
  byte-for-byte equal in canonical form, every new rule must be one of the
  run's, and no pack member other than `schema` and `lineAttestations` may
  differ. Anything else refuses the merge ("changes a rule the run did not
  produce").
- On any refusal the pack file is not touched. The engine reports a rule whose
  fact its registry does not define only as a failed check; the message then
  names the facts the added rules require that no existing rule uses.

**With `--withdraw`** the run is read as the extractor's current answer for the
pairs it derived, and the rules it no longer produces are withdrawn: every
active mechanical rule of the run's extractor whose subject is the anchor
transition of a derived pair of the run, and whose id is not among that pair's
rules, gets `evidence.state` set to `withdrawn`. Nothing else changes (the
file differs by those state values only), a withheld pair withdraws nothing,
and a rule of another extractor or of a reviewed rule is never touched. The
result is audited the same way, and the knowledge gate classifies each such
change as a tightening change (`withdraw`).

A rule is withdrawn only when the run supersedes it: the run is not older than
the rule, carries the same extractor code digest, and its pair read both
commits (from and to) that the rule cites; the rule must cite exactly those two
and no other. Otherwise the command refuses with exit 3 and touches nothing.
Because extractors are deterministic, a rerun with the same code over the same
commits re-derives the same rules, so today this applies to a run that was
edited or trimmed. When extractor upgrades or upstream re-tags should trigger
withdrawals is a separate decision, not covered here.

The command prints what it did, one line per rule. `gate classify` on the
tree before and after reports exactly those rules (`new` for a merge,
`withdraw` for a withdrawal) and, when attestations are merged or the schema
moves, the pack members that changed.

**With `--rules-only`** only the run's rules are merged. The run's
attestations are ignored, so the pack's `lineAttestations` member stays as it
was, and the pack schema never changes: if the engine loader refuses the
merged pack at its own schema the merge is refused (a schema move is part of
an attested apply). It does not combine with `--withdraw`. Every other check
above applies unchanged.

## `extract supersede`

```
prufyx-maintainer extract supersede --out DIR --pack FILE
```

Replaces reviewed rules by the rules of a run that cover them. It is not part
of the automated flow: a reviewed rule is superseded only by a change the
owner makes and the knowledge gate admits as a supersede.

A reviewed rule is any rule whose evidence basis is not `mechanical`, in any
state. A rule of the run replaces a reviewed rule when both are for the same
component and have the same constraint key (the operator and the constrained
fact: side, component and fact id) and their match regions overlap. The run's
rule must then cover the reviewed rule completely: its from and to regions
contain the reviewed rule's (a range contains an anchor pair inside it; an
anchor-only rule covers only the same anchor pair), and for set rules its
members include all of the reviewed rule's. The command then removes exactly
those reviewed rules, adds the run's rules, and prints the old to new map as
canonical JSON on stdout:

```
{"added":[...new rule ids...],"map":{"<old id>":"<new id>"},"unchanged":[...]}
```

`unchanged` lists run rules already in the pack with identical content; a
second supersede of the same run changes nothing and prints an empty map.

Refused with exit 3, a message on stderr, nothing on stdout and the pack file
untouched:

- a reviewed rule that a run rule overlaps with the same key but covers only
  in part (a wider region, or set members the run's rule lacks);
- a reviewed rule that overlaps more than one run rule;
- a mechanical rule of the pack that a run rule overlaps (only reviewed rules
  can be superseded);
- a run that adds rules but matches no reviewed rule (use `extract apply`);
- a run rule whose id is in the pack with different content;
- a result that differs from the base in anything but the removed reviewed
  rules and the run's rules (the final audit, the same one `apply` runs; the
  schema and every other pack member must be unchanged).

A run rule that replaces nothing is simply added. The checks of `apply` on the
added rules (`rule validate`, the engine loader, the attestation exact-set
check) run on the result; a pack that the loader refuses at its own schema is
refused, since supersede never moves the schema. A damaged run or an unreadable
pack exits 2, as in `apply`.

## `extract inventory`

```
prufyx-maintainer extract inventory --extractor ID (--mirror-state DIR | --fixture DIR) \
    --repo OWNER/NAME --commit SHA
```

Prints, as canonical JSON on standard output, the complete inventory the
extractor parses at one commit:

| Extractor | `kind` | Lists |
| --- | --- | --- |
| `k8s.feature-gate-removal` | `feature-gates` | `declared`: the gates declared in the registries; `names`: every gate name the walk of the tree finds |
| `k8s.served-api-removal` | `served-apis` | `gvks`: every group/version/kind the OpenAPI specification declares |
| `crd.version-removal.<project>` | `crd-versions` | `crds`: every CustomResourceDefinition with its group, kind, scope, path, storage version and each version's `served` and `storage` flags |

The inventory is complete or it is not printed. If the extractor cannot
establish the commit completely (a file is not in the mirror, a listed path is
missing, a parse is refused) the command prints the reason on standard error,
prints nothing on standard output and exits 3. Repository and commit mistakes
(a commit that is not a full SHA, a repository the extractor does not read)
exit 2. The output is the same on every run for the same bytes.

## `extract run --wants-out`

```
prufyx-maintainer extract run --extractor ID --mirror-state DIR --out DIR --wants-out FILE
```

The offline mirror never fetches file contents. Without `--wants-out` a pair
whose files are missing is withheld, or the run fails, as before. With it, a
run that meets files the mirror does not hold derives nothing that is kept:
it writes `FILE` in the format `factory mirror --wants` reads (repository,
commit and sorted paths, grouped and sorted), writes nothing to `--out`, and
exits 3. Run `factory mirror --wants FILE` and then the same `extract run`
again; repeat until the exit code is not 3. **Stop the loop** when `factory mirror`
exits non-zero (it exits 1 when a want could not be materialized), when the wants
file is byte-for-byte the one of the previous round, or after a bounded number of
rounds. If the mirror does not hold a commit or repository at all the run prints
`needs commit <repo>@<sha>`, writes no wants file for it and also exits 3: run
`factory mirror` without `--wants` to fetch it, then run again. A single round may not list every
file: an extractor decides what to read from the files it has already read, so
the files after the first missing ones are listed in the next round. Files
whose bytes the mirror already holds under another path or commit are never
listed (git stores a blob once). A pair withheld for any other reason (a file
that does not parse, an incomplete registry) is not a "needs blobs" result: it
is reported as before, the exit code is 0 and no wants file is written.

## `factory mirror --test-releases-api-base`

```
prufyx-maintainer factory mirror ... --test-allow-file-remote --test-releases-api-base URL
```

For tests only. Release metadata is read from `URL` (an `http` or `https` URL
with no credentials, query or fragment) instead of `api.github.com`; the
credential in the environment, or a GitHub App key, is then sent to that URL
and nowhere else. The option is refused with exit 2 unless
`--test-allow-file-remote`, which already limits the command to local test
remotes, is also given.
