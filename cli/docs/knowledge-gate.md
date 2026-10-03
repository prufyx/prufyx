# Knowledge gate

`prufyx-maintainer gate classify|limits|verify` checks a proposed change to
the published knowledge — the rule packs, their corpus attestations, the
generated support inventory and the reattestation records — before it can
merge. The `Knowledge gate` workflow (`.github/workflows/knowledge-gate.yml`)
runs it on every pull request to `main` and once a day on `main`.

The gate compares two checkouts of the repository: the **base** the change is
proposed against and the proposed **head**. It is built from the base and only
reads the head's files; nothing from the proposed change is executed. A change
therefore cannot weaken the gate that checks it.

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
file is not a change.

### Proofs for loosening changes

| Evidence basis | Admitted when |
| --- | --- |
| `mechanical` | the extractor named in `evidence.extractor`, as compiled into the gate, re-derives the rule from upstream bytes pinned by commit SHA and fetched by the gate itself, and the re-derived entry is byte-identical (canonical JSON) to the proposed one. The rule's own `derivedAt` and lease (`validUntil` − `derivedAt`) are reused, so a renewal is a re-derivation at a later time. The extractor id, version and code digest must equal the gate's. |
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
| `size/<pack>` | the published target exceeds its size cap, or is at or above 80% of it and the change loosens and grows the pack. At or above 80% an alarm is reported |
| `stagger/<pack>` | a loosening change moves a lease into an ISO week that then holds more than 15% of the pack's rules (at least one) |
| `attestation/<pack>` | the committed corpus attestation differs from a regeneration from the head's pack |
| `generated/…` | the committed support inventory differs from a regeneration from the head's files |
| `block-only/<pack>` | an active rule has basis `consensus` (see above) |
| `reattestation/<pack>` | the statement chain changed and the appended statement does not verify |
| `limits` | the change holds more loosening changes than the cap (default 200) |
| `kill-switch` | the file `factory/PAUSE` exists in the base or the head and the change holds any loosening change |

The kill switch blocks every loosening change and lets tightening through. A
change that adds `factory/PAUSE` pauses itself; a change that deletes it is
still paused, because the base has it.

## Automatic merge eligibility

The gate reports, and never acts on, whether a change would be eligible for
automatic merging. It is eligible only when every check passes, the author is
the automation account (`--bot-login`), it contains at least one knowledge
change, and it touches only these files:

- `cli/internal/cncfcheck/data/rules.json`, `cli/internal/cncfcheck/data/corpus-attestation.json`
- `cli/internal/projectcheck/data/rules.json`, `cli/internal/projectcheck/data/corpus-attestation.json`
- `cli/docs/generated/community-support-inventory.json`, `cli/docs/generated/community-support-inventory.md`
- anything under `cli/knowledge/`

## File layout

| Path | Read from | Holds |
| --- | --- | --- |
| `factory/PAUSE` | base and head | kill switch (any content) |
| `cli/knowledge/reattestation/<pack>/chain/` | base and head | the pack's signed statement chain: `<stem>.statement.json` and `<stem>.statement.sig.json` pairs |
| `cli/knowledge/reattestation/<pack>/worklists/<stem>.worklist.json` | head | the worklist the statement `<stem>` was prepared from |
| `cli/knowledge/reattestation/<pack>/review-records/<rule id>.json` | head | individual review records, when a human statement uses them |
| `cli/knowledge/reattestation/trust-root.json` | base only | the reattestation trust root; its digest is passed separately (`--trust-root-digest`) |
| `cli/knowledge/approvals/<pack>/<rule id>.json` | head | owner approvals |
| `cli/knowledge/trust/web-approval-keys.json` | base only | the pinned owner-approval keys |

`<pack>` is `cncf` or `community`. A reattestation worklist names each pack by
its repository path (`cli/internal/cncfcheck/data/rules.json`,
`cli/internal/projectcheck/data/rules.json`); run `evidence repin` from the
repository root with those `--rules` paths.

## Owner approvals

An owner approval admits one exact reviewed entry. The committed file is:

```json
{
  "schema": "prufyx.io/knowledge-approval/v1",
  "record": {
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
  `requiredFacts`, `rule`) with object keys sorted, two-space indentation,
  no HTML escaping and one final newline.
- `signature` is the standard base64 Ed25519 signature over the bytes
  `prufyx.io/knowledge-approval/v1`, one NUL byte, then the record as compact
  JSON with its keys in the order shown. Every record field is plain ASCII
  from a restricted alphabet, so any JSON encoder produces the same bytes.
- `keyId` is `sha256:` and the hex sha256 of the raw 32-byte public key.

The gate accepts an approval only if the key is pinned in the base's
`web-approval-keys.json` (`"role": "web-approval"`) and not past its
`notAfter`, the signature verifies, the decision is `approve`, the identity is
one of the pinned `owners`, the pack and rule id match, the decision time is
not in the future (five minutes of clock skew allowed) and at most 14 days
old, and the digest matches the proposed entry. Changing anything in the
entry after approval invalidates it. Approvals never admit a mechanical rule.

```json
{
  "schema": "prufyx.io/web-approval-keys/v1",
  "role": "web-approval",
  "owners": ["owner-login"],
  "keys": [{"keyId": "sha256:…", "publicKey": "<64 hex>", "notAfter": "2027-10-01T00:00:00Z"}]
}
```

No approval key is pinned in this repository yet, so no approval is accepted.

## Commands

All three commands take `--base DIR` and `--head DIR` (repository roots).
Exit codes: `0` the gate passes (for `classify`: always, when the input can be
read), `1` it fails, `2` rejected input or an error.

### `gate classify`

Prints every changed rule with its class, kinds and basis, the packs whose
statement chain changed, and whether the kill switch is set.

| Flag | Meaning |
| --- | --- |
| `--json` | print JSON instead (`changes`, `totals`, `chainsChanged`, `paused`) |

Change kinds: `withdraw`, `expire`, `add-withdrawn` (tightening); `new`,
`remove`, `reactivate`, `renew`, `repin`, `widen`, `narrow`, `range-change`,
`basis-change`, `modify` (loosening).

### `gate limits`

Only the loosening cap and the kill switch.

| Flag | Meaning |
| --- | --- |
| `--max-loosening N` | cap on loosening changes (default 200) |
| `--json` | print the report as JSON |

### `gate verify`

The whole gate.

| Flag | Meaning |
| --- | --- |
| `--source github` | fetch pinned upstream bytes from GitHub for re-derivation |
| `--source fixture:DIR` | read them from a fixture tree instead (`<host>/<owner>/<name>/tags.json` and `commits/<sha>/…`, the layout `extract run --fixture` reads) |
| `--author LOGIN` | the change's author, for automatic-merge eligibility |
| `--bot-login LOGIN` | the automation account (default `prufyx-factory[bot]`) |
| `--max-loosening N` | cap on loosening changes (default 200) |
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
`detail`), `checks`, `alarms`, `limits`, `changedPaths`, `chainsChanged` and
`autoMerge` (`eligible` and the reasons it is not).

## Example

Comparing a checkout with itself passes and is not eligible for automatic
merging (no knowledge change):

```sh
cd cli
go run ./cmd/prufyx-maintainer gate verify --base .. --head ..
```

```text
ok   check admit/cncf: 191 entries admitted
ok   check registry/cncf: 160 of 256 facts
ok   check size/cncf: target 578749 of 1048576 bytes (55%)
…
ok   check limits: 0 loosening changes, cap 200
gate: PASS (0 tightening, 0 loosening; kill switch not set)
auto-merge: not eligible (author "" is not the automation account "prufyx-factory[bot]"; the change holds no knowledge change)
```

## The workflow

`Knowledge gate` runs on `pull_request_target` so that its definition and
the gate code always come from the base branch. It checks out the base and the
proposed change separately, without stored credentials, requires the change to
be based on the current base, builds the gate from the base with module
caching off, and runs `gate classify` and `gate verify --source github`. When
a statement chain changed it first runs `evidence repin` itself and passes the
result as `--rerun-worklist`. The token is read-only and the workflow uses no
secrets. On the daily run it adds `--rederive-all`.

Repository variables: `REATTEST_TRUST_ROOT_DIGEST` (the pinned trust root
digest; unset means no statement is accepted), `KNOWLEDGE_BOT_LOGIN` (default
`prufyx-factory[bot]`), `KNOWLEDGE_MAX_LOOSENING` (default 200).

The job's outputs `result` and `auto-merge-eligible` and the uploaded
`knowledge-gate-report` artifact carry the result. The workflow never merges.
