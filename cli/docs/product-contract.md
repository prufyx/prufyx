# Community product contract

Prufyx checks an explicitly named configuration question against an exact
upstream revision. A report records its input and knowledge identities, the
finding, source references, omissions and next action. The same admitted inputs
and evaluation parameters produce the same output.

## Current checks

| Check | Scope |
| --- | --- |
| cert-manager removed monitoring values | Presence of three exact removed settings in proposed merged JSON values for the reviewed 1.20.3 → 1.21.1 chart transition |
| Prometheus declared Agent mode | Declared mode preservation from 2.55.1 → 3.1.0 with the reviewed Linux arm64/v8 image manifests and supported direct-entrypoint forms |
| SPIFFE X.509-SVID public-leaf URI-SAN subset | Standards conformance for non-CA, one URI SAN, lowercase `spiffe` scheme and non-root path; no version transition or complete SPIFFE/trust/runtime claim |
| CloudEvents structured JSON core-envelope subset | Standards conformance for one staged edition 1.0 object envelope; no version transition or payload/transport/SDK/runtime claim |
| TiKV 8.5.8 GCS WIF full-backup setting | Target-only planned-operation preflight for one explicit `backup.gcp-v2-enable`/`backup.gcp_v2_enable` Boolean; no from-version, full backup-readiness, restore, log-backup or runtime claim |

For cert-manager, version arguments select the exact reviewed chart contract.
The report shows the expected chart digests. The selection alone does not prove
which chart is deployed or will be installed. The checker does not merge Helm
values or evaluate the entire target chart schema.

For Prometheus, the real path admits a local producer-v3 observation plus the
proposed workload artifact. Capture time, evaluation time and freshness policy
are explicit. The synthetic demo is separately marked and cannot serve as
authoritative current evidence in the real observation path.

## Results and exit status

The `check` command's exit status describes its named claim:

| Claim or failure | Exit | Meaning |
| --- | --- | --- |
| PASS | 0 | The named predicate passes within the report's declared scope |
| BLOCKED or FAIL | 10 | The named transition check found a source-backed blocker, or the named conformance subset found a failed predicate |
| UNKNOWN or ATTENTION | 11 | The claim is unresolved or requires the stated review |
| Invalid input | 2 | Correct the command or input before evaluating it |
| Integrity failure | 3 | The supplied or bound bytes do not match the expected identity |

A claim may also be `NOTICE`: a reviewed rule states that the declared
transition cannot be rolled back, and human output prints it as
`cannot be rolled back: <rule>` with the reviewed text of what to do before
upgrading. `NOTICE` is informational and never a verdict. It never changes the
exit status or any aggregate: notices are left out, so a report whose only
claims are notices exits 11, and a notice beside passing or blocking claims
leaves their exit status as it was. The absence of a notice means nothing; it
does not say that a rollback is possible.

A claim may also be `UNSUPPORTED`: a reviewed support-range rule found the
declared combination outside a documented support range (for example an
add-on release line on a Kubernetes minor its project does not list as
supported). Outside the documented range means unsupported, not shown to be
broken. `UNSUPPORTED` carries the rule's own reason code and next action; it
is neither a pass nor a blocker, so the exit status is 11 unless another
claim blocks (10), and a report with only passing and `UNSUPPORTED` claims
exits 11. In a scope assessment the rule is applicable but not verified: the
aggregate is UNKNOWN with `UNSUPPORTED_COMBINATION`, or BLOCKED when another
rule blocks, and never a scope-complete pass. Human output adds a headline
line `N component combinations are outside their documented support range`.
A source that states a hard incompatibility is an ordinary blocking rule.

### Evidence bases and the trust policy

Every rule states how it was produced, and the basis limits what it may
decide:

| Basis | Produced by | May block | May pass |
| --- | --- | --- | --- |
| `reviewed` (or none) | a maintainer read the cited source | yes | yes |
| `mechanical` | a versioned extractor over pinned upstream source | yes | yes |
| `empirical` | the behaviour was reproduced with upstream artifacts | yes | yes |
| `consensus` | two independent model readings agree, every citation verified | yes | no |
| `lead` | one unverified model reading | no | no |

A `consensus` rule that would pass yields the claim `NO_KNOWN_ISSUE`
(`CONSENSUS_NO_KNOWN_ISSUE`). It is not a pass: the exit status is 11, and in a
scope assessment it is applicable but not verified, so the aggregate stays
UNKNOWN with `CONSENSUS_ONLY_SCOPE`. A `consensus` rule that would block
yields `BLOCKED` like any other. A `lead` that would block yields `NOTICE`
(`LEAD_NOT_VERIFIED`), printed as `unverified lead (does not block): <rule>`;
otherwise it yields `NO_KNOWN_ISSUE` (`LEAD_NO_KNOWN_ISSUE`) and prints
nothing. Leads never change an exit status or an aggregate, exactly like
one-way notices.

`check cncf --require-basis LIST` selects which bases are evaluated, as a
comma-separated subset of `reviewed,mechanical,empirical,consensus,lead`
without spaces. The default is `reviewed,mechanical,empirical,consensus`:
leads are left out unless listed. Rules of any other basis are left out when
the rule document is assembled, on every route and for embedded and external
knowledge alike. A report that left out rules carries
`trustPolicy: {requiredBasis, excludedRules, excludedLeadRules}` in JSON and a
`trust policy:` line in human output. When a verdict rule was left out the
check never exits 0 and a scope assessment loses its completeness
attestation, so it stays UNKNOWN; leaving out only leads changes no verdict.
An unknown or repeated token, or an empty list, is a usage error (exit 2).
Replay a report with the `--require-basis` it was made with. Human output
states `N findings rely on model consensus` when any finding does.
`check batch` has no `--require-basis`; it always uses the default policy.

The whole-upgrade aggregate remains UNKNOWN. No result in this release
authorizes a rollout or establishes full runtime, data, rollback or component
compatibility. The older `validate-prometheus-mode` command retains its
aggregate exit 11 for every completed assessment, including a scoped PASS.
The TiKV target-only report separately keeps aggregate backup readiness
`UNKNOWN` for every scoped result.

Unsupported versions, shapes, image identities, ambiguous declarations and
missing or stale evidence cannot produce an unsupported PASS. A removed-key
PASS says nothing about other Helm schema properties.

## Local execution and evidence

Evaluation requires no network, model, account or cluster permission. Reports
contain curated facts and digests rather than raw values or full objects.
Replay requires the original local inputs and the same recorded parameters;
a report alone cannot reconstruct omitted private input. Hashes bind content
but do not establish its independent authenticity.

Collection is optional and explicit. It reads Kubernetes APIs through a named
kubeconfig/context and may execute its credential helpers under the disclosed
environment policy. It never applies a proposed change. See
[local collection](local-collection.md) for permissions, retained fields and
omissions, and [data handling](data-handling.md) for the file boundary.

The source policy, complete selected tests and native execution evidence define
the release package. Research candidates, planned checks and previous package
lists do not expand the published CLI's capability or support contract.

Public project onboarding is a separate maintainer workflow. It can turn one
public GitHub repository URL into a private, locally verified snapshot of recent
release observations and commit-pinned changelog or license files. The explicit
`project sync` operation contacts GitHub; `init`, `verify`, `status`, `inspect`,
and `proposal` remain offline. A collected project does not change support
counts, evaluator inputs, result semantics, embedded rules, or signed knowledge
selection. See [public project onboarding](project-onboarding.md) and
[data handling](data-handling.md).

## Community contribution boundary

Local validation, optional minimized observations, public project source
snapshots, source provenance and replay are Community capabilities. New checks
need exact public source evidence,
independent expected outcomes and a falsifiable test. No model-generated text,
review flag or synthetic fixture can by itself authorize a safety claim.

Broader coverage and easier Helm/Kustomize input preparation remain future work.
Demand, time savings and adoption must be measured with real users.
