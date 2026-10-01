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
