# Data handling

The Community evaluator runs locally. It does not contact Prufyx, invoke a model,
upload a report or require an account. Obtaining the source, compiler, release
assets and upstream references is separate from offline evaluation.

## Public project source onboarding

The optional [public project onboarding workflow](project-onboarding.md) keeps
evaluation offline while adding one explicit network operation:
`prufyx-maintainer project sync`. Sync contacts only GitHub's public API and raw
content host for the repository, recent-release limit, optional tag prefix,
optional public changelog paths, and bounded built-in license filenames. GitHub
sees the public repository names and ordinary connection data such as IP address
and timing. Prufyx receives no request, account identifier, configuration, or
telemetry.

The private local snapshot retains public GitHub release bodies, normalized
release and tag observations, commit-pinned public repository files, content
digests, and receipts. Those bytes are untrusted data: onboarding does not run,
build, render, extract, or send them to a model. Offline `project verify`,
`status`, `inspect`, and `proposal` commands make no network request. A public
proposal contains only repository and immutable-source references, generated
hashes, bounded declarations, and license or attribution references; it excludes
the retained bodies and object store.

Project onboarding requests and proposals reject customer configuration, cluster
objects, credentials, Secrets, logs, private paths, non-public proprietary
source, and production data. Sync may retain publicly served repository bytes
whose license is still unknown or restrictive; that state remains unreviewed and
raw bytes are excluded from the public proposal. The workflow does
not infer repository ownership, foundation membership, component identity,
license permission, maintainer approval, or compatibility. Captured objects are
private evidence inputs, not client knowledge targets or training authorization.

## Proposed files and reports

Provide an exact local JSON artifact. The cert-manager check takes already
merged proposed Helm values; it does not fetch Helm release Secrets or merge
overrides. The Prometheus check takes a proposed workload JSON artifact. These
files may contain information beyond the recognized predicates and remain under
the operator's control.

The parsers enforce bounded input and strict JSON. Reports retain curated setting
identities, projected predicates, version and source identities, hashes, scoped
results and remediation. They omit raw values, command lines, environment values,
unknown user-supplied setting names and local input paths. Generic input failures
do not echo the rejected document.

Hashes are content identifiers, not anonymization or proof of a trusted origin.
Identical input can produce an identical digest. Keep original artifacts locally
when replay is required and review a report before choosing to share it.

The SPIFFE X.509-SVID subset accepts one private local DER certificate or PEM
certificate block. It minimizes the parsed certificate to four typed
predicates. Its report and knowledge store exclude certificate bytes, subject,
URI, host, path, input file path and raw certificate digest. The optional
current raw digest and mandatory replay raw digest are caller-side byte pins;
they are never an identity or trust-chain proof. See the
[named conformance guide](spiffe-x509-svid.md).

The CloudEvents structured JSON subset accepts one private native JSON event.
It retains only staged typed predicates for root admission, edition, required
core strings, and mutually exclusive payload members. Reports and stores
exclude raw event bytes, input path, raw digest, and caller-supplied member
names and values. Nested payload and extension data is syntax-checked but
semantically opaque. The optional current raw digest and mandatory replay raw
digest remain caller-side byte pins. See the [CloudEvents conformance
guide](cloudevents-structured-json.md).

The TiKV target preflight accepts one private native TOML configuration that
the operator supplies as the intended TiKV configuration for a declared GCS
WIF full-backup plan. It parses the complete TOML document but retains only a
covered/unsupported target class, a reviewed-operation Boolean, and the one
unambiguous explicit backup setting Boolean when available. Reports and stores
exclude raw TOML, its path and raw digest, comments, unrelated keys and values,
addresses, endpoints, buckets and credentials. The optional current raw digest
and mandatory replay raw digest remain caller-side byte pins. See the [TiKV
target preflight guide](tikv-gcp-v2-wif-backup.md).

## Optional offline knowledge database

The unreleased [CNCF preview](CNCF-SOURCE-PREVIEW.md) accepts only minimized local
operator declarations: public component identities, numeric versions and
compiled boolean or finite-enum facts. It rejects unknown fields, arbitrary
configuration strings and raw argument arrays. Parsing those declarations does
not establish cluster observation. Input and replay files require private mode
0600, bounded regular-file reads and no symlinks or hardlinks. Reports retain
input hashes and public rule evidence; the CLI does not echo rejected input or
local paths. Evaluation reads no network endpoint and persists no input file.
Its generic rule pack is embedded by default. An explicit signed CNCF selection
uses the same minimized input and a separate local store from cert-manager.

Optional `prepare cncf` reads a private proposed Kyverno Pod or Deployment JSON
and derives a single registered flag-presence declaration. Linkerd preparation
reads one private MeshTLSAuthentication JSON resource and derives only the
closed selector-emptiness fact. Karmada preparation reads one private
policy.karmada.io/v1alpha1 PropagationPolicy or ClusterPropagationPolicy JSON
resource and can witness an explicit legacy `Immediately` or `Graciously`
purge-mode value; a singleton resource never proves absence or produces PASS.
All three emit only closed minimized facts and retain no raw workload names, image
reference, arguments, environment values, configuration, or resource content in
the output. The declared version endpoints come from the operator; preparation
does not authenticate an image, validate a CRD, observe a cluster, or contact a
network. The source digest binds the exact private file, and the input digest
binds the exact minimized output, including its trailing newline. Both are
ordinary content hashes. Missing, ambiguous, unsupported, or unknown invocations
remain unresolved, and preparation does not run a compatibility check, invoke a
model, or persist a file.

The unreleased external knowledge paths read only an explicitly named local
package, bootstrap root on first use, private database directory, and private
values file or minimized CNCF input. Evaluation and import have no upload path.
The separate, explicit [`db update`](knowledge-updates.md) command fetches a
complete package from an operator-selected HTTPS URL. It accepts no evaluation
input and sends no configuration, report, local path, input digest or component
selection. It has no account, stable installation identifier or telemetry.
The package host sees ordinary connection information, including IP and timing.
There is no configured Prufyx feed or automatic startup refresh.
Each database retains verified
public TUF metadata, public knowledge targets, trust receipts, rollback and clock
floors, and the selected revision identity. It does not retain the proposed
values bytes, CNCF input bytes, TiKV TOML bytes, filename, local path, raw input
digest, or unrecognized values fields.
Package and parser bounds apply per import. This slice does not provide
automatic garbage collection or a total database-size cap.

An external report records the operator-provisioned trust source, knowledge
purpose, revision, bundle and rule digests, TUF role receipt, evidence freshness,
evaluation time, and build identity. `synthetic_test_only` remains visible in
status and reports. Historical replay contains the exact original safe report
and states that current non-revocation was not checked offline. See the
[cert-manager database guide](knowledge-database.md) and
[CNCF database guide](cncf-knowledge-database.md) for the package and replay
contracts. An external signature authenticates a package under the chosen root;
it does not establish source correctness, maintainer review or runtime evidence.

## Optional Kubernetes collection

Collection requires an explicit kubeconfig and named context. The read-only
collector uses local kubectl and the operator's credential-helper configuration;
it does not run inside the cluster. Explicit acknowledgement of that helper
execution boundary is required. HOME and the trusted executable search path
remain local configuration boundaries. Additional environment forwarding is
explicit; an ambient proxy is not silently bypassed.

Raw objects are projected locally before output is retained. Private image paths,
workload names, raw commands, environment values, credentials, Secrets and
ConfigMap contents are omitted. Collection adds no write permissions and does
not execute commands in Pods. Exact resources and disclosed retained fields are
listed in [local collection](local-collection.md).

Context pseudonyms use a random per-run key that is discarded. Repeated contexts
within that collection can match; a new collection gets new pseudonyms. These
identifiers do not authenticate cluster identity. Replaying the same admitted
observation still produces the same result for the same evaluation parameters.

The optional collector communicates with the selected Kubernetes API and any
configured credential-helper service. That is distinct from the offline
evaluator, which makes no such connections. No Prufyx upload is part of either
workflow.
