# Local kubeconfig collection

`prufyx-collector collect` creates a local, unsigned observation for
one or more explicitly selected kubeconfig contexts. Collection is optional,
read-only, and does not install or change cluster resources.

The supported collector is a native Go executable on macOS or Linux. Its only
runtime command dependency is the caller-trusted `kubectl` executable. It does
not invoke Python, jq, or a shell projection pipeline. Build it from a reviewed
source checkout with `cd cli && go build -o bin/prufyx-collector ./cmd/prufyx-collector`,
or use the matching packaged executable. The kubeconfig must be a regular,
non-symlink file owned by the invoking user with no group or other permission
bits. Before any `kubectl` call, the collector opens it through no-follow
descriptors, validates the opened file, and makes one private temporary
snapshot outside the observation directory. Every collector command receives
that one snapshot; it is removed before the observation is finalized. To
preserve that relocation safely, credential and certificate file references
(`certificate-authority`, `client-certificate`, `client-key`, and `tokenFile`)
must be absolute. Relative exec command paths and `auth-provider` blocks are
rejected. Bare exec program names retain their existing `PATH` lookup behavior,
while absolute exec command paths are accepted. This is a bounded input guard,
not a claim that the collector validates the entire kubeconfig or its referenced
files. A v3 collection can be
run as follows; replace the paths and context with local values, and add
`--exec-env NAME` only for variables the reviewed auth plugin requires.

```sh
cli/bin/prufyx-collector collect /secure/output \
  --kubeconfig /secure/kubeconfig \
  --acknowledge-kubeconfig-exec-risk \
  --include-component-configuration \
  --component-configuration-profile v3 \
  reviewed-context
```

The compatibility script `cli/scripts/kubeconfig-api-snapshot.sh` only locates
the native executable (or uses `go run` in a source checkout) and forwards its
arguments. New automation should invoke `prufyx-collector` directly.

Persisted collector `*Digest` fields identify canonical, versioned behavioral
contracts for the native JSON validator, kubectl runner, and projection stages.
They are not source-file or executable hashes; source review and packaged
binary provenance bind those artifacts separately. The observation importer
admits the closed `crd-pagination-policy-v2-go` identity while retaining the
earlier policy identity for historical observations.

The collector stores exact registry-bound public component summaries for every
workload projection. Unrecognized and private workload image references,
commands, arguments, environment values, object names, namespaces, and raw API
objects are not written, including to intermediate files. The legacy raw-image
diagnostic output is no longer produced. Current-bundle evaluation consumes the
typed public component summaries.

`--include-pod-status-images` adds the declared Pod read without changing that
privacy boundary. A recognized reference with strict public version syntax is
reduced to a typed component/version summary. Other image identities use the
fixed `PRIVATE_IMAGE_IDENTITY_OMITTED` marker. Runtime image IDs reduce to a
boolean that says whether the ID independently binds to the same public
component; the raw reference and digest are not retained.

The declared API read footprint is fixed. All collection uses GET or LIST:

| Mode | Kubernetes API requests | Retained projection |
| --- | --- | --- |
| Always | `/version`, `/api`, `/apis`; Nodes; Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs, CronJobs, ReplicationControllers; paginated CustomResourceDefinitions; APIServices; mutating and validating webhook configurations; validating admission policies and bindings; StorageClasses; CSIDrivers; RuntimeClasses | Bounded version, architecture, public component/version, API capability, admission-rule, storage, CSI, and runtime-class fields described in `snapshot-metadata.json`; raw objects and names are discarded |
| `--include-pod-status-images` | Pods across all namespaces | Typed public component/version summaries, a same-component image-ID binding boolean, scope class, and aggregate ready/restart counts; raw Pod/image/image-ID values are discarded |
| `--include-component-configuration` | Workloads with registered public component identities; after an exact cert-manager workload match, ClusterRoles, Roles, RoleBindings, ClusterRoleBindings, Deployments, Services and Pods, ServiceMonitors, and PodMonitors | Typed public component/version and bounded command projections; cert-manager-specific CRD, admission, RBAC, health-count, monitor-presence, and install-mode predicates when its workload match gates the extra reads; names, subjects, labels, selectors, commands, and raw values are discarded |

The component-configuration opt-in first reduces already-read workloads through
the selected public adapter registry. An exact cert-manager workload match is
then the gate for the additional cert-manager RBAC, health, Service/Pod, and
monitor reads shown above. The opt-in is not limited to cert-manager: Prometheus,
Argo, Cilium, and other registered public component identities can produce their
allow-listed projections.

The v2 and v3 component profiles use the same API resources. The v2 preserves the
existing flag-projection semantics. V3 changes the source-bound declared
entrypoint/command interpretation for registered v3 adapters, including the
Prometheus Agent-mode predicates used by [`prometheus-mode.md`](prometheus-mode.md).
Select it explicitly with `--include-component-configuration --component-configuration-profile v3`;
it does not add another API request.
Unsupported APIs and denied or failed requests become bounded omissions and
leave dependent evaluation UNKNOWN. They are not converted into successful or
absent observations.

Each observation run creates an in-memory 256-bit random key. A context is
represented as a domain-separated HMAC-SHA256 pseudonym using that key while
preserving the existing `sha256:<hex>` transport grammar. Repeated occurrences
of the same context match within one run. The key is discarded and never
printed or written, so separate collections intentionally produce unlinkable
context values. Replay means reevaluating the same captured observation bytes;
it does not mean reproducing the context pseudonym in a later collection.

Kubectl and kubeconfig exec plugins receive a closed process environment. The
collector forwards `PATH`, `HOME`, `USER`, and `TMPDIR` when present, and
supplies a fixed C locale and sets `KUBECONFIG` to point to a verified private
snapshot of the accepted kubeconfig bytes. `PATH` and `HOME`
remain part of the trusted local exec-plugin boundary. Forward any additional
required variable by repeating `--exec-env NAME`; only a variable that existed
in the invoking environment can be selected, and its value is never printed or
stored by the collector. Common examples are `CLOUDSDK_CONFIG`,
`GOOGLE_APPLICATION_CREDENTIALS`, `AWS_PROFILE`, `AWS_CONFIG_FILE`,
`AWS_SHARED_CREDENTIALS_FILE`, and `AZURE_CONFIG_DIR`.

Ambient proxy variables are not discarded silently. If `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, or a lowercase equivalent is present,
the collector refuses before creating an observation unless that exact name is
selected with `--exec-env`. Loader and shell-control variables such as
`BASH_ENV`, `LD_PRELOAD`, `DYLD_*`, and all `PYTHON*` variables cannot be
forwarded.

These controls do not authenticate `kubectl`, an exec plugin, `PATH` contents,
or files referenced by the kubeconfig. Review those local inputs and use a
least-privilege read-only cluster identity before collection. The v3 component
profile adds no Kubernetes API read beyond the opt-in request set above.
