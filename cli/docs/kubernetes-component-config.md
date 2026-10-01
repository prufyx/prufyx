# Kubernetes component configuration check

This route checks local Kubernetes component configuration against reviewed
rules for settings a Kubernetes minor release removed: command-line flags,
feature gates, component configuration file versions and values, admission
plugins, in-tree cloud providers, and a small set of pod-specification fields
(in-tree volume sources, alpha seccomp annotations, static-pod API references).
It never contacts a cluster or runs a component. It reads only the local files
you list, keeps none of their paths, argument values or contents, and evaluates
only rules that a maintainer has published for the minor line the transition
crosses. With no published rule for that line the result is `UNKNOWN`.

```sh
prufyx check cncf --project kubernetes --component-config selection.yaml \
  --from 1.23.17 --to 1.24.0 --distribution official_upstream \
  --now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" [--component-config-digest SHA256] \
  [--format human|json]
```

Exit codes follow every other check: `10` when a reviewed rule is `BLOCKED`,
`0` when every evaluated rule is `PASS`, `11` when anything stays `UNKNOWN`
(including when no rule exists for the transition), `2` for invalid input and
`3` for an integrity failure. The aggregate whole-upgrade assessment is always
`UNKNOWN`.

## Selection document

The selection document and every file it names must be regular files with
mode `0600`, at most 1 MiB each, named by absolute, clean paths with no
symbolic link. JSON is accepted wherever YAML is.

```yaml
apiVersion: prufyx.io/kubernetes-component-config/v1alpha1
kind: ComponentConfigSelection
# Scopes whose listed sources are every source of that scope's arguments and
# configuration, on every node or instance in the target environment.
complete: [kube-apiserver, kube-controller-manager, kube-scheduler, kubelet, kube-proxy, kubeadm, static-pods, workloads]
declarations:
  linuxNodeCgroupV1: false   # optional: does any Linux node use cgroup v1?
  # kubeletNoConfigFile: true  # optional: no kubelet uses --config
  # kubeletNoConfigDir: true   # optional: no kubelet uses --config-dir
sources:
- {scope: kube-apiserver, format: pod-manifest, path: /abs/kube-apiserver.yaml, staticPod: true}
- {scope: kube-controller-manager, format: pod-manifest, path: /abs/kube-controller-manager.yaml, staticPod: true}
- {scope: kube-scheduler, format: pod-manifest, path: /abs/kube-scheduler.yaml, staticPod: true}
- {scope: kube-scheduler, format: scheduler-config, path: /abs/scheduler-config.yaml}
- {scope: kubelet, format: kubelet-env, path: /abs/kubeadm-flags.env}
- {scope: kubelet, format: kubelet-config, path: /abs/kubelet-config.yaml}
- {scope: kube-proxy, format: pod-manifest, path: /abs/kube-proxy-daemonset.yaml}
- {scope: kube-proxy, format: kube-proxy-config, path: /abs/kube-proxy-configmap.yaml}
- {scope: kubeadm, format: kubeadm-config, path: /abs/kubeadm.yaml}
- {scope: static-pods, format: pod-manifest, path: /abs/etcd.yaml}
- {scope: workloads, format: manifests, path: /abs/rendered.yaml, digest: "sha256:..."}
```

### Kubelet configuration files

On kubeadm nodes `--config` is set in the systemd drop-in
(`KUBELET_CONFIG_ARGS`), not in `kubeadm-flags.env`, so an environment file
that names no `--config` does not show that the kubelet reads no configuration
file. Facts that read kubelet configuration (the memory swap behaviour,
feature gates, `failCgroupV1`) are therefore unknown unless one of these holds:

- a `kubelet-config` source (or a KubeletConfiguration embedded in a supplied
  kubeadm document) is listed; or
- `declarations.kubeletNoConfigFile: true` states that no kubelet uses a
  configuration file; or
- the kubelet scope lists no source at all and is declared `complete`.

When the kubelet arguments name `--config-dir`, those facts are also unknown
unless at least one `kubelet-dropin` source is listed, or
`declarations.kubeletNoConfigDir: true` states that no kubelet uses a drop-in
directory. A declaration contradicted by a named `--config` or `--config-dir`,
or by a listed source, is treated as unresolved. Facts that read only
command-line options are unaffected.

A scope listed in `complete` with no sources declares that the scope has no
arguments or configuration at all, for example `kube-proxy` on a cluster that
does not run kube-proxy. Declare completeness only when it is true: it is the
one statement that lets absence become `PASS`.

A source may carry `digest` to pin its exact bytes; a mismatch is an integrity
failure. `--component-config-digest` pins the selection document itself.

| Scope | Formats |
|---|---|
| `kube-apiserver` | `pod-manifest`, `args`, `admission-config` |
| `kube-controller-manager` | `pod-manifest`, `args` |
| `kube-scheduler` | `pod-manifest`, `args`, `scheduler-config` |
| `kubelet` | `kubelet-env`, `args`, `kubelet-config`, `kubelet-dropin` |
| `kube-proxy` | `pod-manifest`, `args`, `kube-proxy-config` |
| `kubeadm` | `kubeadm-config` |
| `static-pods` | `pod-manifest` |
| `workloads` | `manifests` |

Formats:

- `pod-manifest`: one v1 Pod, or an apps/v1 DaemonSet, Deployment or
  StatefulSet. Exactly one container must have an explicit `command` whose
  first element is the component binary (`kube-apiserver` or a path ending in
  it); its remaining command and `args` are the component arguments. With
  `staticPod: true`, or under the `static-pods` scope, the manifest (a v1 Pod)
  is also a static pod for the field-level checks.
- `args`: a flat YAML or JSON list of argument strings, without the binary.
- `kubelet-env`: an environment file such as `kubeadm-flags.env`,
  `/etc/default/kubelet` or `/etc/sysconfig/kubelet`. Every assigned value is
  split on whitespace. Shell expansion (`$`, backticks, backslashes, nested
  quotes) leaves the file unresolved.
- `kubelet-config`, `kube-proxy-config`, `scheduler-config`: the component's
  configuration document, or, for the kubelet and kube-proxy, the v1 ConfigMap
  that carries it (`data.kubelet`, `data["config.conf"]`). Several documents
  may be listed.
- `kubelet-dropin`: one file of the directory named by the kubelet's
  `--config-dir`, a KubeletConfiguration fragment. List every file of the
  directory, one source each.
- `admission-config`: an AdmissionConfiguration, or a standalone webhook
  admission configuration that one of its plugins loads by `path`.
- `kubeadm-config`: kubeadm documents (`kubeadm.k8s.io` v1beta1 to v1beta4),
  optionally with embedded KubeletConfiguration and KubeProxyConfiguration, or
  the `kubeadm-config` ConfigMap. `extraArgs` and `kubeletExtraArgs` are read as
  a string map up to v1beta3 and as a `name`/`value` list from v1beta4; the
  other form for a version leaves the file unresolved. They add to the
  kube-apiserver, kube-controller-manager, kube-scheduler and kubelet scopes.
- `manifests`: rendered manifests, multi-document YAML or a v1 List. Pod
  specifications are found at any depth (Pods, workload templates, CronJob job
  templates, and custom resources that embed a pod template).

## How a result is decided

Each reviewed predicate yields one fact:

- **present** (rule `BLOCKED`) when any supplied source shows the removed
  setting, even if other sources are missing;
- **absent** (rule `PASS`) only when every scope the predicate reads is listed
  in `complete` and every source in those scopes was fully understood;
- **unknown** (rule `UNKNOWN`) otherwise.

A missing source is never read as absence. In particular:

- Flags are matched by long-option name after normalising `_` to `-`
  (`--flag`, `--flag=value`, `--flag value`). Every token is examined. A bare
  `--` or `-`, templating markers (`{{`, `${`), YAML anchors, aliases or custom
  tags, and keys that differ from the expected spelling only by case leave the
  source unresolved. A value containing `$(VAR)` is decided at runtime and is
  unknown.
- Feature gates are read from `--feature-gates` and from `featureGates` in
  kubelet and kube-proxy configuration. A removed gate is rejected by every
  Kubernetes component, so absence needs all five component scopes complete.
- When a component's arguments name `--config` (or the API server's
  `--admission-control-config-file`) and no configuration document was
  supplied for it, predicates over that configuration stay unknown.
- Predicates that a kubelet gate can switch back (gitRepo volumes in 1.33,
  static-pod API references in 1.34) block only when the kubelet scope is
  complete and no kubelet source sets that gate; a gate set anywhere leaves
  the result unknown, because the selection does not map kubelet settings to
  the nodes that run the pods.
- The cgroup v1 predicate (1.35) needs `declarations.linuxNodeCgroupV1`.
  `false` passes. `true` blocks when a kubelet source sets `failCgroupV1` (or
  `--fail-cgroupv1`) to true, or when the kubelet scope is complete and no
  source overrides it; it passes when every occurrence sets it to `false` and
  the kubelet scope is complete. An undeclared node fact stays unknown.
- `--distribution` other than `official_upstream` keeps every fact unknown:
  vendor builds may keep removed settings.

Managed control planes usually hide API server, controller manager and
scheduler arguments. Leave those scopes out of `complete`; their rules then
stay `UNKNOWN` unless a supplied source shows a removed setting.

## Limits

The check does not start a component, validate configuration beyond the
reviewed predicates, follow files a configuration references, resolve systemd
unit precedence, read secrets or kubeconfig files, or establish that an
upgrade is safe. Paths, argument values and raw documents are minimized out;
the report carries only the evaluated facts, rule identifiers, and pinned
upstream sources. External knowledge selection (`--knowledge-db`) and replay
are not available for this route yet.
