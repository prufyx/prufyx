# Kubernetes distribution versions

Prufyx can turn a distribution's version string into the upstream Kubernetes
version it is built on. Only the formats below are accepted. Anything else is
rejected; Prufyx does not guess.

| Distribution | Accepted format | Example | Needs a declared distribution? |
| --- | --- | --- | --- |
| `official_upstream` | `v1.N.P` or `1.N.P` | `v1.29.3` | no (default for a bare version) |
| `kubeadm` | same as upstream | `v1.29.3` | yes |
| `talos` | same as upstream | `v1.29.3` | yes |
| `aks` | `1.N.P` or `v1.N.P` | `1.29.4` | yes |
| `eks` | `v1.N.P-eks-<7 lowercase hex>` | `v1.29.3-eks-adc7111` | no |
| `gke` | `1.N.P-gke.<build>` (optional `v`, as the API server reports it) | `1.29.3-gke.1093000` | no |
| `k3s` | `v1.N.P+k3s<n>` | `v1.29.4+k3s1` | no |
| `rke2` | `v1.N.P+rke2r<n>` | `v1.29.4+rke2r1` | no |
| `openshift` | `4.M` or `4.M.P` | `4.16.3` | yes |

Rules:

- Numbers are plain decimals without leading zeros (`v1.029.3` is rejected)
  and at most six digits; build and release numbers (`<build>`, `<n>`) must be
  at least 1 and at most nine digits.
- Pre-release or build suffixes that are not in the table (`-rc.1`, `+meta`)
  are rejected, as are incomplete markers such as `v1.29.3-eks`, `+k3s` or
  `+rke2r`.
- If a distribution is declared and the string clearly belongs to another one
  (for example `v1.29.4+k3s1` declared as `rke2`), the result is an error.
  A bare version declared as `eks`, `gke`, `k3s` or `rke2` is also an error,
  because those distributions are recognised by their suffix.
- OpenShift versions are mapped to a Kubernetes minor through a built-in
  table. If the OpenShift minor is not in the table the result is "unknown",
  and the patch version of Kubernetes is never reported for OpenShift.

Each successful result reports the distribution, the raw string, the upstream
version and how it was derived: `exact` (the string identifies itself),
`declared` (the distribution came from your declaration) or `mapped`
(OpenShift table).
