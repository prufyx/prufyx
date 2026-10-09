// SPDX-License-Identifier: AGPL-3.0-only

// Package customresources is the reviewed table of catalog projects whose
// CustomResourceDefinition manifests the crd.version-removal extractor
// reads, and of the API groups those manifests define. It is the one place
// that says which custom-resource group belongs to which project:
//
//   - the fact registry registers one custom-resource version set fact per
//     project of the table, and no other;
//   - the preparation attributes an object to a project only when its API
//     group is listed for exactly that project. A group the table does not
//     list, or lists for more than one project, is never attributed to any
//     project, by suffix, by name or otherwise.
//
// The table holds no versions and no rules: what a release serves is
// derived by the extractor and published only through the knowledge gate.
// A test pins the projects to the extractor's target table.
package customresources

import (
	"regexp"
	"sort"
	"strings"
)

// Group is one API group a project's CustomResourceDefinitions define, and
// the upstream manifest, pinned by full commit, that defines it.
type Group struct {
	Name   string
	Source string
}

// Project is one catalog project of the table.
type Project struct {
	// Slug is the catalog project slug.
	Slug string
	// FactProject is the project part of the fact id
	// component.<FactProject>.custom_resource_versions_set.
	FactProject string
	// Component is the catalog component identity the fact belongs to.
	Component string
	// Groups are the API groups of the project's CustomResourceDefinitions.
	Groups []Group
}

// FactID is the project's custom-resource version set fact.
func (p Project) FactID() string { return FactID(p.FactProject) }

// FactID is the custom-resource version set fact of a fact project.
func FactID(factProject string) string {
	return "component." + factProject + ".custom_resource_versions_set"
}

// table is the reviewed table, ordered by slug. Every source is the
// manifest whose spec.group line names the group, at the commit the
// extractor's paths were checked at.
//
// Shared groups: argoproj.io is defined upstream by Argo CD and by Argo
// Workflows, Rollouts and Events. The catalog project argo-cd is the whole
// Argo project, so the group is listed once, for argo-cd, and objects of the
// other Argo components (a Rollout, a Workflow) join argo-cd's set. That is
// harmless while rules name only Argo CD's own kinds. Listing argoproj.io for
// a second project would make it ambiguous: every argoproj.io object would
// then join no set and keep every set incomplete, so a removed Argo CD
// version would no longer block (a missed blocker, never a false pass).
// Before a second project shares a group, attribution must move to
// (group, kind), with kinds taken from the extractor inventory.
var table = []Project{
	{
		Slug: "antrea", FactProject: "antrea", Component: "pkg:github/antrea-io/antrea",
		Groups: []Group{
			{Name: "crd.antrea.io", Source: "https://github.com/antrea-io/antrea/blob/e59003c2c1b13a961ff58a6d7b8f1133049d0bf0/build/charts/antrea/crds/trafficcontrol.yaml"},
			{Name: "multicluster.crd.antrea.io", Source: "https://github.com/antrea-io/antrea/blob/e59003c2c1b13a961ff58a6d7b8f1133049d0bf0/multicluster/config/crd/bases/multicluster.crd.antrea.io_resourceimports.yaml"},
		},
	},
	{
		Slug: "argo-cd", FactProject: "argo_cd", Component: "pkg:github/argoproj/argo-cd",
		Groups: []Group{
			{Name: "argoproj.io", Source: "https://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/crds/application-crd.yaml"},
		},
	},
	{
		Slug: "cert-manager", FactProject: "cert_manager", Component: "pkg:github/cert-manager/cert-manager",
		Groups: []Group{
			{Name: "acme.cert-manager.io", Source: "https://github.com/cert-manager/cert-manager/blob/b8f325e36f49626ba72d7efbe138c01a5e661d96/deploy/crds/acme.cert-manager.io_orders.yaml"},
			{Name: "cert-manager.io", Source: "https://github.com/cert-manager/cert-manager/blob/b8f325e36f49626ba72d7efbe138c01a5e661d96/deploy/crds/cert-manager.io_issuers.yaml"},
		},
	},
	{
		Slug: "cilium", FactProject: "cilium", Component: "pkg:github/cilium/cilium",
		Groups: []Group{
			{Name: "cilium.io", Source: "https://github.com/cilium/cilium/blob/450c53145dc0a872ae20dfb05598c94ef55a71e2/pkg/k8s/apis/cilium.io/client/crds/v2alpha1/ciliumpodippools.yaml"},
		},
	},
	{
		Slug: "cloudnativepg", FactProject: "cloudnativepg", Component: "pkg:github/cloudnative-pg/cloudnative-pg",
		Groups: []Group{
			{Name: "postgresql.cnpg.io", Source: "https://github.com/cloudnative-pg/cloudnative-pg/blob/4b5e244a7d031f67e025c83c1555e7726ecbbfa1/config/crd/bases/postgresql.cnpg.io_subscriptions.yaml"},
		},
	},
	{
		Slug: "contour", FactProject: "contour", Component: "pkg:github/projectcontour/contour",
		Groups: []Group{
			{Name: "projectcontour.io", Source: "https://github.com/projectcontour/contour/blob/3635b068e25d74b7089c272eefd6ccb6a08f2861/examples/contour/01-crds.yaml"},
		},
	},
	{
		Slug: "crossplane", FactProject: "crossplane", Component: "pkg:github/crossplane/crossplane",
		Groups: []Group{
			{Name: "apiextensions.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/apiextensions.crossplane.io_usages.yaml"},
			{Name: "ops.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/ops.crossplane.io_watchoperations.yaml"},
			{Name: "pkg.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/pkg.crossplane.io_providers.yaml"},
			{Name: "protection.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/protection.crossplane.io_usages.yaml"},
			{Name: "secrets.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/2efdb03ae80fc27f4b6b9b0cebc96a462233cf17/cluster/crds/secrets.crossplane.io_storeconfigs.yaml"},
		},
	},
	{
		Slug: "dapr", FactProject: "dapr", Component: "pkg:github/dapr/dapr",
		Groups: []Group{
			{Name: "dapr.io", Source: "https://github.com/dapr/dapr/blob/7c4f540efa3e6f768a45010f2fc0d4b4c287cac3/charts/dapr/crds/workflowaccesspolicy.yaml"},
		},
	},
	{
		Slug: "external-secrets", FactProject: "external_secrets", Component: "pkg:github/external-secrets/external-secrets",
		Groups: []Group{
			{Name: "external-secrets.io", Source: "https://github.com/external-secrets/external-secrets/blob/9d17906e8e4c5532ffe513f72273df03b7b07bc6/config/crds/bases/external-secrets.io_secretstores.yaml"},
			{Name: "generators.external-secrets.io", Source: "https://github.com/external-secrets/external-secrets/blob/9d17906e8e4c5532ffe513f72273df03b7b07bc6/config/crds/bases/generators.external-secrets.io_webhooks.yaml"},
		},
	},
	{
		Slug: "istio", FactProject: "istio", Component: "pkg:github/istio/istio",
		Groups: []Group{
			{Name: "extensions.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "networking.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "security.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "telemetry.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
		},
	},
	{
		Slug: "karmada", FactProject: "karmada", Component: "pkg:github/karmada-io/karmada",
		Groups: []Group{
			{Name: "apps.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/apps/apps.karmada.io_workloadrebalancers.yaml"},
			{Name: "autoscaling.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/autoscaling/autoscaling.karmada.io_federatedhpas.yaml"},
			{Name: "config.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/config/config.karmada.io_resourceinterpreterwebhookconfigurations.yaml"},
			{Name: "networking.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/networking/networking.karmada.io_multiclusterservices.yaml"},
			{Name: "operator.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/operator/config/crds/operator.karmada.io_karmadas.yaml"},
			{Name: "policy.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/policy/policy.karmada.io_propagationpolicies.yaml"},
			{Name: "remedy.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/remedy/remedy.karmada.io_remedies.yaml"},
			{Name: "work.karmada.io", Source: "https://github.com/karmada-io/karmada/blob/6d7b233a54d59c8473803901768153f6e4353d02/charts/karmada/_crds/bases/work/work.karmada.io_works.yaml"},
		},
	},
	{
		Slug: "keda", FactProject: "keda", Component: "pkg:github/kedacore/keda",
		Groups: []Group{
			{Name: "eventing.keda.sh", Source: "https://github.com/kedacore/keda/blob/626ded5d783108bedf647e20bbc83f8e458e02e4/config/crd/bases/eventing.keda.sh_clustercloudeventsources.yaml"},
			{Name: "keda.sh", Source: "https://github.com/kedacore/keda/blob/626ded5d783108bedf647e20bbc83f8e458e02e4/config/crd/bases/keda.sh_triggerauthentications.yaml"},
		},
	},
	{
		Slug: "koordinator", FactProject: "koordinator", Component: "pkg:github/koordinator-sh/koordinator",
		Groups: []Group{
			{Name: "analysis.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/analysis.koordinator.sh_recommendations.yaml"},
			{Name: "config.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/config.koordinator.sh_clustercolocationprofiles.yaml"},
			{Name: "quota.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/quota.koordinator.sh_elasticquotaprofiles.yaml"},
			{Name: "scheduling.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/scheduling.koordinator.sh_scheduleexplanations.yaml"},
			{Name: "slo.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/slo.koordinator.sh_nodeslos.yaml"},
		},
	},
	{
		Slug: "kuma", FactProject: "kuma", Component: "pkg:github/kumahq/kuma",
		Groups: []Group{
			{Name: "kuma.io", Source: "https://github.com/kumahq/kuma/blob/51c6d3819be75d9587942242cdec709bc9934321/deployments/charts/kuma/crds/kuma.io_zones.yaml"},
		},
	},
	{
		Slug: "kyverno", FactProject: "kyverno", Component: "pkg:github/kyverno/kyverno",
		Groups: []Group{
			{Name: "kyverno.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/kyverno/kyverno.io_updaterequests.yaml"},
			{Name: "policies.kyverno.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/policies.kyverno.io/policies.kyverno.io_validatingpolicies.yaml"},
			{Name: "reports.kyverno.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/reports/reports.kyverno.io_ephemeralreports.yaml"},
			{Name: "wgpolicyk8s.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/policyreport/wgpolicyk8s.io_policyreports.yaml"},
		},
	},
	{
		Slug: "longhorn", FactProject: "longhorn", Component: "pkg:github/longhorn/longhorn",
		Groups: []Group{
			{Name: "longhorn.io", Source: "https://github.com/longhorn/longhorn/blob/c3d88832bd8cec4f38dec65e79436984871dc313/deploy/longhorn.yaml"},
		},
	},
	{
		Slug: "metallb", FactProject: "metallb", Component: "pkg:github/metallb/metallb",
		Groups: []Group{
			{Name: "metallb.io", Source: "https://github.com/metallb/metallb/blob/4c613e152c3434f71137b5f2a2ce15ee93681606/config/crd/bases/metallb.io_servicel2statuses.yaml"},
		},
	},
	{
		Slug: "openkruise", FactProject: "openkruise", Component: "pkg:github/openkruise/kruise",
		Groups: []Group{
			{Name: "apps.kruise.io", Source: "https://github.com/openkruise/kruise/blob/b1e001a957ce62bf87894d0212f5e704a8e9c2b4/config/crd/bases/apps.kruise.io_workloadspreads.yaml"},
			{Name: "policy.kruise.io", Source: "https://github.com/openkruise/kruise/blob/b1e001a957ce62bf87894d0212f5e704a8e9c2b4/config/crd/bases/policy.kruise.io_podunavailablebudgets.yaml"},
		},
	},
	{
		Slug: "rook", FactProject: "rook", Component: "pkg:github/rook/rook",
		Groups: []Group{
			{Name: "ceph.rook.io", Source: "https://github.com/rook/rook/blob/f190ca3b45f131da03641741e9e03b2584cd7d5e/deploy/examples/crds.yaml"},
			{Name: "objectbucket.io", Source: "https://github.com/rook/rook/blob/f190ca3b45f131da03641741e9e03b2584cd7d5e/deploy/examples/crds.yaml"},
		},
	},
	{
		Slug: "strimzi", FactProject: "strimzi", Component: "pkg:github/strimzi/strimzi-kafka-operator",
		Groups: []Group{
			{Name: "core.strimzi.io", Source: "https://github.com/strimzi/strimzi-kafka-operator/blob/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator/042-Crd-strimzipodset.yaml"},
			{Name: "kafka.strimzi.io", Source: "https://github.com/strimzi/strimzi-kafka-operator/blob/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator/040-Crd-kafka.yaml"},
		},
	},
	{
		Slug: "tekton", FactProject: "tekton", Component: "pkg:github/tektoncd/pipeline",
		Groups: []Group{
			{Name: "resolution.tekton.dev", Source: "https://github.com/tektoncd/pipeline/blob/61e02215132ce7bef054ff7e1fb074f217716c1a/config/300-crds/300-resolutionrequest.yaml"},
			{Name: "tekton.dev", Source: "https://github.com/tektoncd/pipeline/blob/61e02215132ce7bef054ff7e1fb074f217716c1a/config/300-crds/300-verificationpolicy.yaml"},
		},
	},
	{
		Slug: "velero", FactProject: "velero", Component: "pkg:github/velero-io/velero",
		Groups: []Group{
			{Name: "velero.io", Source: "https://github.com/velero-io/velero/blob/6adcf06b5b0e6fb93998d3e101e2cbdc134fa3c3/config/crd/v1/bases/velero.io_volumesnapshotlocations.yaml"},
		},
	},
	{
		Slug: "volcano", FactProject: "volcano", Component: "pkg:github/volcano-sh/volcano",
		Groups: []Group{
			{Name: "batch.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/batch.volcano.sh_jobs.yaml"},
			{Name: "bus.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/bus.volcano.sh_commands.yaml"},
			{Name: "config.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/config.volcano.sh_colocationconfigurations.yaml"},
			{Name: "flow.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/jobflow/bases/flow.volcano.sh_jobtemplates.yaml"},
			{Name: "nodeinfo.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/nodeinfo.volcano.sh_numatopologies.yaml"},
			{Name: "scheduling.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/scheduling.volcano.sh_queues.yaml"},
			{Name: "shard.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/shard.volcano.sh_nodeshards.yaml"},
			{Name: "topology.volcano.sh", Source: "https://github.com/volcano-sh/volcano/blob/8fc394c11e8db0d0ada5c17816b58bced9d7213d/config/crd/volcano/bases/topology.volcano.sh_hypernodes.yaml"},
		},
	},
}

// Projects returns a copy of the reviewed table, ordered by slug.
func Projects() []Project { return copyProjects(table) }

// ProjectFor returns the table entry of a catalog slug.
func ProjectFor(slug string) (Project, bool) {
	for _, p := range table {
		if p.Slug == slug {
			return copyProjects([]Project{p})[0], true
		}
	}
	return Project{}, false
}

func copyProjects(in []Project) []Project {
	out := make([]Project, len(in))
	for i, p := range in {
		out[i] = p
		out[i].Groups = append([]Group(nil), p.Groups...)
	}
	return out
}

// KubernetesGroup reports whether an API group is a Kubernetes group: the
// core group (empty), any group without a dot (apps, batch, policy, ...)
// and every group ending in ".k8s.io". Every other group is a custom
// resource group. Scan's served-API check covers exactly the Kubernetes
// groups, so every group is covered by one of the two.
func KubernetesGroup(group string) bool {
	return !strings.Contains(group, ".") || strings.HasSuffix(group, ".k8s.io")
}

// GroupOf returns the API group of an apiVersion ("" for "v1").
func GroupOf(apiVersion string) string {
	group, _, found := strings.Cut(apiVersion, "/")
	if !found {
		return ""
	}
	return group
}

// Attribution says whether a custom resource group belongs to a project.
type Attribution int

const (
	// Unknown: no project of the table lists the group.
	Unknown Attribution = iota
	// Owned: exactly one project lists the group.
	Owned
	// Ambiguous: more than one project lists the group.
	Ambiguous
)

// Index attributes custom resource groups to projects.
type Index struct {
	owners map[string][]string
}

// NewIndex indexes a table. A group listed by two projects is ambiguous,
// never attributed to either.
func NewIndex(projects []Project) Index {
	owners := map[string][]string{}
	for _, p := range projects {
		for _, g := range p.Groups {
			if !containsString(owners[g.Name], p.Slug) {
				owners[g.Name] = append(owners[g.Name], p.Slug)
			}
		}
	}
	for _, slugs := range owners {
		sort.Strings(slugs)
	}
	return Index{owners: owners}
}

// DefaultIndex indexes the reviewed table.
func DefaultIndex() Index { return NewIndex(table) }

// Owner returns the project a group belongs to. Only an exact, listed,
// unambiguous group is Owned; the slug is empty otherwise.
func (x Index) Owner(group string) (string, Attribution) {
	slugs := x.owners[group]
	switch len(slugs) {
	case 0:
		return "", Unknown
	case 1:
		return slugs[0], Owned
	}
	return "", Ambiguous
}

func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

var (
	slugRE        = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	factProjectRE = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	groupRE       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	sourceRE      = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/blob/[0-9a-f]{40}/[A-Za-z0-9_./-]+\.ya?ml$`)
)

// Validate checks a table: slugs ascending and unique, well-formed fact
// projects and components, and every group a custom resource group, named
// once per project, with a source pinned by full commit SHA.
func Validate(projects []Project) bool {
	for i, p := range projects {
		if !slugRE.MatchString(p.Slug) || !factProjectRE.MatchString(p.FactProject) || !strings.HasPrefix(p.Component, "pkg:github/") || len(p.Groups) == 0 {
			return false
		}
		if i > 0 && projects[i-1].Slug >= p.Slug {
			return false
		}
		for j, g := range p.Groups {
			if len(g.Name) > 253 || !groupRE.MatchString(g.Name) || KubernetesGroup(g.Name) || !sourceRE.MatchString(g.Source) {
				return false
			}
			if j > 0 && p.Groups[j-1].Name >= g.Name {
				return false
			}
		}
	}
	return true
}
