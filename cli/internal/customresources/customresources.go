// SPDX-License-Identifier: AGPL-3.0-only

// Package customresources is the reviewed table of projects whose
// CustomResourceDefinition manifests the crd.version-removal extractor
// reads, and of the API groups those manifests define. A project is either
// a project of the embedded CNCF landscape catalog or a community project:
// a project outside that catalog, listed here with its reviewed upstream
// provenance (repository and licence) and never described as a CNCF
// project. It is the one place that says which custom-resource group
// belongs to which project:
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

// Catalog names the catalog a project of the table belongs to.
type Catalog string

const (
	// CatalogCNCF: a project of the embedded CNCF landscape catalog,
	// whose identity that catalog carries.
	CatalogCNCF Catalog = "cncf"
	// CatalogCommunity: a project outside the CNCF landscape catalog. Its
	// identity is the reviewed Upstream record of this table, and nothing
	// about it asserts CNCF status. Its version set fact is registered,
	// but no rule, line review or check route reads it until the
	// community knowledge step (rules of community projects in the pack,
	// community targets in the knowledge store) lands.
	CatalogCommunity Catalog = "community"
)

// Upstream is the reviewed provenance of a community project: its public
// name, the upstream repository its component names, and the licence of
// that repository, cited from the licence file at a full commit.
type Upstream struct {
	Name          string
	Repository    string
	License       string
	LicenseSource string
}

// Project is one project of the table.
type Project struct {
	// Slug is the catalog project slug: a CNCF landscape catalog slug, or
	// for a community project a slug that is not one.
	Slug string
	// Catalog is the catalog the project belongs to.
	Catalog Catalog
	// Upstream is the provenance of a community project; it is empty for
	// a CNCF catalog project.
	Upstream Upstream
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

// Community reports whether the project is a community project (outside
// the CNCF landscape catalog).
func (p Project) Community() bool { return p.Catalog == CatalogCommunity }

// Label is the user-facing catalog label of the project.
func (p Project) Label() string {
	if p.Community() {
		return CommunityLabel
	}
	return "CNCF catalog"
}

// CommunityLabel is how every user-facing text names a community project's
// catalog: it says what Prufyx knows (the project is not in the CNCF
// landscape catalog Prufyx embeds) and asserts nothing about CNCF status.
// Some community projects are Kubernetes SIG subprojects, so "not a CNCF
// project" would be wrong for them.
const CommunityLabel = "community catalog (not in the embedded CNCF landscape catalog; no CNCF status asserted)"

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
//
// Community projects list only groups they define themselves. The Percona
// Operator for PostgreSQL ships Crunchy Data's postgres-operator.crunchydata.com
// CRDs (it is a fork, up to its 2.x lines): that group belongs to Crunchy
// Data's operator, so it is not listed for Percona, and its objects keep
// every set incomplete. Groups in the namespaces Kubernetes reserves are
// listed only with a reviewed ownership record (reserved, below).
var table = []Project{
	{
		Slug: "antrea", Catalog: CatalogCNCF, FactProject: "antrea", Component: "pkg:github/antrea-io/antrea",
		Groups: []Group{
			{Name: "crd.antrea.io", Source: "https://github.com/antrea-io/antrea/blob/e59003c2c1b13a961ff58a6d7b8f1133049d0bf0/build/charts/antrea/crds/trafficcontrol.yaml"},
			{Name: "multicluster.crd.antrea.io", Source: "https://github.com/antrea-io/antrea/blob/e59003c2c1b13a961ff58a6d7b8f1133049d0bf0/multicluster/config/crd/bases/multicluster.crd.antrea.io_resourceimports.yaml"},
		},
	},
	{
		Slug: "argo-cd", Catalog: CatalogCNCF, FactProject: "argo_cd", Component: "pkg:github/argoproj/argo-cd",
		Groups: []Group{
			{Name: "argoproj.io", Source: "https://github.com/argoproj/argo-cd/blob/e98f483bfd5781df2592fef1aeed1148f150d9c9/manifests/crds/application-crd.yaml"},
		},
	},
	{
		Slug: "cert-manager", Catalog: CatalogCNCF, FactProject: "cert_manager", Component: "pkg:github/cert-manager/cert-manager",
		Groups: []Group{
			{Name: "acme.cert-manager.io", Source: "https://github.com/cert-manager/cert-manager/blob/b8f325e36f49626ba72d7efbe138c01a5e661d96/deploy/crds/acme.cert-manager.io_orders.yaml"},
			{Name: "cert-manager.io", Source: "https://github.com/cert-manager/cert-manager/blob/b8f325e36f49626ba72d7efbe138c01a5e661d96/deploy/crds/cert-manager.io_issuers.yaml"},
		},
	},
	{
		Slug: "cilium", Catalog: CatalogCNCF, FactProject: "cilium", Component: "pkg:github/cilium/cilium",
		Groups: []Group{
			{Name: "cilium.io", Source: "https://github.com/cilium/cilium/blob/450c53145dc0a872ae20dfb05598c94ef55a71e2/pkg/k8s/apis/cilium.io/client/crds/v2alpha1/ciliumpodippools.yaml"},
		},
	},
	{
		Slug: "cloudnativepg", Catalog: CatalogCNCF, FactProject: "cloudnativepg", Component: "pkg:github/cloudnative-pg/cloudnative-pg",
		Groups: []Group{
			{Name: "postgresql.cnpg.io", Source: "https://github.com/cloudnative-pg/cloudnative-pg/blob/4b5e244a7d031f67e025c83c1555e7726ecbbfa1/config/crd/bases/postgresql.cnpg.io_subscriptions.yaml"},
		},
	},
	{
		Slug: "cluster-api", Catalog: CatalogCommunity, FactProject: "cluster_api", Component: "pkg:github/kubernetes-sigs/cluster-api",
		Upstream: Upstream{Name: "Cluster API", Repository: "https://github.com/kubernetes-sigs/cluster-api", License: "Apache-2.0", LicenseSource: "https://github.com/kubernetes-sigs/cluster-api/blob/560d4acf507bc7cac34b2da449fa5cd53eaeb149/LICENSE"},
		Groups: []Group{
			{Name: "cluster.x-k8s.io", Source: "https://github.com/kubernetes-sigs/cluster-api/blob/560d4acf507bc7cac34b2da449fa5cd53eaeb149/core/config/crd/bases/cluster.x-k8s.io_machinesets.yaml"},
			{Name: "clusterctl.cluster.x-k8s.io", Source: "https://github.com/kubernetes-sigs/cluster-api/blob/560d4acf507bc7cac34b2da449fa5cd53eaeb149/cmd/clusterctl/config/crd/bases/clusterctl.cluster.x-k8s.io_providers.yaml"},
			{Name: "runtime.cluster.x-k8s.io", Source: "https://github.com/kubernetes-sigs/cluster-api/blob/560d4acf507bc7cac34b2da449fa5cd53eaeb149/core/config/crd/bases/runtime.cluster.x-k8s.io_extensionconfigs.yaml"},
		},
	},
	{
		Slug: "contour", Catalog: CatalogCNCF, FactProject: "contour", Component: "pkg:github/projectcontour/contour",
		Groups: []Group{
			{Name: "projectcontour.io", Source: "https://github.com/projectcontour/contour/blob/3635b068e25d74b7089c272eefd6ccb6a08f2861/examples/contour/01-crds.yaml"},
		},
	},
	{
		Slug: "crossplane", Catalog: CatalogCNCF, FactProject: "crossplane", Component: "pkg:github/crossplane/crossplane",
		Groups: []Group{
			{Name: "apiextensions.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/apiextensions.crossplane.io_usages.yaml"},
			{Name: "ops.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/ops.crossplane.io_watchoperations.yaml"},
			{Name: "pkg.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/pkg.crossplane.io_providers.yaml"},
			{Name: "protection.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/61fa450c0c14a75bf5632872bd4a5b6945ec5a26/cluster/crds/protection.crossplane.io_usages.yaml"},
			{Name: "secrets.crossplane.io", Source: "https://github.com/crossplane/crossplane/blob/2efdb03ae80fc27f4b6b9b0cebc96a462233cf17/cluster/crds/secrets.crossplane.io_storeconfigs.yaml"},
		},
	},
	{
		Slug: "dapr", Catalog: CatalogCNCF, FactProject: "dapr", Component: "pkg:github/dapr/dapr",
		Groups: []Group{
			{Name: "dapr.io", Source: "https://github.com/dapr/dapr/blob/7c4f540efa3e6f768a45010f2fc0d4b4c287cac3/charts/dapr/crds/workflowaccesspolicy.yaml"},
		},
	},
	{
		Slug: "eck-operator", Catalog: CatalogCommunity, FactProject: "eck_operator", Component: "pkg:github/elastic/cloud-on-k8s",
		Upstream: Upstream{Name: "Elastic Cloud on Kubernetes", Repository: "https://github.com/elastic/cloud-on-k8s", License: "Elastic-2.0", LicenseSource: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/LICENSE.txt"},
		Groups: []Group{
			{Name: "agent.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "apm.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "autoops.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "autoscaling.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "beat.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "elasticsearch.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "enterprisesearch.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "kibana.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "logstash.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "maps.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "packageregistry.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
			{Name: "stackconfigpolicy.k8s.elastic.co", Source: "https://github.com/elastic/cloud-on-k8s/blob/386c7b14f2d1bbb7f2af1e7da997e64875f16e47/config/crds/v1/all-crds.yaml"},
		},
	},
	{
		Slug: "external-secrets", Catalog: CatalogCNCF, FactProject: "external_secrets", Component: "pkg:github/external-secrets/external-secrets",
		Groups: []Group{
			{Name: "external-secrets.io", Source: "https://github.com/external-secrets/external-secrets/blob/9d17906e8e4c5532ffe513f72273df03b7b07bc6/config/crds/bases/external-secrets.io_secretstores.yaml"},
			{Name: "generators.external-secrets.io", Source: "https://github.com/external-secrets/external-secrets/blob/9d17906e8e4c5532ffe513f72273df03b7b07bc6/config/crds/bases/generators.external-secrets.io_webhooks.yaml"},
		},
	},
	{
		Slug: "gateway-api", Catalog: CatalogCommunity, FactProject: "gateway_api", Component: "pkg:github/kubernetes-sigs/gateway-api",
		Upstream: Upstream{Name: "Gateway API", Repository: "https://github.com/kubernetes-sigs/gateway-api", License: "Apache-2.0", LicenseSource: "https://github.com/kubernetes-sigs/gateway-api/blob/89b3b0c3fa63f9342f43ba0fb2cf93d6aab53af7/LICENSE"},
		Groups: []Group{
			{Name: "gateway.networking.k8s.io", Source: "https://github.com/kubernetes-sigs/gateway-api/blob/89b3b0c3fa63f9342f43ba0fb2cf93d6aab53af7/config/crd/standard/gateway.networking.k8s.io_udproutes.yaml"},
		},
	},
	{
		Slug: "istio", Catalog: CatalogCNCF, FactProject: "istio", Component: "pkg:github/istio/istio",
		Groups: []Group{
			{Name: "extensions.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "networking.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "security.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
			{Name: "telemetry.istio.io", Source: "https://github.com/istio/istio/blob/8825a6b7f8c9a2d66005a5f8b64e98aaee0dda99/manifests/charts/base/files/crd-all.gen.yaml"},
		},
	},
	{
		Slug: "karmada", Catalog: CatalogCNCF, FactProject: "karmada", Component: "pkg:github/karmada-io/karmada",
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
		Slug: "keda", Catalog: CatalogCNCF, FactProject: "keda", Component: "pkg:github/kedacore/keda",
		Groups: []Group{
			{Name: "eventing.keda.sh", Source: "https://github.com/kedacore/keda/blob/626ded5d783108bedf647e20bbc83f8e458e02e4/config/crd/bases/eventing.keda.sh_clustercloudeventsources.yaml"},
			{Name: "keda.sh", Source: "https://github.com/kedacore/keda/blob/626ded5d783108bedf647e20bbc83f8e458e02e4/config/crd/bases/keda.sh_triggerauthentications.yaml"},
		},
	},
	{
		Slug: "kong-ingress-controller", Catalog: CatalogCommunity, FactProject: "kong_ingress_controller", Component: "pkg:github/kong/kubernetes-ingress-controller",
		Upstream: Upstream{Name: "Kong Ingress Controller", Repository: "https://github.com/kong/kubernetes-ingress-controller", License: "Apache-2.0", LicenseSource: "https://github.com/kong/kubernetes-ingress-controller/blob/17f5dafd2a447a7e5ff7be84006a83787ac2882c/LICENSE"},
		Groups: []Group{
			{Name: "configuration.konghq.com", Source: "https://github.com/kong/kubernetes-ingress-controller/blob/17f5dafd2a447a7e5ff7be84006a83787ac2882c/config/crd/bases/configuration.konghq.com_udpingresses.yaml"},
		},
	},
	{
		Slug: "koordinator", Catalog: CatalogCNCF, FactProject: "koordinator", Component: "pkg:github/koordinator-sh/koordinator",
		Groups: []Group{
			{Name: "analysis.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/analysis.koordinator.sh_recommendations.yaml"},
			{Name: "config.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/config.koordinator.sh_clustercolocationprofiles.yaml"},
			{Name: "quota.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/quota.koordinator.sh_elasticquotaprofiles.yaml"},
			{Name: "scheduling.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/scheduling.koordinator.sh_scheduleexplanations.yaml"},
			{Name: "slo.koordinator.sh", Source: "https://github.com/koordinator-sh/koordinator/blob/989ca85c62abcca92b303aa12fd2ccff2ed30fed/config/crd/bases/slo.koordinator.sh_nodeslos.yaml"},
		},
	},
	{
		Slug: "kueue", Catalog: CatalogCommunity, FactProject: "kueue", Component: "pkg:github/kubernetes-sigs/kueue",
		Upstream: Upstream{Name: "Kueue", Repository: "https://github.com/kubernetes-sigs/kueue", License: "Apache-2.0", LicenseSource: "https://github.com/kubernetes-sigs/kueue/blob/f850823bead72095aaba55025a7efadfdfe3782a/LICENSE"},
		Groups: []Group{
			{Name: "kueue.x-k8s.io", Source: "https://github.com/kubernetes-sigs/kueue/blob/f850823bead72095aaba55025a7efadfdfe3782a/config/components/crd/bases/kueue.x-k8s.io_workloads.yaml"},
		},
	},
	{
		Slug: "kuma", Catalog: CatalogCNCF, FactProject: "kuma", Component: "pkg:github/kumahq/kuma",
		Groups: []Group{
			{Name: "kuma.io", Source: "https://github.com/kumahq/kuma/blob/51c6d3819be75d9587942242cdec709bc9934321/deployments/charts/kuma/crds/kuma.io_zones.yaml"},
		},
	},
	{
		Slug: "kyverno", Catalog: CatalogCNCF, FactProject: "kyverno", Component: "pkg:github/kyverno/kyverno",
		Groups: []Group{
			{Name: "kyverno.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/kyverno/kyverno.io_updaterequests.yaml"},
			{Name: "policies.kyverno.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/policies.kyverno.io/policies.kyverno.io_validatingpolicies.yaml"},
			{Name: "reports.kyverno.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/reports/reports.kyverno.io_ephemeralreports.yaml"},
			{Name: "wgpolicyk8s.io", Source: "https://github.com/kyverno/kyverno/blob/ee97ce09538b09b6f1b03853cc41a62654d6a58f/config/crds/policyreport/wgpolicyk8s.io_policyreports.yaml"},
		},
	},
	{
		Slug: "longhorn", Catalog: CatalogCNCF, FactProject: "longhorn", Component: "pkg:github/longhorn/longhorn",
		Groups: []Group{
			{Name: "longhorn.io", Source: "https://github.com/longhorn/longhorn/blob/c3d88832bd8cec4f38dec65e79436984871dc313/deploy/longhorn.yaml"},
		},
	},
	{
		Slug: "metallb", Catalog: CatalogCNCF, FactProject: "metallb", Component: "pkg:github/metallb/metallb",
		Groups: []Group{
			{Name: "metallb.io", Source: "https://github.com/metallb/metallb/blob/4c613e152c3434f71137b5f2a2ce15ee93681606/config/crd/bases/metallb.io_servicel2statuses.yaml"},
		},
	},
	{
		Slug: "mongodb-kubernetes", Catalog: CatalogCommunity, FactProject: "mongodb_kubernetes", Component: "pkg:github/mongodb/mongodb-kubernetes",
		Upstream: Upstream{Name: "MongoDB Controllers for Kubernetes", Repository: "https://github.com/mongodb/mongodb-kubernetes", License: "Apache-2.0 OR LicenseRef-MongoDB-Customer-Agreement", LicenseSource: "https://github.com/mongodb/mongodb-kubernetes/blob/75fa89bca8c1395a1beb0f244723f255f67f8719/LICENSE-MCK"},
		Groups: []Group{
			{Name: "ai.mongodb.com", Source: "https://github.com/mongodb/mongodb-kubernetes/blob/75fa89bca8c1395a1beb0f244723f255f67f8719/config/crd/bases/ai.mongodb.com_voyageais.yaml"},
			{Name: "mongodb.com", Source: "https://github.com/mongodb/mongodb-kubernetes/blob/75fa89bca8c1395a1beb0f244723f255f67f8719/config/crd/bases/mongodb.com_opsmanagers.yaml"},
			{Name: "mongodbcommunity.mongodb.com", Source: "https://github.com/mongodb/mongodb-kubernetes/blob/75fa89bca8c1395a1beb0f244723f255f67f8719/config/crd/bases/mongodbcommunity.mongodb.com_mongodbcommunity.yaml"},
		},
	},
	{
		Slug: "node-feature-discovery", Catalog: CatalogCommunity, FactProject: "node_feature_discovery", Component: "pkg:github/kubernetes-sigs/node-feature-discovery",
		Upstream: Upstream{Name: "Node Feature Discovery", Repository: "https://github.com/kubernetes-sigs/node-feature-discovery", License: "Apache-2.0", LicenseSource: "https://github.com/kubernetes-sigs/node-feature-discovery/blob/45d276ed9d3f0f67fb642aa78969721df3034451/LICENSE"},
		Groups: []Group{
			{Name: "nfd.k8s-sigs.io", Source: "https://github.com/kubernetes-sigs/node-feature-discovery/blob/45d276ed9d3f0f67fb642aa78969721df3034451/deployment/base/nfd-crds/nfd-api-crds.yaml"},
		},
	},
	{
		Slug: "openkruise", Catalog: CatalogCNCF, FactProject: "openkruise", Component: "pkg:github/openkruise/kruise",
		Groups: []Group{
			{Name: "apps.kruise.io", Source: "https://github.com/openkruise/kruise/blob/b1e001a957ce62bf87894d0212f5e704a8e9c2b4/config/crd/bases/apps.kruise.io_workloadspreads.yaml"},
			{Name: "policy.kruise.io", Source: "https://github.com/openkruise/kruise/blob/b1e001a957ce62bf87894d0212f5e704a8e9c2b4/config/crd/bases/policy.kruise.io_podunavailablebudgets.yaml"},
		},
	},
	{
		Slug: "percona-postgresql-operator", Catalog: CatalogCommunity, FactProject: "percona_postgresql_operator", Component: "pkg:github/percona/percona-postgresql-operator",
		Upstream: Upstream{Name: "Percona Operator for PostgreSQL", Repository: "https://github.com/percona/percona-postgresql-operator", License: "Apache-2.0", LicenseSource: "https://github.com/percona/percona-postgresql-operator/blob/a6cb60bf372f0eec5c9680437c300e2c07362d70/LICENSE.md"},
		Groups: []Group{
			{Name: "pgv2.percona.com", Source: "https://github.com/percona/percona-postgresql-operator/blob/a6cb60bf372f0eec5c9680437c300e2c07362d70/config/crd/bases/pgv2.percona.com_perconapgclusters.yaml"},
			{Name: "upstream.pgv2.percona.com", Source: "https://github.com/percona/percona-postgresql-operator/blob/a6cb60bf372f0eec5c9680437c300e2c07362d70/config/crd/bases/upstream.pgv2.percona.com_postgresclusters.yaml"},
		},
	},
	{
		Slug: "prometheus-operator", Catalog: CatalogCommunity, FactProject: "prometheus_operator", Component: "pkg:github/prometheus-operator/prometheus-operator",
		Upstream: Upstream{Name: "Prometheus Operator", Repository: "https://github.com/prometheus-operator/prometheus-operator", License: "Apache-2.0", LicenseSource: "https://github.com/prometheus-operator/prometheus-operator/blob/2e4af1d7d8f0ae634fcf0ac967a76fb381a65542/LICENSE"},
		Groups: []Group{
			{Name: "monitoring.coreos.com", Source: "https://github.com/prometheus-operator/prometheus-operator/blob/2e4af1d7d8f0ae634fcf0ac967a76fb381a65542/example/prometheus-operator-crd/monitoring.coreos.com_thanosrulers.yaml"},
		},
	},
	{
		Slug: "rancher", Catalog: CatalogCommunity, FactProject: "rancher", Component: "pkg:github/rancher/rancher",
		Upstream: Upstream{Name: "Rancher", Repository: "https://github.com/rancher/rancher", License: "Apache-2.0", LicenseSource: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/LICENSE"},
		Groups: []Group{
			{Name: "auditlog.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/auditlog.cattle.io_auditpolicies.yaml"},
			{Name: "catalog.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/catalog.cattle.io_uiplugins.yaml"},
			{Name: "management.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/management.cattle.io_users.yaml"},
			{Name: "operation.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/operation.cattle.io_etcdsnapshotsaves.yaml"},
			{Name: "plan.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/plan.cattle.io_beacons.yaml"},
			{Name: "provisioning.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/provisioning.cattle.io_clusters.yaml"},
			{Name: "rke.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/rke.cattle.io_rkecontrolplanes.yaml"},
			{Name: "scc.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/scc.cattle.io_registrations.yaml"},
			{Name: "telemetry.cattle.io", Source: "https://github.com/rancher/rancher/blob/9994cd93198c4b1692bcda733eb08d1e81c26eed/pkg/crds/yaml/generated/telemetry.cattle.io_secretrequests.yaml"},
		},
	},
	{
		Slug: "rook", Catalog: CatalogCNCF, FactProject: "rook", Component: "pkg:github/rook/rook",
		Groups: []Group{
			{Name: "ceph.rook.io", Source: "https://github.com/rook/rook/blob/f190ca3b45f131da03641741e9e03b2584cd7d5e/deploy/examples/crds.yaml"},
			{Name: "objectbucket.io", Source: "https://github.com/rook/rook/blob/f190ca3b45f131da03641741e9e03b2584cd7d5e/deploy/examples/crds.yaml"},
		},
	},
	{
		Slug: "strimzi", Catalog: CatalogCNCF, FactProject: "strimzi", Component: "pkg:github/strimzi/strimzi-kafka-operator",
		Groups: []Group{
			{Name: "core.strimzi.io", Source: "https://github.com/strimzi/strimzi-kafka-operator/blob/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator/042-Crd-strimzipodset.yaml"},
			{Name: "kafka.strimzi.io", Source: "https://github.com/strimzi/strimzi-kafka-operator/blob/4836c7dd74ce973f06d97936916ed7f20c1a2ff0/install/cluster-operator/040-Crd-kafka.yaml"},
		},
	},
	{
		Slug: "tekton", Catalog: CatalogCNCF, FactProject: "tekton", Component: "pkg:github/tektoncd/pipeline",
		Groups: []Group{
			{Name: "resolution.tekton.dev", Source: "https://github.com/tektoncd/pipeline/blob/61e02215132ce7bef054ff7e1fb074f217716c1a/config/300-crds/300-resolutionrequest.yaml"},
			{Name: "tekton.dev", Source: "https://github.com/tektoncd/pipeline/blob/61e02215132ce7bef054ff7e1fb074f217716c1a/config/300-crds/300-verificationpolicy.yaml"},
		},
	},
	{
		Slug: "velero", Catalog: CatalogCNCF, FactProject: "velero", Component: "pkg:github/velero-io/velero",
		Groups: []Group{
			{Name: "velero.io", Source: "https://github.com/velero-io/velero/blob/6adcf06b5b0e6fb93998d3e101e2cbdc134fa3c3/config/crd/v1/bases/velero.io_volumesnapshotlocations.yaml"},
		},
	},
	{
		Slug: "volcano", Catalog: CatalogCNCF, FactProject: "volcano", Component: "pkg:github/volcano-sh/volcano",
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
// and every group ending in ".k8s.io", except a group of the reviewed
// reserved-group ownership list (ReservedGroups): that group is defined by
// CustomResourceDefinitions of one upstream project, kube-apiserver does
// not serve it, and it is a custom resource group. Every other group is a
// custom resource group. Scan's served-API check covers exactly the
// Kubernetes groups, so every group is covered by one of the two.
func KubernetesGroup(group string) bool {
	if !strings.Contains(group, ".") {
		return true
	}
	return strings.HasSuffix(group, ".k8s.io") && !reviewedReserved(reserved, group)
}

// ReservedNamespace reports whether an API group lies in a namespace the
// Kubernetes project reserves for its own APIs and those of its SIG
// subprojects: k8s.io, x-k8s.io and kubernetes.io and their subdomains.
// Such a group may be defined by kube-apiserver, by a SIG subproject's
// CustomResourceDefinitions, or (x-k8s.io) by an API several projects
// implement, so the table lists one only through a reviewed ownership
// record (ReservedGroup) and never by its suffix.
func ReservedNamespace(group string) bool {
	for _, ns := range []string{"k8s.io", "x-k8s.io", "kubernetes.io"} {
		if group == ns || strings.HasSuffix(group, "."+ns) {
			return true
		}
	}
	return false
}

// ReservedGroup is a reviewed ownership record: an API group in a
// Kubernetes-reserved namespace that the CustomResourceDefinitions of one
// upstream repository define, and that kube-apiserver does not serve. The
// owner must list the group in the table, its component must name exactly
// that repository, and no other project may list the group. A group of a
// reserved namespace without a record is never listed (Validate refuses
// it): a .k8s.io group stays a Kubernetes group, and any other reserved
// group, like an API that several projects implement
// (multicluster.x-k8s.io) or a provider namespace
// (infrastructure.cluster.x-k8s.io), belongs to no project.
type ReservedGroup struct {
	Name string
	// Owner is the table slug of the project that defines the group.
	Owner string
	// Repository is the upstream repository whose CustomResourceDefinitions
	// define the group, https://github.com/<owner>/<name>.
	Repository string
	// Reason says why the group belongs to that repository alone.
	Reason string
}

// reserved is the reviewed ownership list, ordered by group name.
//
// Not listed, so attributed to no project: the provider namespaces of
// Cluster API (addons, bootstrap, controlplane, infrastructure and ipam
// .cluster.x-k8s.io), whose CRDs other providers define too (the Helm
// add-on provider, the RKE2 and Talos bootstrap and control-plane
// providers, cloud providers, IPAM providers); the experimental Gateway API
// group gateway.networking.x-k8s.io (its CRDs lie outside the standard
// channel the extractor reads); the multicluster services API
// multicluster.x-k8s.io (Karmada and Antrea both ship it);
// snapshot.storage.k8s.io and topology.node.k8s.io (shipped by several
// projects, none of which is in the table as its definer). An object of
// such a group keeps every set incomplete, which never passes.
var reserved = []ReservedGroup{
	{Name: "cluster.x-k8s.io", Owner: "cluster-api", Repository: "https://github.com/kubernetes-sigs/cluster-api", Reason: "the core Cluster API types (Cluster, Machine, MachineSet, ...) are CRDs of kubernetes-sigs/cluster-api; providers define theirs in their own *.cluster.x-k8s.io groups"},
	{Name: "clusterctl.cluster.x-k8s.io", Owner: "cluster-api", Repository: "https://github.com/kubernetes-sigs/cluster-api", Reason: "the clusterctl Provider and Metadata types are CRDs of kubernetes-sigs/cluster-api (cmd/clusterctl) only"},
	{Name: "gateway.networking.k8s.io", Owner: "gateway-api", Repository: "https://github.com/kubernetes-sigs/gateway-api", Reason: "Gateway API is defined by the CRDs of kubernetes-sigs/gateway-api and is not served by kube-apiserver; implementations ship copies of those CRDs"},
	{Name: "kueue.x-k8s.io", Owner: "kueue", Repository: "https://github.com/kubernetes-sigs/kueue", Reason: "the Kueue types (ClusterQueue, LocalQueue, Workload, ...) are CRDs of kubernetes-sigs/kueue only"},
	{Name: "runtime.cluster.x-k8s.io", Owner: "cluster-api", Repository: "https://github.com/kubernetes-sigs/cluster-api", Reason: "the runtime extension type ExtensionConfig is a CRD of kubernetes-sigs/cluster-api only"},
}

// ReservedGroups returns a copy of the reviewed ownership list.
func ReservedGroups() []ReservedGroup { return append([]ReservedGroup(nil), reserved...) }

func reviewedReserved(records []ReservedGroup, group string) bool {
	for _, r := range records {
		if r.Name == group {
			return true
		}
	}
	return false
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
	// licenseRE is an SPDX licence expression of identifiers joined by OR
	// or AND (LicenseRef-* for a licence SPDX does not list).
	licenseRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}( (OR|AND) [A-Za-z0-9][A-Za-z0-9.+-]{0,63}){0,3}$`)
	licenseFileRE = regexp.MustCompile(`^/blob/[0-9a-f]{40}/(LICENSE|COPYING)([.-][A-Za-z0-9]{1,16})?$`)
)

// Validate checks a table against the reviewed ownership list: slugs
// ascending and unique, well-formed fact projects and components, a known
// catalog, provenance exactly for community projects, and every group a
// custom resource group, named once per project, with a source pinned by
// full commit SHA. A group of a Kubernetes-reserved namespace needs a
// reviewed ownership record naming that project and its repository, and
// every record must be listed by its owner and by no other project.
func Validate(projects []Project) bool { return validate(projects, reserved) }

func validate(projects []Project, records []ReservedGroup) bool {
	listed := map[string][]string{}
	for i, p := range projects {
		if !slugRE.MatchString(p.Slug) || !factProjectRE.MatchString(p.FactProject) || !strings.HasPrefix(p.Component, "pkg:github/") || len(p.Groups) == 0 {
			return false
		}
		if i > 0 && projects[i-1].Slug >= p.Slug {
			return false
		}
		repository := "https://github.com/" + strings.TrimPrefix(p.Component, "pkg:github/")
		switch p.Catalog {
		case CatalogCNCF:
			if p.Upstream != (Upstream{}) {
				return false
			}
		case CatalogCommunity:
			u := p.Upstream
			license, found := strings.CutPrefix(u.LicenseSource, repository)
			if strings.TrimSpace(u.Name) != u.Name || u.Name == "" || len(u.Name) > 64 || u.Repository != repository || !licenseRE.MatchString(u.License) || !found || !licenseFileRE.MatchString(license) {
				return false
			}
		default:
			return false
		}
		for j, g := range p.Groups {
			if len(g.Name) > 253 || !groupRE.MatchString(g.Name) || !sourceRE.MatchString(g.Source) {
				return false
			}
			if j > 0 && p.Groups[j-1].Name >= g.Name {
				return false
			}
			if ReservedNamespace(g.Name) {
				if !ownsReserved(records, g.Name, p.Slug, repository) {
					return false
				}
			} else if !strings.Contains(g.Name, ".") {
				return false
			}
			listed[g.Name] = append(listed[g.Name], p.Slug)
		}
	}
	for i, r := range records {
		if i > 0 && records[i-1].Name >= r.Name {
			return false
		}
		if !ReservedNamespace(r.Name) || strings.TrimSpace(r.Reason) != r.Reason || len(r.Reason) < 12 || len(r.Reason) > 300 {
			return false
		}
		// Every record is listed by its owner and by no other project: an
		// overlap is refused here, and would make the group ambiguous (never
		// attributed) at run time.
		if len(listed[r.Name]) != 1 || listed[r.Name][0] != r.Owner {
			return false
		}
	}
	return true
}

// ownsReserved reports whether exactly one record names the group, for
// that owner and repository.
func ownsReserved(records []ReservedGroup, group, owner, repository string) bool {
	n := 0
	for _, r := range records {
		if r.Name != group {
			continue
		}
		n++
		if r.Owner != owner || r.Repository != repository {
			return false
		}
	}
	return n == 1
}
