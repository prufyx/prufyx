// SPDX-License-Identifier: AGPL-3.0-only

// Package k8sremovals holds the reviewed table of Kubernetes API removals:
// the group, kinds and version that stop being served when a cluster enters a
// release line. It is data only, so the adapters that derive facts from it
// (cncfprepare) and the pack loader that checks served lists against it
// (cncfcheck) can both read it without importing each other.
package k8sremovals

import (
	"sort"
	"strconv"
	"strings"
)

// Removal is one reviewed API removal: the named kinds in Group stop
// being served at Removed when a cluster moves into the target minor line.
// Served lists the versions of the same group and kinds that the cited source
// names as still served across the whole target minor line, not only at its
// first patch: Kubernetes removes served API versions only at minor releases,
// and a test checks every Served version against the removals this table
// records. A document of one of these kinds in any other version cannot
// establish the fact either way, so the fact stays unsupported.
type Removal struct {
	Fact    string
	Group   string
	Kinds   []string
	Removed string
	Served  []string
}

// byTargetMinor (read through ByTargetMinor) maps a target minor line to the reviewed
// removals that take effect when a cluster crosses into it. The default path
// (cncfprepare.kubernetesRemovalsForCrossedMinorLine) selects a line by crossing exactly
// one minor boundary from any patch of the previous line to any patch of the
// target line; the published rules carry a range that constrains which of
// those crossings actually decide. cncfprepare.kubernetesRemovalsForAnchor, the older,
// narrower selector, is kept for cncfprepare.kubernetesRemovalsByTransition and the drift
// tests that compare the table against the rule pack's own anchors. The 1.32
// line is handled by PrepareKubernetesFlowControl and deliberately absent
// here.
var byTargetMinor = map[string][]Removal{
	"1.22": {
		{Fact: "component.kubernetes.admissionwebhook_v1beta1_removed_gvk_present", Group: "admissionregistration.k8s.io", Kinds: []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.crd_v1beta1_removed_gvk_present", Group: "apiextensions.k8s.io", Kinds: []string{"CustomResourceDefinition"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.apiservice_v1beta1_removed_gvk_present", Group: "apiregistration.k8s.io", Kinds: []string{"APIService"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.tokenreview_v1beta1_removed_gvk_present", Group: "authentication.k8s.io", Kinds: []string{"TokenReview"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.subjectaccessreview_v1beta1_removed_gvk_present", Group: "authorization.k8s.io", Kinds: []string{"LocalSubjectAccessReview", "SelfSubjectAccessReview", "SubjectAccessReview", "SelfSubjectRulesReview"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.csr_v1beta1_removed_gvk_present", Group: "certificates.k8s.io", Kinds: []string{"CertificateSigningRequest"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.lease_v1beta1_removed_gvk_present", Group: "coordination.k8s.io", Kinds: []string{"Lease"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.ingress_extensions_v1beta1_removed_gvk_present", Group: "extensions", Kinds: []string{"Ingress"}, Removed: "v1beta1", Served: nil},
		{Fact: "component.kubernetes.ingress_networking_v1beta1_removed_gvk_present", Group: "networking.k8s.io", Kinds: []string{"Ingress"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.ingressclass_v1beta1_removed_gvk_present", Group: "networking.k8s.io", Kinds: []string{"IngressClass"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.rbac_v1beta1_removed_gvk_present", Group: "rbac.authorization.k8s.io", Kinds: []string{"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.priorityclass_v1beta1_removed_gvk_present", Group: "scheduling.k8s.io", Kinds: []string{"PriorityClass"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.storage_v1beta1_removed_gvk_present", Group: "storage.k8s.io", Kinds: []string{"CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
	"1.37": {
		{Fact: "component.kubernetes.ipaddress_servicecidr_v1beta1_removed_gvk_present", Group: "networking.k8s.io", Kinds: []string{"IPAddress", "ServiceCIDR"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.volumeattributesclass_v1beta1_removed_gvk_present", Group: "storage.k8s.io", Kinds: []string{"VolumeAttributesClass"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
	"1.34": {
		{Fact: "component.kubernetes.validatingadmissionpolicy_v1beta1_removed_gvk_present", Group: "admissionregistration.k8s.io", Kinds: []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
	"1.33": {
		{Fact: "component.kubernetes.selfsubjectreview_v1beta1_removed_gvk_present", Group: "authentication.k8s.io", Kinds: []string{"SelfSubjectReview"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
	"1.29": {
		{Fact: "component.kubernetes.flowcontrol_v1beta2_removed_gvk_present", Group: "flowcontrol.apiserver.k8s.io", Kinds: []string{"FlowSchema", "PriorityLevelConfiguration"}, Removed: "v1beta2", Served: []string{"v1", "v1beta3"}},
	},
	"1.27": {
		{Fact: "component.kubernetes.csistoragecapacity_v1beta1_removed_gvk_present", Group: "storage.k8s.io", Kinds: []string{"CSIStorageCapacity"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
	"1.26": {
		{Fact: "component.kubernetes.flowcontrol_v1beta1_removed_gvk_present", Group: "flowcontrol.apiserver.k8s.io", Kinds: []string{"FlowSchema", "PriorityLevelConfiguration"}, Removed: "v1beta1", Served: []string{"v1beta2", "v1beta3"}},
		{Fact: "component.kubernetes.hpa_v2beta2_removed_gvk_present", Group: "autoscaling", Kinds: []string{"HorizontalPodAutoscaler"}, Removed: "v2beta2", Served: []string{"v2"}},
	},
	"1.25": {
		{Fact: "component.kubernetes.cronjob_v1beta1_removed_gvk_present", Group: "batch", Kinds: []string{"CronJob"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.endpointslice_v1beta1_removed_gvk_present", Group: "discovery.k8s.io", Kinds: []string{"EndpointSlice"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.event_v1beta1_removed_gvk_present", Group: "events.k8s.io", Kinds: []string{"Event"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.hpa_v2beta1_removed_gvk_present", Group: "autoscaling", Kinds: []string{"HorizontalPodAutoscaler"}, Removed: "v2beta1", Served: []string{"v2"}},
		{Fact: "component.kubernetes.pdb_v1beta1_removed_gvk_present", Group: "policy", Kinds: []string{"PodDisruptionBudget"}, Removed: "v1beta1", Served: []string{"v1"}},
		{Fact: "component.kubernetes.psp_v1beta1_removed_gvk_present", Group: "policy", Kinds: []string{"PodSecurityPolicy"}, Removed: "v1beta1", Served: nil},
		{Fact: "component.kubernetes.runtimeclass_v1beta1_removed_gvk_present", Group: "node.k8s.io", Kinds: []string{"RuntimeClass"}, Removed: "v1beta1", Served: []string{"v1"}},
	},
}

// ByTargetMinor returns a deep copy of the reviewed removal table, so no
// caller can change the table the admission check and the adapters read.
func ByTargetMinor() map[string][]Removal {
	out := make(map[string][]Removal, len(byTargetMinor))
	for line, removals := range byTargetMinor {
		copied := make([]Removal, len(removals))
		for i, removal := range removals {
			removal.Kinds = append([]string(nil), removal.Kinds...)
			removal.Served = append([]string(nil), removal.Served...)
			copied[i] = removal
		}
		out[line] = copied
	}
	return out
}

// RemovedVersion is one reviewed removal of a served API version: the kinds
// of Group at Version stop being served when a cluster enters Line.
type RemovedVersion struct {
	Line    string
	Group   string
	Version string
	Kinds   []string
}

// RemovedVersions lists every removal the rendered apply-set route knows,
// including the 1.32 flow-control removal, ordered by line, group, version.
func RemovedVersions() []RemovedVersion {
	out := []RemovedVersion{{Line: "1.32", Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta3", Kinds: []string{"FlowSchema", "PriorityLevelConfiguration"}}}
	for line, removals := range byTargetMinor {
		for _, removal := range removals {
			out = append(out, RemovedVersion{Line: line, Group: removal.Group, Version: removal.Removed, Kinds: append([]string(nil), removal.Kinds...)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Line != b.Line {
			return lineLess(a.Line, b.Line)
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.Version < b.Version
	})
	return out
}

// lineLess orders "major.minor" lines numerically; a malformed line sorts
// as 0.0.
func lineLess(a, b string) bool {
	am, an := lineParts(a)
	bm, bn := lineParts(b)
	return am < bm || am == bm && an < bn
}

func lineParts(line string) (uint64, uint64) {
	major, minor, _ := strings.Cut(line, ".")
	m, _ := strconv.ParseUint(major, 10, 32)
	n, _ := strconv.ParseUint(minor, 10, 32)
	return m, n
}

// preV122Removals are the API removals before the 1.22 start of the table
// above. They are used only to admit served lists (AdmissionRemovedVersions),
// never as scan or cncfprepare facts. Source: the Kubernetes deprecation
// guide, section "v1.16" (kubernetes/website, content/en/docs/reference/
// using-api/deprecation-guide.md at commit
// 9f1af2971c32124bff0a1f42255ba5a2f3c8a16f): NetworkPolicy
// extensions/v1beta1; DaemonSet extensions/v1beta1 and apps/v1beta2;
// Deployment and ReplicaSet extensions/v1beta1, apps/v1beta1 and
// apps/v1beta2; StatefulSet apps/v1beta1 and apps/v1beta2; PodSecurityPolicy
// extensions/v1beta1. Only what that section names is listed.
var preV122Removals = []RemovedVersion{
	{Line: "1.16", Group: "apps", Version: "v1beta1", Kinds: []string{"Deployment", "ReplicaSet", "StatefulSet"}},
	{Line: "1.16", Group: "apps", Version: "v1beta2", Kinds: []string{"DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"}},
	{Line: "1.16", Group: "extensions", Version: "v1beta1", Kinds: []string{"DaemonSet", "Deployment", "NetworkPolicy", "PodSecurityPolicy", "ReplicaSet"}},
}

// AdmissionRemovedVersions is RemovedVersions plus the pre-1.22 removals,
// ordered by line, group, version. Only the served-list admission reads it.
func AdmissionRemovedVersions() []RemovedVersion {
	out := RemovedVersions()
	for _, removal := range preV122Removals {
		removal.Kinds = append([]string(nil), removal.Kinds...)
		out = append(out, removal)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Line != b.Line {
			return lineLess(a.Line, b.Line)
		}
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.Version < b.Version
	})
	return out
}
