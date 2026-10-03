// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

// adapterFact names the boolean fact the Kubernetes manifest adapter
// (cncfprepare) produces for removed kinds of one served API version when a
// cluster crosses into the target minor line. The adapter builds facts for a
// fixed, reviewed list; the extractor never invents a fact. A derived
// removal whose kinds are not in this table is recorded in the manifest as
// having no adapter fact, and no rule is emitted for it.
//
// The table is a copy of the adapter's removal table plus its flow-control
// 1.32 fact. A test in the adapter package compares the two so they cannot
// drift.
type adapterFact struct {
	Line    int // target minor line, e.g. 25 for 1.25
	Group   string
	Version string
	Kinds   []string
	Fact    string
	Slug    string // short name used to keep rule ids apart when one group version splits into several facts
}

const factPrefix = "component.kubernetes."

// AdapterFact is the exported view of one table entry, for the drift test.
type AdapterFact struct {
	Line    int
	Group   string
	Version string
	Kinds   []string
	Fact    string
}

// AdapterFacts returns the table in its fixed order.
func AdapterFacts() []AdapterFact {
	out := make([]AdapterFact, 0, len(adapterFacts))
	for _, f := range adapterFacts {
		out = append(out, AdapterFact{Line: f.Line, Group: f.Group, Version: f.Version, Kinds: append([]string(nil), f.Kinds...), Fact: f.Fact})
	}
	return out
}

var adapterFacts = []adapterFact{
	{22, "admissionregistration.k8s.io", "v1beta1", []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"}, factPrefix + "admissionwebhook_v1beta1_removed_gvk_present", "webhook"},
	{22, "apiextensions.k8s.io", "v1beta1", []string{"CustomResourceDefinition"}, factPrefix + "crd_v1beta1_removed_gvk_present", "crd"},
	{22, "apiregistration.k8s.io", "v1beta1", []string{"APIService"}, factPrefix + "apiservice_v1beta1_removed_gvk_present", "apiservice"},
	{22, "authentication.k8s.io", "v1beta1", []string{"TokenReview"}, factPrefix + "tokenreview_v1beta1_removed_gvk_present", "tokenreview"},
	{22, "authorization.k8s.io", "v1beta1", []string{"LocalSubjectAccessReview", "SelfSubjectAccessReview", "SubjectAccessReview", "SelfSubjectRulesReview"}, factPrefix + "subjectaccessreview_v1beta1_removed_gvk_present", "subjectaccessreview"},
	{22, "certificates.k8s.io", "v1beta1", []string{"CertificateSigningRequest"}, factPrefix + "csr_v1beta1_removed_gvk_present", "csr"},
	{22, "coordination.k8s.io", "v1beta1", []string{"Lease"}, factPrefix + "lease_v1beta1_removed_gvk_present", "lease"},
	{22, "extensions", "v1beta1", []string{"Ingress"}, factPrefix + "ingress_extensions_v1beta1_removed_gvk_present", "ingress"},
	{22, "networking.k8s.io", "v1beta1", []string{"Ingress"}, factPrefix + "ingress_networking_v1beta1_removed_gvk_present", "ingress"},
	{22, "networking.k8s.io", "v1beta1", []string{"IngressClass"}, factPrefix + "ingressclass_v1beta1_removed_gvk_present", "ingressclass"},
	{22, "rbac.authorization.k8s.io", "v1beta1", []string{"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}, factPrefix + "rbac_v1beta1_removed_gvk_present", "rbac"},
	{22, "scheduling.k8s.io", "v1beta1", []string{"PriorityClass"}, factPrefix + "priorityclass_v1beta1_removed_gvk_present", "priorityclass"},
	{22, "storage.k8s.io", "v1beta1", []string{"CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"}, factPrefix + "storage_v1beta1_removed_gvk_present", "storage"},
	{25, "batch", "v1beta1", []string{"CronJob"}, factPrefix + "cronjob_v1beta1_removed_gvk_present", "cronjob"},
	{25, "discovery.k8s.io", "v1beta1", []string{"EndpointSlice"}, factPrefix + "endpointslice_v1beta1_removed_gvk_present", "endpointslice"},
	{25, "events.k8s.io", "v1beta1", []string{"Event"}, factPrefix + "event_v1beta1_removed_gvk_present", "event"},
	{25, "autoscaling", "v2beta1", []string{"HorizontalPodAutoscaler"}, factPrefix + "hpa_v2beta1_removed_gvk_present", "hpa"},
	{25, "policy", "v1beta1", []string{"PodDisruptionBudget"}, factPrefix + "pdb_v1beta1_removed_gvk_present", "pdb"},
	{25, "policy", "v1beta1", []string{"PodSecurityPolicy"}, factPrefix + "psp_v1beta1_removed_gvk_present", "psp"},
	{25, "node.k8s.io", "v1beta1", []string{"RuntimeClass"}, factPrefix + "runtimeclass_v1beta1_removed_gvk_present", "runtimeclass"},
	{26, "flowcontrol.apiserver.k8s.io", "v1beta1", []string{"FlowSchema", "PriorityLevelConfiguration"}, factPrefix + "flowcontrol_v1beta1_removed_gvk_present", "flowcontrol"},
	{26, "autoscaling", "v2beta2", []string{"HorizontalPodAutoscaler"}, factPrefix + "hpa_v2beta2_removed_gvk_present", "hpa"},
	{27, "storage.k8s.io", "v1beta1", []string{"CSIStorageCapacity"}, factPrefix + "csistoragecapacity_v1beta1_removed_gvk_present", "csistoragecapacity"},
	{29, "flowcontrol.apiserver.k8s.io", "v1beta2", []string{"FlowSchema", "PriorityLevelConfiguration"}, factPrefix + "flowcontrol_v1beta2_removed_gvk_present", "flowcontrol"},
	{32, "flowcontrol.apiserver.k8s.io", "v1beta3", []string{"FlowSchema", "PriorityLevelConfiguration"}, factPrefix + "flowcontrol_v1beta3_removed_gvk_present", "flowcontrol"},
	{33, "authentication.k8s.io", "v1beta1", []string{"SelfSubjectReview"}, factPrefix + "selfsubjectreview_v1beta1_removed_gvk_present", "selfsubjectreview"},
	{34, "admissionregistration.k8s.io", "v1beta1", []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}, factPrefix + "validatingadmissionpolicy_v1beta1_removed_gvk_present", "validatingadmissionpolicy"},
	{37, "networking.k8s.io", "v1beta1", []string{"IPAddress", "ServiceCIDR"}, factPrefix + "ipaddress_servicecidr_v1beta1_removed_gvk_present", "ipaddress"},
	{37, "storage.k8s.io", "v1beta1", []string{"VolumeAttributesClass"}, factPrefix + "volumeattributesclass_v1beta1_removed_gvk_present", "volumeattributesclass"},
}

// factFor returns the adapter fact covering kind of group/version removed at
// the given line.
func factFor(line int, group, version, kind string) (adapterFact, bool) {
	for _, f := range adapterFacts {
		if f.Line != line || f.Group != group || f.Version != version {
			continue
		}
		for _, k := range f.Kinds {
			if k == kind {
				return f, true
			}
		}
	}
	return adapterFact{}, false
}
