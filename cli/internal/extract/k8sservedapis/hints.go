// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

import (
	"fmt"
	"strings"
)

// hint is the reviewed migration guidance for one removed (group, version,
// kind). The table is hand-reviewed against the upstream deprecation guide
// (the revision the earlier reviewed rules cite) and the next-action texts of
// those reviewed rules. The extractor reads no guide at run time: the text is
// a pure function of the removed group, version and kinds, so it is
// deterministic and offline. A removal whose kind has no entry (a removal later
// than the reviewed guide, or a kind added to the adapter table) gets the
// generic text of genericAction.
type hint struct {
	// Target is the group version to migrate to, e.g. "batch/v1"; empty with
	// NoReplacement.
	Target string
	// Alternative is a second served target, "" if none.
	Alternative string
	// Note is the one change of the target the guide stresses most, written
	// as a short sentence. It is dropped when the text would exceed the
	// 256-byte limit of a rule's next action.
	Note string
	// Label names the kinds in place of the kind list when the list does not
	// fit the limit (the four authorization review kinds).
	Label string
	// NoReplacement marks a kind with no served replacement API.
	NoReplacement bool
}

// maxNextAction is the limit of a rule's next action (rulecheck).
const maxNextAction = 256

const (
	reassess   = "Reassess the complete target apply set."
	validation = "Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately."
	// compactTail is the same two instructions with less punctuation, used
	// when the kinds are so many that the full tail does not fit.
	compactTail = "Reassess the complete target apply set; validate admission, CRDs, stored objects, runtime clients, API-server configuration separately."
)

func hintKey(group, version, kind string) string {
	return groupVersion(group, version) + "/" + kind
}

const (
	v1 = "/v1"
	// Shared notes.
	webhookNote = "failurePolicy now defaults to Fail."
	flowNote    = "Rename assuredConcurrencyShares to nominalConcurrencyShares."
	hpaNote     = "Use target.averageUtilization."
	ingressNote = "pathType is now required."
	reviewNote  = "spec.group is now spec.groups."
)

var hints = map[string]hint{
	// 1.22 removals (deprecation guide v1.22).
	"admissionregistration.k8s.io/v1beta1/MutatingWebhookConfiguration":   {Target: "admissionregistration.k8s.io/v1", Note: webhookNote},
	"admissionregistration.k8s.io/v1beta1/ValidatingWebhookConfiguration": {Target: "admissionregistration.k8s.io/v1", Note: webhookNote},
	"apiextensions.k8s.io/v1beta1/CustomResourceDefinition":               {Target: "apiextensions.k8s.io/v1", Note: "spec.versions[*].schema is required."},
	"apiregistration.k8s.io/v1beta1/APIService":                           {Target: "apiregistration.k8s.io/v1"},
	"authentication.k8s.io/v1beta1/TokenReview":                           {Target: "authentication.k8s.io/v1"},
	"authorization.k8s.io/v1beta1/LocalSubjectAccessReview":               {Target: "authorization.k8s.io/v1", Note: reviewNote, Label: "SubjectAccessReview resources"},
	"authorization.k8s.io/v1beta1/SelfSubjectAccessReview":                {Target: "authorization.k8s.io/v1", Note: reviewNote, Label: "SubjectAccessReview resources"},
	"authorization.k8s.io/v1beta1/SelfSubjectRulesReview":                 {Target: "authorization.k8s.io/v1", Note: reviewNote, Label: "SubjectAccessReview resources"},
	"authorization.k8s.io/v1beta1/SubjectAccessReview":                    {Target: "authorization.k8s.io/v1", Note: reviewNote, Label: "SubjectAccessReview resources"},
	"certificates.k8s.io/v1beta1/CertificateSigningRequest":               {Target: "certificates.k8s.io/v1", Note: "spec.signerName is required."},
	"coordination.k8s.io/v1beta1/Lease":                                   {Target: "coordination.k8s.io/v1"},
	"extensions/v1beta1/Ingress":                                          {Target: "networking.k8s.io/v1", Note: ingressNote},
	"networking.k8s.io/v1beta1/Ingress":                                   {Target: "networking.k8s.io/v1", Note: ingressNote},
	"networking.k8s.io/v1beta1/IngressClass":                              {Target: "networking.k8s.io/v1"},
	"rbac.authorization.k8s.io/v1beta1/ClusterRole":                       {Target: "rbac.authorization.k8s.io/v1"},
	"rbac.authorization.k8s.io/v1beta1/ClusterRoleBinding":                {Target: "rbac.authorization.k8s.io/v1"},
	"rbac.authorization.k8s.io/v1beta1/Role":                              {Target: "rbac.authorization.k8s.io/v1"},
	"rbac.authorization.k8s.io/v1beta1/RoleBinding":                       {Target: "rbac.authorization.k8s.io/v1"},
	"scheduling.k8s.io/v1beta1/PriorityClass":                             {Target: "scheduling.k8s.io/v1"},
	"storage.k8s.io/v1beta1/CSIDriver":                                    {Target: "storage.k8s.io/v1"},
	"storage.k8s.io/v1beta1/CSINode":                                      {Target: "storage.k8s.io/v1"},
	"storage.k8s.io/v1beta1/StorageClass":                                 {Target: "storage.k8s.io/v1"},
	"storage.k8s.io/v1beta1/VolumeAttachment":                             {Target: "storage.k8s.io/v1"},

	// 1.25 removals (guide v1.25).
	"batch/v1beta1/CronJob":                       {Target: "batch/v1"},
	"discovery.k8s.io/v1beta1/EndpointSlice":      {Target: "discovery.k8s.io/v1", Note: "Use nodeName and zone, not topology."},
	"events.k8s.io/v1beta1/Event":                 {Target: "events.k8s.io/v1", Note: "involvedObject is now regarding."},
	"autoscaling/v2beta1/HorizontalPodAutoscaler": {Target: "autoscaling/v2", Note: hpaNote},
	"policy/v1beta1/PodDisruptionBudget":          {Target: "policy/v1", Note: "An empty selector now selects all pods."},
	"policy/v1beta1/PodSecurityPolicy":            {NoReplacement: true},
	"node.k8s.io/v1beta1/RuntimeClass":            {Target: "node.k8s.io/v1"},

	// 1.26, 1.27, 1.29 and 1.32 removals (guides v1.26, v1.27, v1.29, v1.32).
	"flowcontrol.apiserver.k8s.io/v1beta1/FlowSchema":                 {Target: "flowcontrol.apiserver.k8s.io/v1beta2", Alternative: "flowcontrol.apiserver.k8s.io/v1beta3"},
	"flowcontrol.apiserver.k8s.io/v1beta1/PriorityLevelConfiguration": {Target: "flowcontrol.apiserver.k8s.io/v1beta2", Alternative: "flowcontrol.apiserver.k8s.io/v1beta3"},
	"autoscaling/v2beta2/HorizontalPodAutoscaler":                     {Target: "autoscaling/v2", Note: hpaNote},
	"storage.k8s.io/v1beta1/CSIStorageCapacity":                       {Target: "storage.k8s.io/v1"},
	"flowcontrol.apiserver.k8s.io/v1beta2/FlowSchema":                 {Target: "flowcontrol.apiserver.k8s.io/v1", Alternative: "flowcontrol.apiserver.k8s.io/v1beta3", Note: flowNote},
	"flowcontrol.apiserver.k8s.io/v1beta2/PriorityLevelConfiguration": {Target: "flowcontrol.apiserver.k8s.io/v1", Alternative: "flowcontrol.apiserver.k8s.io/v1beta3", Note: flowNote},
	"flowcontrol.apiserver.k8s.io/v1beta3/FlowSchema":                 {Target: "flowcontrol.apiserver.k8s.io/v1"},
	"flowcontrol.apiserver.k8s.io/v1beta3/PriorityLevelConfiguration": {Target: "flowcontrol.apiserver.k8s.io/v1"},

	// Removals later than the reviewed guide (1.33, 1.34, 1.37): the stable
	// version of the same group.
	"authentication.k8s.io/v1beta1/SelfSubjectReview":                       {Target: "authentication.k8s.io/v1"},
	"admissionregistration.k8s.io/v1beta1/ValidatingAdmissionPolicy":        {Target: "admissionregistration.k8s.io/v1"},
	"admissionregistration.k8s.io/v1beta1/ValidatingAdmissionPolicyBinding": {Target: "admissionregistration.k8s.io/v1"},
	"networking.k8s.io/v1beta1/IPAddress":                                   {Target: "networking.k8s.io/v1"},
	"networking.k8s.io/v1beta1/ServiceCIDR":                                 {Target: "networking.k8s.io/v1"},
	"storage.k8s.io/v1beta1/VolumeAttributesClass":                          {Target: "storage.k8s.io/v1"},
}

// genericAction is the text for a removal with no table entry.
func genericAction(group string, replacements []string) string {
	if n := len(replacements); n > 0 {
		return fmt.Sprintf("Migrate the named manifests to %s. %s %s", groupVersion(group, replacements[n-1]), reassess, validation)
	}
	return "Remove the named manifests or replace them with a kind and version the target release serves. " + reassess + " " + validation
}

type clause struct {
	h     hint
	kinds []string
}

// migrationAction returns the next action for the removed group, version and
// kinds. Kinds with the same hint share one sentence, in the order of kinds, so
// the text is a function of its arguments. A kind missing from the table gives
// the generic text for the whole rule. replacements are the versions the
// target release serves for all kinds; the table wins over them.
func migrationAction(group, version string, kinds, replacements []string) string {
	var clauses []clause
	for _, k := range kinds {
		h, ok := hints[hintKey(group, version, k)]
		if !ok {
			return genericAction(group, replacements)
		}
		placed := false
		for i := range clauses {
			if clauses[i].h == h {
				clauses[i].kinds = append(clauses[i].kinds, k)
				placed = true
				break
			}
		}
		if !placed {
			clauses = append(clauses, clause{h, []string{k}})
		}
	}
	removed := groupVersion(group, version)
	// Forms from most to least informative; the first that fits wins.
	forms := []struct {
		notes, manifests, label bool
		tail                    string
	}{
		{true, true, false, reassess + " " + validation},
		{true, true, false, compactTail},
		{true, false, false, compactTail},
		{false, true, false, reassess + " " + validation},
		{false, true, false, compactTail},
		{false, false, false, compactTail},
		{false, false, true, compactTail},
	}
	for _, f := range forms {
		parts := make([]string, 0, len(clauses)+1)
		removeOnly := false
		for _, c := range clauses {
			parts = append(parts, c.sentence(removed, f.notes, f.manifests, f.label))
			removeOnly = removeOnly || c.h.NoReplacement
		}
		text := strings.Join(parts, " ") + " " + f.tail
		if removeOnly {
			// Removal-only text carries its own closing instruction.
			text = strings.Join(parts, " ") + " " + reassess
		}
		if len(text) <= maxNextAction {
			return text
		}
	}
	return genericAction(group, replacements)
}

func (c clause) sentence(removed string, withNote, manifests, label bool) string {
	kinds := joinKinds(c.kinds)
	h := c.h
	if label && h.Label != "" {
		kinds = h.Label
	}
	if h.NoReplacement {
		return fmt.Sprintf("Remove %s (%s) from the target apply set; it has no served replacement API. Migrate to Pod Security Admission or a 3rd party admission webhook.", kinds, removed)
	}
	noun := " manifests"
	if !manifests {
		noun = ""
	}
	s := fmt.Sprintf("Migrate the named %s%s to %s", kinds, noun, h.Target)
	if h.Alternative != "" {
		// Same group: name only the other version.
		s += " or " + h.Alternative[strings.LastIndex(h.Alternative, "/")+1:]
	}
	s += "."
	if withNote && h.Note != "" {
		s += " " + h.Note
	}
	return s
}
