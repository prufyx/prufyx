// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

const (
	ReasonKubernetesRemovedGVKPresent    Reason = "KUBERNETES_REMOVED_GVK_PRESENT"
	ReasonKubernetesRemovedGVKAbsent     Reason = "KUBERNETES_REMOVED_GVK_ABSENT"
	ReasonKubernetesGVKVersionUnreviewed Reason = "KUBERNETES_GVK_VERSION_UNREVIEWED"
)

// kubernetesRemoval is one reviewed API removal: the named kinds in Group stop
// being served at Removed when a cluster moves into the target minor line.
// Served lists the versions of the same group and kinds that the cited source
// names as still served across the whole target minor line, not only at its
// first patch: Kubernetes removes served API versions only at minor releases,
// and a test checks every Served version against the removals this table
// records. A document of one of these kinds in any other version cannot
// establish the fact either way, so the fact stays unsupported.
type kubernetesRemoval struct {
	Fact    string
	Group   string
	Kinds   []string
	Removed string
	Served  []string
}

// kubernetesRemovalsByTargetMinor maps a target minor line to the reviewed
// removals that take effect when a cluster crosses into it. The default path
// (kubernetesRemovalsForCrossedMinorLine) selects a line by crossing exactly
// one minor boundary from any patch of the previous line to any patch of the
// target line; the published rules carry a range that constrains which of
// those crossings actually decide. kubernetesRemovalsForAnchor, the older,
// narrower selector, is kept for kubernetesRemovalsByTransition and the drift
// tests that compare the table against the rule pack's own anchors. The 1.32
// line is handled by PrepareKubernetesFlowControl and deliberately absent
// here.
var kubernetesRemovalsByTargetMinor = map[string][]kubernetesRemoval{
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

// kubernetesRemovalsByTransition is the anchor-pair view of the table: each
// target line M.m keyed by its M.(m-1).0 -> M.m.0 pair, the pair the reviewed
// rules are anchored on. It is derived, never edited, and it is the table the
// default (exact-anchor) selection in kubernetesRemovalsForAnchor reads from;
// tests also compare it against the rule pack's own anchors.
var kubernetesRemovalsByTransition = func() map[[2]string][]kubernetesRemoval {
	view := make(map[[2]string][]kubernetesRemoval, len(kubernetesRemovalsByTargetMinor))
	for line, removals := range kubernetesRemovalsByTargetMinor {
		major, minor, _ := strings.Cut(line, ".")
		number, _ := strconv.ParseUint(minor, 10, 32)
		view[[2]string{major + "." + strconv.FormatUint(number-1, 10) + ".0", line + ".0"}] = removals
	}
	return view
}()

// kubernetesRemovalsForAnchor selects the removals for exactly the reviewed
// anchor pair, M.(m-1).0 -> M.m.0. It is no longer on the default path; it
// remains for kubernetesRemovalsByTransition and the drift tests that check
// the table against the rule pack's own anchors.
func kubernetesRemovalsForAnchor(from, to string) ([]kubernetesRemoval, bool) {
	removals, reviewed := kubernetesRemovalsByTransition[[2]string{from, to}]
	return removals, reviewed
}

// kubernetesRemovalsForCrossedMinorLine selects the removals for a transition
// that crosses exactly one minor boundary within one major version: from any
// M.(m-1).x to any M.m.y. A same-line patch upgrade, a downgrade, a
// multi-minor jump, or a major crossing selects nothing. Selection never
// widens the reviewed rules: a rule still decides only transitions its own
// subject (including its published range) matches. This is the default
// selection now that the rule pack carries reviewed ranges: it emits facts
// for every crossing pair on a reviewed line, and the engine's own range
// evaluation is what actually decides whether a given off-anchor pair is
// BLOCKED, PASS, or UNKNOWN.
func kubernetesRemovalsForCrossedMinorLine(from, to string) ([]kubernetesRemoval, bool) {
	line, ok := kubernetesCrossedMinorLine(from, to)
	if !ok {
		return nil, false
	}
	removals, reviewed := kubernetesRemovalsByTargetMinor[line]
	return removals, reviewed
}

// kubernetesCrossedMinorLine returns "M.m" when from is on M.(m-1) and to is
// on M.m.
func kubernetesCrossedMinorLine(from, to string) (string, bool) {
	fromParts, fromOK := kubernetesVersionParts(from)
	toParts, toOK := kubernetesVersionParts(to)
	if !fromOK || !toOK || fromParts[0] != toParts[0] || fromParts[1]+1 != toParts[1] {
		return "", false
	}
	return strconv.FormatUint(toParts[0], 10) + "." + strconv.FormatUint(toParts[1], 10), true
}

func kubernetesVersionParts(value string) ([3]uint64, bool) {
	var parts [3]uint64
	if !validVersionSyntax(value) {
		return parts, false
	}
	for index, part := range strings.Split(value, ".") {
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return parts, false
		}
		parts[index] = number
	}
	return parts, true
}

// KubernetesRemovedAPIFacts returns the fact IDs this adapter can derive for a
// transition that crosses a reviewed minor line, in table order. It is empty
// for any pair that does not cross exactly one reviewed minor line.
func KubernetesRemovedAPIFacts(from, to string) []string {
	removals, _ := kubernetesRemovalsForCrossedMinorLine(from, to)
	facts := make([]string, 0, len(removals))
	for _, removal := range removals {
		facts = append(facts, removal.Fact)
	}
	return facts
}

// KubernetesRemovedAPIAllFacts returns every fact the rendered apply-set
// adapters derive (each reviewed removal plus the 1.32 flow-control fact),
// sorted. The native route evaluates exactly the rules over these facts, so
// rules about other Kubernetes evidence on the same transition neither run
// nor turn its result UNKNOWN.
func KubernetesRemovedAPIAllFacts() []string {
	facts := []string{KubernetesFlowControlFact}
	for _, removals := range kubernetesRemovalsByTargetMinor {
		for _, removal := range removals {
			facts = append(facts, removal.Fact)
		}
	}
	sort.Strings(facts)
	return facts
}

// PrepareKubernetesRemovedAPIs converts a bounded caller-selected rendered apply
// set to one canonical fact per reviewed API removal for a transition that
// crosses exactly one reviewed minor line. It never reads a cluster. Pairs
// that do not cross a reviewed minor line, including 1.31.0 -> 1.32.0 and any
// multi-minor jump, keep the established flow-control behaviour unchanged.
func PrepareKubernetesRemovedAPIs(raw []byte, from, to, distribution string, targetApplyRequired, complete bool) (Prepared, error) {
	if _, reviewed := kubernetesRemovalsForCrossedMinorLine(from, to); !reviewed {
		return PrepareKubernetesFlowControl(raw, from, to, distribution, targetApplyRequired, complete)
	}
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) {
		return Prepared{}, ErrInvalid
	}
	prepared, _, err := prepareKubernetesRemovedAPIs(func() (kubernetesApplySet, error) { return kubernetesApplySetFromBytes(raw) }, digestBytes(raw), from, to, distribution, targetApplyRequired, complete)
	return prepared, err
}

// prepareKubernetesRemovedAPIs is the removed-API preparation over an apply
// set that read resolves on demand, after the target guard, as the byte route
// always did. It also returns, for every fact declared true, the documents
// that made it true. It must only be called for a pair that crosses a
// reviewed minor line.
func prepareKubernetesRemovedAPIs(read func() (kubernetesApplySet, error), sourceDigest, from, to, distribution string, targetApplyRequired, complete bool) (Prepared, map[string][]intake.Source, error) {
	removals, reviewed := kubernetesRemovalsForCrossedMinorLine(from, to)
	if !reviewed {
		return Prepared{}, nil, ErrInvalid
	}
	unsupported := func() []inputFact {
		facts := make([]inputFact, 0, len(removals))
		for _, removal := range removals {
			facts = append(facts, inputFact{ID: removal.Fact, State: "unsupported"})
		}
		return facts
	}
	prepare := func(facts []inputFact, state State, reason Reason, sources map[string][]intake.Source) (Prepared, map[string][]intake.Source, error) {
		prepared, err := kubernetesRemovedPrepared(sourceDigest, from, to, facts, state, reason)
		if err != nil {
			return Prepared{}, nil, err
		}
		return prepared, sources, nil
	}
	if !targetApplyRequired || distribution != "official_upstream" {
		return prepare(unsupported(), StateUnknown, ReasonKubernetesTargetGuard, nil)
	}
	set, err := read()
	if err != nil {
		return Prepared{}, nil, ErrInvalid
	}
	if set.reason != "" {
		if !complete || set.readablePaginated {
			return prepare(unsupported(), StateUnknown, set.reason, nil)
		}
		// Some documents could not be read or placed. The documents that
		// were read still prove a removed version present: that fact is
		// declared true. They never prove one absent, so every other fact
		// stays unsupported and the set stays UNKNOWN for its own reason.
		facts := make([]inputFact, 0, len(removals))
		sources := map[string][]intake.Source{}
		for _, removal := range removals {
			present, unreviewed, matched := classifyKubernetesRemoval(set.readable, removal)
			if present && !unreviewed {
				v := true
				facts = append(facts, inputFact{ID: removal.Fact, State: "declared", BoolValue: &v})
				sources[removal.Fact] = matched
				continue
			}
			facts = append(facts, inputFact{ID: removal.Fact, State: "unsupported"})
		}
		return prepare(facts, StateUnknown, set.reason, sources)
	}
	if !complete {
		return prepare(unsupported(), StateUnknown, ReasonKubernetesScopeIncomplete, nil)
	}
	if set.paginated {
		return prepare(unsupported(), StateUnknown, ReasonKubernetesPagination, nil)
	}

	facts := make([]inputFact, 0, len(removals))
	sources := map[string][]intake.Source{}
	anyPresent, anyUnreviewed := false, false
	for _, removal := range removals {
		present, unreviewed, matched := classifyKubernetesRemoval(set.documents, removal)
		switch {
		case unreviewed:
			anyUnreviewed = true
			facts = append(facts, inputFact{ID: removal.Fact, State: "unsupported"})
		case present:
			anyPresent = true
			v := true
			facts = append(facts, inputFact{ID: removal.Fact, State: "declared", BoolValue: &v})
			sources[removal.Fact] = matched
		default:
			v := false
			facts = append(facts, inputFact{ID: removal.Fact, State: "declared", BoolValue: &v})
		}
	}
	// A present removed GVK is the decisive signal and is reported even when
	// another fact in the same set is undecidable; the undecidable fact still
	// keeps the overall state UNKNOWN.
	state, overall := StatePrepared, ReasonKubernetesRemovedGVKAbsent
	if anyUnreviewed {
		state, overall = StateUnknown, ReasonKubernetesGVKVersionUnreviewed
	}
	if anyPresent {
		overall = ReasonKubernetesRemovedGVKPresent
	}
	return prepare(facts, state, overall, sources)
}

// classifyKubernetesRemoval reports whether the removed GVK is present, and
// whether a document of the same group and kind carries a version the cited
// source does not name, which makes this one fact undecidable. matched lists
// the documents at the removed version, in apply-set order.
func classifyKubernetesRemoval(documents []kubernetesDocument, removal kubernetesRemoval) (present, unreviewed bool, matched []intake.Source) {
	for _, document := range documents {
		api, kind, _ := kubernetesGVK(document.value)
		if !containsString(removal.Kinds, kind) {
			continue
		}
		group, version, hasVersion := strings.Cut(api, "/")
		if !hasVersion || group != removal.Group {
			continue
		}
		switch {
		case version == removal.Removed:
			present = true
			matched = append(matched, document.source)
		case containsString(removal.Served, version):
		default:
			unreviewed = true
		}
	}
	return present, unreviewed, matched
}

// kubernetesDocument is one object of a rendered apply set and where it came
// from. The source never reaches a prepared input.
type kubernetesDocument struct {
	value  map[string]any
	source intake.Source
}

// kubernetesApplySet is a resolved apply set. A non-empty reason means the
// set is unresolved and documents must not be used.
type kubernetesApplySet struct {
	documents []kubernetesDocument
	paginated bool
	reason    Reason
	// readable are, for an unresolved set only, the documents that were
	// read and placed as Kubernetes objects, and readablePaginated whether
	// one of their lists is paginated. They can show that an object is
	// present, never that one is absent.
	readable          []kubernetesDocument
	readablePaginated bool
}

// kubernetesApplySetFromBytes reads the caller's apply set through the shared
// intake decoder: single or multi-document YAML or JSON, with core v1 Lists and
// typed lists flattened one level.
func kubernetesApplySetFromBytes(raw []byte) (kubernetesApplySet, error) {
	workspace, err := intake.Decode("input", raw)
	if err != nil {
		return kubernetesApplySet{}, err
	}
	return kubernetesApplySetOf(workspace), nil
}

// kubernetesApplySetOf resolves decoded documents into an apply set. Anything
// the decoder could not place as a Kubernetes object (template syntax, a
// nested list, a document that is not Kubernetes shaped, invalid list
// metadata) leaves the set unresolved. An unresolved set keeps the documents
// that were placed in readable.
func kubernetesApplySetOf(workspace intake.Workspace) kubernetesApplySet {
	var reason Reason
	for _, omission := range workspace.Omissions {
		if omission.Reason == intake.ReasonTemplated || omission.Reason == intake.ReasonUnparseable {
			reason = ReasonKubernetesTemplated
			break
		}
	}
	if reason == "" && (len(workspace.Omissions) > 0 || len(workspace.Documents) == 0) {
		reason = ReasonKubernetesUnresolved
	}
	placed := make([]kubernetesDocument, 0, len(workspace.Documents))
	paginated := false
	for _, document := range workspace.Documents {
		if _, _, ok := kubernetesGVK(document.Value); !ok {
			if reason == "" {
				reason = ReasonKubernetesUnresolved
			}
			continue
		}
		if document.Source.Item >= 0 {
			listPaginated, metadataOK := kubernetesListPagination(map[string]any{"metadata": document.ListMetadata})
			if !metadataOK {
				if reason == "" {
					reason = ReasonKubernetesUnresolved
				}
				continue
			}
			paginated = paginated || listPaginated
		}
		placed = append(placed, kubernetesDocument{value: document.Value, source: document.Source})
	}
	if reason != "" {
		return kubernetesApplySet{reason: reason, readable: appliedAsWritten(workspace, placed), readablePaginated: paginated}
	}
	return kubernetesApplySet{documents: placed, paginated: paginated}
}

// appliedAsWritten keeps, of the placed documents of an unresolved set, the
// ones that are applied as written whatever the unread documents hold. A
// document is left out when it cannot be shown to be rendered and applied
// unconditionally:
//   - its file holds an omitted document with a template control action
//     that the document does not close (the action can span the file's
//     other documents);
//   - it belongs to a raw Helm chart (a directory with a Chart.yaml) and sits
//     under templates/tests/, or under charts/ in a subchart that the
//     Chart.yaml does not list as a dependency without a condition or tags;
//   - it is a Helm test hook, which is applied only by helm test.
func appliedAsWritten(workspace intake.Workspace, placed []kubernetesDocument) []kubernetesDocument {
	spanned := map[string]bool{}
	charts := map[string]map[string]bool{} // chart directory -> unconditional subcharts
	for _, omission := range workspace.Omissions {
		if omission.OpenAction {
			spanned[omission.Source.Display] = true
		}
		if dir, ok := chartDirectory(omission.Source.Display); ok && charts[dir] == nil {
			charts[dir] = map[string]bool{}
		}
	}
	for _, auxiliary := range workspace.Auxiliary {
		dir, ok := chartDirectory(auxiliary.Source.Display)
		if !ok || auxiliary.Source.Document != 0 {
			continue
		}
		if charts[dir] == nil {
			charts[dir] = map[string]bool{}
		}
		dependencies, _ := auxiliary.Value["dependencies"].([]any)
		for _, entry := range dependencies {
			dependency, _ := entry.(map[string]any)
			name, _ := dependency["name"].(string)
			_, conditional := dependency["condition"]
			_, tagged := dependency["tags"]
			_, aliased := dependency["alias"]
			if name != "" && !conditional && !tagged && !aliased {
				charts[dir][name] = true
			}
		}
	}
	kept := make([]kubernetesDocument, 0, len(placed))
	for _, document := range placed {
		if spanned[document.source.Display] || helmTestHook(document.value) || insideConditionalChart(charts, document.source.Display) {
			continue
		}
		kept = append(kept, document)
	}
	return kept
}

// chartDirectory returns the directory of a file named Chart.yaml.
func chartDirectory(display string) (string, bool) {
	clean := path.Clean(filepath.ToSlash(display))
	if path.Base(clean) != "Chart.yaml" {
		return "", false
	}
	return path.Dir(clean), true
}

// insideConditionalChart reports whether a file of a raw chart may not be
// rendered: a test template, or a file of a subchart that is not listed as
// an unconditional dependency.
func insideConditionalChart(charts map[string]map[string]bool, display string) bool {
	clean := path.Clean(filepath.ToSlash(display))
	for dir, unconditional := range charts {
		prefix := dir + "/"
		if dir == "." {
			prefix = ""
		}
		if !strings.HasPrefix(clean, prefix) {
			continue
		}
		rest := strings.TrimPrefix(clean, prefix)
		if strings.HasPrefix(rest, "templates/tests/") {
			return true
		}
		if sub, found := strings.CutPrefix(rest, "charts/"); found {
			name, _, _ := strings.Cut(sub, "/")
			if !unconditional[name] {
				return true
			}
		}
	}
	return false
}

// helmTestHook reports a document annotated as a Helm test hook.
func helmTestHook(value map[string]any) bool {
	metadata, _ := value["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	hooks, _ := annotations["helm.sh/hook"].(string)
	for _, hook := range strings.Split(hooks, ",") {
		if strings.HasPrefix(strings.TrimSpace(hook), "test") {
			return true
		}
	}
	return false
}

// kubernetesApplySetDocuments is kubernetesApplySetFromBytes in its original
// shape: the documents, whether a list is paginated, and the reason the set is
// unresolved.
func kubernetesApplySetDocuments(raw []byte) ([]map[string]any, bool, Reason, error) {
	set, err := kubernetesApplySetFromBytes(raw)
	if err != nil {
		return nil, false, "", err
	}
	if set.reason != "" {
		return nil, false, set.reason, nil
	}
	documents := make([]map[string]any, 0, len(set.documents))
	for _, document := range set.documents {
		documents = append(documents, document.value)
	}
	return documents, set.paginated, "", nil
}

func kubernetesRemovedPrepared(sourceDigest, from, to string, facts []inputFact, state State, reason Reason) (Prepared, error) {
	if !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalid
	}
	// Sort by fact ID so the canonical input does not depend on table order.
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	canonical, err := marshalComponentInput(KubernetesComponent, from, to, facts)
	if err != nil {
		return Prepared{}, ErrInvalid
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: sourceDigest, InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{"SELECTED_RENDERED_APPLY_SET_IS_CALLER_SUPPLIED_NOT_LIVE_OBSERVATION", "CLUSTER_OBJECTS_CRDS_RUNTIME_CLIENTS_AND_STORAGE_VERSIONS_NOT_EVALUATED"}}, nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
