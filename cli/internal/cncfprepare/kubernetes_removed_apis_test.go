// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
)

type k8sFactView struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	BoolValue *bool  `json:"boolValue"`
}

func k8sProposedFacts(t *testing.T, prepared Prepared) map[string]k8sFactView {
	t.Helper()
	var envelope struct {
		Proposed struct {
			Components []struct {
				Facts []k8sFactView `json:"facts"`
			} `json:"components"`
		} `json:"proposed"`
	}
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &envelope); err != nil {
		t.Fatalf("decode canonical input: %v", err)
	}
	if len(envelope.Proposed.Components) != 1 {
		t.Fatalf("proposed components = %d", len(envelope.Proposed.Components))
	}
	out := map[string]k8sFactView{}
	for _, fact := range envelope.Proposed.Components[0].Facts {
		if _, dup := out[fact.ID]; dup {
			t.Fatalf("duplicate fact %s", fact.ID)
		}
		out[fact.ID] = fact
	}
	return out
}

func k8sList(items ...string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"apiVersion":"v1","kind":"List","items":[`)
	for i, item := range items {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(item)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

func k8sDoc(api, kind string) string {
	return `{"apiVersion":"` + api + `","kind":"` + kind + `","metadata":{"name":"x"}}`
}

func prepareK8s(t *testing.T, raw []byte, from, to string, complete bool) Prepared {
	t.Helper()
	prepared, err := PrepareKubernetesRemovedAPIs(raw, from, to, "official_upstream", true, complete)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return prepared
}

func wantBool(t *testing.T, facts map[string]k8sFactView, id string, want bool) {
	t.Helper()
	fact, ok := facts[id]
	if !ok {
		t.Fatalf("missing fact %s", id)
	}
	if fact.State != "declared" || fact.BoolValue == nil || *fact.BoolValue != want {
		t.Fatalf("fact %s = %+v, want declared %v", id, fact, want)
	}
}

func wantUnsupported(t *testing.T, facts map[string]k8sFactView, id string) {
	t.Helper()
	fact, ok := facts[id]
	if !ok {
		t.Fatalf("missing fact %s", id)
	}
	if fact.State != "unsupported" || fact.BoolValue != nil {
		t.Fatalf("fact %s = %+v, want unsupported", id, fact)
	}
}

const (
	factCronJob    = "component.kubernetes.cronjob_v1beta1_removed_gvk_present"
	factEndpoint   = "component.kubernetes.endpointslice_v1beta1_removed_gvk_present"
	factEvent      = "component.kubernetes.event_v1beta1_removed_gvk_present"
	factHPA125     = "component.kubernetes.hpa_v2beta1_removed_gvk_present"
	factPDB        = "component.kubernetes.pdb_v1beta1_removed_gvk_present"
	factPSP        = "component.kubernetes.psp_v1beta1_removed_gvk_present"
	factRuntime    = "component.kubernetes.runtimeclass_v1beta1_removed_gvk_present"
	factFlowB1     = "component.kubernetes.flowcontrol_v1beta1_removed_gvk_present"
	factHPA126     = "component.kubernetes.hpa_v2beta2_removed_gvk_present"
	factCSI        = "component.kubernetes.csistoragecapacity_v1beta1_removed_gvk_present"
	factFlowB2     = "component.kubernetes.flowcontrol_v1beta2_removed_gvk_present"
	from125, to125 = "1.24.0", "1.25.0"
)

// The established 1.31.0 -> 1.32.0 path must stay byte-identical: the new entry
// point delegates to the reviewed flow-control adapter for that pair.
func TestK8sRemovedAPIsKeepsFlowControlPathIdentical(t *testing.T) {
	inputs := [][]byte{
		k8sList(k8sDoc("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema")),
		k8sList(k8sDoc("flowcontrol.apiserver.k8s.io/v1", "FlowSchema")),
		k8sList(k8sDoc("flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema")),
	}
	for _, raw := range inputs {
		for _, complete := range []bool{true, false} {
			got, gotErr := PrepareKubernetesRemovedAPIs(raw, "1.31.0", "1.32.0", "official_upstream", true, complete)
			want, wantErr := PrepareKubernetesFlowControl(raw, "1.31.0", "1.32.0", "official_upstream", true, complete)
			if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got.CanonicalInputJSON, want.CanonicalInputJSON) || got.Reason != want.Reason || got.State != want.State {
				t.Fatalf("1.32 path diverged: got %s/%s want %s/%s", got.State, got.Reason, want.State, want.Reason)
			}
		}
	}
}

func TestK8sRemovedAPIsWitnessBlocksOnlyItsOwnFact(t *testing.T) {
	raw := k8sList(
		k8sDoc("batch/v1beta1", "CronJob"),
		k8sDoc("policy/v1", "PodDisruptionBudget"),
		k8sDoc("autoscaling/v2", "HorizontalPodAutoscaler"),
	)
	prepared := prepareK8s(t, raw, from125, to125, true)
	facts := k8sProposedFacts(t, prepared)
	wantBool(t, facts, factCronJob, true)
	for _, id := range []string{factEndpoint, factEvent, factHPA125, factPDB, factPSP, factRuntime} {
		wantBool(t, facts, id, false)
	}
	if prepared.State != StatePrepared || prepared.Reason != ReasonKubernetesRemovedGVKPresent {
		t.Fatalf("state/reason = %s/%s", prepared.State, prepared.Reason)
	}
}

func TestK8sRemovedAPIsAllServedIsAbsent(t *testing.T) {
	raw := k8sList(
		k8sDoc("batch/v1", "CronJob"),
		k8sDoc("discovery.k8s.io/v1", "EndpointSlice"),
		k8sDoc("events.k8s.io/v1", "Event"),
		k8sDoc("node.k8s.io/v1", "RuntimeClass"),
	)
	prepared := prepareK8s(t, raw, from125, to125, true)
	facts := k8sProposedFacts(t, prepared)
	for _, id := range KubernetesRemovedAPIFacts(from125, to125) {
		wantBool(t, facts, id, false)
	}
	if prepared.State != StatePrepared || prepared.Reason != ReasonKubernetesRemovedGVKAbsent {
		t.Fatalf("state/reason = %s/%s", prepared.State, prepared.Reason)
	}
}

// An unreviewed version makes only its own fact undecidable; every other fact
// in the same apply set is still declared.
func TestK8sRemovedAPIsUnreviewedVersionIsolatesOneFact(t *testing.T) {
	raw := k8sList(
		k8sDoc("autoscaling/v1", "HorizontalPodAutoscaler"),
		k8sDoc("batch/v1", "CronJob"),
	)
	prepared := prepareK8s(t, raw, from125, to125, true)
	facts := k8sProposedFacts(t, prepared)
	wantUnsupported(t, facts, factHPA125)
	for _, id := range []string{factCronJob, factEndpoint, factEvent, factPDB, factPSP, factRuntime} {
		wantBool(t, facts, id, false)
	}
	if prepared.State != StateUnknown || prepared.Reason != ReasonKubernetesGVKVersionUnreviewed {
		t.Fatalf("state/reason = %s/%s", prepared.State, prepared.Reason)
	}
}

// Same semantics as the reviewed 1.32 adapter: an unreviewed version of the
// same group and kind keeps the fact undecidable even beside a witness.
func TestK8sRemovedAPIsUnreviewedBesideWitnessStaysUnsupported(t *testing.T) {
	raw := k8sList(
		k8sDoc("autoscaling/v2beta1", "HorizontalPodAutoscaler"),
		k8sDoc("autoscaling/v1", "HorizontalPodAutoscaler"),
	)
	facts := k8sProposedFacts(t, prepareK8s(t, raw, from125, to125, true))
	wantUnsupported(t, facts, factHPA125)
}

func TestK8sRemovedAPIsCoreEventIsNotTheRemovedGroup(t *testing.T) {
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("v1", "Event")), from125, to125, true))
	wantBool(t, facts, factEvent, false)
}

func TestK8sRemovedAPIsSameGroupKindsStaySeparate(t *testing.T) {
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("policy/v1beta1", "PodDisruptionBudget")), from125, to125, true))
	wantBool(t, facts, factPDB, true)
	wantBool(t, facts, factPSP, false)

	facts = k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("policy/v1beta1", "PodSecurityPolicy")), from125, to125, true))
	wantBool(t, facts, factPSP, true)
	wantBool(t, facts, factPDB, false)
}

// PodSecurityPolicy has no served replacement in the cited source, so any other
// version of it is undecidable rather than absent.
func TestK8sRemovedAPIsPSPWithoutReplacement(t *testing.T) {
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("policy/v1", "PodSecurityPolicy")), from125, to125, true))
	wantUnsupported(t, facts, factPSP)
}

func TestK8sRemovedAPIsGuardsKeepEveryFactUnsupported(t *testing.T) {
	witness := k8sList(k8sDoc("batch/v1beta1", "CronJob"))
	cases := []struct {
		name   string
		raw    []byte
		dist   string
		target bool
		full   bool
		reason Reason
	}{
		{"incomplete set", witness, "official_upstream", true, false, ReasonKubernetesScopeIncomplete},
		{"custom distribution", witness, "custom_build", true, true, ReasonKubernetesTargetGuard},
		{"no target apply intent", witness, "official_upstream", false, true, ReasonKubernetesTargetGuard},
		{"templated", []byte(`{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"{{ .x }}"}}`), "official_upstream", true, true, ReasonKubernetesTemplated},
		{"paginated", []byte(`{"apiVersion":"v1","kind":"List","metadata":{"continue":"abc"},"items":[` + k8sDoc("batch/v1beta1", "CronJob") + `]}`), "official_upstream", true, true, ReasonKubernetesPagination},
		{"typed list", []byte(`{"apiVersion":"batch/v1","kind":"CronJobList","items":[]}`), "official_upstream", true, true, ReasonKubernetesUnresolved},
		{"nested list", k8sList(`{"apiVersion":"v1","kind":"List","items":[]}`), "official_upstream", true, true, ReasonKubernetesUnresolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKubernetesRemovedAPIs(tc.raw, from125, to125, tc.dist, tc.target, tc.full)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if prepared.State != StateUnknown || prepared.Reason != tc.reason {
				t.Fatalf("state/reason = %s/%s want UNKNOWN/%s", prepared.State, prepared.Reason, tc.reason)
			}
			facts := k8sProposedFacts(t, prepared)
			for _, id := range KubernetesRemovedAPIFacts(from125, to125) {
				wantUnsupported(t, facts, id)
			}
		})
	}
}

func TestK8sRemovedAPIsEachTransitionEmitsExactlyItsFacts(t *testing.T) {
	cases := map[[2]string][]string{
		{"1.24.0", "1.25.0"}: {factCronJob, factEndpoint, factEvent, factHPA125, factPDB, factPSP, factRuntime},
		{"1.25.0", "1.26.0"}: {factFlowB1, factHPA126},
		{"1.26.0", "1.27.0"}: {factCSI},
		{"1.28.0", "1.29.0"}: {factFlowB2},
	}
	for pair, want := range cases {
		facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("v1", "ConfigMap")), pair[0], pair[1], true))
		got := make([]string, 0, len(facts))
		for id := range facts {
			got = append(got, id)
		}
		sort.Strings(got)
		sorted := append([]string(nil), want...)
		sort.Strings(sorted)
		if len(got) != len(sorted) {
			t.Fatalf("%v facts = %v, want %v", pair, got, sorted)
		}
		for i := range got {
			if got[i] != sorted[i] {
				t.Fatalf("%v facts = %v, want %v", pair, got, sorted)
			}
		}
	}
}

func TestK8sRemovedAPIsVersionSpecificWitnesses(t *testing.T) {
	cases := []struct {
		from, to, api, kind, fact string
	}{
		{"1.25.0", "1.26.0", "flowcontrol.apiserver.k8s.io/v1beta1", "PriorityLevelConfiguration", factFlowB1},
		{"1.25.0", "1.26.0", "autoscaling/v2beta2", "HorizontalPodAutoscaler", factHPA126},
		{"1.26.0", "1.27.0", "storage.k8s.io/v1beta1", "CSIStorageCapacity", factCSI},
		{"1.28.0", "1.29.0", "flowcontrol.apiserver.k8s.io/v1beta2", "FlowSchema", factFlowB2},
	}
	for _, tc := range cases {
		facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc(tc.api, tc.kind)), tc.from, tc.to, true))
		wantBool(t, facts, tc.fact, true)
	}
	// A version still served at the target is not a witness.
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("flowcontrol.apiserver.k8s.io/v1beta3", "FlowSchema")), "1.28.0", "1.29.0", true))
	wantBool(t, facts, factFlowB2, false)
}

func TestK8sRemovedAPIsCanonicalInputIsDeterministic(t *testing.T) {
	raw := k8sList(k8sDoc("batch/v1beta1", "CronJob"), k8sDoc("policy/v1", "PodDisruptionBudget"))
	first := prepareK8s(t, raw, from125, to125, true)
	for i := 0; i < 20; i++ {
		next := prepareK8s(t, raw, from125, to125, true)
		if !bytes.Equal(first.CanonicalInputJSON, next.CanonicalInputJSON) || first.InputDigest != next.InputDigest {
			t.Fatal("canonical input is not deterministic")
		}
	}
}

func TestK8sRemovedAPIsFactIDsAreUniqueAcrossTable(t *testing.T) {
	seen := map[string][2]string{}
	for pair, removals := range kubernetesRemovalsByTransition {
		for _, removal := range removals {
			if previous, dup := seen[removal.Fact]; dup {
				t.Fatalf("fact %s reused by %v and %v", removal.Fact, previous, pair)
			}
			seen[removal.Fact] = pair
			if removal.Fact == KubernetesFlowControlFact {
				t.Fatal("the 1.32 fact must stay owned by the flow-control adapter")
			}
		}
	}
}

const from122, to122 = "1.21.0", "1.22.0"

func k8sFact122(slug string) string {
	return "component.kubernetes." + slug + "_removed_gvk_present"
}

// Ingress was removed in two groups at 1.22; each group is its own fact, and
// the served networking.k8s.io/v1 Ingress witnesses neither.
func TestK8sRemovedAPIs122IngressGroupsStaySeparate(t *testing.T) {
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("extensions/v1beta1", "Ingress")), from122, to122, true))
	wantBool(t, facts, k8sFact122("ingress_extensions_v1beta1"), true)
	wantBool(t, facts, k8sFact122("ingress_networking_v1beta1"), false)

	facts = k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("networking.k8s.io/v1beta1", "Ingress")), from122, to122, true))
	wantBool(t, facts, k8sFact122("ingress_networking_v1beta1"), true)
	wantBool(t, facts, k8sFact122("ingress_extensions_v1beta1"), false)
	wantBool(t, facts, k8sFact122("ingressclass_v1beta1"), false)

	facts = k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("networking.k8s.io/v1", "Ingress"), k8sDoc("networking.k8s.io/v1", "IngressClass")), from122, to122, true))
	for _, slug := range []string{"ingress_extensions_v1beta1", "ingress_networking_v1beta1", "ingressclass_v1beta1"} {
		wantBool(t, facts, k8sFact122(slug), false)
	}
}

// CSIStorageCapacity shares storage.k8s.io/v1beta1 but was still served at
// 1.22 (removed in 1.27), so it must not witness the 1.22 storage removal.
func TestK8sRemovedAPIs122StorageKindsOnly(t *testing.T) {
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("storage.k8s.io/v1beta1", "CSIStorageCapacity")), from122, to122, true))
	wantBool(t, facts, k8sFact122("storage_v1beta1"), false)

	facts = k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("storage.k8s.io/v1beta1", "StorageClass")), from122, to122, true))
	wantBool(t, facts, k8sFact122("storage_v1beta1"), true)
}

func TestK8sRemovedAPIs122Witnesses(t *testing.T) {
	cases := []struct{ api, kind, slug string }{
		{"admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration", "admissionwebhook_v1beta1"},
		{"apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", "crd_v1beta1"},
		{"apiregistration.k8s.io/v1beta1", "APIService", "apiservice_v1beta1"},
		{"authentication.k8s.io/v1beta1", "TokenReview", "tokenreview_v1beta1"},
		{"authorization.k8s.io/v1beta1", "SelfSubjectRulesReview", "subjectaccessreview_v1beta1"},
		{"certificates.k8s.io/v1beta1", "CertificateSigningRequest", "csr_v1beta1"},
		{"coordination.k8s.io/v1beta1", "Lease", "lease_v1beta1"},
		{"networking.k8s.io/v1beta1", "IngressClass", "ingressclass_v1beta1"},
		{"rbac.authorization.k8s.io/v1beta1", "RoleBinding", "rbac_v1beta1"},
		{"scheduling.k8s.io/v1beta1", "PriorityClass", "priorityclass_v1beta1"},
	}
	for _, tc := range cases {
		facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc(tc.api, tc.kind)), from122, to122, true))
		wantBool(t, facts, k8sFact122(tc.slug), true)
		for _, other := range KubernetesRemovedAPIFacts(from122, to122) {
			if other != k8sFact122(tc.slug) {
				wantBool(t, facts, other, false)
			}
		}
	}
	if n := len(KubernetesRemovedAPIFacts(from122, to122)); n != 13 {
		t.Fatalf("1.22 facts = %d, want 13", n)
	}
}

// extensions has no served replacement for Ingress in the cited source, so an
// Ingress in any other extensions version is undecidable, not absent.
func TestK8sRemovedAPIs122ExtensionsIngressOtherVersion(t *testing.T) {
	facts := k8sProposedFacts(t, prepareK8s(t, k8sList(k8sDoc("extensions/v1", "Ingress")), from122, to122, true))
	wantUnsupported(t, facts, k8sFact122("ingress_extensions_v1beta1"))
	wantBool(t, facts, k8sFact122("ingress_networking_v1beta1"), false)
}
