// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// TestScanKnowledgeMatchesPackageFunctions: the snapshot answers exactly as
// the package-level lookups over the same embedded knowledge.
func TestScanKnowledgeMatchesPackageFunctions(t *testing.T) {
	k, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	catalogue, err := Catalog(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if k.Origin() != "embedded" || k.Revision() != catalogue.KnowledgeRevision || k.PackDigest() != catalogue.KnowledgePackDigest {
		t.Fatal("snapshot identity differs from the catalogue")
	}
	if len(k.Projects()) != len(catalogue.Projects) {
		t.Fatal("project list differs")
	}
	component, ok := k.Component("kubernetes")
	want, _ := Component("kubernetes")
	if !ok || component != want {
		t.Fatalf("component %q", component)
	}
	if _, ok := k.Component("no-such-project"); ok {
		t.Fatal("unknown project has a component")
	}
	identities, err := EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, identity := range identities {
		if identity.Project == "kubernetes" {
			count++
		}
	}
	rules := k.Rules("kubernetes")
	if len(rules) != count || count == 0 {
		t.Fatalf("rules %d, identities %d", len(rules), count)
	}
	family := 0
	for index, rule := range rules {
		if index > 0 && rules[index-1].Scope.ID >= rule.Scope.ID {
			t.Fatal("rules not in id order")
		}
		if len(rule.Scope.Families) > 0 {
			family++
		}
		if rule.Description == "" || rule.NextAction == "" || rule.Project != "kubernetes" {
			t.Fatalf("rule %+v", rule)
		}
	}
	if family == 0 || family == count {
		t.Fatalf("family rules %d of %d", family, count)
	}
	statuses, err := AttestationsFor(component, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, now)
	if err != nil || len(statuses) != len(k.AttestationsFor(component, "1.25", lineattest.FamilyKubernetesRemovedServedGVK, now)) {
		t.Fatal("attestation lookup differs")
	}
	policy, err := PathPolicyFor(component, now)
	if err != nil || !reflect.DeepEqual(policy, k.PathPolicyFor(component, now)) {
		t.Fatal("path policy lookup differs")
	}
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.24.0","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"1.25.0","facts":[{"id":"component.kubernetes.cronjob_v1beta1_removed_gvk_present","state":"declared","boolValue":true}]}]}}`)
	facts := []string{"component.kubernetes.cronjob_v1beta1_removed_gvk_present"}
	viaPackage, err := CheckFacts("kubernetes", facts, input, now)
	if err != nil {
		t.Fatal(err)
	}
	viaSnapshot, err := k.CheckFacts("kubernetes", facts, input, now)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := MarshalReport(viaPackage)
	b, _ := MarshalReport(viaSnapshot)
	if string(a) != string(b) || len(a) == 0 {
		t.Fatal("snapshot evaluation differs")
	}
}
