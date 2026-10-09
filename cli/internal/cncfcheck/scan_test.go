// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// TestScanKnowledgeMatchesPackageFunctions: the snapshot answers exactly as
// the package-level lookups over the same embedded knowledge.
func TestScanKnowledgeMatchesPackageFunctions(t *testing.T) {
	k, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	now := supersedeids.Clock()
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
	viaPolicy, err := k.CheckFactsWithPolicy(TrustPolicy{}, "kubernetes", facts, input, now)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := MarshalReport(viaPolicy)
	// The Kubernetes rules have one basis, reviewed or mechanical, depending
	// on the shipped pack; a policy of the other basis leaves them out and
	// must disclose it.
	otherBasis := "mechanical"
	if supersedeids.Superseded() {
		otherBasis = "reviewed"
	}
	mechanicalOnly, _ := ParseTrustPolicy(otherBasis)
	viaChecker, err := WithTrustPolicy(mechanicalOnly).CheckFacts("kubernetes", facts, input, now)
	if err != nil {
		t.Fatal(err)
	}
	viaMechanical, err := k.CheckFactsWithPolicy(mechanicalOnly, "kubernetes", facts, input, now)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := MarshalReport(viaChecker)
	e, _ := MarshalReport(viaMechanical)
	if string(d) != string(e) || viaMechanical.TrustPolicy == nil {
		t.Fatal("snapshot evaluation under a trust policy differs from the checker")
	}
	for _, rule := range rules {
		want := "reviewed"
		if strings.HasPrefix(rule.Scope.ID, supersedeids.MechanicalPrefix) {
			want = "mechanical"
		}
		if rule.Basis != want {
			t.Fatalf("basis %q, want %q", rule.Basis, want)
		}
	}
	a, _ := MarshalReport(viaPackage)
	b, _ := MarshalReport(viaSnapshot)
	if string(a) != string(b) || string(a) != string(c) || len(a) == 0 {
		t.Fatal("snapshot evaluation differs")
	}
}

// TestNewScanRuleBasisAndNotice: a lead is told by its basis, not as a
// one-way notice; the facts a rule reads are listed.
func TestNewScanRuleBasisAndNotice(t *testing.T) {
	lead := `{"id":"kubernetes.x","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.25.0","to":"1.26.0"},"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.hpa_v2beta2_removed_gvk_present","boolValue":true},"evidence":{"basis":"lead"},"nextAction":"x"}`
	rule, err := NewScanRule("kubernetes", "d", []byte(lead))
	if err != nil || rule.Notice || rule.Basis != "lead" || len(rule.Facts) != 1 || rule.Facts[0] != "component.kubernetes.hpa_v2beta2_removed_gvk_present" {
		t.Fatalf("lead %+v %v", rule, err)
	}
	notice := `{"id":"kubernetes.y","operator":"notice_one_way","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.25.0","to":"1.26.0"},"evidence":{},"nextAction":"x"}`
	rule, err = NewScanRule("kubernetes", "d", []byte(notice))
	if err != nil || !rule.Notice || rule.Basis != "reviewed" || len(rule.Facts) != 0 {
		t.Fatalf("notice %+v %v", rule, err)
	}
}
