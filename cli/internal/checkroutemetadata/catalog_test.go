// SPDX-License-Identifier: AGPL-3.0-only

package checkroutemetadata

import (
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

func TestDescriptorSetBindsCompiledIdentity(t *testing.T) {
	known := map[string]bool{}
	cncf, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cncf {
		known[identityKey(FamilyCNCF, item.Project, item.Component, item.RuleID, item.From, item.To)] = true
	}
	community, err := projectcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range community {
		known[identityKey(FamilyCommunity, item.Project, item.Component, item.RuleID, item.From, item.To)] = true
	}
	for _, item := range descriptorSet() {
		if !known[identityKey(item.family, item.project, item.component, item.ruleID, item.from, item.to)] {
			t.Errorf("unbound: %#v", item)
		}
	}
}

// kubernetesExtra is how many more checks (and native routes) the embedded
// pack has once the mechanical Kubernetes rules replace the reviewed ones.
func kubernetesExtra() int {
	if supersedeids.Superseded() {
		return 4
	}
	return 0
}

// Both generations of Kubernetes descriptors name exactly the rules of their
// generation, so that whichever the pack holds is complete and exact.
func TestKubernetesDescriptorGenerations(t *testing.T) {
	reviewed := map[string]bool{}
	for _, id := range supersedeids.ReviewedIDs() {
		reviewed[id] = true
	}
	for _, item := range kubernetesReviewedDescriptors() {
		if !reviewed[item.ruleID] {
			t.Errorf("reviewed descriptor for %s", item.ruleID)
		}
		delete(reviewed, item.ruleID)
	}
	if len(reviewed) != 0 {
		t.Errorf("reviewed rules without a descriptor: %v", reviewed)
	}
	mechanical := map[string]bool{}
	for _, id := range supersedeids.ReplacementIDs() {
		mechanical[id] = true
	}
	for _, id := range supersedeids.AddedIDs() {
		mechanical[id] = true
	}
	for _, item := range kubernetesMechanicalDescriptors() {
		if !mechanical[item.ruleID] {
			t.Errorf("mechanical descriptor for %s", item.ruleID)
		}
		delete(mechanical, item.ruleID)
	}
	if len(mechanical) != 0 {
		t.Errorf("mechanical rules without a descriptor: %v", mechanical)
	}
}

func TestDiscoverCompleteEmbeddedIdentityCatalog(t *testing.T) {
	result, err := Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != Schema || len(result.Checks) != 225+kubernetesExtra() {
		t.Fatalf("catalog schema/count = %q/%d", result.Schema, len(result.Checks))
	}
	if result.Scope.SourceEvidenceFreshness != "NOT_EVALUATED" {
		t.Fatalf("freshness = %q", result.Scope.SourceEvidenceFreshness)
	}
	bound := 0
	for _, item := range result.Checks {
		if item.NativeDescriptor.State == DescriptorExact {
			bound++
		}
		if item.Family == FamilyCommunity && item.GenericDeclarationRoute.State != RouteNotExposed {
			t.Fatalf("community generic route exposed: %#v", item)
		}
	}
	if bound != 194+kubernetesExtra() {
		t.Fatalf("bound native routes = %d", bound)
	}
}

func TestDiscoverExactPairExcludesCrossMode(t *testing.T) {
	result, err := Discover("prometheus", "2.55.1", "3.14.0")
	if err != nil {
		t.Fatal(err)
	}
	bound := 0
	for _, item := range result.Checks {
		if item.NativeDescriptor.State == DescriptorExact {
			bound++
			if item.RuleID != "prometheus.remote-write-http2-default.2-55-1-to-3-14-0" {
				t.Fatalf("cross-mode native descriptor = %#v", item)
			}
		}
	}
	if bound != 1 {
		t.Fatalf("remote-write descriptor count = %d", bound)
	}
	result, err = Discover("envoy", "1.17.2", "1.18.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Checks) != 1 || result.Checks[0].NativeDescriptor.State != DescriptorNone {
		t.Fatalf("historical Envoy = %#v", result.Checks)
	}
}

func TestDiscoverRookHasNoWorkingNativeRoute(t *testing.T) {
	result, err := Discover("rook", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Checks) != 11 {
		t.Fatalf("rook rule identity count = %d", len(result.Checks))
	}
	for _, item := range result.Checks {
		if item.NativeDescriptor.State != DescriptorNone {
			t.Fatalf("rook has no working native adapter today; unexpected bound descriptor: %#v", item)
		}
		if item.GenericDeclarationRoute.State != RouteExposed {
			t.Fatalf("rook generic declaration route should remain exposed: %#v", item)
		}
	}
}

func TestDescriptorValidationRejectsUnsafeTypedCommand(t *testing.T) {
	item := descriptorSet()[0]
	item.command[0] = literal("prepare")
	if validDescriptor(item) {
		t.Fatal("accepted wrong public command guard")
	}
	item = descriptorSet()[0]
	for index := range item.command {
		if item.command[index].Kind == "timestamp_placeholder" {
			item.command[index].Name = "--at"
			break
		}
	}
	if validDescriptor(item) {
		t.Fatal("accepted wrong timestamp guard")
	}
	item = descriptorSet()[12]
	for index := range item.command {
		if item.command[index].Kind == "boolean_operator_declaration" {
			item.command[index].AllowedValues = []string{"true", "maybe"}
			break
		}
	}
	if validDescriptor(item) {
		t.Fatal("accepted unsafe boolean values")
	}
}

// identitiesOf are cncf identities for the given descriptors.
func identitiesOf(descriptors []descriptor) []cncfcheck.RuleIdentity {
	var out []cncfcheck.RuleIdentity
	for _, item := range descriptors {
		out = append(out, cncfcheck.RuleIdentity{Project: item.project, Component: item.component, RuleID: item.ruleID, From: item.from, To: item.to})
	}
	return out
}

// withoutKubernetesAPIRemovals drops both generations from the embedded
// identities.
func withoutKubernetesAPIRemovals(t *testing.T, identities []cncfcheck.RuleIdentity) []cncfcheck.RuleIdentity {
	t.Helper()
	drop := map[string]bool{}
	for _, item := range append(kubernetesReviewedDescriptors(), kubernetesMechanicalDescriptors()...) {
		drop[item.ruleID] = true
	}
	var kept []cncfcheck.RuleIdentity
	for _, item := range identities {
		if !drop[item.RuleID] {
			kept = append(kept, item)
		}
	}
	return kept
}

// A pack that holds the rules of both generations is refused by the catalog
// with ErrIntegrity, whichever way it is mixed; a pack of one generation, and
// the embedded pack, are accepted.
func TestDiscoverRefusesAMixOfBothGenerations(t *testing.T) {
	cncf, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	community, err := projectcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	base := withoutKubernetesAPIRemovals(t, cncf)
	reviewed, mechanical := identitiesOf(kubernetesReviewedDescriptors()), identitiesOf(kubernetesMechanicalDescriptors())
	pack := func(parts ...[]cncfcheck.RuleIdentity) []cncfcheck.RuleIdentity {
		out := append([]cncfcheck.RuleIdentity(nil), base...)
		for _, part := range parts {
			out = append(out, part...)
		}
		return out
	}
	for name, identities := range map[string][]cncfcheck.RuleIdentity{
		"all of both":                  pack(reviewed, mechanical),
		"all reviewed, one mechanical": pack(reviewed, mechanical[:1]),
		"all mechanical, one reviewed": pack(mechanical, reviewed[:1]),
		"one of each":                  pack(reviewed[:1], mechanical[:1]),
	} {
		if _, err := discover(identities, community, "", "", ""); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: error %v, want ErrIntegrity", name, err)
		}
	}
	for name, identities := range map[string][]cncfcheck.RuleIdentity{"reviewed": pack(reviewed), "mechanical": pack(mechanical)} {
		result, err := discover(identities, community, "", "", "")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		bound := 0
		for _, item := range result.Checks {
			if item.NativeDescriptor.State == DescriptorExact {
				bound++
			}
		}
		if want := 169 + len(identities) - len(base); bound != want {
			t.Errorf("%s: bound %d, want %d", name, bound, want)
		}
	}
}
