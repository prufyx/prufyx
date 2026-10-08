// SPDX-License-Identifier: AGPL-3.0-only

package checkroutemetadata

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
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

func TestDiscoverCompleteEmbeddedIdentityCatalog(t *testing.T) {
	result, err := Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != Schema || len(result.Checks) != 225 {
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
	if bound != 194 {
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
