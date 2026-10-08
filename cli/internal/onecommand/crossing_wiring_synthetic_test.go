// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package onecommand

// Run with: go test -tags prufyx_synthetic_knowledge -run Synthetic ./internal/onecommand/

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	syntheticCrossingFact = "component.kubernetes.synthetic_crossing_probe"
	syntheticCrossingID   = "kubernetes.synthetic-crossing-probe.1-36-0-to-1-37-0"
)

// TestSyntheticCrossingPackReachesAssess drives a synthetic crossing rule in
// the pack through the production wiring: the pack loader and
// cncfcheck.EmbeddedRuleIdentities, checkroutemetadata.Discover and the
// assess version gate. Dropping the crossing from either catalogue
// (RuleIdentity or the discovered Check) fails it: the rule would be filtered
// out of discovery, or assess would call a blocked hop not applicable.
func TestSyntheticCrossingPackReachesAssess(t *testing.T) {
	const component = "pkg:github/kubernetes/kubernetes"
	rule := `{"id":"` + syntheticCrossingID + `","operator":"forbid_predicate_value","subject":{"component":"` + component + `","from":"1.36.0","to":"1.37.0"},` +
		`"crossing":{"change":{"version":"1.37.0","basis":"REMOVED_IN_RELEASE","sourceId":"synthetic-crossing-source"},"horizon":{"lt":"1.40.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"synthetic-crossing-source"}},` +
		`"condition":{"side":"proposed","component":"` + component + `","factId":"` + syntheticCrossingFact + `","boolValue":true},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"synthetic-crossing-source","url":"https://github.com/kubernetes/kubernetes/blob/0123456789abcdef0123456789abcdef01234567/pkg/features/kube_features.go","revision":"0123456789abcdef0123456789abcdef01234567","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"FEATURE_REMOVED","nextAction":"remove the synthetic probe before upgrading"}`
	entry := cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only removal crossing.",
		RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: syntheticCrossingFact, Component: component, Type: constraintengine.FactBool, Description: "Synthetic."}},
		Rule:          json.RawMessage(rule)}
	restore, err := cncfcheck.UseSyntheticKnowledge([]constraintengine.FactDefinition{{ID: syntheticCrossingFact, Component: component, Type: constraintengine.FactBool}}, []cncfcheck.Entry{entry})
	if err != nil {
		t.Fatalf("synthetic crossing pack refused: %v", err)
	}
	defer restore()

	identities, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	var identity *cncfcheck.RuleIdentity
	for i := range identities {
		if identities[i].RuleID == syntheticCrossingID {
			identity = &identities[i]
		}
	}
	if identity == nil || identity.Crossing == nil || identity.Transition().Crossing == nil {
		t.Fatalf("EmbeddedRuleIdentities dropped the crossing: %+v", identity)
	}

	result, err := checkroutemetadata.Discover("kubernetes", "1.30.0", "1.38.0")
	if err != nil {
		t.Fatal(err)
	}
	var route *checkroutemetadata.Check
	for i := range result.Checks {
		if result.Checks[i].RuleID == syntheticCrossingID {
			route = &result.Checks[i]
		}
	}
	if route == nil {
		t.Fatalf("Discover does not list the crossing rule for a hop across C: %d checks", len(result.Checks))
	}
	if route.MatchMode != "crossing" || route.Crossing == nil {
		t.Fatalf("Discover dropped the crossing: matchMode %q crossing %v", route.MatchMode, route.Crossing)
	}

	got := classifyKubernetes(CheckAssessment{Project: route.Project, From: route.From, To: route.To}, *route, kubernetesObservedBundle("1.30.2"), false, "1.38.5")
	if got.Applicability != ApplicableNeedsDeclaration || got.MatchMode != "crossing" || !strings.Contains(got.Reason, "never passes") {
		t.Fatalf("assess on the discovered route: %s mode %q (%s)", got.Applicability, got.MatchMode, got.Reason)
	}
	if got := classifyKubernetes(CheckAssessment{}, *route, kubernetesObservedBundle("1.30.2"), false, "1.41.0"); got.Applicability != IndeterminateHopOutsideReviewedRange {
		t.Fatalf("assess past the cap: %s", got.Applicability)
	}
}
