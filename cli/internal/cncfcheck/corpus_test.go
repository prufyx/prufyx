// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	containerdComponent = "pkg:github/containerd/containerd"
	otelComponent       = "pkg:github/open-telemetry/opentelemetry-collector"
	rookComponent       = "pkg:github/rook/rook"
	kubernetesComponent = "pkg:github/kubernetes/kubernetes"
	absentComponent     = "pkg:github/example/not-in-this-landscape"

	// unroutedRuleID has no EXACT_PAIR_NATIVE_ROUTE descriptor in
	// checkroutemetadata: it is one of the 31 CNCF rules the CLI exposes only
	// through the generic declaration route. It shares containerd's single
	// reviewed transition with a fully routed rule, which is what makes it the
	// right probe for "unrouted rules are never silently dropped".
	unroutedRuleID = "containerd.cri-v1alpha2-removed.2-0"
	routedRuleID   = "containerd.selected-official-runtime-shim-removed.1-7-28-to-2-0-0"
)

func testBundle(t *testing.T) bundle {
	t.Helper()
	b, err := load()
	if err != nil {
		t.Fatalf("load embedded pack: %v", err)
	}
	return b
}

func embeddedAttestation(t *testing.T) []byte {
	t.Helper()
	raw, err := attestationAsset.ReadFile(AttestationPath)
	if err != nil {
		t.Fatalf("read embedded attestation: %v", err)
	}
	return raw
}

// reattest re-serializes the embedded attestation with a mutation applied. It
// keeps every other field, including the fixed limitations, intact so a test
// exercises exactly the one property it names.
func reattest(t *testing.T, mutate func(*Attestation)) []byte {
	t.Helper()
	attestation, err := ParseAttestation(embeddedAttestation(t))
	if err != nil {
		t.Fatalf("parse embedded attestation: %v", err)
	}
	mutate(&attestation)
	raw, err := json.Marshal(attestation)
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	return raw
}

// declaredFact is one operator declaration. Exactly one of boolValue/enumValue
// is carried, matching the engine's own fact contract.
type declaredFact struct {
	id   string
	side string
	b    *bool
	e    string
}

func boolFact(id string, value bool) declaredFact {
	return declaredFact{id: id, side: "proposed", b: &value}
}
func currentBoolFact(id string, value bool) declaredFact {
	return declaredFact{id: id, side: "current", b: &value}
}
func enumFact(id, value string) declaredFact {
	return declaredFact{id: id, side: "proposed", e: value}
}

// scopeInput builds an operator-declared constraint input with a scope
// declaration over the CNCF corpus.
func scopeInput(t *testing.T, components []string, versions map[string][2]string, facts map[string][]declaredFact) []byte {
	t.Helper()
	type factJSON struct {
		ID        string `json:"id"`
		State     string `json:"state"`
		BoolValue *bool  `json:"boolValue,omitempty"`
		EnumValue string `json:"enumValue,omitempty"`
	}
	type componentJSON struct {
		Component string     `json:"component"`
		Version   string     `json:"version"`
		Facts     []factJSON `json:"facts"`
	}
	ordered := append([]string(nil), components...)
	sort.Strings(ordered)
	current := make([]componentJSON, 0, len(ordered))
	proposed := make([]componentJSON, 0, len(ordered))
	for _, component := range ordered {
		pair := versions[component]
		sides := map[string][]factJSON{"current": {}, "proposed": {}}
		for _, fact := range facts[component] {
			sides[fact.side] = append(sides[fact.side], factJSON{ID: fact.id, State: "declared", BoolValue: fact.b, EnumValue: fact.e})
		}
		for _, side := range []string{"current", "proposed"} {
			sort.Slice(sides[side], func(i, j int) bool { return sides[side][i].ID < sides[side][j].ID })
		}
		current = append(current, componentJSON{Component: component, Version: pair[0], Facts: sides["current"]})
		proposed = append(proposed, componentJSON{Component: component, Version: pair[1], Facts: sides["proposed"]})
	}
	document := map[string]any{
		"schema":    constraintengine.InputSchema,
		"authority": constraintengine.InputAuthority,
		"scope":     map[string]any{"declaration": constraintengine.ScopeDeclaration, "components": ordered},
		"current":   map[string]any{"components": current},
		"proposed":  map[string]any{"components": proposed},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	return raw
}

// containerdInput declares every fact both containerd rules read, at values
// that make both of them PASS. The unrouted rule's fact is among them.
func containerdInput(t *testing.T) []byte {
	return scopeInput(t, []string{containerdComponent},
		map[string][2]string{containerdComponent: {"1.7.28", "2.0.0"}},
		map[string][]declaredFact{containerdComponent: {
			enumFact("component.containerd.cri_api", "v1"),
			boolFact("component.containerd.official_bundled_runtimes_only", true),
			boolFact("component.containerd.official_upstream_distribution", true),
			boolFact("component.containerd.selected_runtime_uses_removed_official_shim", false),
		}})
}

// otelInput is the same shape for a component whose whole reviewed rule set is
// still current well past the corpus's first expiries.
func otelInput(t *testing.T) []byte {
	return scopeInput(t, []string{otelComponent},
		map[string][2]string{otelComponent: {"0.110.0", "0.111.0"}},
		map[string][]declaredFact{otelComponent: {
			enumFact("component.opentelemetry.distribution", "official"),
			boolFact("component.opentelemetry.logging_exporter_present", false),
			boolFact("component.opentelemetry.internal_metrics_override_absent", true),
			boolFact("component.opentelemetry.internal_metrics_localhost_remote_conflict", false),
			boolFact("component.opentelemetry.config_complete", true),
			boolFact("component.opentelemetry.config_precedence_resolved", true),
		}})
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed.UTC()
}

// TestAttestationOverAComponentWithNoRuleIsRejected is the single most
// important check in this change. "Complete" must not be trivially satisfiable
// by attesting a component the pack holds no rule for: with nothing to
// evaluate there would be nothing left unevaluated, and the aggregate would
// claim completeness over an empty applicable set.
//
// The rejection is asserted twice and independently: once through the
// constraint engine's own parser (the attestation cannot even become a rule
// document) and once through the cncfcheck binding, so neither check alone is
// load-bearing.
func TestAttestationOverAComponentWithNoRuleIsRejected(t *testing.T) {
	b := testBundle(t)
	present, err := b.corpusComponents()
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range present {
		if component == absentComponent {
			t.Fatalf("%s unexpectedly has a rule in the pack", absentComponent)
		}
	}

	// At parse time: ParseRuleSet refuses the document outright.
	vacuous := append(append([]string(nil), present...), absentComponent)
	sort.Strings(vacuous)
	raw, err := b.unfilteredRuleDocument(vacuous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := constraintengine.ParseRuleSet(raw, b.registry); !errors.Is(err, constraintengine.ErrInvalid) {
		t.Fatalf("ParseRuleSet accepted an attestation over a component with no reviewed rule: %v", err)
	}

	// And through the attestation binding, which refuses it before that.
	forged := reattest(t, func(a *Attestation) {
		a.Components = vacuous
	})
	if _, _, err := b.attestedRuleSet(forged); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("attestedRuleSet accepted a vacuous attestation: %v", err)
	}

	// And end to end: no report is produced at all.
	if _, err := assessScopeWith(b, forged, containerdInput(t), mustTime(t, "2026-09-20T00:00:00Z")); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("assessScopeWith accepted a vacuous attestation: %v", err)
	}
}

// TestEmptyAttestedComponentSetIsRejected: an attestation listing nothing at
// all is the degenerate form of the same attack.
func TestEmptyAttestedComponentSetIsRejected(t *testing.T) {
	empty := reattest(t, func(a *Attestation) { a.Components = nil })
	if _, err := ParseAttestation(empty); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ParseAttestation accepted an empty attested component set: %v", err)
	}
}

// TestAttestationPackDigestMismatchIsRejected: the attestation is bound to the
// pack it describes through the engine's own RuleSetDigest, so it cannot be
// moved onto a different or narrowed pack.
func TestAttestationPackDigestMismatchIsRejected(t *testing.T) {
	b := testBundle(t)
	cases := map[string][]byte{
		"ruleSetDigest mismatch": reattest(t, func(a *Attestation) { a.RuleSetDigest = flipDigest(a.RuleSetDigest) }),
		"packDigest mismatch":    reattest(t, func(a *Attestation) { a.PackDigest = flipDigest(a.PackDigest) }),
		"revision mismatch":      reattest(t, func(a *Attestation) { a.Revision = a.Revision + "-forged" }),
		"rule count mismatch":    reattest(t, func(a *Attestation) { a.RuleCount = a.RuleCount - 1 }),
	}
	for name, forged := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := b.attestedRuleSet(forged); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("attestedRuleSet accepted %s: %v", name, err)
			}
		})
	}
}

// TestFilteredPackCannotCarryTheAttestation pins the reason this change exists.
// rulesForAdmittedInput and selectedRuleSet narrow the pack to one project —
// and, on an exact-pair match, to that pair — before parsing; the resulting
// document's digest is not the corpus digest, so the attestation cannot be
// attached to it.
func TestFilteredPackCannotCarryTheAttestation(t *testing.T) {
	b := testBundle(t)
	corpusDigest, err := b.unfilteredRuleSetDigest()
	if err != nil {
		t.Fatal(err)
	}
	selected, err := b.selectedRuleSet("containerd", unroutedRuleID)
	if err != nil {
		t.Fatal(err)
	}
	selectedDigest, err := selected.Digest()
	if err != nil {
		t.Fatal(err)
	}
	projectOnly, err := b.ruleSet("containerd")
	if err != nil {
		t.Fatal(err)
	}
	projectDigest, err := projectOnly.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for name, digest := range map[string]string{"single rule": selectedDigest, "single project": projectDigest} {
		if digest == corpusDigest {
			t.Fatalf("a %s document produced the corpus digest; the attestation would bind to a selection", name)
		}
	}
	attestation, err := ParseAttestation(embeddedAttestation(t))
	if err != nil {
		t.Fatal(err)
	}
	if attestation.RuleSetDigest != corpusDigest {
		t.Fatalf("attestation ruleSetDigest=%s, unfiltered corpus digest=%s", attestation.RuleSetDigest, corpusDigest)
	}
	if attestation.RuleCount != len(b.pack.Entries) {
		t.Fatalf("attestation covers %d rules; the pack holds %d", attestation.RuleCount, len(b.pack.Entries))
	}
}

// TestComponentInScopeWithoutAnAttestationStaysUnknown: a declared component
// the maintainer never attested completeness for cannot reach a completeness
// verdict, however many of its rules passed.
func TestComponentInScopeWithoutAnAttestationStaysUnknown(t *testing.T) {
	b := testBundle(t)
	narrowed := reattest(t, func(a *Attestation) {
		kept := make([]string, 0, len(a.Components))
		for _, component := range a.Components {
			if component != containerdComponent {
				kept = append(kept, component)
			}
		}
		a.Components = kept
	})
	report, err := assessScopeWith(b, narrowed, containerdInput(t), mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("assessment=%q, want UNKNOWN for an unattested component", report.Assessment)
	}
	block := report.Check.ScopeCompleteness
	if block == nil || block.Resolved || block.UnresolvedReason != "SCOPE_COMPONENT_NOT_ATTESTED" {
		t.Fatalf("scope block=%+v", block)
	}
	if len(block.Components) != 1 || block.Components[0].CorpusAttested {
		t.Fatalf("components=%+v", block.Components)
	}
	// Every passing claim is still enumerated. Absence of an attestation
	// downgrades the aggregate; it does not hide the evidence.
	if len(block.Components[0].EvaluatedRuleIDs) != 2 {
		t.Fatalf("evaluated=%v", block.Components[0].EvaluatedRuleIDs)
	}
	if _, err := MarshalScopeReport(report); err != nil {
		t.Fatalf("marshal scope report: %v", err)
	}
}

// TestExpiredRuleDoesNotPoisonAnUnrelatedComponent is the property
// constraintengine/scope.go:24 warns about, exercised against the real CNCF
// corpus at a real post-expiry clock.
//
// This pack's evidence expires between 2026-12-07T12:07:56Z and
// 2026-12-12T09:29:22Z. At 2026-12-10T00:00:00Z fifty of its 167 rules have
// already expired — including one of containerd's two — while the
// opentelemetry-collector component's whole reviewed rule set is still current.
// A completeness verdict for opentelemetry must survive that: applicability
// rests on declared versions and declared fact values, never on another rule's
// evidence freshness.
func TestExpiredRuleDoesNotPoisonAnUnrelatedComponent(t *testing.T) {
	b := testBundle(t)
	now := mustTime(t, "2026-12-10T00:00:00Z")

	// Confirm the premise rather than assuming it: containerd's unrouted rule
	// really is stale at this instant, and it really is in the same corpus.
	stale, err := assessScopeWith(b, embeddedAttestation(t), containerdInput(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if stale.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("containerd assessment=%q at an expired instant, want UNKNOWN", stale.Assessment)
	}
	sawStale := false
	for _, skipped := range stale.Check.ScopeCompleteness.Components[0].NotEvaluated {
		if skipped.RuleID == unroutedRuleID {
			if skipped.ReasonCode != "RULE_EVIDENCE_STALE" {
				t.Fatalf("expected a stale containerd rule, got %+v", skipped)
			}
			sawStale = true
		}
	}
	if !sawStale {
		t.Fatalf("the expired rule was not enumerated at all: %+v", stale.Check.ScopeCompleteness.Components[0])
	}

	report, err := assessScopeWith(b, embeddedAttestation(t), otelInput(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentScopeCompletePass {
		t.Fatalf("assessment=%q, want SCOPE_COMPLETE_PASS; an expired rule elsewhere destroyed an unrelated component's verdict: %+v", report.Assessment, report.Check.ScopeCompleteness)
	}
	block := report.Check.ScopeCompleteness
	if !block.Resolved || block.UnresolvedReason != "" {
		t.Fatalf("scope block=%+v", block)
	}
	if block.OutOfScopeRules != len(b.pack.Entries)-2 {
		t.Fatalf("outOfScopeRules=%d, want %d", block.OutOfScopeRules, len(b.pack.Entries)-2)
	}
	if _, err := MarshalScopeReport(report); err != nil {
		t.Fatalf("marshal scope report: %v", err)
	}
}

// TestScopeCompletePassOverTheAttestedCorpus is the reachable happy path: a
// genuinely complete, genuinely attested component set, evaluated against the
// unfiltered corpus, with everything not evaluated enumerated.
//
// containerd is chosen deliberately: one of its two reviewed rules has no
// native descriptor, so this verdict is only honest because the unrouted rule
// was evaluated too.
func TestScopeCompletePassOverTheAttestedCorpus(t *testing.T) {
	b := testBundle(t)
	now := mustTime(t, "2026-09-20T00:00:00Z")
	report, err := assessScopeWith(b, embeddedAttestation(t), containerdInput(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentScopeCompletePass {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.Check.ScopeCompleteness)
	}
	if report.Assessment == "SAFE" {
		t.Fatal("SAFE is never a legal verdict")
	}
	block := report.Check.ScopeCompleteness
	if block == nil || !block.Resolved || block.CorpusAttestation != constraintengine.CorpusAttestation {
		t.Fatalf("scope block=%+v", block)
	}
	if len(block.Components) != 1 || !block.Components[0].CorpusAttested {
		t.Fatalf("components=%+v", block.Components)
	}
	evaluated := block.Components[0].EvaluatedRuleIDs
	if len(evaluated) != 2 || evaluated[0] != unroutedRuleID || evaluated[1] != routedRuleID {
		t.Fatalf("evaluated=%v, want both the unrouted and the routed containerd rule", evaluated)
	}
	// The corpus is unfiltered: every other rule in the pack is accounted for
	// as out of scope, not quietly dropped.
	if block.OutOfScopeRules != len(b.pack.Entries)-2 {
		t.Fatalf("outOfScopeRules=%d, want %d", block.OutOfScopeRules, len(b.pack.Entries)-2)
	}
	raw, err := MarshalScopeReport(report)
	if err != nil {
		t.Fatalf("marshal scope report: %v", err)
	}
	if strings.Contains(string(raw), `"assessment":"SAFE"`) {
		t.Fatal("report carried SAFE")
	}
	if _, err := constraintengine.MarshalReport(report.Check); err != nil {
		t.Fatalf("engine integrity gate rejected the sealed report: %v", err)
	}
}

// TestUnroutedRuleIsNeverDroppedFromTheApplicableSet is the CNCF-specific
// property, and the one this pack makes possible to get wrong.
//
// 31 of the 167 CNCF rules have NO_NATIVE_DESCRIPTOR: no config-file parser
// derives their facts, so an operator must declare those facts themselves.
// Routing is a property of the CLI, not of the corpus, and an unrouted rule is
// a reviewed constraint like any other. Silently excluding it would produce a
// SCOPE_COMPLETE_PASS over constraints nobody evaluated — exactly the
// negative-presence pass this machinery exists to refuse.
//
// Here the unrouted rule's own fact is withheld while the routed rule's facts
// are all declared. The routed rule passes; the unrouted rule must still be
// carried into the applicable set, enumerated as UNDETERMINED, and must force
// the aggregate to UNKNOWN.
func TestUnroutedRuleIsNeverDroppedFromTheApplicableSet(t *testing.T) {
	b := testBundle(t)
	withheld := scopeInput(t, []string{containerdComponent},
		map[string][2]string{containerdComponent: {"1.7.28", "2.0.0"}},
		map[string][]declaredFact{containerdComponent: {
			boolFact("component.containerd.official_bundled_runtimes_only", true),
			boolFact("component.containerd.official_upstream_distribution", true),
			boolFact("component.containerd.selected_runtime_uses_removed_official_shim", false),
		}})
	report, err := assessScopeWith(b, embeddedAttestation(t), withheld, mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment == constraintengine.AssessmentScopeCompletePass {
		t.Fatal("an unrouted rule with an undeclared fact was dropped from the applicable set and bought a SCOPE_COMPLETE_PASS")
	}
	if report.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("assessment=%q, want UNKNOWN", report.Assessment)
	}
	block := report.Check.ScopeCompleteness
	if block.Resolved || block.UnresolvedReason != "APPLICABILITY_UNDETERMINED" {
		t.Fatalf("scope block=%+v", block)
	}
	component := block.Components[0]
	if len(component.EvaluatedRuleIDs) != 1 || component.EvaluatedRuleIDs[0] != routedRuleID {
		t.Fatalf("evaluated=%v, want only the routed rule", component.EvaluatedRuleIDs)
	}
	if len(component.NotEvaluated) != 1 {
		t.Fatalf("notEvaluated=%+v", component.NotEvaluated)
	}
	skipped := component.NotEvaluated[0]
	if skipped.RuleID != unroutedRuleID {
		t.Fatalf("notEvaluated names %q, want the unrouted rule %q", skipped.RuleID, unroutedRuleID)
	}
	if skipped.Applicability != constraintengine.ApplicabilityUndetermined {
		t.Fatalf("the unrouted rule was excluded as %q; absence of a declared fact is never an exclusion", skipped.Applicability)
	}
	if skipped.ReasonCode != "RULE_FACT_UNAVAILABLE" {
		t.Fatalf("reasonCode=%q", skipped.ReasonCode)
	}
	if _, err := MarshalScopeReport(report); err != nil {
		t.Fatalf("marshal scope report: %v", err)
	}
}

// TestUnroutedRuleCanAlsoBlock: the unrouted rule is a real constraint, not a
// permanent unknown. With its fact declared at the reviewed value it decides,
// and a decided applicable blocker outranks the completeness machinery.
func TestBlockedIsReachableOverTheAttestedCorpus(t *testing.T) {
	b := testBundle(t)
	blocked := scopeInput(t, []string{containerdComponent},
		map[string][2]string{containerdComponent: {"1.7.28", "2.0.0"}},
		map[string][]declaredFact{containerdComponent: {
			enumFact("component.containerd.cri_api", "v1alpha2"),
			boolFact("component.containerd.official_bundled_runtimes_only", true),
			boolFact("component.containerd.official_upstream_distribution", true),
			boolFact("component.containerd.selected_runtime_uses_removed_official_shim", false),
		}})
	report, err := assessScopeWith(b, embeddedAttestation(t), blocked, mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentBlocked {
		t.Fatalf("assessment=%q", report.Assessment)
	}
	if _, err := MarshalScopeReport(report); err != nil {
		t.Fatal(err)
	}
}

// TestUndeclaredFactStaysUnknown: absence of evidence is UNKNOWN. A rule whose
// applicability fact was never declared is counted as unresolved, never
// assumed away and never turned into a negative-presence pass.
func TestUndeclaredFactStaysUnknown(t *testing.T) {
	b := testBundle(t)
	partial := scopeInput(t, []string{otelComponent},
		map[string][2]string{otelComponent: {"0.110.0", "0.111.0"}},
		map[string][]declaredFact{otelComponent: {
			boolFact("component.opentelemetry.logging_exporter_present", false),
		}})
	report, err := assessScopeWith(b, embeddedAttestation(t), partial, mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("assessment=%q, want UNKNOWN when a required fact was never declared", report.Assessment)
	}
	block := report.Check.ScopeCompleteness
	if block.Resolved || block.UnresolvedReason != "APPLICABILITY_UNDETERMINED" {
		t.Fatalf("scope block=%+v", block)
	}
	for _, skipped := range block.Components[0].NotEvaluated {
		if skipped.Applicability != constraintengine.ApplicabilityUndetermined {
			t.Fatalf("notEvaluated=%+v", skipped)
		}
	}
	if len(block.Components[0].EvaluatedRuleIDs) != 0 {
		t.Fatalf("evaluated=%v", block.Components[0].EvaluatedRuleIDs)
	}
}

// TestCrossComponentDependencyStaysUnknownWhenTheDependencyIsOutOfScope is the
// other CNCF-specific gap, and it is genuine rather than a routing artefact:
// rook's reviewed rules constrain the Kubernetes version, which a single-
// component rook scope does not declare at all. The rule cannot be decided, so
// it is carried as undetermined and the aggregate stays UNKNOWN.
func TestCrossComponentDependencyStaysUnknownWhenTheDependencyIsOutOfScope(t *testing.T) {
	b := testBundle(t)
	input := scopeInput(t, []string{rookComponent},
		map[string][2]string{rookComponent: {"1.19.5", "1.20.0"}},
		map[string][]declaredFact{})
	report, err := assessScopeWith(b, embeddedAttestation(t), input, mustTime(t, "2026-09-20T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentUnknown && report.Assessment != constraintengine.AssessmentBlocked {
		t.Fatalf("assessment=%q", report.Assessment)
	}
	found := false
	for _, skipped := range report.Check.ScopeCompleteness.Components[0].NotEvaluated {
		if skipped.ReasonCode == "RULE_DEPENDENCY_COMPONENT_MISSING" {
			if skipped.Applicability != constraintengine.ApplicabilityUndetermined {
				t.Fatalf("an undecidable dependency rule was excluded as %q", skipped.Applicability)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no dependency rule was enumerated as undetermined: %+v", report.Check.ScopeCompleteness.Components[0])
	}
	if _, err := MarshalScopeReport(report); err != nil {
		t.Fatal(err)
	}
}

// TestCompletenessForADependentComponentNeedsItsDependencyInScope is the
// honest counterpart to the test above, and it is the reason the reachable set
// is smaller than the attested one.
//
// rook's reviewed constraint is on the Kubernetes version, so a rook-only scope
// can never resolve. Widening the scope to {rook, kubernetes} does resolve it —
// but only because kubernetes is declared on a reviewed transition of its own
// with its own facts declared. A component dragged into scope purely to satisfy
// somebody else's dependency, on a transition nobody reviewed, would have no
// evaluated rule of its own and would send the aggregate straight back to
// UNKNOWN. Completeness is not something a wider scope buys for free.
func TestCompletenessForADependentComponentNeedsItsDependencyInScope(t *testing.T) {
	b := testBundle(t)
	now := currentKubernetesReviewClock(t, mustTime(t, "2026-09-20T00:00:00Z"))
	versions := map[string][2]string{
		rookComponent:       {"1.19.5", "1.20.0"},
		kubernetesComponent: {"1.31.0", "1.32.0"},
	}
	facts := map[string][]declaredFact{
		kubernetesComponent: {boolFact("component.kubernetes.flowcontrol_v1beta3_removed_gvk_present", false)},
	}
	// Every published Kubernetes rule on this transition needs its own fact
	// for a scope-complete result; declare the component-configuration facts
	// the pack consumes as clear as well.
	for _, fact := range cncfprepare.KubernetesComponentConfigFacts("1.31.0", "1.32.0") {
		if RegisteredFact(fact) {
			facts[kubernetesComponent] = append(facts[kubernetesComponent], boolFact(fact, false))
		}
	}
	report, err := assessScopeWith(b, embeddedAttestation(t), scopeInput(t, []string{rookComponent, kubernetesComponent}, versions, facts), now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentScopeCompletePass {
		t.Fatalf("assessment=%q scope=%+v", report.Assessment, report.Check.ScopeCompleteness)
	}
	for _, component := range report.Check.ScopeCompleteness.Components {
		if !component.CorpusAttested || len(component.EvaluatedRuleIDs) == 0 {
			t.Fatalf("component=%+v", component)
		}
	}

	// Now put the dependency on a transition nobody reviewed. Its own rules all
	// become NOT_APPLICABLE, it has nothing evaluated, and the aggregate falls
	// back to UNKNOWN rather than riding on rook's passing claim.
	versions[kubernetesComponent] = [2]string{"1.32.0", "1.33.0"}
	fallback, err := assessScopeWith(b, embeddedAttestation(t), scopeInput(t, []string{rookComponent, kubernetesComponent}, versions, map[string][]declaredFact{}), now)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("assessment=%q, want UNKNOWN for a component with no applicable rule", fallback.Assessment)
	}
	if fallback.Check.ScopeCompleteness.UnresolvedReason != "NO_APPLICABLE_RULE_FOR_COMPONENT" {
		t.Fatalf("unresolvedReason=%q", fallback.Check.ScopeCompleteness.UnresolvedReason)
	}
	if _, err := MarshalScopeReport(fallback); err != nil {
		t.Fatal(err)
	}
}

// TestScopeDeclarationIsValidatedNotTrusted: a declaration that does not match
// the caller's own declared bundle, or that names a component the pack has no
// compiled Landscape identity for, is a caller error rather than an evidence
// gap.
func TestScopeDeclarationIsValidatedNotTrusted(t *testing.T) {
	b := testBundle(t)
	attestation := embeddedAttestation(t)
	now := mustTime(t, "2026-09-20T00:00:00Z")

	t.Run("no scope declaration at all", func(t *testing.T) {
		raw := containerdInput(t)
		var document map[string]any
		if json.Unmarshal(raw, &document) != nil {
			t.Fatal("unmarshal")
		}
		delete(document, "scope")
		stripped, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assessScopeWith(b, attestation, stripped, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted an input with no scope declaration: %v", err)
		}
	})

	t.Run("scope narrower than the declared bundle", func(t *testing.T) {
		raw := scopeInput(t, []string{containerdComponent, kubernetesComponent},
			map[string][2]string{containerdComponent: {"1.7.28", "2.0.0"}, kubernetesComponent: {"1.23.17", "1.24.0"}},
			map[string][]declaredFact{})
		var document map[string]any
		if json.Unmarshal(raw, &document) != nil {
			t.Fatal("unmarshal")
		}
		document["scope"] = map[string]any{"declaration": constraintengine.ScopeDeclaration, "components": []string{containerdComponent}}
		narrowed, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assessScopeWith(b, attestation, narrowed, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted a scope narrower than its own bundle: %v", err)
		}
	})

	t.Run("component unknown to the pinned Landscape", func(t *testing.T) {
		raw := scopeInput(t, []string{absentComponent},
			map[string][2]string{absentComponent: {"1.0.0", "2.0.0"}},
			map[string][]declaredFact{})
		if _, err := assessScopeWith(b, attestation, raw, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted a component the pack has no identity for: %v", err)
		}
	})
}

// TestEmbeddedAttestationIsCurrent keeps the committed asset honest: it must be
// exactly what the maintainer command would emit for the embedded pack today.
func TestEmbeddedAttestationIsCurrent(t *testing.T) {
	built, err := BuildAttestation()
	if err != nil {
		t.Fatal(err)
	}
	committed, err := ParseAttestation(embeddedAttestation(t))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(committed)
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != string(actual) {
		t.Fatalf("committed attestation is stale; run: prufyx-maintainer corpus-attestation generate --pack cncf\nwant %s\ngot  %s", expected, actual)
	}
}

// TestUnfilteredCorpusCoversEveryPackEntry: the inventory the attestation is
// built from must see the whole pack, in a single ascending rule-id order.
//
// It also pins the ordering fact the community implementation had to work
// around: that pack's entries are ordered by (project, rule id) and needed a
// re-sort, while the CNCF pack is already in one ascending rule-id order, so
// the sort in unfilteredRules is a no-op and the document preserves pack order.
func TestUnfilteredCorpusCoversEveryPackEntry(t *testing.T) {
	b := testBundle(t)
	inventory, err := b.unfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if inventory.RuleCount != len(b.pack.Entries) {
		t.Fatalf("ruleCount=%d, pack entries=%d", inventory.RuleCount, len(b.pack.Entries))
	}
	sorted, err := b.unfilteredRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != len(b.pack.Entries) {
		t.Fatalf("document holds %d rules, pack holds %d", len(sorted), len(b.pack.Entries))
	}
	for index, raw := range sorted {
		if string(raw) != string(b.pack.Entries[index].Rule) {
			t.Fatalf("the CNCF pack is no longer in ascending rule-id order at entry %d; the re-sort is now load-bearing", index)
		}
	}
	raw, err := b.unfilteredRuleDocument(inventory.Components)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
		Corpus struct {
			Completeness string   `json:"completeness"`
			Components   []string `json:"components"`
		} `json:"corpus"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for index := 1; index < len(document.Rules); index++ {
		if document.Rules[index-1].ID >= document.Rules[index].ID {
			t.Fatalf("rules are not in a single ascending order at %d: %q then %q", index, document.Rules[index-1].ID, document.Rules[index].ID)
		}
	}
	if document.Corpus.Completeness != constraintengine.CorpusAttestation {
		t.Fatalf("corpus completeness token=%q", document.Corpus.Completeness)
	}
	if len(document.Corpus.Components) != len(inventory.Components) {
		t.Fatalf("corpus block lists %d components, inventory holds %d", len(document.Corpus.Components), len(inventory.Components))
	}
}

// TestAttestationCoversEveryUnroutedRule: the attestation is over the pack, not
// over the routed subset of it. Every component that owns an unrouted rule is
// attested, and the unfiltered document carries all 167 rules.
func TestAttestationCoversEveryUnroutedRule(t *testing.T) {
	attestation, err := ParseAttestation(embeddedAttestation(t))
	if err != nil {
		t.Fatal(err)
	}
	attested := make(map[string]struct{}, len(attestation.Components))
	for _, component := range attestation.Components {
		attested[component] = struct{}{}
	}
	identities, err := EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != attestation.RuleCount {
		t.Fatalf("attestation covers %d rules, the pack exposes %d identities", attestation.RuleCount, len(identities))
	}
	for _, identity := range identities {
		if _, ok := attested[identity.Component]; !ok {
			t.Fatalf("rule %s has a subject component the attestation omits: %s", identity.RuleID, identity.Component)
		}
	}
}

func flipDigest(value string) string {
	if value[len(value)-1] == '0' {
		return value[:len(value)-1] + "1"
	}
	return value[:len(value)-1] + "0"
}
