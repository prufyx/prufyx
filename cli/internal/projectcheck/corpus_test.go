// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const (
	lokiComponent     = "pkg:github/grafana/loki"
	mariadbComponent  = "pkg:github/mariadb/server"
	operatorComponent = "pkg:github/mariadb-operator/mariadb-operator"
	absentComponent   = "pkg:github/example/not-in-this-pack"
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

type declaredFact struct {
	id    string
	value bool
}

// scopeInput builds an operator-declared constraint input with a scope
// declaration. Facts land on the proposed side, which is where every rule in
// this pack reads them.
func scopeInput(t *testing.T, components []string, versions map[string][2]string, facts map[string][]declaredFact) []byte {
	t.Helper()
	type factJSON struct {
		ID        string `json:"id"`
		State     string `json:"state"`
		BoolValue *bool  `json:"boolValue,omitempty"`
	}
	type componentJSON struct {
		Component string     `json:"component"`
		Version   string     `json:"version"`
		Facts     []factJSON `json:"facts"`
	}
	current := make([]componentJSON, 0, len(components))
	proposed := make([]componentJSON, 0, len(components))
	for _, component := range components {
		pair := versions[component]
		current = append(current, componentJSON{Component: component, Version: pair[0], Facts: []factJSON{}})
		declared := make([]factJSON, 0, len(facts[component]))
		for _, fact := range facts[component] {
			value := fact.value
			declared = append(declared, factJSON{ID: fact.id, State: "declared", BoolValue: &value})
		}
		proposed = append(proposed, componentJSON{Component: component, Version: pair[1], Facts: declared})
	}
	document := map[string]any{
		"schema":    constraintengine.InputSchema,
		"authority": constraintengine.InputAuthority,
		"scope":     map[string]any{"declaration": constraintengine.ScopeDeclaration, "components": components},
		"current":   map[string]any{"components": current},
		"proposed":  map[string]any{"components": proposed},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	return raw
}

func lokiInput(t *testing.T) []byte {
	return scopeInput(t, []string{lokiComponent},
		map[string][2]string{lokiComponent: {"2.9.8", "3.0.0"}},
		map[string][]declaredFact{lokiComponent: {
			{id: "component.loki.compactor_legacy_shared_store_present", value: false},
			{id: "component.loki.structured_metadata_requires_tsdb_v13", value: false},
		}})
}

func operatorInput(t *testing.T) []byte {
	return scopeInput(t, []string{operatorComponent},
		map[string][2]string{operatorComponent: {"26.3.0", "26.6.0"}},
		map[string][]declaredFact{operatorComponent: {
			{id: "component.mariadb_operator.auto_update_data_plane", value: true},
			{id: "component.mariadb_operator.galera_enabled", value: true},
			{id: "component.mariadb_operator.pre_operator_update", value: true},
			{id: "component.mariadb_operator.replication_enabled", value: false},
			{id: "component.mariadb_operator.resource_complete", value: true},
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
// document) and once through the projectcheck binding, so neither check alone
// is load-bearing.
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
	raw, err := b.unfilteredRuleDocument(vacuous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := constraintengine.ParseRuleSet(raw, b.registry); !errors.Is(err, constraintengine.ErrInvalid) {
		t.Fatalf("ParseRuleSet accepted an attestation over a component with no reviewed rule: %v", err)
	}

	// And through the attestation binding, which refuses it before that.
	forged := reattest(t, func(a *Attestation) {
		a.Components = append(append([]string(nil), a.Components...), absentComponent)
	})
	if _, _, err := b.attestedRuleSet(forged); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("attestedRuleSet accepted a vacuous attestation: %v", err)
	}

	// And end to end: no report is produced at all.
	if _, err := assessScopeWith(b, forged, lokiInput(t), mustTime(t, "2026-09-20T00:00:00Z")); !errors.Is(err, ErrIntegrity) {
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
// ruleSetSelected narrows the pack to one project and one exact version pair
// before parsing; the resulting document's digest is not the corpus digest, so
// the attestation cannot be attached to it.
func TestFilteredPackCannotCarryTheAttestation(t *testing.T) {
	b := testBundle(t)
	selected, count, err := b.ruleSet("loki", "2.9.8", "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("selected %d loki rules, want 2", count)
	}
	selectedDigest, err := selected.Digest()
	if err != nil {
		t.Fatal(err)
	}
	corpusDigest, err := b.unfilteredRuleSetDigest()
	if err != nil {
		t.Fatal(err)
	}
	if selectedDigest == corpusDigest {
		t.Fatal("a filtered rule document produced the corpus digest; the attestation would bind to a selection")
	}
	attestation, err := ParseAttestation(embeddedAttestation(t))
	if err != nil {
		t.Fatal(err)
	}
	if attestation.RuleSetDigest != corpusDigest {
		t.Fatalf("attestation ruleSetDigest=%s, unfiltered corpus digest=%s", attestation.RuleSetDigest, corpusDigest)
	}
	if attestation.RuleCount != len(b.pack.Entries) || attestation.RuleCount <= count {
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
			if component != lokiComponent {
				kept = append(kept, component)
			}
		}
		a.Components = kept
	})
	report, err := assessScopeWith(b, narrowed, lokiInput(t), mustTime(t, "2026-09-20T00:00:00Z"))
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

// TestExpiredRuleDoesNotPoisonAnUnrelatedComponent is the property scope.go:24
// warns about, exercised against the real corpus at a real expiry boundary.
//
// This pack's evidence expires between 2026-12-10T19:30:00Z and
// 2026-12-12T08:16:03Z. At 2026-12-11T13:00:00Z every rule in the pack has
// expired except the mariadb-operator rule. A completeness verdict for
// mariadb-operator must survive that: applicability rests on declared versions
// and declared fact values, never on another rule's evidence freshness.
func TestExpiredRuleDoesNotPoisonAnUnrelatedComponent(t *testing.T) {
	b := testBundle(t)
	now := mustTime(t, "2026-12-11T13:00:00Z")

	// Confirm the premise rather than assuming it: loki's rules really are
	// stale at this instant, and they really are in the same corpus.
	stale, err := assessScopeWith(b, embeddedAttestation(t), lokiInput(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if stale.Assessment != constraintengine.AssessmentUnknown {
		t.Fatalf("loki assessment=%q at an expired instant, want UNKNOWN", stale.Assessment)
	}
	for _, skipped := range stale.Check.ScopeCompleteness.Components[0].NotEvaluated {
		if skipped.RuleID == "loki.compactor-shared-store.2-9-to-3-0" && skipped.ReasonCode != "RULE_EVIDENCE_STALE" {
			t.Fatalf("expected a stale loki rule, got %+v", skipped)
		}
	}

	report, err := assessScopeWith(b, embeddedAttestation(t), operatorInput(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Assessment != constraintengine.AssessmentScopeCompletePass {
		t.Fatalf("assessment=%q, want SCOPE_COMPLETE_PASS; one expired rule elsewhere destroyed an unrelated component's verdict: %+v", report.Assessment, report.Check.ScopeCompleteness)
	}
	block := report.Check.ScopeCompleteness
	if !block.Resolved || block.UnresolvedReason != "" {
		t.Fatalf("scope block=%+v", block)
	}
	if block.OutOfScopeRules != len(b.pack.Entries)-1 {
		t.Fatalf("outOfScopeRules=%d, want %d", block.OutOfScopeRules, len(b.pack.Entries)-1)
	}
	if _, err := MarshalScopeReport(report); err != nil {
		t.Fatalf("marshal scope report: %v", err)
	}
}

// TestScopeCompletePassOverTheAttestedCorpus is the reachable happy path: a
// genuinely complete, genuinely attested component set, evaluated against the
// unfiltered corpus, with everything not evaluated enumerated.
func TestScopeCompletePassOverTheAttestedCorpus(t *testing.T) {
	b := testBundle(t)
	now := mustTime(t, "2026-09-20T00:00:00Z")
	report, err := assessScopeWith(b, embeddedAttestation(t), lokiInput(t), now)
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
	if len(block.Components) != 1 || !block.Components[0].CorpusAttested || len(block.Components[0].EvaluatedRuleIDs) != 2 {
		t.Fatalf("components=%+v", block.Components)
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

// TestBlockedIsReachableOverTheAttestedCorpus: a decided applicable blocker
// still outranks the completeness machinery.
func TestBlockedIsReachableOverTheAttestedCorpus(t *testing.T) {
	b := testBundle(t)
	blocked := scopeInput(t, []string{lokiComponent},
		map[string][2]string{lokiComponent: {"2.9.8", "3.0.0"}},
		map[string][]declaredFact{lokiComponent: {
			{id: "component.loki.compactor_legacy_shared_store_present", value: true},
			{id: "component.loki.structured_metadata_requires_tsdb_v13", value: false},
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

// TestScopeDeclarationIsValidatedNotTrusted: a declaration that does not match
// the caller's own declared bundle, or that names a component the corpus has
// no identity for, is a caller error rather than an evidence gap.
func TestScopeDeclarationIsValidatedNotTrusted(t *testing.T) {
	b := testBundle(t)
	attestation := embeddedAttestation(t)
	now := mustTime(t, "2026-09-20T00:00:00Z")

	t.Run("no scope declaration at all", func(t *testing.T) {
		raw := lokiInput(t)
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
		raw := scopeInput(t, []string{lokiComponent, mariadbComponent},
			map[string][2]string{lokiComponent: {"2.9.8", "3.0.0"}, mariadbComponent: {"10.11.8", "11.4.2"}},
			map[string][]declaredFact{})
		var document map[string]any
		if json.Unmarshal(raw, &document) != nil {
			t.Fatal("unmarshal")
		}
		document["scope"] = map[string]any{"declaration": constraintengine.ScopeDeclaration, "components": []string{lokiComponent}}
		narrowed, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := assessScopeWith(b, attestation, narrowed, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted a scope narrower than its own bundle: %v", err)
		}
	})

	t.Run("component unknown to the corpus", func(t *testing.T) {
		raw := scopeInput(t, []string{absentComponent},
			map[string][2]string{absentComponent: {"1.0.0", "2.0.0"}},
			map[string][]declaredFact{})
		if _, err := assessScopeWith(b, attestation, raw, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted a component the corpus has no identity for: %v", err)
		}
	})
}

// TestUndeclaredFactStaysUnknown: absence of evidence is UNKNOWN. A rule whose
// applicability fact was never declared is counted as unresolved, never
// assumed away and never turned into a negative-presence pass.
func TestUndeclaredFactStaysUnknown(t *testing.T) {
	b := testBundle(t)
	partial := scopeInput(t, []string{operatorComponent},
		map[string][2]string{operatorComponent: {"26.3.0", "26.6.0"}},
		map[string][]declaredFact{operatorComponent: {
			{id: "component.mariadb_operator.galera_enabled", value: true},
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
	skipped := block.Components[0].NotEvaluated
	if len(skipped) != 1 || skipped[0].Applicability != constraintengine.ApplicabilityUndetermined {
		t.Fatalf("notEvaluated=%+v", skipped)
	}
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
		t.Fatalf("committed attestation is stale; run: prufyx-maintainer corpus-attestation generate\nwant %s\ngot  %s", expected, actual)
	}
}

// TestUnfilteredCorpusCoversEveryPackEntry: the inventory the attestation is
// built from must see the whole pack, in a single ascending rule-id order.
func TestUnfilteredCorpusCoversEveryPackEntry(t *testing.T) {
	b := testBundle(t)
	inventory, err := b.unfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if inventory.RuleCount != len(b.pack.Entries) {
		t.Fatalf("ruleCount=%d, pack entries=%d", inventory.RuleCount, len(b.pack.Entries))
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
	if len(document.Rules) != len(b.pack.Entries) {
		t.Fatalf("document holds %d rules, pack holds %d", len(document.Rules), len(b.pack.Entries))
	}
	for index := 1; index < len(document.Rules); index++ {
		if document.Rules[index-1].ID >= document.Rules[index].ID {
			t.Fatalf("rules are not in a single ascending order at %d: %q then %q", index, document.Rules[index-1].ID, document.Rules[index].ID)
		}
	}
	if document.Corpus.Completeness != constraintengine.CorpusAttestation {
		t.Fatalf("corpus completeness token=%q", document.Corpus.Completeness)
	}
}

func flipDigest(value string) string {
	if value[len(value)-1] == '0' {
		return value[:len(value)-1] + "1"
	}
	return value[:len(value)-1] + "0"
}
