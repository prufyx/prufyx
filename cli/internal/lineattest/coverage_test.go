// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func rangedRule(id, fromGte, fromLt, toGte, toLt string) json.RawMessage {
	rng := fmt.Sprintf(`,"range":{"from":{"gte":%q,"lt":%q},"to":{"gte":%q,"lt":%q}}`, fromGte, fromLt, toGte, toLt)
	return ruleWith(id, "1.31.0", "1.32.0", rng, "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present")
}

// A listed rule must match every transition into the line, not only exist.
func TestListedRuleMustCoverTheWholeLine(t *testing.T) {
	att := reviewed("1.32", "flow.132")
	for name, c := range map[string]struct {
		rule json.RawMessage
		wide bool
	}{
		"line-wide range":        {rangedRule("flow.132", "1.31.0", "1.32.0", "1.32.0", "1.33.0"), true},
		"wider bounds still ok":  {rangedRule("flow.132", "1.30.0", "1.32.0", "1.32.0", "1.33.0"), true},
		"anchor pair only":       {anchorRule("flow.132", "1.31.0", "1.32.0", "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"), false},
		"from starts late":       {rangedRule("flow.132", "1.31.1", "1.32.0", "1.32.0", "1.33.0"), false},
		"from ends early":        {rangedRule("flow.132", "1.31.0", "1.31.9", "1.32.0", "1.33.0"), false},
		"to starts late":         {rangedRule("flow.132", "1.31.0", "1.32.0", "1.32.1", "1.33.0"), false},
		"to ends early":          {rangedRule("flow.132", "1.31.0", "1.32.0", "1.32.0", "1.32.9"), false},
		"unparseable bound":      {rangedRule("flow.132", "1.31.x", "1.32.0", "1.32.0", "1.33.0"), false},
		"from on the wrong line": {rangedRule("flow.132", "1.30.0", "1.31.0", "1.32.0", "1.33.0"), false},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := CheckRuleSets([]LineAttestation{att}, []json.RawMessage{c.rule})
			if err != nil {
				t.Fatal(err)
			}
			if c.wide && len(p) != 0 {
				t.Fatalf("line-wide rule rejected: %+v", p)
			}
			if !c.wide && (len(p) != 1 || p[0].Kind != ProblemRuleNotLineWide || p[0].RuleID != "flow.132") {
				t.Fatalf("problems %+v, want one %s", p, ProblemRuleNotLineWide)
			}
		})
	}
	// Leaving the anchor-only rule out is a missing rule: the line cannot be
	// attested at all while the pack holds a rule that is not line-wide.
	anchor := anchorRule("flow.132", "1.31.0", "1.32.0", "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present")
	if p, _ := CheckRuleSets([]LineAttestation{reviewed("1.32")}, []json.RawMessage{anchor}); len(p) != 1 || p[0].Kind != ProblemMissingRule {
		t.Fatalf("quiet attestation over an anchor-only rule: %+v", p)
	}
}

// CoversLine agrees with the engine's matcher: a line-wide rule matches
// every sampled transition into the line, and a rule that CoversLine
// rejects misses at least one of them.
func TestCoversLineAgreesWithTheEngineMatcher(t *testing.T) {
	family, _ := LookupFamily(FamilyKubernetesRemovedServedGVK)
	froms := []string{"1.31.0", "1.31.1", "1.31.4", "1.31.99", "1.31.4294967295"}
	tos := []string{"1.32.0", "1.32.1", "1.32.7", "1.32.4294967295"}
	matchesAll := func(tr constraintengine.RuleTransition) bool {
		for _, f := range froms {
			for _, to := range tos {
				if tr.Match(f, to) == constraintengine.MatchNone {
					return false
				}
			}
		}
		return true
	}
	for _, raw := range []json.RawMessage{
		rangedRule("a", "1.31.0", "1.32.0", "1.32.0", "1.33.0"),
		rangedRule("b", "1.31.1", "1.32.0", "1.32.0", "1.33.0"),
		rangedRule("c", "1.31.0", "1.32.0", "1.32.0", "1.32.5"),
		anchorRule("d", "1.31.0", "1.32.0", "component.kubernetes.flowcontrol_v1beta3_removed_gvk_present"),
	} {
		s, err := ScopeOf(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := family.CoversLine(s.Transition, "1.32"), matchesAll(s.Transition); got != want {
			t.Fatalf("rule %s: CoversLine=%v, engine matches every sampled transition=%v", s.ID, got, want)
		}
	}
	if from, to, ok := family.LineTransitions("1.32"); !ok || from.Gte != "1.31.0" || from.Lt != "1.32.0" || to.Gte != "1.32.0" || to.Lt != "1.33.0" {
		t.Fatalf("LineTransitions(1.32) = %+v %+v %v", from, to, ok)
	}
	// A line with no previous minor line in its major cannot be covered.
	if _, _, ok := family.LineTransitions("2.0"); ok {
		t.Fatal("line 2.0 has no previous minor line")
	}
	if family.CoversLine(constraintengine.RuleTransition{Range: &constraintengine.VersionRange{From: constraintengine.VersionBound{Gte: "1.0.0", Lt: "2.0.0"}, To: constraintengine.VersionBound{Gte: "2.0.0", Lt: "2.1.0"}}}, "2.0") {
		t.Fatal("line 2.0 reported as covered")
	}
}

// Only family rules are placed on a line, so a rule of another project with
// a version that has no minor line does not break the check.
func TestNonFamilyRulesAreNotPlacedOnALine(t *testing.T) {
	odd := json.RawMessage(`{"id":"other.rule","subject":{"component":"pkg:github/x/y","from":"2024.1","to":"2024.2-rc1"},"condition":{"component":"pkg:github/x/y","factId":"component.y.thing"}}`)
	s, err := ScopeOf(odd)
	if err != nil || s.Line != "" || len(s.Families) != 0 {
		t.Fatalf("non-family rule: %+v %v", s, err)
	}
	k8sOdd := json.RawMessage(`{"id":"k8s.other","subject":{"component":"` + k8s + `","from":"1.23","to":"1.24"},"condition":{"component":"` + k8s + `","factId":"` + dockFact + `"}}`)
	if _, err := ScopeOf(k8sOdd); err != nil {
		t.Fatalf("a component rule outside the family must not need a line: %v", err)
	}
	if p, err := CheckRuleSets([]LineAttestation{reviewed("1.25", "cron.125", "mixed.125", "pdb.125")}, append(packRules(), odd, k8sOdd)); err != nil || len(p) != 0 {
		t.Fatalf("check broken by a non-family rule: %+v %v", p, err)
	}
	broken := json.RawMessage(`{"id":"k8s.broken","subject":{"component":"` + k8s + `","from":"1.24","to":"1.25"},"condition":{"component":"` + k8s + `","factId":"` + cronFact + `"}}`)
	if _, err := ScopeOf(broken); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a family rule without a release version must fail closed: %v", err)
	}
}

// A set rule that reads a family fact belongs to the family.
func TestSetRuleReadingAFamilyFactIsInTheFamily(t *testing.T) {
	raw := json.RawMessage(`{"id":"set.125","subject":{"component":"` + k8s + `","from":"1.24.0","to":"1.25.0"},"setCondition":{"side":"proposed","component":"` + k8s + `","factId":"` + cronFact + `","members":["x"]}}`)
	s, err := ScopeOf(raw)
	if err != nil || s.Line != "1.25" || !slices.Equal(s.Families, []string{FamilyKubernetesRemovedServedGVK}) {
		t.Fatalf("set rule scope %+v %v", s, err)
	}
}

func TestClassifyRejectsDuplicateScopes(t *testing.T) {
	base := mechanical("1.28", "a.rule")
	dropped := mechanical("1.28")
	if _, err := Classify([]LineAttestation{base}, []LineAttestation{dropped, base}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate scope in after collapsed: %v", err)
	}
	if _, err := Classify([]LineAttestation{dropped, base}, []LineAttestation{base}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate scope in before collapsed: %v", err)
	}
}

func TestClassifyRenewalAndRuleSwap(t *testing.T) {
	base := mechanical("1.28", "a.rule")
	swapped := mechanical("1.28", "b.rule")
	got, err := Classify([]LineAttestation{base}, []LineAttestation{swapped})
	if err != nil || len(got) != 1 || got[0].Class != Loosening || !slices.Equal(got[0].Fields, []string{"ruleIds"}) {
		t.Fatalf("same-length rule swap: %+v %v", got, err)
	}
	set := func(a LineAttestation, reviewedAt, derivedAt, until string) LineAttestation {
		a.Evidence.ReviewedAt, a.Evidence.DerivedAt, a.Evidence.ValidUntil = reviewedAt, derivedAt, until
		return a
	}
	rev := reviewed("1.28")
	for name, c := range map[string]struct {
		before, after LineAttestation
		renewal       bool
	}{
		"renewal":                     {base, set(base, "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2027-01-30T00:00:00Z"), true},
		"backdated, lease extended":   {base, set(base, "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", "2027-01-01T00:00:00Z"), false},
		"lease extended, same review": {base, set(base, base.Evidence.ReviewedAt, base.Evidence.DerivedAt, "2026-12-31T00:00:00Z"), false},
		"reviewed later, derived not": {base, set(base, "2026-11-01T00:00:00Z", base.Evidence.DerivedAt, "2027-01-30T00:00:00Z"), false},
		"reviewed renewal":            {rev, set(rev, "2026-11-01T00:00:00Z", "", "2027-01-30T00:00:00Z"), true},
		"reviewed backdated":          {rev, set(rev, "2026-09-15T00:00:00Z", "", "2027-01-01T00:00:00Z"), false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Classify([]LineAttestation{c.before}, []LineAttestation{c.after})
			if err != nil || len(got) != 1 || got[0].Class != Loosening || got[0].Renewal != c.renewal {
				t.Fatalf("got %+v %v, want loosening renewal=%v", got, err, c.renewal)
			}
		})
	}
}

func TestUnreadableTimesAreNeverCurrent(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2026-11-01T00:00:00Z")
	for _, bad := range []func(*LineAttestation){
		func(a *LineAttestation) { a.Evidence.ReviewedAt = "yesterday" },
		func(a *LineAttestation) { a.Evidence.ValidUntil = "2026-12-30" },
	} {
		a := reviewed("1.28")
		bad(&a)
		got := NewIndex([]LineAttestation{a}).AttestationsFor(k8s, "1.28", FamilyKubernetesRemovedServedGVK, now)
		if len(got) != 1 || got[0].Current() || got[0].Freshness != FreshnessStale {
			t.Fatalf("unreadable time: %+v", got)
		}
	}
}

func TestWindowBoundaryIsNinetyDays(t *testing.T) {
	at := reviewed("1.28")
	reviewedAt, _ := time.Parse(time.RFC3339, at.Evidence.ReviewedAt)
	at.Evidence.ValidUntil = reviewedAt.Add(MaxWindow).Format(time.RFC3339)
	if err := at.Validate(); err != nil {
		t.Fatalf("a window of exactly %s is rejected: %v", MaxWindow, err)
	}
	at.Evidence.ValidUntil = reviewedAt.Add(MaxWindow + time.Second).Format(time.RFC3339)
	if err := at.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a window of %s + 1s is accepted", MaxWindow)
	}
}

func TestPackSectionMatchesMemberNamesExactly(t *testing.T) {
	sec := `[{"x":1}]`
	pack := func(members ...string) []byte { return []byte(`{` + strings.Join(members, ",") + `}`) }
	got, present, err := PackSection(pack(`"schema":"s"`, `"entries":[]`, `"lineAttestations":`+sec))
	if err != nil || !present || string(got) != sec {
		t.Fatalf("section %s %v %v", got, present, err)
	}
	if got, present, err := PackSection(pack(`"schema":"s"`, `"entries":[]`)); err != nil || present || got != nil {
		t.Fatalf("absent section: %s %v %v", got, present, err)
	}
	if got, present, err := PackSection(pack(`"lineAttestations":null`)); err != nil || !present || string(got) != "null" {
		t.Fatalf("null section must be present (and then refused by Parse): %s %v %v", got, present, err)
	}
	for name, raw := range map[string][]byte{
		"capitalised":                pack(`"LineAttestations":` + sec),
		"upper case":                 pack(`"LINEATTESTATIONS":` + sec),
		"long s fold":                pack(`"lineAttestationſ":` + sec),
		"case variant beside member": pack(`"entries":[]`, `"lineAttestations":`+sec, `"Entries":[]`),
		"two spellings":              pack(`"lineAttestations":`+sec, `"LineAttestations":`+sec),
		"repeated":                   pack(`"lineAttestations":`+sec, `"lineAttestations":`+sec),
		"repeated other member":      pack(`"schema":"a"`, `"schema":"b"`),
		"unknown member":             pack(`"extra":1`),
		"case variant of other":      pack(`"Schema":"s"`),
		"not an object":              []byte(`[]`),
		"trailing data":              append(pack(`"schema":"s"`), []byte(`{}`)...),
		"empty":                      nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := PackSection(raw); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %s", raw)
			}
		})
	}
}
