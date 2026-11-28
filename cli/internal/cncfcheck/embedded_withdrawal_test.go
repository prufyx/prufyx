// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The embedded pack holds this rule withdrawn.
const (
	withdrawnTestProject = "cri-o"
	withdrawnTestRule    = "cri-o.artifact-short-name-rejected.1-35"
)

// storeWithRule is the cri-o target of a store whose pack is the packaged one
// with edit applied to the withdrawn rule.
func storeWithRule(t *testing.T, edit func(subject, evidence map[string]any)) ExternalBundle {
	t.Helper()
	raw, err := packagedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, item := range pack["entries"].([]any) {
		rule := item.(map[string]any)["rule"].(map[string]any)
		if rule["id"] != withdrawnTestRule {
			continue
		}
		evidence := rule["evidence"].(map[string]any)
		if evidence["state"] != "withdrawn" {
			t.Fatalf("the packaged %s is %v; this test needs a withdrawn rule", withdrawnTestRule, evidence["state"])
		}
		edit(rule["subject"].(map[string]any), evidence)
		found++
	}
	if found != 1 {
		t.Fatalf("%d rules %s", found, withdrawnTestRule)
	}
	edited, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	_, targets, err := BuildExternalTargetsFromPack(edited, "99")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.Path == ProjectTargetPath(withdrawnTestProject) {
			bundle, err := ParseExternalBundle(target.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			return bundle
		}
	}
	t.Fatal("no cri-o target")
	return ExternalBundle{}
}

// embeddedReview is the review time of the packaged withdrawn rule.
func embeddedReview(t *testing.T) time.Time {
	t.Helper()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range base.pack.Entries {
		review, at, err := reviewOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		if review.ID == withdrawnTestRule {
			return at
		}
	}
	t.Fatal("rule not embedded")
	return time.Time{}
}

func crioInput(to string, short bool) []byte {
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED",` +
		`"current":{"components":[{"component":"pkg:github/cri-o/cri-o","version":"1.34.0","facts":[]}]},` +
		`"proposed":{"components":[{"component":"pkg:github/cri-o/cri-o","version":"` + to + `","facts":[` +
		`{"id":"component.crio.artifact_named_reference_is_short","state":"declared","boolValue":` + strconv.FormatBool(short) + `},` +
		`{"id":"component.crio.artifact_named_reference_resolution_planned","state":"declared","boolValue":true}]}]}}`)
}

// everyStoreRoute evaluates the withdrawn rule's transition through the three
// ways a store target is evaluated: a check, a selected-rule check and a scan.
func everyStoreRoute(t *testing.T, store ExternalBundle, to string, short bool, now time.Time) map[string]Report {
	t.Helper()
	input := crioInput(to, short)
	check, err := store.Evaluate(withdrawnTestProject, input, now)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	selected, err := store.EvaluateRule(withdrawnTestProject, withdrawnTestRule, input, now)
	if err != nil {
		t.Fatalf("selected rule: %v", err)
	}
	snapshot, err := NewStoreScanKnowledge(map[string]ExternalBundle{withdrawnTestProject: store})
	if err != nil {
		t.Fatalf("scan knowledge: %v", err)
	}
	scan, err := snapshot.CheckFacts(withdrawnTestProject, []string{"component.crio.artifact_named_reference_is_short", "component.crio.artifact_named_reference_resolution_planned"}, input, now)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return map[string]Report{"check": check, "selected rule": selected, "scan": scan}
}

// A store signed before this build withdrew a rule cannot make it active
// again: neither PASS nor BLOCKED, on any route.
func TestStoreCannotUnwithdrawEmbeddedWithdrawal(t *testing.T) {
	t.Parallel()
	reviewed := embeddedReview(t)
	now := reviewed.Add(24 * time.Hour)
	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339) }
	for name, c := range map[string]struct {
		to   string
		edit func(subject, evidence map[string]any)
	}{
		"same review date": {"1.35.0", func(_, e map[string]any) { e["state"] = "active" }},
		"earlier review date": {"1.35.0", func(_, e map[string]any) {
			// The validity moves too: a lease has a longest span.
			e["state"], e["reviewedAt"], e["validUntil"] = "active", stamp(reviewed.Add(-time.Second)), stamp(reviewed.Add(80*24*time.Hour))
		}},
		"other validity only": {"1.35.0", func(_, e map[string]any) {
			e["state"], e["validUntil"] = "active", stamp(reviewed.Add(80*24*time.Hour))
		}},
		"other transition, same review date": {"1.35.1", func(s, e map[string]any) {
			s["to"], e["state"] = "1.35.1", "active"
		}},
		"store withdrawn too": {"1.35.0", func(_, _ map[string]any) {}},
	} {
		store := storeWithRule(t, c.edit)
		for _, short := range []bool{false, true} {
			for route, report := range everyStoreRoute(t, store, c.to, short, now) {
				claims := report.Check.Claims
				if len(claims) != 1 || claims[0].RuleID != withdrawnTestRule || claims[0].Status != "UNKNOWN" || claims[0].ReasonCode != "RULE_EVIDENCE_WITHDRAWN" || claims[0].EvidenceFreshness != "withdrawn" {
					t.Fatalf("%s, %s, short=%v: claims %+v", name, route, short, claims)
				}
				if exit := ClaimExit(report); exit != 11 {
					t.Fatalf("%s, %s, short=%v: exit %d", name, route, short, exit)
				}
			}
		}
		// The admitted envelope is not changed by an evaluation.
		if !store.valid() {
			t.Fatalf("%s: envelope changed", name)
		}
	}
}

// A strictly later review of the rule is the only thing that makes a store
// rule active again.
func TestStoreLaterReviewKeepsRuleActive(t *testing.T) {
	t.Parallel()
	reviewed := embeddedReview(t)
	store := storeWithRule(t, func(_, e map[string]any) {
		e["state"], e["reviewedAt"] = "active", reviewed.Add(time.Second).UTC().Format(time.RFC3339)
	})
	now := reviewed.Add(24 * time.Hour)
	for short, want := range map[bool]string{false: "PASS", true: "BLOCKED"} {
		for route, report := range everyStoreRoute(t, store, "1.35.0", short, now) {
			if claims := report.Check.Claims; len(claims) != 1 || claims[0].Status != want {
				t.Fatalf("%s short=%v: claims %+v, want %s", route, short, claims, want)
			}
		}
	}
}

// Every rule the embedded pack withdraws binds a store, not one of them only:
// a store pack that holds all of them as active, with their embedded review
// dates, evaluates each as withdrawn.
func TestStoreCannotUnwithdrawAnyEmbeddedWithdrawal(t *testing.T) {
	t.Parallel()
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	withdrawn := map[string]Entry{}
	for _, entry := range base.pack.Entries {
		review, _, err := reviewOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		if review.Evidence.State == "withdrawn" {
			withdrawn[review.ID] = entry
		}
	}
	if len(withdrawn) == 0 {
		t.Fatal("the embedded pack withdraws no rule; this test needs one")
	}
	raw, err := packagedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	for _, item := range pack["entries"].([]any) {
		rule := item.(map[string]any)["rule"].(map[string]any)
		if _, held := withdrawn[rule["id"].(string)]; held {
			rule["evidence"].(map[string]any)["state"] = "active"
		}
	}
	edited, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	_, targets, err := BuildExternalTargetsFromPack(edited, "99")
	if err != nil {
		t.Fatal(err)
	}
	stores := map[string]ExternalBundle{}
	for _, target := range targets {
		project, _ := ProjectFromTargetPath(target.Path)
		for _, entry := range withdrawn {
			if entry.Project != project {
				continue
			}
			if stores[project], err = ParseExternalBundle(target.Bytes); err != nil {
				t.Fatal(err)
			}
		}
	}
	for id, entry := range withdrawn {
		store, ok := stores[entry.Project]
		if !ok {
			t.Fatalf("%s: no store target", id)
		}
		subject, err := constraintengine.RuleTransitionOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := NewStoreScanKnowledge(map[string]ExternalBundle{entry.Project: store})
		if err != nil {
			t.Fatal(err)
		}
		held := 0
		for _, selected := range snapshot.selected[entry.Project].pack.Entries {
			review, _, err := reviewOf(selected.Rule)
			if err != nil {
				t.Fatal(err)
			}
			if review.ID != id {
				continue
			}
			held++
			if review.Evidence.State != "withdrawn" {
				t.Fatalf("%s: scan evaluates it as %s", id, review.Evidence.State)
			}
		}
		if held != 1 {
			t.Fatalf("%s: %d rules in the scan selection", id, held)
		}
		// A withdrawn rule answers before any version or fact is read.
		component := `{"components":[{"component":"` + subject.Component + `","version":"1.0.0","facts":[]}]}`
		input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":` + component + `,"proposed":` + component + `}`)
		_, at, err := reviewOf(entry.Rule)
		if err != nil {
			t.Fatal(err)
		}
		report, err := store.EvaluateRule(entry.Project, id, input, at.Add(24*time.Hour))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if claims := report.Check.Claims; len(claims) != 1 || claims[0].Status != "UNKNOWN" || claims[0].ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
			t.Fatalf("%s: claims %+v", id, claims)
		}
	}
}

func TestEmbeddedWithdrawalsOverPack(t *testing.T) {
	t.Parallel()
	entry := func(project, rule string) Entry { return Entry{Project: project, Rule: json.RawMessage(rule)} }
	const (
		gone   = `{"id":"a.rule","evidence":{"state":"withdrawn","reviewedAt":"2026-09-02T00:00:00Z"}}`
		active = `{"id":"a.rule","evidence":{"state":"active","reviewedAt":"2026-09-02T00:00:00Z"}}`
		other  = `{"id":"b.rule","evidence":{"state":"active","reviewedAt":"2026-09-01T00:00:00Z"}}`
	)
	embedded := rulePack{Entries: []Entry{entry("a", gone)}}
	external := rulePack{Entries: []Entry{entry("moved", active), entry("a", other)}}
	out, err := packWithEmbeddedWithdrawals(embedded, external)
	if err != nil {
		t.Fatal(err)
	}
	// Matched by id in any project; other rules are untouched; a rule the
	// store does not hold is not added.
	if review, _, err := reviewOf(out.Entries[0].Rule); err != nil || review.Evidence.State != "withdrawn" || len(out.Entries) != 2 || string(out.Entries[1].Rule) != other {
		t.Fatalf("entries %s / %s (%v)", out.Entries[0].Rule, out.Entries[1].Rule, err)
	}
	if string(external.Entries[0].Rule) != active {
		t.Fatalf("the store's entries were changed: %s", external.Entries[0].Rule)
	}
	for name, rule := range map[string]string{
		"no review time":      `{"id":"a.rule","evidence":{"state":"active"}}`,
		"bad review time":     `{"id":"a.rule","evidence":{"state":"active","reviewedAt":"later"}}`,
		"no state":            `{"id":"a.rule","evidence":{"reviewedAt":"2026-09-03T00:00:00Z"}}`,
		"no id":               `{"evidence":{"state":"active","reviewedAt":"2026-09-03T00:00:00Z"}}`,
		"aliased state":       `{"id":"a.rule","evidence":{"State":"active","reviewedAt":"2026-09-02T00:00:00Z"}}`,
		"aliased evidence":    `{"id":"a.rule","Evidence":{"state":"active","reviewedAt":"2026-09-02T00:00:00Z"}}`,
		"evidence not object": `{"id":"a.rule","evidence":"active"}`,
		// Not UTC: refused, whether the instant is the same or later.
		"offset, same instant":  `{"id":"a.rule","evidence":{"state":"active","reviewedAt":"2026-09-02T02:00:00+02:00"}}`,
		"offset, later instant": `{"id":"a.rule","evidence":{"state":"active","reviewedAt":"2026-09-03T00:00:00-01:00"}}`,
		"zero offset":           `{"id":"a.rule","evidence":{"state":"active","reviewedAt":"2026-09-03T00:00:00+00:00"}}`,
		"fraction":              `{"id":"a.rule","evidence":{"state":"active","reviewedAt":"2026-09-02T00:00:00.5Z"}}`,
	} {
		if _, err := packWithEmbeddedWithdrawals(embedded, rulePack{Entries: []Entry{entry("a", rule)}}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("store %s: %v", name, err)
		}
	}
	if _, err := packWithEmbeddedWithdrawals(rulePack{Entries: []Entry{entry("a", `{"id":"a.rule"}`)}}, external); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unreadable embedded rule: %v", err)
	}
}
