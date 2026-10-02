// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const reasonSetIncomplete = "RULE_SET_FACT_INCOMPLETE"

type inputDoc struct {
	Schema    string    `json:"schema"`
	Authority string    `json:"authority"`
	Current   inputSide `json:"current"`
	Proposed  inputSide `json:"proposed"`
}

type inputSide struct {
	Components []inputComponent `json:"components"`
}

type inputComponent struct {
	Component string      `json:"component"`
	Version   string      `json:"version"`
	Facts     []inputFact `json:"facts"`
}

type inputFact struct {
	ID       string                     `json:"id"`
	State    string                     `json:"state"`
	SetValue constraintengine.SetValue `json:"setValue"`
}

// GenerateVectors derives the test vectors of one forbid_set_member entry:
//
//   - blocked: the declared set holds every forbidden member plus the pass
//     members and is NOT declared complete; presence alone blocks;
//   - pass-complete: the set holds only the pass members and is complete;
//   - unknown-incomplete: the same set, not declared complete.
func GenerateVectors(entry Entry, pass []string) ([]Vector, error) {
	rule := entry.Rule
	if rule.Operator != constraintengine.OperatorForbidSetMember || rule.SetCondition == nil {
		return nil, fmt.Errorf("rule %s: vectors are generated for forbid_set_member rules only", rule.ID)
	}
	cond := *rule.SetCondition
	for _, m := range pass {
		if slices.Contains(cond.Members, m) {
			return nil, fmt.Errorf("rule %s: pass member %s is forbidden", rule.ID, m)
		}
	}
	passSet := sortedUnique(pass)
	blockedSet := sortedUnique(append(append([]string(nil), cond.Members...), pass...))
	mk := func(kind string, members []string, complete bool, expect VectorExpect) (Vector, error) {
		if cond.Side != "proposed" {
			return Vector{}, fmt.Errorf("rule %s: vectors support proposed-side set facts only", rule.ID)
		}
		doc := inputDoc{
			Schema:    constraintengine.InputSchema,
			Authority: constraintengine.InputAuthority,
			Current:   inputSide{Components: []inputComponent{{Component: rule.Subject.Component, Version: rule.Subject.From, Facts: []inputFact{}}}},
			Proposed:  inputSide{Components: []inputComponent{{Component: rule.Subject.Component, Version: rule.Subject.To, Facts: []inputFact{{ID: cond.FactID, State: "declared", SetValue: constraintengine.SetValue{Members: members, Complete: complete}}}}}},
		}
		if cond.Component != rule.Subject.Component {
			return Vector{}, fmt.Errorf("rule %s: set fact component differs from the subject", rule.ID)
		}
		raw, err := compact(doc)
		if err != nil {
			return Vector{}, err
		}
		return Vector{Name: rule.ID + "/" + kind, RuleID: rule.ID, Kind: kind, Input: raw, Expect: expect}, nil
	}
	var out []Vector
	for _, spec := range []struct {
		kind     string
		members  []string
		complete bool
		expect   VectorExpect
	}{
		{VectorBlocked, blockedSet, false, VectorExpect{Status: "BLOCKED", ReasonCode: rule.ReasonCode, MatchedMembers: append([]string(nil), cond.Members...)}},
		{VectorPassComplete, passSet, true, VectorExpect{Status: "PASS", ReasonCode: rule.ReasonCode}},
		{VectorUnknownIncomplete, passSet, false, VectorExpect{Status: "UNKNOWN", ReasonCode: reasonSetIncomplete}},
	} {
		v, err := mk(spec.kind, spec.members, spec.complete, spec.expect)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func sortedUnique(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return slices.Compact(out)
}

// CheckVectors evaluates every vector through the constraint engine against
// its own entry and returns an error for the first vector whose claim
// differs from what it expects. now must lie inside the rules' validity.
func CheckVectors(entries []Entry, vectors []Vector, now time.Time) error {
	byID := map[string]Entry{}
	for _, e := range entries {
		byID[e.Rule.ID] = e
	}
	covered := map[string]map[string]bool{}
	for _, v := range vectors {
		entry, ok := byID[v.RuleID]
		if !ok {
			return fmt.Errorf("vector %s names an unknown rule", v.Name)
		}
		if covered[v.RuleID] == nil {
			covered[v.RuleID] = map[string]bool{}
		}
		covered[v.RuleID][v.Kind] = true
		claim, err := evaluateOne(entry, v.Input, now)
		if err != nil {
			return fmt.Errorf("vector %s: %w", v.Name, err)
		}
		if claim.Status != v.Expect.Status || claim.ReasonCode != v.Expect.ReasonCode || !slices.Equal(claim.MatchedMembers, v.Expect.MatchedMembers) {
			return fmt.Errorf("vector %s: engine says %s/%s %v, vector expects %s/%s %v", v.Name, claim.Status, claim.ReasonCode, claim.MatchedMembers, v.Expect.Status, v.Expect.ReasonCode, v.Expect.MatchedMembers)
		}
	}
	for id := range byID {
		for _, kind := range []string{VectorBlocked, VectorPassComplete, VectorUnknownIncomplete} {
			if !covered[id][kind] {
				return fmt.Errorf("rule %s has no %s vector", id, kind)
			}
		}
	}
	return nil
}

func evaluateOne(entry Entry, input json.RawMessage, now time.Time) (constraintengine.Claim, error) {
	var defs []constraintengine.FactDefinition
	seen := map[string]bool{}
	for _, f := range entry.RequiredFacts {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		defs = append(defs, constraintengine.FactDefinition{ID: f.ID, Component: f.Component, Type: constraintengine.FactType(f.Type), EnumTokens: f.EnumTokens})
	}
	registry, err := constraintengine.NewRegistry(defs)
	if err != nil {
		return constraintengine.Claim{}, err
	}
	ruleRaw, err := json.Marshal(entry.Rule)
	if err != nil {
		return constraintengine.Claim{}, err
	}
	schema, err := constraintengine.RulesSchemaFor([]json.RawMessage{ruleRaw})
	if err != nil {
		return constraintengine.Claim{}, err
	}
	doc, err := json.Marshal(map[string]any{
		"schema": schema, "revision": "extractor-vectors", "policyId": "extractor-vectors",
		"policyDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"rules":        []json.RawMessage{ruleRaw},
	})
	if err != nil {
		return constraintengine.Claim{}, err
	}
	rules, err := constraintengine.ParseRuleSet(doc, registry)
	if err != nil {
		return constraintengine.Claim{}, fmt.Errorf("engine rejected the rule: %w", err)
	}
	in, err := constraintengine.ParseInput(input, registry)
	if err != nil {
		return constraintengine.Claim{}, fmt.Errorf("engine rejected the input: %w", err)
	}
	report, err := constraintengine.Evaluate(in, rules, now)
	if err != nil {
		return constraintengine.Claim{}, err
	}
	if len(report.Claims) != 1 {
		return constraintengine.Claim{}, fmt.Errorf("engine returned %d claims", len(report.Claims))
	}
	return report.Claims[0], nil
}
