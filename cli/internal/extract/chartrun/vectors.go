// SPDX-License-Identifier: AGPL-3.0-only

package chartrun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	reasonSetIncomplete     = "RULE_SET_FACT_INCOMPLETE"
	reasonDependencyMissing = "RULE_DEPENDENCY_COMPONENT_MISSING"
	dependencyOperator      = "require_component_version"
)

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
	Component string                     `json:"component"`
	Chart     *constraintengine.ChartRef `json:"chart,omitempty"`
	Version   string                     `json:"version"`
	Facts     []inputFact                `json:"facts"`
}

type inputFact struct {
	ID       string                     `json:"id"`
	State    string                     `json:"state"`
	SetValue *constraintengine.SetValue `json:"setValue,omitempty"`
}

// GenerateVectors derives the three test vectors (extract.VectorBlocked,
// extract.VectorPassComplete, extract.VectorUnknownIncomplete) of one chart
// entry. The rule's subject component is declared through the rule's chart
// on both sides of every vector. Per operator:
//
//   - forbid_set_member: blocked is a set holding every forbidden member and
//     the pass members, NOT declared complete (presence alone blocks);
//     pass-complete is a complete set of the pass members; unknown-incomplete
//     is the same set, not complete;
//   - require_set_member: see generateRequireSetVectors;
//   - require_component_version: see generateDependencyVectors.
//
// Any other operator or shape is refused.
func GenerateVectors(entry Entry, pass []string) ([]Vector, error) {
	rule := entry.Rule
	switch rule.Operator {
	case constraintengine.OperatorForbidSetMember:
		return generateForbidSetVectors(entry, pass)
	case constraintengine.OperatorRequireSetMember:
		return generateRequireSetVectors(entry, pass)
	case dependencyOperator:
		return generateDependencyVectors(entry)
	}
	return nil, fmt.Errorf("rule %s: chart vectors are generated for forbid_set_member, require_set_member and require_component_version rules only", rule.ID)
}

func setDoc(rule RuleJSON, cond extract.SetCondition, members []string, complete bool) inputDoc {
	return inputDoc{
		Schema:    constraintengine.InputSchema,
		Authority: constraintengine.InputAuthority,
		Current:   inputSide{Components: []inputComponent{{Component: rule.Subject.Component, Chart: rule.Subject.Chart, Version: rule.Subject.From, Facts: []inputFact{}}}},
		Proposed:  inputSide{Components: []inputComponent{{Component: rule.Subject.Component, Chart: rule.Subject.Chart, Version: rule.Subject.To, Facts: []inputFact{{ID: cond.FactID, State: "declared", SetValue: &constraintengine.SetValue{Members: members, Complete: complete}}}}}},
	}
}

func setCondition(rule RuleJSON) (extract.SetCondition, error) {
	if rule.SetCondition == nil || rule.SetCondition.Side != "proposed" || rule.SetCondition.Component != rule.Subject.Component {
		return extract.SetCondition{}, fmt.Errorf("rule %s: vectors support a proposed-side set fact on the subject component only", rule.ID)
	}
	return *rule.SetCondition, nil
}

func generateForbidSetVectors(entry Entry, pass []string) ([]Vector, error) {
	rule := entry.Rule
	cond, err := setCondition(rule)
	if err != nil {
		return nil, err
	}
	for _, m := range pass {
		if slices.Contains(cond.Members, m) {
			return nil, fmt.Errorf("rule %s: pass member %s is forbidden", rule.ID, m)
		}
	}
	passSet := sortedUnique(pass)
	blockedSet := sortedUnique(append(append([]string(nil), cond.Members...), pass...))
	var out []Vector
	for _, spec := range []struct {
		kind     string
		members  []string
		complete bool
		expect   VectorExpect
	}{
		{extract.VectorBlocked, blockedSet, false, VectorExpect{Status: "BLOCKED", ReasonCode: rule.ReasonCode, MatchedMembers: append([]string(nil), cond.Members...)}},
		{extract.VectorPassComplete, passSet, true, VectorExpect{Status: "PASS", ReasonCode: rule.ReasonCode}},
		{extract.VectorUnknownIncomplete, passSet, false, VectorExpect{Status: "UNKNOWN", ReasonCode: reasonSetIncomplete}},
	} {
		raw, err := compact(setDoc(rule, cond, spec.members, spec.complete))
		if err != nil {
			return nil, err
		}
		out = append(out, Vector{Name: rule.ID + "/" + spec.kind, RuleID: rule.ID, Kind: spec.kind, Input: raw, Expect: spec.expect})
	}
	return out, nil
}

// generateRequireSetVectors derives the vectors of a require_set_member
// entry. The pass members here are extra members that are never required:
//
//   - blocked: a complete set holding only the extra members, so every
//     required member is missing;
//   - pass-complete: a complete set holding every required member and the
//     extra members;
//   - unknown-incomplete: the same set, not declared complete: holding the
//     members proves nothing until the set is complete.
func generateRequireSetVectors(entry Entry, pass []string) ([]Vector, error) {
	rule := entry.Rule
	cond, err := setCondition(rule)
	if err != nil {
		return nil, err
	}
	for _, m := range pass {
		if slices.Contains(cond.Members, m) {
			return nil, fmt.Errorf("rule %s: extra member %s is required", rule.ID, m)
		}
	}
	extra := sortedUnique(pass)
	full := sortedUnique(append(append([]string(nil), cond.Members...), pass...))
	var out []Vector
	for _, spec := range []struct {
		kind     string
		members  []string
		complete bool
		expect   VectorExpect
	}{
		{extract.VectorBlocked, extra, true, VectorExpect{Status: "BLOCKED", ReasonCode: rule.ReasonCode, MissingMembers: sortedUnique(cond.Members)}},
		{extract.VectorPassComplete, full, true, VectorExpect{Status: "PASS", ReasonCode: rule.ReasonCode}},
		{extract.VectorUnknownIncomplete, full, false, VectorExpect{Status: "UNKNOWN", ReasonCode: reasonSetIncomplete}},
	} {
		raw, err := compact(setDoc(rule, cond, spec.members, spec.complete))
		if err != nil {
			return nil, err
		}
		out = append(out, Vector{Name: rule.ID + "/" + spec.kind, RuleID: rule.ID, Kind: spec.kind, Input: raw, Expect: spec.expect})
	}
	return out, nil
}

// generateDependencyVectors derives the vectors of a proposed-side gte
// require_component_version entry on another component:
//
//   - blocked: the dependency is declared just below the bound;
//   - pass-complete: the dependency is declared at the bound;
//   - unknown-incomplete: the dependency is not declared at all.
func generateDependencyVectors(entry Entry) ([]Vector, error) {
	rule := entry.Rule
	dep := rule.Dependency
	if dep == nil || dep.Side != "proposed" || dep.Comparison != "gte" || dep.Component == rule.Subject.Component {
		return nil, fmt.Errorf("rule %s: vectors support a proposed-side gte bound on another component only", rule.ID)
	}
	below, ok := versionBelow(dep.Version)
	if !ok {
		return nil, fmt.Errorf("rule %s: bound %s has no version below it", rule.ID, dep.Version)
	}
	subject := func(version string) inputComponent {
		return inputComponent{Component: rule.Subject.Component, Chart: rule.Subject.Chart, Version: version, Facts: []inputFact{}}
	}
	var out []Vector
	for _, spec := range []struct {
		kind    string
		version string
		expect  VectorExpect
	}{
		{extract.VectorBlocked, below, VectorExpect{Status: "BLOCKED", ReasonCode: rule.ReasonCode}},
		{extract.VectorPassComplete, dep.Version, VectorExpect{Status: "PASS", ReasonCode: rule.ReasonCode}},
		{extract.VectorUnknownIncomplete, "", VectorExpect{Status: "UNKNOWN", ReasonCode: reasonDependencyMissing}},
	} {
		proposed := []inputComponent{subject(rule.Subject.To)}
		if spec.version != "" {
			proposed = append(proposed, inputComponent{Component: dep.Component, Version: spec.version, Facts: []inputFact{}})
		}
		doc := inputDoc{
			Schema:    constraintengine.InputSchema,
			Authority: constraintengine.InputAuthority,
			Current:   inputSide{Components: []inputComponent{subject(rule.Subject.From)}},
			Proposed:  inputSide{Components: proposed},
		}
		raw, err := compact(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, Vector{Name: rule.ID + "/" + spec.kind, RuleID: rule.ID, Kind: spec.kind, Input: raw, Expect: spec.expect})
	}
	return out, nil
}

// versionBelow returns a strict major.minor.patch version just below v:
// the previous patch, else the previous minor's .0, else the previous
// major's .0.0.
func versionBelow(v string) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", false
	}
	var n [3]uint64
	for i, p := range parts {
		x, err := strconv.ParseUint(p, 10, 32)
		if err != nil || strconv.FormatUint(x, 10) != p {
			return "", false
		}
		n[i] = x
	}
	switch {
	case n[2] > 0:
		n[2]--
	case n[1] > 0:
		n[1]--
	case n[0] > 0:
		n[0]--
	default:
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d", n[0], n[1], n[2]), true
}

func sortedUnique(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return slices.Compact(out)
}

// compact renders v as canonical single-line JSON.
func compact(v any) (json.RawMessage, error) {
	pretty, err := extract.Canonical(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, pretty); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CheckVectors evaluates every vector through the constraint engine against
// its own entry and returns an error for the first vector whose claim
// differs from what it expects (status, reason code, matched and missing
// members), or for an entry without all three vector kinds. now must lie
// inside the rules' validity.
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
		if claim.Status != v.Expect.Status || claim.ReasonCode != v.Expect.ReasonCode || !slices.Equal(claim.MatchedMembers, v.Expect.MatchedMembers) || !slices.Equal(claim.MissingMembers, v.Expect.MissingMembers) {
			return fmt.Errorf("vector %s: engine says %s/%s %v missing %v, vector expects %s/%s %v missing %v", v.Name, claim.Status, claim.ReasonCode, claim.MatchedMembers, claim.MissingMembers, v.Expect.Status, v.Expect.ReasonCode, v.Expect.MatchedMembers, v.Expect.MissingMembers)
		}
	}
	for id := range byID {
		for _, kind := range []string{extract.VectorBlocked, extract.VectorPassComplete, extract.VectorUnknownIncomplete} {
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
