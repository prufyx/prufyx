// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

// Expected is an independent account of a run to compare it with: the
// outcome of each pair (found by reading both charts by hand) and the rules
// it must hold.
type Expected struct {
	Pairs []ExpectedPair `json:"pairs"`
	Rules []ExpectedRule `json:"rules"`
}

// ExpectedPair is the outcome of one pair. Status is "derived" or
// "withheld"; Rules, when given, is the number of rules.
type ExpectedPair struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status string `json:"status"`
	Rules  *int   `json:"rules,omitempty"`
}

// ExpectedRule is one rule the run must hold: its operator and either its
// members (set rules) or its Kubernetes bound.
type ExpectedRule struct {
	ID       string   `json:"id"`
	Operator string   `json:"operator"`
	Members  []string `json:"members,omitempty"`
	Minimum  string   `json:"minimum,omitempty"`
}

// Oracle compares a recorded run in outDir with an expected-results file
// and returns the disagreements, one per line. Every listed pair must be
// in the run with the listed outcome, every listed rule must be in the run
// as listed, and the run may hold no rule the file does not list.
func Oracle(outDir string, expected []byte) ([]string, error) {
	var exp Expected
	dec := json.NewDecoder(bytes.NewReader(expected))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&exp); err != nil {
		return nil, fmt.Errorf("expected file: %w", err)
	}
	m, err := extract.ReadManifest(outDir)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(outDir, extract.FileCandidates))
	if err != nil {
		return nil, err
	}
	var entries []chartrun.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	var diffs []string
	pairs := map[string]extract.PairRecord{}
	for _, p := range m.Pairs {
		pairs[p.From+"->"+p.To] = p
	}
	for _, e := range exp.Pairs {
		p, ok := pairs[e.From+"->"+e.To]
		switch {
		case !ok:
			diffs = append(diffs, fmt.Sprintf("pair %s->%s is not in the run", e.From, e.To))
		case p.Status != e.Status:
			diffs = append(diffs, fmt.Sprintf("pair %s->%s is %s, expected %s", e.From, e.To, p.Status, e.Status))
		case e.Rules != nil && len(p.Rules) != *e.Rules:
			diffs = append(diffs, fmt.Sprintf("pair %s->%s has %d rules, expected %d", e.From, e.To, len(p.Rules), *e.Rules))
		}
	}
	got := map[string]chartrun.Entry{}
	for _, e := range entries {
		got[e.Rule.ID] = e
	}
	listed := map[string]bool{}
	for _, r := range exp.Rules {
		listed[r.ID] = true
		e, ok := got[r.ID]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("rule %s is not in the run", r.ID))
			continue
		}
		var members []string
		if e.Rule.SetCondition != nil {
			members = e.Rule.SetCondition.Members
		}
		minimum := ""
		if e.Rule.Dependency != nil {
			minimum = e.Rule.Dependency.Version
		}
		if e.Rule.Operator != r.Operator || !slices.Equal(members, r.Members) || minimum != r.Minimum {
			diffs = append(diffs, fmt.Sprintf("rule %s is %s %v %s, expected %s %v %s", r.ID, e.Rule.Operator, members, minimum, r.Operator, r.Members, r.Minimum))
		}
	}
	var extra []string
	for id := range got {
		if !listed[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		diffs = append(diffs, fmt.Sprintf("rule %s is not expected", id))
	}
	return diffs, nil
}
