// SPDX-License-Identifier: AGPL-3.0-only

package k8sfeaturegates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Expected is an independent account of gate removals to compare a run
// with: removals found some other way (for example a manual diff of the
// declarations between release tags), and hand-written rules whose gates
// the run must forbid.
type Expected struct {
	Removals []ExpectedRemoval `json:"removals"`
	Rules    []ExpectedRule    `json:"rules"`
}

// ExpectedRemoval is one gate removed in a release. DeclFile and DeclLine,
// when given, are where the earlier release declares it.
type ExpectedRemoval struct {
	Gate      string `json:"gate"`
	RemovedIn string `json:"removedIn"` // "1.23"
	DeclFile  string `json:"declFile,omitempty"`
	DeclLine  int    `json:"declLine,omitempty"`
}

// ExpectedRule is a rule whose gates must be forbidden for each listed
// component on the from -> to transition.
type ExpectedRule struct {
	Name       string   `json:"name"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Gates      []string `json:"gates"`
	Components []string `json:"components"`
}

// Oracle compares the run recorded in outDir with expected and returns one
// line per disagreement, sorted.
func Oracle(outDir string, expectedRaw []byte) ([]string, error) {
	var exp Expected
	dec := json.NewDecoder(bytes.NewReader(expectedRaw))
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
	var entries []extract.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("candidates: %w", err)
	}
	type pairInfo struct {
		rec   extract.PairRecord
		proof pairProof
	}
	pairs := map[string]*pairInfo{} // keyed by target "1.23"
	for _, p := range m.Pairs {
		info := &pairInfo{rec: p}
		if p.Proof != nil {
			pr, _ := json.Marshal(p.Proof)
			if err := json.Unmarshal(pr, &info.proof); err != nil {
				return nil, fmt.Errorf("pair %s proof: %w", p.To, err)
			}
		}
		pairs[minorOf(p.To)] = info
	}
	var diffs []string
	expectedSet := map[string]bool{}
	for _, e := range exp.Removals {
		expectedSet[e.RemovedIn+"\x00"+e.Gate] = true
		info := pairs[e.RemovedIn]
		switch {
		case info == nil:
			diffs = append(diffs, fmt.Sprintf("MISSING %s removed in %s: the run has no pair for %s", e.Gate, e.RemovedIn, e.RemovedIn))
			continue
		case info.rec.Status != extract.PairDerived:
			diffs = append(diffs, fmt.Sprintf("WITHHELD %s removed in %s: %s", e.Gate, e.RemovedIn, info.rec.Reason))
			continue
		}
		idx := slices.IndexFunc(info.proof.Removed, func(g gateDecl) bool { return g.Name == e.Gate })
		if idx < 0 {
			why := "not declared at " + info.rec.FromTag
			if slices.Contains(info.proof.From.Declared, e.Gate) {
				why = "still present at " + info.rec.ToTag
			}
			diffs = append(diffs, fmt.Sprintf("MISSING %s removed in %s: extractor finds it %s", e.Gate, e.RemovedIn, why))
			continue
		}
		g := info.proof.Removed[idx]
		if (e.DeclFile != "" && e.DeclFile != g.Declared.Path) || (e.DeclLine != 0 && e.DeclLine != g.Declared.Line) {
			diffs = append(diffs, fmt.Sprintf("LOCATION %s removed in %s: expected %s:%d, extractor %s:%d", e.Gate, e.RemovedIn, e.DeclFile, e.DeclLine, g.Declared.Path, g.Declared.Line))
		}
	}
	if len(exp.Removals) > 0 {
		for target, info := range pairs {
			for _, g := range info.proof.Removed {
				if !expectedSet[target+"\x00"+g.Name] {
					diffs = append(diffs, fmt.Sprintf("EXTRA %s removed in %s: declared at %s:%d in %s, absent at %s", g.Name, target, g.Declared.Path, g.Declared.Line, info.rec.FromTag, info.rec.ToTag))
				}
			}
		}
	}
	for _, r := range exp.Rules {
		for _, compName := range r.Components {
			ci := slices.IndexFunc(Components, func(c Component) bool { return c.Name == compName })
			if ci < 0 {
				return nil, fmt.Errorf("expected rule %s: unknown component %s", r.Name, compName)
			}
			forbidden := map[string]bool{}
			for _, e := range entries {
				sc := e.Rule.SetCondition
				if sc != nil && (constraintengine.RuleTransition{Component: e.Rule.Subject.Component, From: e.Rule.Subject.From, To: e.Rule.Subject.To}).IsAnchor(r.From, r.To) && sc.FactID == Components[ci].Fact {
					for _, mem := range sc.Members {
						forbidden[mem] = true
					}
				}
			}
			for _, gate := range r.Gates {
				if !forbidden[gate] {
					diffs = append(diffs, fmt.Sprintf("RULE %s: no %s rule for %s -> %s forbids %s", r.Name, compName, r.From, r.To, gate))
				}
			}
		}
	}
	sort.Strings(diffs)
	return diffs, nil
}

func minorOf(v string) string {
	m := releaseTagRE.FindStringSubmatch("v" + v)
	if m == nil {
		return v
	}
	return m[1] + "." + m[2]
}
