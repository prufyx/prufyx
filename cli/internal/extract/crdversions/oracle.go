// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/derivefloor"
)

// Expected is an independent account of CRD version removals to compare a
// run with: removals found another way (a hand check of the manifests at
// both tags), reviewed rules whose versions the run must forbid, the
// storage-version changes the proof must record, and pair outcomes (for a
// quiet pair: derived with no removal).
type Expected struct {
	Removals       []ExpectedRemoval `json:"removals"`
	Rules          []ExpectedRule    `json:"rules"`
	StorageChanges []ExpectedStorage `json:"storageChanges"`
	Pairs          []ExpectedPair    `json:"pairs"`
	// Floor, when present, is the claimed floor of the target the run was
	// made for. It is checked by derivefloor.Verify, the one derivation the
	// verify-pr recompute uses too; a claim that Verify refuses makes the
	// oracle fail (an error, not a difference line).
	Floor *ExpectedFloor `json:"floor,omitempty"`
}

// ExpectedFloor is a claimed floor: minFrom and derivedFrom as major.minor
// lines, the bound of the derivation (1..derivefloor.MaxDepth) and the
// recorded final stops of the pairs below minFrom.
type ExpectedFloor struct {
	MinFrom     string         `json:"minFrom"`
	DerivedFrom string         `json:"derivedFrom"`
	Depth       int            `json:"depth"`
	Stops       []ExpectedStop `json:"stops"`
}

// ExpectedStop is one recorded hop-stop: the pair's from and to lines and
// the final stop code.
type ExpectedStop struct {
	FromLine string `json:"fromLine"`
	ToLine   string `json:"toLine"`
	Code     string `json:"code"`
}

// ExpectedPair is the outcome of one pair. Status is "derived" or
// "withheld"; Removals, LineWide and Attestable are checked when given.
type ExpectedPair struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Status     string `json:"status"`
	Removals   *int   `json:"removals,omitempty"`
	LineWide   *bool  `json:"lineWide,omitempty"`
	Attestable *bool  `json:"attestable,omitempty"`
}

// ExpectedRemoval is one group/version/Kind the release To no longer
// serves; Reason is "absent" or "unserved".
type ExpectedRemoval struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Member string `json:"member"`
	Reason string `json:"reason"`
}

// ExpectedRule is a rule (for example a reviewed one) whose members must be
// forbidden on the From -> To transition.
type ExpectedRule struct {
	Name    string   `json:"name"`
	From    string   `json:"from"`
	To      string   `json:"to"`
	Members []string `json:"members"`
}

// ExpectedStorage is one storage-version change the proof must record.
type ExpectedStorage struct {
	From        string `json:"from"`
	To          string `json:"to"`
	CRD         string `json:"crd"`
	FromStorage string `json:"fromStorage"`
	ToStorage   string `json:"toStorage"`
}

// Oracle compares the run recorded in outDir with expected and returns one
// line per disagreement, sorted. When expected lists removals (or storage
// changes), every removal (storage change) of the run's derived pairs that
// it does not list is reported as EXTRA.
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
		proof PairProof
	}
	pairs2inventories := func(pairs map[string]*pairInfo) []*Inventory {
		var out []*Inventory
		for _, info := range pairs {
			if info.rec.Status == extract.PairDerived {
				out = append(out, info.proof.From, info.proof.To)
			}
		}
		return out
	}
	if exp.Floor != nil {
		if err := checkFloor(m.Pairs, *exp.Floor); err != nil {
			return nil, fmt.Errorf("floor refused: %w", err)
		}
	}
	pairs := map[string]*pairInfo{}
	key := func(from, to string) string { return from + "->" + to }
	for _, p := range m.Pairs {
		info := &pairInfo{rec: p}
		if p.Proof != nil {
			pr, _ := json.Marshal(p.Proof)
			if err := json.Unmarshal(pr, &info.proof); err != nil {
				return nil, fmt.Errorf("pair %s proof: %w", p.To, err)
			}
		}
		pairs[key(p.From, p.To)] = info
	}
	forbidden := func(from, to string) map[string]bool {
		out := map[string]bool{}
		for _, e := range entries {
			sc := e.Rule.SetCondition
			if sc == nil || !strings.HasSuffix(sc.FactID, ".custom_resource_versions_set") {
				continue
			}
			if (constraintengine.RuleTransition{Component: e.Rule.Subject.Component, From: e.Rule.Subject.From, To: e.Rule.Subject.To}).IsAnchor(from, to) {
				for _, mem := range sc.Members {
					out[mem] = true
				}
			}
		}
		return out
	}
	var diffs []string
	usable := func(what, from, to string) *pairInfo {
		info := pairs[key(from, to)]
		switch {
		case info == nil:
			diffs = append(diffs, fmt.Sprintf("MISSING %s: the run has no pair %s -> %s", what, from, to))
			return nil
		case info.rec.Status != extract.PairDerived:
			diffs = append(diffs, fmt.Sprintf("WITHHELD %s: %s", what, info.rec.Reason))
			return nil
		}
		return info
	}
	expected := map[string]bool{}
	for _, e := range exp.Removals {
		expected[key(e.From, e.To)+"\x00"+e.Member] = true
		what := fmt.Sprintf("%s removed in %s", e.Member, e.To)
		info := usable(what, e.From, e.To)
		if info == nil {
			continue
		}
		found := false
		for _, rm := range info.proof.Removals {
			if rm.Member == e.Member {
				found = true
				if rm.Reason != e.Reason {
					diffs = append(diffs, fmt.Sprintf("REASON %s: expected %s, extractor %s", what, e.Reason, rm.Reason))
				}
			}
		}
		if !found {
			diffs = append(diffs, fmt.Sprintf("MISSING %s: the extractor finds no removal", what))
		} else if !forbidden(e.From, e.To)[e.Member] {
			diffs = append(diffs, fmt.Sprintf("NO-RULE %s: no rule forbids it", what))
		}
	}
	if len(exp.Removals) > 0 {
		for _, info := range pairs {
			for _, rm := range info.proof.Removals {
				if !expected[key(info.rec.From, info.rec.To)+"\x00"+rm.Member] {
					diffs = append(diffs, fmt.Sprintf("EXTRA %s removed in %s (%s): not expected", rm.Member, info.rec.To, rm.Reason))
				}
			}
		}
	}
	for _, r := range exp.Rules {
		got := forbidden(r.From, r.To)
		for _, mem := range r.Members {
			if !got[mem] {
				diffs = append(diffs, fmt.Sprintf("RULE %s: no rule for %s -> %s forbids %s", r.Name, r.From, r.To, mem))
			}
		}
	}
	expectedStorage := map[string]string{}
	for _, s := range exp.StorageChanges {
		expectedStorage[key(s.From, s.To)+"\x00"+s.CRD] = s.FromStorage + "->" + s.ToStorage
		what := fmt.Sprintf("storage change of %s in %s", s.CRD, s.To)
		info := usable(what, s.From, s.To)
		if info == nil {
			continue
		}
		found := false
		for _, sc := range info.proof.StorageChanges {
			if sc.CRD == s.CRD {
				found = true
				if sc.Earlier != s.FromStorage || sc.Later != s.ToStorage {
					diffs = append(diffs, fmt.Sprintf("STORAGE %s: expected %s -> %s, extractor %s -> %s", what, s.FromStorage, s.ToStorage, sc.Earlier, sc.Later))
				}
			}
		}
		if !found {
			diffs = append(diffs, fmt.Sprintf("MISSING %s", what))
		}
	}
	if len(exp.StorageChanges) > 0 {
		for _, info := range pairs {
			for _, sc := range info.proof.StorageChanges {
				if _, ok := expectedStorage[key(info.rec.From, info.rec.To)+"\x00"+sc.CRD]; !ok {
					diffs = append(diffs, fmt.Sprintf("EXTRA storage change of %s in %s: %s -> %s", sc.CRD, info.rec.To, sc.Earlier, sc.Later))
				}
			}
		}
	}
	for _, e := range exp.Pairs {
		what := fmt.Sprintf("pair %s -> %s", e.From, e.To)
		info := pairs[key(e.From, e.To)]
		if info == nil {
			diffs = append(diffs, fmt.Sprintf("MISSING %s: the run has no such pair", what))
			continue
		}
		if info.rec.Status != e.Status {
			diffs = append(diffs, fmt.Sprintf("STATUS %s: expected %s, extractor %s (%s)", what, e.Status, info.rec.Status, info.rec.Reason))
			continue
		}
		if e.Removals != nil && len(info.proof.Removals) != *e.Removals {
			diffs = append(diffs, fmt.Sprintf("REMOVALS %s: expected %d, extractor %d", what, *e.Removals, len(info.proof.Removals)))
		}
		if e.LineWide != nil && (info.proof.Lines == nil || info.proof.Lines.LineWide != *e.LineWide) {
			diffs = append(diffs, fmt.Sprintf("LINE-WIDE %s: expected %v", what, *e.LineWide))
		}
		if e.Attestable != nil && (info.proof.Completeness == nil || info.proof.Completeness.Attestable != *e.Attestable) {
			diffs = append(diffs, fmt.Sprintf("ATTESTABLE %s: expected %v", what, *e.Attestable))
		}
	}
	diffs = append(diffs, sourceDiffs(pairs2inventories(pairs))...)
	sort.Strings(diffs)
	return diffs, nil
}

// sourceDiffs checks, for every definition of a derived pair that was read
// from a source apiVersion other than v1, what no expectation can state: the
// apiVersion is the one the narrow reader admits, and the lines of every
// version (entry, served, storage) are set, so a citation never points at
// line 0.
func sourceDiffs(invs []*Inventory) []string {
	var diffs []string
	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, c := range inv.CRDs {
			if c.SourceAPIVersion == "" {
				continue
			}
			if c.SourceAPIVersion != crdAPIVersionV1beta1 {
				diffs = append(diffs, fmt.Sprintf("SOURCE %s at %s: unexpected sourceApiVersion %q", c.Name, inv.Tag, c.SourceAPIVersion))
			}
			if err := checkCitedLines(c); err != nil {
				diffs = append(diffs, fmt.Sprintf("LINES %s at %s: %v", c.Name, inv.Tag, err))
			}
		}
	}
	return diffs
}

func parseFloorLine(s string) (derivefloor.Line, error) {
	if !lineattest.ValidLine(s) {
		return derivefloor.Line{}, fmt.Errorf("%q is not major.minor", s)
	}
	var l derivefloor.Line
	if _, err := fmt.Sscanf(s, "%d.%d", &l[0], &l[1]); err != nil {
		return l, err
	}
	return l, nil
}

// checkFloor builds the per-pair facts of the run (a pair attests when the
// run recorded an attestation for it; a stop is one the claim lists) and
// asks derivefloor.Verify, the shared derivation, whether the claimed floor
// is exactly what the facts give. Any problem refuses, fail closed.
func checkFloor(pairs []extract.PairRecord, ef ExpectedFloor) error {
	claim := derivefloor.Claim{}
	var err error
	if claim.MinFrom, err = parseFloorLine(ef.MinFrom); err != nil {
		return fmt.Errorf("minFrom: %w", err)
	}
	if claim.DerivedFrom, err = parseFloorLine(ef.DerivedFrom); err != nil {
		return fmt.Errorf("derivedFrom: %w", err)
	}
	stopOf := map[[2]derivefloor.Line]string{}
	for _, st := range ef.Stops {
		from, err := parseFloorLine(st.FromLine)
		if err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		to, err := parseFloorLine(st.ToLine)
		if err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		k := [2]derivefloor.Line{from, to}
		if _, dup := stopOf[k]; dup {
			return fmt.Errorf("stop %s -> %s is listed twice", st.FromLine, st.ToLine)
		}
		stopOf[k] = st.Code
		claim.Stops = append(claim.Stops, derivefloor.Stop{From: from, To: to, Code: st.Code})
	}
	facts := derivefloor.Facts{Depth: ef.Depth}
	for _, p := range pairs {
		fl, ok1 := lineattest.LineOf(p.From)
		tl, ok2 := lineattest.LineOf(p.To)
		if !ok1 || !ok2 {
			return fmt.Errorf("pair %s -> %s has no release line", p.From, p.To)
		}
		from, err1 := parseFloorLine(fl)
		to, err2 := parseFloorLine(tl)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("pair %s -> %s has an unreadable line", p.From, p.To)
		}
		pf := derivefloor.PairFact{From: from, To: to, Attested: p.Attestation != nil && p.Attestation.Status == extract.PairAttested}
		if code, ok := stopOf[[2]derivefloor.Line{from, to}]; ok && !pf.Attested {
			pf.Stop = code
		}
		facts.Pairs = append(facts.Pairs, pf)
	}
	sort.Slice(facts.Pairs, func(i, j int) bool {
		a, b := facts.Pairs[i].From, facts.Pairs[j].From
		return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1])
	})
	return derivefloor.Verify(facts, claim)
}
