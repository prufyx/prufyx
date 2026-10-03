// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Expected is an independent account of served-API removals to compare a
// run with, for example the reviewed API-removal rules.
type Expected struct {
	Removals []ExpectedRemoval `json:"removals"`
}

// ExpectedRemoval is one reviewed removal: the kinds of Group that stop
// being served at Version when a cluster crosses into the target line.
type ExpectedRemoval struct {
	Line    string   `json:"line"` // target line, "1.25"
	Group   string   `json:"group"`
	Version string   `json:"version"`
	Kinds   []string `json:"kinds"`
	Rule    string   `json:"rule,omitempty"` // reviewed rule id, for reports
}

// Oracle compares the run recorded in outDir with expected and returns one
// line per disagreement, sorted. Lines the expected file does not mention
// are compared too: every removal the run derives for a line with at least
// one expected removal is reported as EXTRA when unexpected; lines with no
// expected removal are not compared (their removals are reported by the
// manifest, and the unreviewed ones are explained in the findings record).
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
	type pairInfo struct {
		rec   extract.PairRecord
		proof pairProof
	}
	pairs := map[string]*pairInfo{}
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
	// The rules each removal produced must carry its kinds and target line.
	raw, err := os.ReadFile(filepath.Join(outDir, extract.FileCandidates))
	if err != nil {
		return nil, err
	}
	var entries []extract.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("candidates: %w", err)
	}
	var diffs []string
	expectedLines := map[string]bool{}
	expectedKey := map[string]bool{}
	for _, e := range exp.Removals {
		expectedLines[e.Line] = true
		expectedKey[e.Line+"\x00"+e.Group+"\x00"+e.Version] = true
		name := fmt.Sprintf("%s %s", e.Line, groupVersion(e.Group, e.Version))
		info := pairs[e.Line]
		switch {
		case info == nil:
			diffs = append(diffs, fmt.Sprintf("MISSING %s: the run has no pair for %s", name, e.Line))
			continue
		case info.rec.Status != extract.PairDerived:
			diffs = append(diffs, fmt.Sprintf("WITHHELD %s: %s", name, info.rec.Reason))
			continue
		}
		idx := slices.IndexFunc(info.proof.Removals, func(r removalProof) bool { return r.Group == e.Group && r.Version == e.Version })
		if idx < 0 {
			diffs = append(diffs, fmt.Sprintf("MISSING %s: not derived (reviewed rule %s)", name, e.Rule))
			continue
		}
		got := info.proof.Removals[idx]
		want := append([]string(nil), e.Kinds...)
		sort.Strings(want)
		if !slices.Equal(got.Kinds, want) {
			diffs = append(diffs, fmt.Sprintf("KINDS %s: reviewed %s, derived %s", name, strings.Join(want, ","), strings.Join(got.Kinds, ",")))
		}
		if len(got.NoFactKinds) > 0 {
			diffs = append(diffs, fmt.Sprintf("NOFACT %s: no adapter fact for %s", name, strings.Join(got.NoFactKinds, ",")))
		}
		covered := false
		for _, id := range info.rec.Rules {
			if strings.HasPrefix(id, "kubernetes.served-api-removal."+groupSlug(e.Group)+"-"+e.Version) {
				covered = true
			}
		}
		if !covered {
			diffs = append(diffs, fmt.Sprintf("NORULE %s: no rule derived", name))
		}
	}
	for line, info := range pairs {
		if !expectedLines[line] || info.rec.Status != extract.PairDerived {
			continue
		}
		for _, r := range info.proof.Removals {
			if !expectedKey[line+"\x00"+r.Group+"\x00"+r.Version] {
				diffs = append(diffs, fmt.Sprintf("EXTRA %s %s: derived kinds %s, not in the reviewed rules", line, groupVersion(r.Group, r.Version), strings.Join(r.Kinds, ",")))
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
