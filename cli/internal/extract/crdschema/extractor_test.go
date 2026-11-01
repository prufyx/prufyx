// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

const kubeComponent = "pkg:github/kubernetes/kubernetes"

var commitC = strings.Repeat("c", 40)

type tagList []extract.Tag

func (t tagList) Tags(extract.RepoRef) ([]extract.Tag, error) { return t, nil }

var runOpts = extract.Options{Repo: repo, DerivedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}

func newExtractor(t *testing.T, withFamily bool) *Extractor {
	t.Helper()
	x, err := New("example", testTarget, kubeComponent)
	if err != nil {
		t.Fatal(err)
	}
	if withFamily {
		// The attested path needs a registered family; the crd.schema family
		// does not exist yet, so the test borrows an existing one.
		x.family = lineattest.FamilyKubernetesRemovedServedGVK
	}
	return x
}

func runOne(t *testing.T, x *Extractor, tags tagList, rd extract.PinnedReader) (*extract.Output, extract.PairRecord, []LedgerEntry) {
	t.Helper()
	out, err := extract.Run(context.Background(), x, tags, rd, runOpts)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Manifest.Pairs) != 1 {
		t.Fatalf("want 1 pair, got %d", len(out.Manifest.Pairs))
	}
	p := out.Manifest.Pairs[0]
	raw, err := json.Marshal(p.Proof)
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		Ledger []LedgerEntry `json:"ledger"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	return out, p, proof.Ledger
}

var twoLines = tagList{{Name: "v1.0.0", Commit: commitA}, {Name: "v1.1.0", Commit: commitB}}

// Every fixture with omissions or a ledger yields a not-attested pair through
// extract.Run, with the ledger at the top level of the proof, even when the
// extractor has a family to attest. Every other fixture is attested only when
// it removes nothing.
func TestEveryFixtureWithOmissionsIsNotAttested(t *testing.T) {
	refused, attested, withMembers := 0, 0, 0
	for _, c := range allCases(t) {
		if c.exp.Lossy {
			continue // runs with a test-only encoder; the real extractor uses the default
		}
		out, p, ledger := runOne(t, newExtractor(t, true), twoLines, c.reader())
		if p.Attestation == nil {
			t.Fatalf("%s: no attestation record", c.name)
		}
		if len(c.exp.Omissions) > 0 {
			refused++
			if len(ledger) == 0 || p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
				t.Errorf("%s: withheld items but ledger=%d attestation=%+v", c.name, len(ledger), p.Attestation)
			}
			continue
		}
		if len(ledger) != 0 {
			t.Errorf("%s: no omissions but ledger %v", c.name, ledger)
		}
		if len(c.exp.Fields)+len(c.exp.Enums) > 0 {
			withMembers++
			if p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
				t.Errorf("%s: removals but attestation=%+v", c.name, p.Attestation)
			}
			continue
		}
		if len(c.from) == 0 {
			continue
		}
		attested++
		if p.Attestation.Status != extract.PairAttested || len(out.Attestations) != 1 {
			t.Errorf("%s: nothing withheld, nothing removed, attestation=%+v", c.name, p.Attestation)
		}
	}
	if refused == 0 || attested == 0 || withMembers == 0 {
		t.Fatalf("fixtures exercised %d refused, %d attested, %d with removals", refused, attested, withMembers)
	}
}

// Without a registered family nothing is attested.
func TestNoFamilyNeverAttests(t *testing.T) {
	x := newExtractor(t, false)
	if len(x.AttestedFamilies()) != 0 {
		t.Fatalf("families %v", x.AttestedFamilies())
	}
	for _, c := range allCases(t) {
		if c.exp.Lossy {
			continue
		}
		out, p, _ := runOne(t, x, twoLines, c.reader())
		if p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
			t.Errorf("%s: attestation=%+v", c.name, p.Attestation)
		}
	}
}

func caseNamed(t *testing.T, name string) testCase {
	t.Helper()
	for _, c := range allCases(t) {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no case %s", name)
	return testCase{}
}

// The decision is for the line: a later release of a line whose sets differ
// from the first release makes the pair not attested, while the same line
// with an identical later release is attested.
func TestLineDecisionNeedsAStableLine(t *testing.T) {
	c := caseNamed(t, "added_only")
	if len(c.exp.Omissions) != 0 || len(c.exp.Fields)+len(c.exp.Enums) != 0 {
		t.Fatalf("fixture is not a quiet pair: %+v", c.exp)
	}
	tags := tagList{{Name: "v1.0.0", Commit: commitA}, {Name: "v1.0.1", Commit: commitC}, {Name: "v1.1.0", Commit: commitB}}

	same := c.reader() // v1.0.1 identical to v1.0.0
	for p, d := range c.from {
		same.put(commitC, p, d)
	}
	out, p, ledger := runOne(t, newExtractor(t, true), tags, same)
	if p.Attestation.Status != extract.PairAttested || len(out.Attestations) != 1 || len(ledger) != 0 {
		t.Fatalf("stable line: attestation=%+v ledger=%v", p.Attestation, ledger)
	}

	diff := c.reader() // v1.0.1 carries the new line's content
	for p, d := range c.to {
		diff.put(commitC, p, d)
	}
	out, p, ledger = runOne(t, newExtractor(t, true), tags, diff)
	if p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
		t.Fatalf("unstable line: attestation=%+v", p.Attestation)
	}
	found := false
	for _, e := range ledger {
		found = found || (e.Code == ReasonLineUnstable && e.Item == "line:1.0")
	}
	if !found {
		t.Fatalf("unstable line: ledger %v", ledger)
	}
}

func TestUnreadableTagMarksTheLine(t *testing.T) {
	c := caseNamed(t, "added_only")
	tags := tagList{{Name: "v1.0.0", Commit: commitA}, {Name: "v1.0.01", Commit: commitC}, {Name: "v1.1.0", Commit: commitB}}
	out, p, ledger := runOne(t, newExtractor(t, true), tags, c.reader())
	if p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 {
		t.Fatalf("attestation=%+v", p.Attestation)
	}
	if len(ledger) != 1 || ledger[0].Code != ReasonLineUnread || ledger[0].Item != "line:1.0" {
		t.Fatalf("ledger %v", ledger)
	}
}

func TestPairsAreAdjacentMinorLines(t *testing.T) {
	x := newExtractor(t, false)
	ix := extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{
		{Name: "v1.0.0", Commit: commitA}, {Name: "v1.0.2", Commit: commitC}, {Name: "v1.1.0", Commit: commitB},
		{Name: "v1.3.0", Commit: commitB}, {Name: "v2.0.0", Commit: commitB}, {Name: "v1.1.0-rc1", Commit: commitC},
	}}
	ps := x.Pairs(ix)
	if len(ps) != 1 || ps[0].From != "1.0.0" || ps[0].To != "1.1.0" {
		t.Fatalf("pairs %+v", ps)
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	if _, err := New("Bad Slug", testTarget, kubeComponent); err == nil {
		t.Fatal("bad slug accepted")
	}
	if _, err := New("ok", Target{Repo: repo}, kubeComponent); err == nil {
		t.Fatal("empty target accepted")
	}
}
