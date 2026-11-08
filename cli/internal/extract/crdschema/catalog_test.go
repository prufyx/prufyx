// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

func catalogTarget(prefixes []string, minFrom [2]int) crdversions.Target {
	t := okTarget()
	t.Repo = repo.Key
	t.TagPrefixes = prefixes
	t.MinFrom = minFrom
	t.Paths = []crdversions.PathSpec{dirSpec("crd")}
	return t
}

func newCatalog(t *testing.T, prefixes []string, minFrom [2]int) *Catalog {
	t.Helper()
	x, err := FromCRDVersions(catalogTarget(prefixes, minFrom))
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func fakeCommit(c byte) string { return strings.Repeat(string(c), 40) }

func lineIndex(names ...string) extract.ReleaseIndex {
	idx := extract.ReleaseIndex{Repo: repo}
	for i, n := range names {
		idx.Tags = append(idx.Tags, extract.Tag{Name: n, Commit: fakeCommit(byte('1' + i))})
	}
	return idx
}

func pairNames(ps []extract.VersionPair) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.From+">"+p.To)
	}
	return out
}

// Sibling spellings and other components' tags never become lines: the
// index is filtered with the target's exact prefixes before releaseLines.
func TestCatalogFiltersTheIndexBeforeLines(t *testing.T) {
	idx := lineIndex("v1.0.0", "v1.1.0", "1.2.0", "helm-chart-1.2.0", "api/v1.2.0", "v1.3.0-rc.1", "v1.3.0")
	got := pairNames(newCatalog(t, []string{"v"}, [2]int{1, 0}).Pairs(idx))
	if want := []string{"1.0.0>1.1.0"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("v-only: %v want %v", got, want)
	}
	// Without the filter the extra tags would change the lines.
	if raw := pairNames(newCatalog(t, []string{"v"}, [2]int{1, 0}).Extractor.Pairs(idx)); reflect.DeepEqual(raw, got) {
		t.Fatalf("test index does not show the unfiltered difference: %v", raw)
	}
	bare := pairNames(newCatalog(t, []string{""}, [2]int{1, 0}).Pairs(lineIndex("1.0.0", "1.1.0", "v1.2.0", "1.2.0")))
	if want := []string{"1.0.0>1.1.0", "1.1.0>1.2.0"}; !reflect.DeepEqual(bare, want) {
		t.Fatalf("bare-only: %v want %v", bare, want)
	}
}

func TestCatalogMinFromIsApplied(t *testing.T) {
	idx := lineIndex("v1.0.0", "v1.1.0", "v1.2.0", "v1.3.0")
	cases := []struct {
		min  [2]int
		want []string
	}{
		{[2]int{1, 0}, []string{"1.0.0>1.1.0", "1.1.0>1.2.0", "1.2.0>1.3.0"}},
		{[2]int{1, 1}, []string{"1.1.0>1.2.0", "1.2.0>1.3.0"}},
		{[2]int{1, 3}, []string{}},
		{[2]int{2, 0}, []string{}},
		{[2]int{0, 9}, []string{"1.0.0>1.1.0", "1.1.0>1.2.0", "1.2.0>1.3.0"}},
	}
	for _, c := range cases {
		if got := pairNames(newCatalog(t, []string{"v"}, c.min).Pairs(idx)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("minFrom %v: %v want %v", c.min, got, c.want)
		}
	}
	// The bare extractor pairs every line: the catalog layer is what drops them.
	if n := len(newCatalog(t, []string{"v"}, [2]int{1, 2}).Extractor.Pairs(idx)); n != 3 {
		t.Fatalf("unfiltered pairs %d", n)
	}
}

func TestAtOrAfterFailsClosed(t *testing.T) {
	for _, v := range []string{"", "1", "x.y.z", "1.x.0"} {
		if atOrAfter(v, [2]int{0, 0}) {
			t.Errorf("%q accepted", v)
		}
	}
}

// A release named by both spellings at different commits withholds the line
// even when the target names both prefixes; the pair is then not attested.
func TestCatalogDualSpellingConflictWithholds(t *testing.T) {
	x := newCatalog(t, []string{"v", ""}, [2]int{1, 0})
	idx := extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{
		{Name: "v1.0.0", Commit: commitA}, {Name: "1.0.0", Commit: commitC}, {Name: "v1.1.0", Commit: commitB}}}
	ps := x.Pairs(idx)
	if len(ps) != 1 {
		t.Fatalf("pairs %v", pairNames(ps))
	}
	e, err := x.Extract(context.Background(), newMem(), ps[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Ledger) != 1 || e.Ledger[0].Code != ReasonLineUnread || e.NotAttested == "" || len(e.Attestations) != 0 || len(e.Candidates) != 0 {
		t.Fatalf("extraction %+v", e)
	}
}

type catalogTags struct{}

func (catalogTags) Tags(extract.RepoRef) ([]extract.Tag, error) {
	return []extract.Tag{{Name: "v1.0.0", Commit: commitA}, {Name: "v1.1.0", Commit: commitB}}, nil
}

// Every fixture through extract.Run with the catalog extractor: the pair's
// ledger is the proof's ledger (authoritative), a pair with items withheld is
// not attested, and nothing is ever attested and no rule is ever emitted.
func TestCatalogLedgerFlowsAndNothingIsAttested(t *testing.T) {
	withheld, clean := 0, 0
	for _, c := range allCases(t) {
		if c.exp.Lossy {
			continue
		}
		x := newCatalog(t, []string{"v"}, [2]int{1, 0})
		if len(x.AttestedFamilies()) != 0 {
			t.Fatalf("catalog extractor attests %v", x.AttestedFamilies())
		}
		out, err := extract.Run(context.Background(), x, catalogTags{}, c.reader(), runOpts)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(out.Manifest.Pairs) != 1 {
			t.Fatalf("%s: %d pairs", c.name, len(out.Manifest.Pairs))
		}
		p := out.Manifest.Pairs[0]
		raw, _ := json.Marshal(p.Proof)
		var proof struct {
			Ledger []LedgerEntry `json:"ledger"`
		}
		if err := json.Unmarshal(raw, &proof); err != nil {
			t.Fatal(err)
		}
		got := []LedgerEntry{}
		for _, e := range p.Ledger {
			got = append(got, LedgerEntry{Code: e.Code, Item: e.Item})
		}
		if len(proof.Ledger) == 0 {
			proof.Ledger = []LedgerEntry{}
		}
		if !reflect.DeepEqual(got, proof.Ledger) {
			t.Errorf("%s: pair ledger %v differs from the proof ledger %v", c.name, got, proof.Ledger)
		}
		if p.Attestation == nil || p.Attestation.Status != extract.PairNotAttested || len(out.Attestations) != 0 || len(out.Entries) != 0 {
			t.Errorf("%s: attestation=%+v attestations=%d entries=%d", c.name, p.Attestation, len(out.Attestations), len(out.Entries))
		}
		if len(c.exp.Omissions) > 0 {
			withheld++
			if len(p.Ledger) == 0 {
				t.Errorf("%s: withheld items but the pair has no ledger", c.name)
			}
		} else {
			clean++
		}
	}
	if withheld == 0 || clean == 0 {
		t.Fatalf("fixtures exercised %d withheld, %d clean", withheld, clean)
	}
}

func TestFrameworkLedgerKeepsEntriesInOrder(t *testing.T) {
	in := &Result{Ledger: []LedgerEntry{{Code: "A_CODE", Item: "x"}, {Code: "LEDGER_INVALID", Item: "ledger"}}}
	got := frameworkLedger(in)
	want := []extract.LedgerEntry{{Code: "A_CODE", Item: "x"}, {Code: "LEDGER_INVALID", Item: "ledger"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if got := frameworkLedger(&Result{}); got == nil || len(got) != 0 {
		t.Fatalf("empty ledger %#v", got)
	}
}

// A target the mapper refuses is never an extractor.
func TestFromCRDVersionsRefusesWhatTheMapperRefuses(t *testing.T) {
	refused := 0
	for _, tg := range crdversions.Targets {
		_, rs := TargetFromCRDVersions(tg)
		x, err := FromCRDVersions(tg)
		if len(rs) > 0 {
			refused++
			if err == nil || x != nil {
				t.Errorf("%s: refused by the mapper but built", tg.Project)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tg.Project, err)
		}
	}
	if refused == 0 {
		t.Fatal("no refused real target")
	}
	bad := catalogTarget([]string{"v"}, [2]int{1, 0})
	bad.Attest = false
	if _, err := FromCRDVersions(bad); err == nil {
		t.Fatal("a target that does not attest was built")
	}
}

func TestCatalogProjectsMapAndExcludedAreNotListed(t *testing.T) {
	byProject := map[string]crdversions.Target{}
	for _, tg := range crdversions.Targets {
		byProject[tg.Project] = tg
	}
	for _, p := range CatalogProjects {
		tg, ok := byProject[p]
		if !ok {
			t.Fatalf("pilot %s has no crdversions target", p)
		}
		if _, err := FromCRDVersions(tg); err != nil {
			t.Errorf("pilot %s: %v", p, err)
		}
	}
	for _, p := range []string{"cert-manager", "kuma", "mariadb-operator"} {
		for _, q := range CatalogProjects {
			if p == q {
				t.Errorf("%s is refused by the mapper and must not be listed", p)
			}
		}
	}
}
