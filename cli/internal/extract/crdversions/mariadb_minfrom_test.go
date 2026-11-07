// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The tag list is a fixture of tag names only (testdata/tags), taken once from
// the public repository; commits are synthetic.
func mariadbTarget(t *testing.T) Target {
	t.Helper()
	for _, tg := range Targets {
		if tg.Project == "mariadb-operator" {
			return tg
		}
	}
	t.Fatal("no mariadb-operator target")
	return Target{}
}

func TestMariadbOperatorLinesFrom034(t *testing.T) {
	tg := mariadbTarget(t)
	if tg.MinFrom != [2]int{0, 34} || !tg.Attest {
		t.Fatalf("minFrom %v attest %v, want 0.34 and attest on", tg.MinFrom, tg.Attest)
	}
	raw, err := os.ReadFile("testdata/tags/mariadb-operator.txt")
	if err != nil {
		t.Fatal(err)
	}
	idx := extract.ReleaseIndex{Repo: extract.RepoRef{Key: tg.Repo}}
	for _, name := range strings.Fields(string(raw)) {
		idx.Tags = append(idx.Tags, extract.Tag{Name: name, Commit: commitOf(name)})
	}
	x := New(tg)
	pairs := x.Pairs(idx)
	if len(pairs) == 0 || pairs[0].From != "0.34.0" {
		t.Fatalf("pairs %+v", pairs)
	}
	var attestable, other []string
	for _, p := range pairs {
		fl, tl := x.lineFor(p.FromTag, p.FromCommit, p.From), x.lineFor(p.ToTag, p.ToCommit, p.To)
		hop := p.From + "->" + p.To
		if hopShape(tg.Component, fl, tl) == HopPreviousMinor {
			attestable = append(attestable, hop)
		} else {
			other = append(other, hop)
		}
	}
	want := "0.34.0->0.35.0 0.35.0->0.36.0 0.36.0->0.37.0 0.37.0->0.38.0"
	if got := strings.Join(attestable, " "); got != want {
		t.Fatalf("attestable hops %q, want %q", got, want)
	}
	if len(other) == 0 || other[0] != "0.38.0->25.0.0" {
		t.Fatalf("non-attestable hops %v: the major hop must follow 0.38", other)
	}
	for _, h := range other {
		if strings.HasPrefix(h, "0.3") && h != "0.38.0->25.0.0" {
			t.Fatalf("0.x hop %s outside the consecutive lines is attestable-shaped", h)
		}
	}
}
