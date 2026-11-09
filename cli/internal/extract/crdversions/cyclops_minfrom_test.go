// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Releases 0.16 to 0.18 carry an empty generated stub definition that the
// scan cannot read; the target starts at 0.19, the first clean release. The
// start must not creep back below it, and attestation stays on. The tag list
// is a fixture of tag names only (testdata/tags), taken once from the public
// repository (patch tags included); commits are synthetic.
func TestCyclopsStartsAtFirstCleanRelease(t *testing.T) {
	var tg Target
	for _, c := range Targets {
		if c.Project == "cyclops" {
			tg = c
		}
	}
	if tg.Project == "" {
		t.Fatal("no cyclops target")
	}
	if tg.MinFrom != [2]int{0, 19} || !tg.Attest {
		t.Fatalf("minFrom %v attest %v, want 0.19 and attest on", tg.MinFrom, tg.Attest)
	}
	raw, err := os.ReadFile("testdata/tags/cyclops.txt")
	if err != nil {
		t.Fatal(err)
	}
	idx := extract.ReleaseIndex{Repo: extract.RepoRef{Key: tg.Repo}}
	for _, name := range strings.Fields(string(raw)) {
		idx.Tags = append(idx.Tags, extract.Tag{Name: name, Commit: commitOf(name)})
	}
	x := New(tg)
	pairs := x.Pairs(idx)
	var attestable, other []string
	for _, p := range pairs {
		fl, tl := x.lineFor(p.FromTag, p.FromCommit, p.From), x.lineFor(p.ToTag, p.ToCommit, p.To)
		hop := p.From + "->" + p.To
		if hopShape(tg.Component, fl, tl) == HopPreviousMinor {
			attestable = append(attestable, hop)
		} else {
			other = append(other, hop)
		}
		for _, v := range []string{p.From, p.To} {
			for _, low := range []string{"0.16", "0.17", "0.18"} {
				if strings.HasPrefix(v, low) {
					t.Fatalf("pair %s touches release %s below 0.19", hop, v)
				}
			}
		}
	}
	if got, want := strings.Join(attestable, " "), "0.19.0->0.20.0 0.20.0->0.21.0"; got != want {
		t.Fatalf("attestable hops %q, want %q", got, want)
	}
	if len(other) != 0 || len(pairs) != 2 {
		t.Fatalf("pairs %+v, non-attestable %v: want exactly the two attestable hops", pairs, other)
	}
}
