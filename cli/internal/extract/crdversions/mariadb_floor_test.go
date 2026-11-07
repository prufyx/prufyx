// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The mariadb-operator target starts its 0.x pairs at line 0.34: the lines
// 0.34 to 0.38 are consecutive in the upstream tags, the lines below carry no
// semver release tag the extractor reads. The tag names are the public ones;
// commits are synthetic.
func TestMariadbOperatorFloorIs034(t *testing.T) {
	var tg Target
	for _, c := range Targets {
		if c.Project == "mariadb-operator" {
			tg = c
		}
	}
	if tg.Project == "" {
		t.Fatal("no mariadb-operator target")
	}
	if tg.MinFrom != [2]int{0, 34} || !tg.Attest {
		t.Fatalf("minFrom %v attest %v, want 0.34 and attest on", tg.MinFrom, tg.Attest)
	}
	tags := "v0.33.0 v0.34.0 v0.35.0 v0.35.1 v0.36.0 v0.37.0 v0.37.1 v0.38.0 v0.38.1"
	idx := extract.ReleaseIndex{Repo: extract.RepoRef{Key: tg.Repo}}
	for _, n := range strings.Fields(tags) {
		idx.Tags = append(idx.Tags, extract.Tag{Name: n, Commit: commitOf(n)})
	}
	var got []string
	for _, p := range New(tg).Pairs(idx) {
		got = append(got, p.From+">"+p.To)
	}
	want := "0.34.0>0.35.0 0.35.0>0.36.0 0.36.0>0.37.0 0.37.0>0.38.0"
	if strings.Join(got, " ") != want {
		t.Fatalf("pairs %q, want %q (no pair may start below 0.34)", got, want)
	}
}
