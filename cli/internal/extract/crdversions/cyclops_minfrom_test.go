// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Releases 0.16 to 0.18 carry an empty generated stub definition that the
// scan cannot read; the target starts at 0.19, the first clean release. The
// start must not creep back below it, and attestation stays on.
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
	idx := extract.ReleaseIndex{Repo: extract.RepoRef{Key: tg.Repo}}
	for _, name := range []string{"v0.16.0", "v0.17.0", "v0.18.0", "v0.19.0", "v0.20.0", "v0.21.0"} {
		idx.Tags = append(idx.Tags, extract.Tag{Name: name, Commit: commitOf(name)})
	}
	var hops []string
	for _, p := range New(tg).Pairs(idx) {
		hops = append(hops, p.From+"->"+p.To)
	}
	if got, want := strings.Join(hops, " "), "0.19.0->0.20.0 0.20.0->0.21.0"; got != want {
		t.Fatalf("pairs %q, want %q (no pair may start below 0.19)", got, want)
	}
}
