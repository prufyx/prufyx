// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestRowDigestGoldenAndSensitive(t *testing.T) {
	base := Target{Component: "notes", Repo: extract.RepoRef{Key: "github.com/example/notes"}, Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern: `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`, BoundaryPatterns: []string{`^Unreleased$`}}
	const want = "902db864d45b131f13ef3d2724d823476e3f37cabb63bceb53986ab7a4e5a398"
	got := base.RowDigest()
	if got != want {
		t.Fatalf("RowDigest = %s", got)
	}
	for name, mut := range map[string]func(*Target){
		"path":     func(x *Target) { x.Path = "docs/CHANGELOG.md" },
		"heading":  func(x *Target) { x.HeadingPattern = `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$` },
		"boundary": func(x *Target) { x.BoundaryPatterns = []string{`^\[Unreleased\]$`} },
		"repo":     func(x *Target) { x.Repo = extract.RepoRef{Key: "github.com/example/other"} },
		"maxBytes": func(x *Target) { x.MaxBytes = 5 },
	} {
		m := base
		mut(&m)
		if m.RowDigest() == got {
			t.Errorf("%s change did not alter the digest", name)
		}
	}
	a, b := base, base
	a.BoundaryPatterns, b.BoundaryPatterns = nil, []string{}
	if a.RowDigest() != b.RowDigest() {
		t.Error("nil and empty boundary differ")
	}
}
