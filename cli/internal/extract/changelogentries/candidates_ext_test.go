// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"os"
	"path/filepath"
	"testing"
)

// The excerpt in testdata/candidates is cut from the public gateway-api
// (Apache-2.0) CHANGELOG/1.6-CHANGELOG.md at
// 4547ab868b4a3e71ceaaab7dbf0276cfb8d9f77c, up to the v1.6.1 heading.
func TestProposeGatewayPerLineTemplate(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "candidates", "gateway-api--CHANGELOG-1.6-CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	gw := string(b)
	// Only the newest section is scored: the v1.6.2 section follows a heading
	// "Major Changes Since v1.6.2", which the unchanged rule withholds.
	tags := map[string]byte{"v1.6.3": 'a'}
	p, err := propose(t, rcFixture(t, tags, map[string]string{"a|CHANGELOG/1.6-CHANGELOG.md": gw}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Row.Form != FormPerLineFile || p.Row.Path != "CHANGELOG/{line}-CHANGELOG.md" || p.Row.HeadingStyle != "version-v-prefixed" || p.Located != 1 {
		t.Fatalf("%+v", p)
	}
	for _, near := range []string{"CHANGELOG/v1.6-CHANGELOG.md", "changelog/1.6-CHANGELOG.md", "CHANGELOG/1.6-CHANGELOG.txt", "CHANGELOG/1.6.0-CHANGELOG.md", "CHANGELOG/1.7-CHANGELOG.md"} {
		_, err := propose(t, rcFixture(t, tags, map[string]string{"a|" + near: gw}))
		wantNoRow(t, err, NoRowNoCandidate)
	}
}

func TestCandidateListIsClosedAndLoads(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range candidatePaths {
		if seen[c.Path] {
			t.Fatalf("duplicate candidate %s", c.Path)
		}
		seen[c.Path] = true
		r := rowData{Component: "notes", Repo: rcRepo, Form: c.Form, Path: c.Path}
		if c.Form != FormPerVersionFile {
			r.HeadingStyle, r.BoundaryStyles = "version-plain", []string{"unreleased"}
		}
		if _, err := r.target(); err != nil {
			t.Errorf("%s: %v", c.Path, err)
		}
	}
	if !seen["CHANGELOG/{line}-CHANGELOG.md"] {
		t.Error("gateway-api template missing")
	}
	if len(headingOrder) != len(headingStyles) {
		t.Errorf("headingOrder has %d styles, table %d", len(headingOrder), len(headingStyles))
	}
}
