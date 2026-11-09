// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// A published-line component's pair across skipped lines is decided by the
// from-line its attestation carries; a hand-crafted attestation that lists a
// rule is never line-wide for it.
func TestPublishedLineAttestedFamilies(t *testing.T) {
	const comp = "pkg:github/example/published"
	defer lineattest.SetPublishedLineComponentsForTest(comp)()
	commit := strings.Repeat("a", 40)
	att := func(ruleIDs ...string) lineattest.LineAttestation {
		return lineattest.LineAttestation{Component: comp, Line: "26.3", FactFamily: lineattest.FamilyCustomResourceVersions,
			Completeness: lineattest.Completeness, RuleIDs: ruleIDs,
			Releases: &lineattest.Releases{From: []lineattest.Release{{Version: "25.10.1", Commit: commit}}, To: []lineattest.Release{{Version: "26.3.0", Commit: commit}}}}
	}
	releases := map[string][]string{"25.10": {"25.10.1"}, "26.3": {"26.3.0"}}
	got, listed := attestedFamilies("25.10", "26.3", []lineattest.LineAttestation{att()}, nil, releases)
	if len(got) != 1 || listed {
		t.Fatalf("25.10 -> 26.3: %v %v", got, listed)
	}
	for _, from := range []string{"26.1", "26.2", "25.8"} {
		if got, _ := attestedFamilies(from, "26.3", []lineattest.LineAttestation{att()}, nil, releases); len(got) != 0 {
			t.Errorf("%s -> 26.3 decided by an attestation that carries 25.10: %v", from, got)
		}
	}
	// A listed rule, even one whose range spans the lines, is not line-wide.
	rule := &ruleRec{id: "r1", valid: true, tr: constraintengine.RuleTransition{Range: &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: "25.10.0", Lt: "25.11.0"},
		To:   constraintengine.VersionBound{Gte: "26.3.0", Lt: "26.4.0"},
	}}}
	if got, _ := attestedFamilies("25.10", "26.3", []lineattest.LineAttestation{att("r1")}, map[string]*ruleRec{"r1": rule}, releases); len(got) != 0 {
		t.Fatalf("an attestation listing a rule for a published-line component was decided: %v", got)
	}
	// Unregistered: the same document is a plain 26.2 -> 26.3 attestation.
	restore := lineattest.SetPublishedLineComponentsForTest()
	defer restore()
	if got, _ := attestedFamilies("25.10", "26.3", []lineattest.LineAttestation{att()}, nil, releases); len(got) != 0 {
		t.Fatalf("an unregistered component decided a skipped-line pair: %v", got)
	}
}
