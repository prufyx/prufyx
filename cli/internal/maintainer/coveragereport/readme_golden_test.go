// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"strings"
	"testing"
)

const goldenInventory = `{"counts":{"cncfSourceRules":1,"cncfRuleProjects":1,"cncfSourceRulesWithdrawn":0,"communityProjectSourceRules":1,"communityProjectRuleProjects":1,"executableProjects":1,"selectedSourceProjects":1,"selectedSourceOnlyProjects":0}}`

func goldenReadmeBlock(t *testing.T) string {
	t.Helper()
	r, err := Compute(Input{Pack: read(t, "testdata/pack-cncf-2026-09-13.4-reduced.json"), Lines: read(t, "testdata/lines-2026-10-08.json"), Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	block, err := RenderREADMEBlock(r, []byte(goldenInventory), baselineNow)
	if err != nil {
		t.Fatal(err)
	}
	return block
}

// A pack without any changelog attestation has no changelog sentence and no L
// pair in the README coverage block.
func TestReadmeBlockWithoutChangelog(t *testing.T) {
	got := goldenReadmeBlock(t)
	if strings.Contains(got, "Changelog-attested") {
		t.Fatalf("a changelog sentence without a changelog attestation:\n%s", got)
	}
	if !strings.Contains(got, "<summary>Per project:") {
		t.Fatalf("the per-project table is missing:\n%s", got)
	}
}
