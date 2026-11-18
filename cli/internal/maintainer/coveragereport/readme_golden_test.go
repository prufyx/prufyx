// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"os"
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

// A pack without any changelog attestation renders the README coverage block
// byte for byte as it was before the changelog row existed.
func TestReadmeBlockUnchangedWithoutChangelog(t *testing.T) {
	want, err := os.ReadFile("testdata/readme-block-no-changelog.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := goldenReadmeBlock(t); got != string(want) {
		t.Fatalf("README block differs from the golden:\n%s", got)
	}
}
