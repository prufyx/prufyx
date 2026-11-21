// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import "testing"

const overlayFile = "cli/internal/cncfcheck/data/cncf-subprojects.json"

// The CNCF sub-project overlay sits under a data tree but is a hand-cited,
// owner-signed trust file: a factory export (or any data author) touching it
// is a trust-path change, never data.
func TestOverlayFileIsNeverData(t *testing.T) {
	for _, pr := range []*PRInput{
		{Author: "prufyx-bot", Ref: "factory/export-0123456789ab"},
		{Author: markerAuthor, Ref: "feature/x"},
		{Author: "prufyx-bot", Ref: "other"},
	} {
		for _, files := range [][]string{
			{overlayFile},
			{"cli/internal/cncfcheck/data/rules.json", overlayFile},
		} {
			if class, _ := classify(pr, files, false); class != ClassTrustPath {
				t.Errorf("author %s ref %s files %v: class %s, want trust-path", pr.Author, pr.Ref, files, class)
			}
		}
	}
	// The sibling data file keeps its data class (the rule is exact).
	pr := &PRInput{Author: "prufyx-bot", Ref: "factory/export-0123456789ab"}
	if class, _ := classify(pr, []string{"cli/internal/cncfcheck/data/rules.json"}, false); class != ClassData {
		t.Errorf("sibling data file class %s, want data", class)
	}
}
