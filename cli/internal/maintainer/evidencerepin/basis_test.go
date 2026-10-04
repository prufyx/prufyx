// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// TestLoadCitationsRefusesModelBases: evidence repin accepts only reviewed
// and mechanical rules; an empirical, consensus or lead rule is refused.
func TestLoadCitationsRefusesModelBases(t *testing.T) {
	digest := sourcecorpus.SHA([]byte("line1\nline2"))
	for _, basis := range []string{"empirical", "consensus", "lead"} {
		entry := ruleEntry("argo-cd", "argo-cd.rule-1", source("argo-cd-src", "argoproj", "argo-cd", commitA, "VERSION", digest, 1, 2))
		evidence := entry["rule"].(map[string]any)["evidence"].(map[string]any)
		evidence["basis"], evidence["derivedAt"] = basis, "2026-09-12T10:00:00Z"
		if _, err := LoadCitations("rules.json", rulePackJSON(t, entry)); err == nil {
			t.Fatalf("%s rule accepted", basis)
		}
	}
}
