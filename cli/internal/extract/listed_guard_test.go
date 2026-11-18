// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// A changelog.listed.* extractor declares only the listed family as mechanical.
// No fact maps to that family, so any rule candidate it emits fails the run.
func TestListedExtractorCannotEmitARuleCandidate(t *testing.T) {
	if !mechanicalAllowed("changelog.listed.prometheus") {
		t.Fatal("the listed prefix is not on the allowlist")
	}
	fams := map[string]bool{lineattest.FamilyChangelogListedEntries: true}
	for _, id := range []string{
		"component.example.flags_set",
		"component.kubernetes.v1_removed_gvk_present",
		"component.prometheus.custom_resource_versions_set",
		"component.kubernetes.x_feature_gates_set",
	} {
		c := Candidate{RequiredFacts: []Fact{{ID: id}}}
		if err := checkMechanicalCandidate("changelog.listed.prometheus", fams, c); err == nil {
			t.Errorf("a rule candidate over %s was admitted", id)
		}
	}
	if err := checkMechanicalCandidate("changelog.listed.prometheus", fams, Candidate{}); err == nil {
		t.Error("a candidate with no fact was admitted")
	}
	for _, id := range []string{"component.example.flags_set"} {
		if FactFamily(Fact{ID: id}) == lineattest.FamilyChangelogListedEntries {
			t.Errorf("fact %s maps to the listed family", id)
		}
	}
}
