// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
)

// A pack holding a distributions section still has its records read and its
// rules classified: a tightening rule change beside an unchanged
// distributions section and line attestations is classified as usual, and
// the section is no change at all.
func TestRecordsAreReadBesideADistributionSection(t *testing.T) {
	revision := strings.Repeat("a", 40)
	evidence := distribution.Evidence{
		State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + revision + "/versions.md", Revision: revision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
	}
	raw, err := distribution.Marshal(distribution.Section{
		Records:       []distribution.Record{{Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged, Evidence: evidence}},
		Applicability: []distribution.Applicability{{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusApplies, Evidence: evidence}},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22"}, nil)
	withdrawn := ""
	for _, tr := range []Tree{base, head} {
		p := readPack(t, tr, cncfRulesPath)
		p.fields[distribution.PackMember] = json.RawMessage(raw)
		p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha9"`)
		if tr == head {
			withdrawn = p.activeReviewed()[0]
			evidenceOf(p.find(t, withdrawn))["state"] = "withdrawn"
		}
		p.write(t, tr, cncfRulesPath)
	}
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(cls.Changes) != 1 || cls.Changes[0].RuleID != withdrawn || cls.Changes[0].Class != ClassTightening {
		t.Fatalf("changes %+v", cls.Changes)
	}
	if n := len(cls.head["cncf"].Records); n != 1 {
		t.Fatalf("%d records read", n)
	}
}
