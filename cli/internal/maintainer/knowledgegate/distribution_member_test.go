// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
)

// A distribution section is a top-level pack member, so adding or changing
// one is a pack-member change: classified as loosening and never admitted,
// even when the section itself is valid and the pack carries the right
// schema. The section here is test data, not knowledge.
func TestDistributionSectionIsAPackMemberChange(t *testing.T) {
	revision := strings.Repeat("a", 40)
	evidence := distribution.Evidence{
		State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
		Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + revision + "/versions.md", Revision: revision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
	}
	section := distribution.Section{
		Records:       []distribution.Record{{Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged, Evidence: evidence}},
		Applicability: []distribution.Applicability{{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusApplies, Evidence: evidence}},
	}
	raw, err := distribution.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	changed := section
	changed.Applicability = []distribution.Applicability{{Distribution: "eks", Family: distribution.FamilyRemovedServedGVK, Status: distribution.StatusNotApplicable, Evidence: evidence}}
	changedRaw, err := distribution.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	const schema = `"prufyx.io/cncf-source-rule-pack/v1alpha9"`
	withSection := func(tr Tree, body []byte) {
		p := readPack(t, tr, cncfRulesPath)
		p.fields[distribution.PackMember] = json.RawMessage(body)
		p.fields["schema"] = json.RawMessage(schema)
		// The derived files are not regenerated: the support inventory
		// refuses a pack with distribution records.
		p.write(t, tr, cncfRulesPath)
	}
	for name, setup := range map[string]func(base, head Tree){
		"added":   func(_, head Tree) { withSection(head, raw) },
		"changed": func(base, head Tree) { withSection(base, raw); withSection(head, changedRaw) },
		"removed": func(base, _ Tree) { withSection(base, raw) },
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			setup(base, head)
			cls, err := Classify(DefaultLayout(), base, head)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			found := false
			for _, c := range cls.Changes {
				if c.Member == distribution.PackMember {
					found = true
					if c.Class != ClassLoosening || len(c.Kinds) != 1 || c.Kinds[0] != KindPackMember {
						t.Fatalf("distribution change classified %+v", c)
					}
				}
			}
			if !found {
				t.Fatalf("no %s change classified: %+v", distribution.PackMember, cls.Changes)
			}
			r, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			if !blocked {
				t.Fatal("a distribution section change passed the gate")
			}
			if r != nil {
				if r.AutoMerge.Eligible {
					t.Fatal("a distribution section change is eligible for automatic merging")
				}
				requireFail(t, r, "the top-level member "+distribution.PackMember+" changed")
			}
		})
	}
}
