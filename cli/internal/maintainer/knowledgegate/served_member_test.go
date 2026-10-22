// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

// A served-API list is a record of its own section: adding or changing one is a
// loosening record change, removing one is tightening. A list of any basis but
// mechanical is never admitted, even when the section itself is valid and the
// pack carries the right schema. The section here is test data, not knowledge.
func TestServedAPIsSectionIsRecordsNotAPackMember(t *testing.T) {
	t.Parallel()
	revision := strings.Repeat("a", 40)
	record := func(apis ...string) []servedapis.Record {
		return []servedapis.Record{{
			Component: servedapis.KubernetesComponent, Line: "1.29", Completeness: servedapis.Completeness, APIs: apis,
			Evidence: lineattest.Evidence{
				Basis: constraintengine.BasisReviewed, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
				Sources: []constraintengine.SourceEvidence{{ID: "statement", URL: "https://github.com/example/docs/blob/" + revision + "/versions.md", Revision: revision, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 2}},
			},
		}}
	}
	raw, err := servedapis.Marshal(record("v1 ConfigMap"))
	if err != nil {
		t.Fatal(err)
	}
	changedRaw, err := servedapis.Marshal(record("v1 ConfigMap", "v1 Secret"))
	if err != nil {
		t.Fatal(err)
	}
	const schema = `"prufyx.io/cncf-source-rule-pack/v1alpha10"`
	withSection := func(tr Tree, body []byte) {
		p := readPack(t, tr, cncfRulesPath)
		p.fields[servedapis.PackMember] = json.RawMessage(body)
		p.fields["schema"] = json.RawMessage(schema)
		// The derived files are not regenerated: the support inventory
		// refuses a pack with served-API lists.
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
				if c.Member == servedapis.PackMember {
					t.Fatalf("the section is classified as a pack member: %+v", c)
				}
				if c.Section != servedapis.PackMember {
					continue
				}
				found = true
				wantClass, wantKind := ClassLoosening, KindNew
				switch name {
				case "changed":
					wantKind = KindModify
				case "removed":
					wantClass, wantKind = ClassTightening, KindRemove
				}
				if c.Class != wantClass || !containsKind(c.Kinds, wantKind) {
					t.Fatalf("served-list change classified %+v", c)
				}
			}
			if !found {
				t.Fatalf("no %s record change classified: %+v", servedapis.PackMember, cls.Changes)
			}
			if name == "removed" {
				return
			}
			r, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
			if !blocked {
				t.Fatal("a served-list section change passed the gate")
			}
			if r != nil {
				if r.AutoMerge.Eligible {
					t.Fatal("a served-list section change is eligible for automatic merging")
				}
				requireFail(t, r, "is admitted only when the gate re-derives it")
			}
		})
	}
}
