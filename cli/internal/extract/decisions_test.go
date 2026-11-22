// SPDX-License-Identifier: AGPL-3.0-only
package extract

import (
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"strings"
	"testing"
)

func TestDecisionEmissionRefusesPostStampSemanticMutation(t *testing.T) {
	for _, tt := range []string{"semantic", "inventory"} {
		t.Run(tt, func(t *testing.T) {
			o := &Output{beforeStamp: map[string][][]byte{}}
			entry := Entry{Project: "example", Rule: RuleJSON{ID: "one", ReasonCode: "ORIGINAL", Evidence: Evidence{Extractor: constraintengine.Extractor{ID: "example"}}}}
			if e := o.capture(FileCandidates, "candidate")(entry); e != nil {
				t.Fatal(e)
			}
			entry.Rule.Evidence.Extractor.Version = "actual"
			entry.Rule.Evidence.Extractor.CodeDigest = "actual"
			o.Entries = []Entry{entry}
			want := "semantic record changed"
			if tt == "semantic" {
				o.Entries[0].Rule.ReasonCode = "CHANGED"
			} else {
				o.Entries = nil
				want = "inventory changed"
			}
			if _, e := o.DecisionFiles(); e == nil || !strings.Contains(e.Error(), want) {
				t.Fatalf("post-stamp mutation: %v", e)
			}
		})
	}
}
