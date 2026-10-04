// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// syntheticDistributionSection is a valid distribution section. Its
// statement is test data, not knowledge.
func syntheticDistributionSection(t *testing.T) []byte {
	t.Helper()
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
	return raw
}

// Evidence reattestation cannot renew distribution records yet: a pack
// carrying a valid distribution section, under its exact member name or a
// case variant, is refused, so its records simply expire. Citation
// monitoring refuses it too, rather than leaving its citations unread.
func TestLoadPackRefusesDistributions(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadPack(raw); err != nil {
		t.Fatalf("the published pack is refused: %v", err)
	}
	section := syntheticDistributionSection(t)
	if _, err := distribution.Parse(section); err != nil {
		t.Fatalf("fixture section invalid: %v", err)
	}
	for _, member := range []string{distribution.PackMember, "Distributions", "DISTRIBUTIONS"} {
		with := bytes.Replace(raw, []byte(`"entries":`), append(append([]byte(`"`+member+`":`), section...), []byte(`,"entries":`)...), 1)
		if bytes.Equal(with, raw) {
			t.Fatal("fixture edit did not apply")
		}
		if _, err := loadPack(with); !errors.Is(err, ErrRejected) {
			t.Fatalf("a pack with %s was accepted: %v", member, err)
		}
		if _, err := evidencerepin.LoadCitations("rules.json", with); err == nil {
			t.Fatalf("citation monitoring read a pack with %s", member)
		}
		if _, err := evidencerepin.PackRecords(with); err == nil {
			t.Fatalf("PackRecords read a pack with %s", member)
		}
	}
	// The record reader still reads the published pack.
	if _, err := evidencerepin.LoadCitations("rules.json", raw); err != nil {
		t.Fatalf("citation monitoring refuses the published pack: %v", err)
	}
}
