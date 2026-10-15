// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"regexp"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/goldenfile"
)

// ruleSetDigestField is a rule set digest in a check report. The digest
// covers the pack's revision, so it moves with every republished pack.
var ruleSetDigestField = regexp.MustCompile(`"ruleSetDigest":"sha256:[0-9a-f]{64}"`)

const maskedRuleSetDigestField = `"ruleSetDigest":"` + goldenfile.PackDigestPlaceholder + `"`

// maskPack replaces the embedded pack's revision, digest and rule set digests
// with fixed placeholders, so the golden files do not move when the pack is
// republished.
func maskPack(t testing.TB, got []byte) []byte {
	t.Helper()
	knowledge, err := cncfcheck.LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	got = ruleSetDigestField.ReplaceAll(got, []byte(maskedRuleSetDigestField))
	return goldenfile.MaskPack(got, knowledge.Revision(), knowledge.PackDigest())
}
