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
// registryDigestField is the fact registry digest a check report names; it
// moves when a project is added to the reviewed custom-resource table.
var (
	ruleSetDigestField  = regexp.MustCompile(`"ruleSetDigest":"sha256:[0-9a-f]{64}"`)
	registryDigestField = regexp.MustCompile(`"registryDigest":"sha256:[0-9a-f]{64}"`)
)

const (
	maskedRuleSetDigestField  = `"ruleSetDigest":"` + goldenfile.PackDigestPlaceholder + `"`
	maskedRegistryDigestField = `"registryDigest":"` + goldenfile.PackDigestPlaceholder + `"`
)

// maskPack replaces the embedded pack's revision, digest, rule set digests and registry digests
// with fixed placeholders, so the golden files do not move when the pack is
// republished.
func maskPack(t testing.TB, got []byte) []byte {
	t.Helper()
	knowledge, err := cncfcheck.LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	got = ruleSetDigestField.ReplaceAll(got, []byte(maskedRuleSetDigestField))
	got = registryDigestField.ReplaceAll(got, []byte(maskedRegistryDigestField))
	return goldenfile.MaskPack(got, knowledge.Revision(), knowledge.PackDigest())
}
