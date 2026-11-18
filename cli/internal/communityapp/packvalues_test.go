// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/goldenfile"
	"github.com/prufyx/prufyx/cli/internal/testclock"
)

// ruleSetDigestField is a rule set digest in a check report. The digest
// covers the pack's revision, so it moves with every republished pack.
// registryDigestField is the fact registry digest a check report names; it
// moves when a project is added to the reviewed custom-resource table.
var (
	ruleSetDigestField  = regexp.MustCompile(`"ruleSetDigest":"sha256:[0-9a-f]{64}"`)
	registryDigestField = regexp.MustCompile(`"registryDigest":"sha256:[0-9a-f]{64}"`)
)

// evaluatedAtField is the evaluation time a report records: the test's own
// pinned clock, which a rule renewal can move up (see floorNowArgs).
var evaluatedAtField = regexp.MustCompile(`"evaluatedAt":"[^"]*"`)

// ruleProvenanceField is the evidence window and digest a claim restates from
// the rule it was decided by: rule data that a renewal moves, never a verdict.
var ruleProvenanceField = regexp.MustCompile(`"(evidenceReviewedAt|evidenceValidUntil)":"[^"]*"|"(ruleDigest|knowledgePackDigest)":"sha256:[0-9a-f]+"`)

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
	got = ruleProvenanceField.ReplaceAllFunc(got, func(field []byte) []byte {
		name := field[1 : bytes.IndexByte(field[1:], '"')+1]
		if bytes.HasSuffix(name, []byte("Digest")) {
			return []byte(`"` + string(name) + `":"` + goldenfile.PackDigestPlaceholder + `"`)
		}
		return []byte(`"` + string(name) + `":"2001-08-01T00:00:00Z"`)
	})
	got = evaluatedAtField.ReplaceAll(got, []byte(`"evaluatedAt":"2001-07-01T00:00:00Z"`))
	return testclock.MaskClocks(goldenfile.MaskPack(got, knowledge.Revision(), knowledge.PackDigest()))
}
