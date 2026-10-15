// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/goldenfile"
)

// maskPack replaces the embedded pack's revision and digest with fixed
// placeholders, so the golden files do not move when the pack is republished.
func maskPack(t testing.TB, got []byte) []byte {
	t.Helper()
	knowledge, err := cncfcheck.LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	return goldenfile.MaskPack(got, knowledge.Revision(), knowledge.PackDigest())
}
