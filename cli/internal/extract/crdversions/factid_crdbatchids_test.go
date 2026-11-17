// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
)

// The pack check of the custom-resource version-removal batch derives the set
// fact id of a project from its slug; it must be the fact id every target's
// extractor emits.
func TestTargetFactIDsMatchBatchCheck(t *testing.T) {
	if len(Targets) == 0 {
		t.Fatal("no targets")
	}
	for _, tg := range Targets {
		if got, want := crdbatchids.FactID(tg.Project), tg.FactID(); got != want {
			t.Errorf("%s: batch check expects %q, extractor emits %q", tg.Project, got, want)
		}
	}
}
