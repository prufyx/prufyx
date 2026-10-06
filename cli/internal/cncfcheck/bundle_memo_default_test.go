// SPDX-License-Identifier: AGPL-3.0-only

//go:build !prufyx_synthetic_knowledge

package cncfcheck

import "testing"

// Default build: the process-wide memo serves the embedded pack, and the
// embedded pack is never the synthetic one.
func TestDefaultBuildServesProductionPack(t *testing.T) {
	b, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if b.pack.Revision == "synthetic-test-only" {
		t.Fatal("production bundle carries the synthetic revision")
	}
	if len(additionalDefinitions()) != 0 {
		t.Fatal("default build has additional definitions")
	}
}
