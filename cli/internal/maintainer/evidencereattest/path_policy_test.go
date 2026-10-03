// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// Re-attestation does not renew upgrade-path policies yet: a pack carrying
// them is refused instead of being rewritten without them, so the policies
// expire and the paths they shaped fall back to gaps.
func TestLoadPackRefusesPathPolicies(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadPack(raw); err != nil {
		t.Fatalf("the published pack is refused: %v", err)
	}
	for _, member := range []string{"pathPolicies", "PathPolicies"} {
		withPolicies := bytes.Replace(raw, []byte(`"entries":`), []byte(`"`+member+`":[{"component":"pkg:github/kubernetes/kubernetes","policy":"sequential_minor"}],"entries":`), 1)
		if bytes.Equal(withPolicies, raw) {
			t.Fatal("fixture edit did not apply")
		}
		if _, err := loadPack(withPolicies); !errors.Is(err, ErrRejected) {
			t.Fatalf("a pack with %s was accepted: %v", member, err)
		}
	}
}
