// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// A path-policy section that does not parse (here: a record without
// evidence), or one under a case variant of its member name, is refused
// rather than carried; records_test.go covers valid sections.
func TestLoadPackRefusesInvalidPathPolicies(t *testing.T) {
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
