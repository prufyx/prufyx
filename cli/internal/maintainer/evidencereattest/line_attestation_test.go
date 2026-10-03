// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// An attestation section that does not parse (here: empty) is refused
// rather than carried; records_test.go covers valid sections.
func TestLoadPackRefusesInvalidLineAttestations(t *testing.T) {
	raw, err := os.ReadFile("../../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadPack(raw); err != nil {
		t.Fatalf("the published pack is refused: %v", err)
	}
	attested := bytes.Replace(raw, []byte(`"entries":`), []byte(`"lineAttestations":[],"entries":`), 1)
	if bytes.Equal(attested, raw) {
		t.Fatal("fixture edit did not apply")
	}
	if _, err := loadPack(attested); !errors.Is(err, ErrRejected) {
		t.Fatalf("a pack with an empty attestation section was accepted: %v", err)
	}
}
