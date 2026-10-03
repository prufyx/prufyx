// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// Re-attestation does not handle line attestations yet: a pack carrying
// them is refused instead of being rewritten without them.
func TestLoadPackRefusesLineAttestations(t *testing.T) {
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
		t.Fatalf("a pack with line attestations was accepted: %v", err)
	}
}
