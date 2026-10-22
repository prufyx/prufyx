// SPDX-License-Identifier: AGPL-3.0-only

package projectcheck

import (
	"encoding/json"
	"errors"
	"testing"
)

// This package's pack is the attested community corpus of the scope route.
// It is not where a community custom-resource project's line attestations
// live (those sit in the CNCF pack beside the project's rules), and it
// decodes strictly: a line attestation section in it is an unknown member.
func TestPackCarriesNoLineAttestations(t *testing.T) {
	registryRaw, err := packaged.ReadFile("data/projects.json")
	if err != nil {
		t.Fatal(err)
	}
	packRaw, err := packaged.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(packRaw, &pack); err != nil {
		t.Fatal(err)
	}
	control, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadRaw(registryRaw, control, definitions()); err != nil {
		t.Fatalf("control: %v", err)
	}
	pack["lineAttestations"] = json.RawMessage(`[]`)
	withSection, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadRaw(registryRaw, withSection, definitions()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a pack with a line attestation section loaded: %v", err)
	}
}
