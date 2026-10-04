// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestReattestationRefusesModelBases: an empirical, consensus or lead rule
// is renewed by its own evidence, never by a reviewer's reattestation, so
// such a rule is refused before anything is renewed.
func TestReattestationRefusesModelBases(t *testing.T) {
	for _, basis := range []string{"empirical", "consensus", "lead"} {
		raw := json.RawMessage(`{"id":"model-rule","evidence":{"state":"active","basis":"` + basis + `","derivedAt":"2026-09-01T00:00:00Z","reviewedAt":"2026-09-01T00:00:00Z","validUntil":"2026-11-01T00:00:00Z","sources":[]}}`)
		if _, err := parseRuleFields(raw); !errors.Is(err, ErrRejected) {
			t.Fatalf("%s rule admitted: %v", basis, err)
		}
	}
	reviewed := json.RawMessage(`{"id":"reviewed-rule","evidence":{"state":"active","reviewedAt":"2026-09-01T00:00:00Z","validUntil":"2026-11-01T00:00:00Z","sources":[]}}`)
	if _, err := parseRuleFields(reviewed); err != nil {
		t.Fatalf("reviewed rule refused: %v", err)
	}
}
