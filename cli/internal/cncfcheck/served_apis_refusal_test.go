// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"testing"
)

// servedSectionForRefusal is a served-list section as test data. The
// refusals below fire on the member being present, not on its content.
const servedSectionForRefusal = `[{"component":"pkg:github/kubernetes/kubernetes","line":"1.29","completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":["v1 ConfigMap"],"evidence":{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[]}}]`

// TestExternalProfileRefusesServedAPIs: an external pack that carries a
// served-API list section is refused by validateExternalPack, and the same
// pack without it is admitted, so the refusal is the section's.
func TestExternalProfileRefusesServedAPIs(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	value := base.pack
	value.Revision = "7"
	if err := validateExternalPack(base, value, "7"); err != nil {
		t.Fatalf("control: the pack without a served list is refused: %v", err)
	}
	value.ServedAPIs, value.Schema = json.RawMessage(servedSectionForRefusal), packSchemaServedAPIs
	if err := validateExternalPack(base, value, "7"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted served-API lists: %v", err)
	}
}

// TestSplitRefusesServedAPIs: a source pack with a served-API list section
// cannot be split into project targets: buildExternalTargets refuses it
// rather than publish targets without the section.
func TestSplitRefusesServedAPIs(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	same := func(string, func(string) ([]byte, error)) (string, error) { return "7", nil }
	if _, targets, err := buildExternalTargets(base, "7", "operator_provided", same); err != nil || len(targets) == 0 {
		t.Fatalf("control: the pack without a served list does not split: %v", err)
	}
	base.pack.ServedAPIs, base.pack.Schema = json.RawMessage(servedSectionForRefusal), packSchemaServedAPIs
	if _, targets, err := buildExternalTargets(base, "7", "operator_provided", same); !errors.Is(err, ErrIntegrity) || targets != nil {
		t.Fatalf("buildExternalTargets admitted served-API lists: %v", err)
	}
}
