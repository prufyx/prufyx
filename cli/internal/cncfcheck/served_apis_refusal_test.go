// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"
	"errors"
	"strings"
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
	if err := validateExternalPack(base, value, "7", false); err != nil {
		t.Fatalf("control: the pack without a served list is refused: %v", err)
	}
	value.ServedAPIs, value.Schema = json.RawMessage(servedSectionForRefusal), packSchemaServedAPIs
	if err := validateExternalPack(base, value, "7", false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("validateExternalPack admitted served-API lists: %v", err)
	}
}

// TestSplitCarriesServedAPIs: a source pack with a served-API list section
// splits (EXTPACK): the list rides in the kubernetes target, a records
// envelope; the old envelope check (validateExternalPack without records)
// still refuses it above.
func TestSplitCarriesServedAPIs(t *testing.T) {
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	same := func(string, func(string) ([]byte, error)) (string, error) { return "7", nil }
	base.pack.ServedAPIs, base.pack.Schema = json.RawMessage(extServedSection("1.29", "v1 ConfigMap")), packSchemaServedAPIs
	_, targets, err := buildExternalTargets(base, "7", "operator_provided", same)
	if err != nil {
		t.Fatalf("buildExternalTargets refused served-API lists: %v", err)
	}
	for _, target := range targets {
		carries := strings.Contains(string(target.Bytes), `"servedAPIs"`)
		if carries != (target.Path == ProjectTargetPath("kubernetes")) {
			t.Fatalf("%s carries served lists: %v", target.Path, carries)
		}
	}
}
