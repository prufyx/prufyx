// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/bundlechart"
)

func writeChartRoot(t *testing.T, declareSchema bool, set *bundlechart.Set) string {
	t.Helper()
	root := syntheticRoot(t)
	ctx := filepath.Join(root, "demo")
	if declareSchema {
		writeJSON(t, filepath.Join(ctx, "snapshot-metadata.json"), map[string]any{"schema": ObservationSchema, "format": "KubeconfigAPIObservation",
			"collectionStatus": "complete_for_declared_surface", "omissionCount": 0, "chartIdentitySchema": bundlechart.Schema})
	}
	if set != nil {
		writeJSON(t, filepath.Join(ctx, bundlechart.FileName), set)
	}
	regenerateManifests(t, root)
	return root
}

func TestImportAdmitsChartIdentityAndIgnoresAbsence(t *testing.T) {
	set := bundlechart.Build([]bundlechart.Declared{{Name: "widget", Version: "1.4.2"}}, nil, 0)
	bundle, err := importTestPath(t, writeChartRoot(t, true, &set))
	if err != nil || bundle.ChartIdentity == nil || bundle.ChartIdentity.Status != bundlechart.StatusIdentified {
		t.Fatalf("chart identity not admitted: %v %+v", err, bundle.ChartIdentity)
	}
	// An observation from before the field existed carries none and is unchanged.
	bundle, err = importTestPath(t, writeChartRoot(t, false, nil))
	if err != nil || bundle.ChartIdentity != nil {
		t.Fatalf("old observation: %v %+v", err, bundle.ChartIdentity)
	}
	raw, _ := json.Marshal(bundle)
	if json.Valid(raw) && containsKey(raw, "chartIdentity") {
		t.Fatal("absent field leaked into the projection")
	}
}

func containsKey(raw []byte, key string) bool {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	_, ok := m[key]
	return ok
}

func TestImportRejectsChartIdentityMismatchAndForgery(t *testing.T) {
	set := bundlechart.Build([]bundlechart.Declared{{Name: "widget", Version: "1.4.2"}}, nil, 0)
	// File without the metadata declaration, and declaration without the file.
	if _, err := importTestPath(t, writeChartRoot(t, false, &set)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("undeclared chart identity file admitted: %v", err)
	}
	if _, err := importTestPath(t, writeChartRoot(t, true, nil)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("declared but missing chart identity admitted: %v", err)
	}
	// A conflict forged to look resolved.
	conflict := bundlechart.Build([]bundlechart.Declared{{Name: "widget", Version: "1.4.2"}, {Name: "widget", Version: "2.0.0"}}, nil, 0)
	forged := conflict
	forged.Entries = append([]bundlechart.Entry(nil), conflict.Entries...)
	forged.Entries[0].State = bundlechart.StateResolved
	forged.Entries[1].State = bundlechart.StateResolved
	forged.Status, forged.NextAction = bundlechart.StatusIdentified, ""
	if _, err := importTestPath(t, writeChartRoot(t, true, &forged)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged resolution admitted: %v", err)
	}
	// An unknown member in the file.
	root := writeChartRoot(t, true, &set)
	raw, _ := json.Marshal(map[string]any{"apiVersion": bundlechart.Schema, "kind": bundlechart.Kind, "status": "identified", "entries": []any{}, "omissions": []any{}, "values": "x"})
	if err := os.WriteFile(filepath.Join(root, "demo", bundlechart.FileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	regenerateManifests(t, root)
	if _, err := importTestPath(t, root); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown member admitted: %v", err)
	}
}
