// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

// TestReportKnowledgeAge: a batch over a database reports the end dates of
// the selected target once, however many items use it, and a neutral
// community item adds nothing; none of it is part of the encoded report.
func TestReportKnowledgeAge(t *testing.T) {
	fixture := makeSignedBatchFixture(t, true)
	root := t.TempDir()
	kyverno := canonical("pkg:github/kyverno/kyverno", "1.12.5", "1.13.0", []any{}, []any{
		map[string]any{"id": "component.kyverno.distribution", "state": "declared", "enumValue": "official_upstream"},
		map[string]any{"id": "component.kyverno.execution_surface", "state": "declared", "enumValue": "reports_controller"},
		map[string]any{"id": "component.kyverno.reports_chunk_size_flag_present", "state": "declared", "boolValue": true},
	})
	writeBatchFile(t, filepath.Join(root, "kyverno.json"), kyverno)
	writeBatchFile(t, filepath.Join(root, "kyverno-2.json"), kyverno)
	writeBatchFile(t, filepath.Join(root, "loki.json"), canonical("pkg:github/grafana/loki", "2.9.8", "3.0.0", []any{}, []any{boolFact("component.loki.compactor_legacy_shared_store_present", false)}))
	plan := signedKnowledgePlan([]Item{
		{ID: "a", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno.json"},
		{ID: "b", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno-2.json"},
		{ID: "c", Kind: "community_project", Project: "loki", From: "2.9.8", To: "3.0.0", InputPath: "loki.json"},
	})
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	report, _, err := evaluate(planPath, root, time.Time{}, fixture.store, currentbundle.OpenDirectoryNoFollow, knowledge.OpenSelectedCNCF)
	if err != nil {
		t.Fatal(err)
	}
	// A batch never mixes the two: with a database every CNCF item is
	// evaluated against it, so no item can use the embedded CNCF pack.
	for _, item := range report.Items {
		if item.Kind == "cncf" && item.KnowledgeOrigin != "external_signed_local" {
			t.Fatalf("item %d used %s knowledge in a database batch", item.Position, item.KnowledgeOrigin)
		}
	}
	sources, embedded := report.KnowledgeAge()
	if embedded || len(sources) != 1 || len(sources[0].Expiries) != 1 || sources[0].ID == "" {
		t.Fatalf("sources=%+v embedded=%v", sources, embedded)
	}
	if !sources[0].Expiries[0].After(time.Now()) {
		t.Fatalf("end %s", sources[0].Expiries[0])
	}
}

// TestReportKnowledgeAgeEmbedded: only a CNCF item uses the embedded CNCF
// knowledge; a batch of neutral community items does not.
func TestReportKnowledgeAgeEmbedded(t *testing.T) {
	root := t.TempDir()
	writeBatchFile(t, filepath.Join(root, "loki.json"), canonical("pkg:github/grafana/loki", "2.9.8", "3.0.0", []any{}, []any{boolFact("component.loki.compactor_legacy_shared_store_present", false)}))
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "c", Kind: "community_project", Project: "loki", From: "2.9.8", To: "3.0.0", InputPath: "loki.json"}}}
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	report, _, err := Evaluate(planPath, root, time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if sources, embedded := report.KnowledgeAge(); embedded || len(sources) != 0 {
		t.Fatalf("sources=%+v embedded=%v", sources, embedded)
	}
}

// TestReportKnowledgeAgeEmbeddedCNCFItem: a batch without a database that has
// a CNCF item reports that the embedded CNCF knowledge was used, and no
// database targets.
func TestReportKnowledgeAgeEmbeddedCNCFItem(t *testing.T) {
	root := t.TempDir()
	writeBatchFile(t, filepath.Join(root, "kyverno.json"), canonical("pkg:github/kyverno/kyverno", "1.12.5", "1.13.0", []any{}, []any{
		map[string]any{"id": "component.kyverno.distribution", "state": "declared", "enumValue": "official_upstream"},
		map[string]any{"id": "component.kyverno.execution_surface", "state": "declared", "enumValue": "reports_controller"},
		map[string]any{"id": "component.kyverno.reports_chunk_size_flag_present", "state": "declared", "boolValue": true},
	}))
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "a", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno.json"}}}
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	report, _, err := Evaluate(planPath, root, time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if sources, embedded := report.KnowledgeAge(); !embedded || len(sources) != 0 {
		t.Fatalf("sources=%+v embedded=%v", sources, embedded)
	}
}
