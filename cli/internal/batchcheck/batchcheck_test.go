// SPDX-License-Identifier: AGPL-3.0-only

package batchcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func writeBatchFile(t *testing.T, path string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func canonical(component, from, to string, factsCurrent, factsProposed []any) map[string]any {
	return map[string]any{
		"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED",
		"current":  map[string]any{"components": []any{map[string]any{"component": component, "version": from, "facts": factsCurrent}}},
		"proposed": map[string]any{"components": []any{map[string]any{"component": component, "version": to, "facts": factsProposed}}},
	}
}

func boolFact(id string, value bool) map[string]any {
	return map[string]any{"id": id, "state": "declared", "boolValue": value}
}

func TestEvaluateMixedOutcomesAndDeterministicPrecedence(t *testing.T) {
	root := t.TempDir()
	thanos := writeBatchFile(t, filepath.Join(root, "thanos.json"), canonical("pkg:github/thanos-io/thanos", "0.41.0", "0.42.0", []any{}, []any{boolFact("component.thanos.removed_subcommand_flags_present", false)}))
	loki := writeBatchFile(t, filepath.Join(root, "loki.json"), canonical("pkg:github/grafana/loki", "2.9.8", "3.0.0", []any{}, []any{boolFact("component.loki.compactor_legacy_shared_store_present", true)}))
	unknown := writeBatchFile(t, filepath.Join(root, "unknown.json"), canonical("pkg:github/thanos-io/thanos", "0.40.0", "0.42.0", []any{}, []any{boolFact("component.thanos.removed_subcommand_flags_present", false)}))
	_ = thanos
	_ = loki
	_ = unknown
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{
		{ID: "z-unknown", Kind: "cncf", Project: "thanos", From: "0.40.0", To: "0.42.0", InputPath: "unknown.json"},
		{ID: "a-pass", Kind: "cncf", Project: "thanos", From: "0.41.0", To: "0.42.0", InputPath: "thanos.json"},
		{ID: "m-blocked", Kind: "community_project", Project: "loki", From: "2.9.8", To: "3.0.0", InputPath: "loki.json"},
	}}
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	report, exit, err := Evaluate(planPath, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC))
	if err != nil || exit != 10 || report.Decision != "UNKNOWN" || report.AggregateCategory != "BLOCKED" {
		t.Fatalf("report=%+v exit=%d err=%v", report, exit, err)
	}
	if len(report.Items) != 3 || report.Items[0].ID != "item-001" || report.Items[0].Position != 1 || report.Items[1].Outcome != "PASS" || report.Items[2].Category != "BLOCKED" {
		t.Fatalf("items=%+v", report.Items)
	}
	if len(report.Items[1].Report) == 0 || !strings.Contains(string(report.Items[1].Report), `"inputDigest":"sha256:`) || strings.Contains(string(report.Items[1].Report), "a-pass") {
		t.Fatalf("sealed child report missing or leaked plan label: %s", report.Items[1].Report)
	}
	if len(report.Items[0].Categories) != 1 || report.Items[0].Categories[0] != "UNKNOWN_CLAIM" {
		t.Fatalf("unexpected category set: %+v", report.Items[0].Categories)
	}
}

func TestEvaluateClassifiesStaleEvidenceAndRejectsUnsafePaths(t *testing.T) {
	root := t.TempDir()
	input := writeBatchFile(t, filepath.Join(root, "input.json"), canonical("pkg:github/thanos-io/thanos", "0.41.0", "0.42.0", []any{}, []any{boolFact("component.thanos.removed_subcommand_flags_present", false)}))
	_ = input
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "stale", Kind: "cncf", Project: "thanos", From: "0.41.0", To: "0.42.0", InputPath: "input.json"}}}
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	report, exit, err := Evaluate(planPath, root, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || exit != 11 || report.AggregateCategory != "STALE_EVIDENCE" || report.Items[0].Category != "STALE_EVIDENCE" {
		t.Fatalf("report=%+v exit=%d err=%v", report, exit, err)
	}
	plan.Items[0].InputPath = "../input.json"
	badPlan := writeBatchFile(t, filepath.Join(root, "bad-plan.json"), plan)
	if _, exit, err := Evaluate(badPlan, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC)); err == nil || exit != 2 {
		t.Fatalf("unsafe path accepted exit=%d err=%v", exit, err)
	}
}

func TestEvaluatePreflightAndPrivacyBoundaries(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "private-secret.json")
	if err := os.WriteFile(secret, []byte(`{"private":"must-not-appear"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "bad-project", Kind: "cncf", Project: "not-a-real-project", From: "1.0.0", To: "1.1.0", InputPath: "private-secret.json"}}}
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	if _, exit, err := Evaluate(planPath, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC)); err == nil || exit != 2 {
		t.Fatalf("unknown project accepted exit=%d err=%v", exit, err)
	}
	if strings.Contains(string(mustJSON(plan)), "must-not-appear") {
		t.Fatal("test fixture unexpectedly exposed secret")
	}
}

func mustJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }

func TestDecodeStrictRejectsTrailingValuesAndNestedDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"schema":"x"}{"schema":"y"}`,
		`{"outer":{"name":1,"name":2}}`,
		`{"items":[{"name":1,"name":2}]}`,
	} {
		var value map[string]any
		if err := decodeStrict([]byte(raw), &value); err == nil {
			t.Fatalf("accepted malformed JSON: %s", raw)
		}
	}
}

func TestEvaluateBindsPlanTransitionAndComponent(t *testing.T) {
	root := t.TempDir()
	writeBatchFile(t, filepath.Join(root, "input.json"), canonical("pkg:github/thanos-io/thanos", "0.41.0", "0.42.0", nil, nil))
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "private-operator-label", Kind: "cncf", Project: "thanos", From: "0.40.0", To: "0.42.0", InputPath: "input.json"}}}
	path := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	if _, exit, err := Evaluate(path, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC)); err == nil || exit != 2 {
		t.Fatalf("mismatched transition accepted: exit=%d err=%v", exit, err)
	}
}

func TestEvaluateAllowsValidatedDependencyComponents(t *testing.T) {
	root := t.TempDir()
	input := canonical("pkg:github/rook/rook", "1.19.5", "1.20.0", []any{}, []any{})
	input["proposed"].(map[string]any)["components"] = []any{
		map[string]any{"component": "pkg:github/kubernetes/kubernetes", "version": "1.31.0", "facts": []any{}},
		map[string]any{"component": "pkg:github/rook/rook", "version": "1.20.0", "facts": []any{}},
	}
	path := writeBatchFile(t, filepath.Join(root, "input.json"), input)
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "rook-with-dependency", Kind: "cncf", Project: "rook", From: "1.19.5", To: "1.20.0", InputPath: filepath.Base(path)}}}
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	report, exit, err := Evaluate(planPath, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("dependency input rejected: exit=%d err=%v", exit, err)
	}
	standalone, standaloneErr := cncfcheck.Check("rook", mustJSON(input), time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC))
	if standaloneErr != nil || len(report.Items) != 1 || len(report.Items[0].Report) == 0 || len(standalone.Check.Claims) == 0 {
		t.Fatalf("batch=%+v standalone=%v", report, standaloneErr)
	}
	if !strings.Contains(string(report.Items[0].Report), standalone.Check.Claims[0].RuleID) {
		t.Fatalf("batch child report differs from standalone report")
	}
}

func TestDetailedExitSeparatesFreshnessStates(t *testing.T) {
	for _, tc := range []struct {
		category string
		want     int
	}{
		{"STALE_EVIDENCE", 12}, {"NOT_YET_REVIEWED", 13}, {"UNKNOWN_CLAIM", 11}, {"BLOCKED", 10},
	} {
		report := Report{AggregateCategory: tc.category, Items: []ItemResult{{Category: tc.category}}}
		got, err := ExitForMode(report, "detailed")
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %d err %v", tc.category, got, err)
		}
	}
}

func TestEvaluateRejectsSymlinkedInputAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeBatchFile(t, filepath.Join(outside, "input.json"), canonical("pkg:github/thanos-io/thanos", "0.41.0", "0.42.0", nil, nil))
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "nested")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "nested")); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "symlinked", Kind: "cncf", Project: "thanos", From: "0.41.0", To: "0.42.0", InputPath: "nested/input.json"}}}
	path := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	if _, exit, err := Evaluate(path, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC)); err == nil || exit != 2 {
		t.Fatalf("symlinked input accepted: exit=%d err=%v", exit, err)
	}
}

func TestEvaluateRejectsRootReplacedBySymlinkBeforeDescriptorAcquisition(t *testing.T) {
	parent := t.TempDir()
	declaredRoot := filepath.Join(parent, "declared")
	if err := os.Mkdir(declaredRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	writeBatchFile(t, filepath.Join(outside, "input.json"), canonical("pkg:github/thanos-io/thanos", "0.41.0", "0.42.0", nil, nil))
	plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: KnowledgeEmbeddedOnly}, Items: []Item{{ID: "root-replacement", Kind: "cncf", Project: "thanos", From: "0.41.0", To: "0.42.0", InputPath: "input.json"}}}
	planPath := writeBatchFile(t, filepath.Join(parent, "plan.json"), plan)
	acquisitions := 0
	replaceThenAcquire := func(path string) (*os.File, error) {
		acquisitions++
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		if err := os.Symlink(outside, path); err != nil {
			return nil, err
		}
		return currentbundle.OpenDirectoryNoFollow(path)
	}
	if _, exit, err := evaluate(planPath, declaredRoot, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC), "", replaceThenAcquire, knowledge.OpenSelectedCNCF); err == nil || exit != 2 || acquisitions != 1 {
		t.Fatalf("root replacement accepted: exit=%d err=%v acquisitions=%d", exit, err, acquisitions)
	}
}

type signedBatchFixture struct {
	store    string
	manifest knowledgefixture.Manifest
	receipt  knowledge.ImportReceipt
}

func makeSignedBatchFixture(t *testing.T, active bool) signedBatchFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	return makeSignedBatchFixtureAt(t, active, now, now.Add(24*time.Hour))
}

func makeSignedBatchFixtureAt(t *testing.T, active bool, generatedAt, evidenceExpiry time.Time) signedBatchFixture {
	t.Helper()
	artifacts, err := knowledgefixture.GenerateConstraintsWithEvidenceExpiry(generatedAt, evidenceExpiry)
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "private-store-name")
	root := filepath.Join(dir, knowledgefixture.RootName)
	packagePath := filepath.Join(dir, knowledgefixture.Revision1Name)
	if err := os.WriteFile(root, artifacts.Root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, artifacts.Revision1, 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: packagePath, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: manifest.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: manifest.Revisions[0].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	if active {
		packagePath = filepath.Join(dir, knowledgefixture.Revision2Name)
		if err := os.WriteFile(packagePath, artifacts.Revision2, 0o600); err != nil {
			t.Fatal(err)
		}
		receipt, err = knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: packagePath, StoreRoot: store, ExpectedRevision: "2", ExpectedBundleDigest: manifest.Revisions[1].BundleDigest})
		if err != nil {
			t.Fatal(err)
		}
	}
	return signedBatchFixture{store: store, manifest: manifest, receipt: receipt}
}

func signedKnowledgePlan(items []Item) Plan {
	return Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: KnowledgeExternalCNCFEmbeddedCommunity, CNCF: "external_signed_local", CommunityProject: "embedded"}, Items: items}
}

func TestEvaluateWithStoreUsesOneCurrentSnapshotForMixedKnowledge(t *testing.T) {
	fixture := makeSignedBatchFixture(t, true)
	root := t.TempDir()
	kyverno := canonical("pkg:github/kyverno/kyverno", "1.12.5", "1.13.0", []any{}, []any{
		map[string]any{"id": "component.kyverno.distribution", "state": "declared", "enumValue": "official_upstream"},
		map[string]any{"id": "component.kyverno.execution_surface", "state": "declared", "enumValue": "reports_controller"},
		map[string]any{"id": "component.kyverno.reports_chunk_size_flag_present", "state": "declared", "boolValue": true},
	})
	writeBatchFile(t, filepath.Join(root, "kyverno.json"), kyverno)
	writeBatchFile(t, filepath.Join(root, "loki.json"), canonical("pkg:github/grafana/loki", "2.9.8", "3.0.0", []any{}, []any{boolFact("component.loki.compactor_legacy_shared_store_present", false)}))
	plan := signedKnowledgePlan([]Item{
		{ID: "signed-cncf", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno.json"},
		{ID: "embedded-neutral", Kind: "community_project", Project: "loki", From: "2.9.8", To: "3.0.0", InputPath: "loki.json"},
	})
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), plan)
	opens := 0
	openOnce := func(selection knowledge.SelectionRequest, projects []string) (knowledge.VerifiedRevision, error) {
		opens++
		return knowledge.OpenSelectedCNCF(selection, projects)
	}
	report, exit, err := evaluate(planPath, root, time.Time{}, fixture.store, currentbundle.OpenDirectoryNoFollow, openOnce)
	if err != nil || exit != 10 || opens != 1 || len(report.Items) != 2 {
		t.Fatalf("report=%+v exit=%d err=%v opens=%d", report, exit, err, opens)
	}
	if report.KnowledgeRevision != "2" || report.KnowledgeBundleDigest != fixture.manifest.Revisions[1].BundleDigest || report.KnowledgeTrustReceiptDigest != fixture.receipt.TrustReceiptDigest {
		t.Fatalf("snapshot binding=%+v", report)
	}
	if report.Items[0].KnowledgeOrigin != "external_signed_local" || report.Items[1].KnowledgeOrigin != "embedded" || !strings.Contains(string(report.Items[0].Report), `"evaluatedAt":"`+report.EvaluatedAt+`"`) || !strings.Contains(string(report.Items[1].Report), `"evaluatedAt":"`+report.EvaluatedAt+`"`) {
		t.Fatalf("mixed knowledge clocks/origins not bound: %+v", report.Items)
	}
	raw, marshalErr := json.Marshal(report)
	if marshalErr != nil || strings.Contains(string(raw), fixture.store) || strings.Contains(string(raw), "private-store-name") || strings.Contains(string(raw), "signed-cncf") {
		t.Fatalf("private store path or label leaked: %s err=%v", raw, marshalErr)
	}
}

func TestEvaluateWithStoreEmptyExternalRulesHaveNoEmbeddedFallback(t *testing.T) {
	fixture := makeSignedBatchFixture(t, false)
	root := t.TempDir()
	writeBatchFile(t, filepath.Join(root, "kyverno.json"), canonical("pkg:github/kyverno/kyverno", "1.12.5", "1.13.0", []any{}, []any{
		map[string]any{"id": "component.kyverno.distribution", "state": "declared", "enumValue": "official_upstream"},
		map[string]any{"id": "component.kyverno.execution_surface", "state": "declared", "enumValue": "reports_controller"},
		map[string]any{"id": "component.kyverno.reports_chunk_size_flag_present", "state": "declared", "boolValue": true},
	}))
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), signedKnowledgePlan([]Item{{ID: "empty-external", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno.json"}}))
	report, exit, err := EvaluateWithStore(planPath, root, fixture.store)
	if err != nil || exit != 11 || len(report.Items) != 1 || report.Items[0].Category != "UNKNOWN_CLAIM" || report.Items[0].KnowledgeOrigin != "external_signed_local" || !strings.Contains(string(report.Items[0].Report), `"claims":[]`) {
		t.Fatalf("empty external revision fell back: report=%+v exit=%d err=%v", report, exit, err)
	}
}

func TestEvaluateWithStoreDifferentiatesSourceEvidenceTimes(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name             string
		generatedAt      time.Time
		evidenceExpiry   time.Time
		category         string
		detailedExitCode int
	}{
		{name: "stale", generatedAt: base, evidenceExpiry: base.Add(-30 * time.Minute), category: "STALE_EVIDENCE", detailedExitCode: 12},
		{name: "clock before review", generatedAt: base.Add(2 * time.Hour), evidenceExpiry: base.Add(26 * time.Hour), category: "NOT_YET_REVIEWED", detailedExitCode: 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := makeSignedBatchFixtureAt(t, true, tc.generatedAt, tc.evidenceExpiry)
			root := t.TempDir()
			writeBatchFile(t, filepath.Join(root, "kyverno.json"), canonical("pkg:github/kyverno/kyverno", "1.12.5", "1.13.0", []any{}, []any{
				map[string]any{"id": "component.kyverno.distribution", "state": "declared", "enumValue": "official_upstream"},
				map[string]any{"id": "component.kyverno.execution_surface", "state": "declared", "enumValue": "reports_controller"},
				map[string]any{"id": "component.kyverno.reports_chunk_size_flag_present", "state": "declared", "boolValue": false},
			}))
			planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), signedKnowledgePlan([]Item{{ID: "source-time", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "kyverno.json"}}))
			report, exit, err := EvaluateWithStore(planPath, root, fixture.store)
			if err != nil || exit != 11 || len(report.Items) != 1 || report.Items[0].Category != tc.category {
				t.Fatalf("report=%+v exit=%d err=%v", report, exit, err)
			}
			detailed, err := ExitForMode(report, "detailed")
			if err != nil || detailed != tc.detailedExitCode {
				t.Fatalf("detailed=%d err=%v", detailed, err)
			}
		})
	}
}

func TestEvaluateWithStorePreflightsAllFilesBeforeStoreOpen(t *testing.T) {
	root := t.TempDir()
	writeBatchFile(t, filepath.Join(root, "bad.json"), map[string]any{"not": "canonical"})
	planPath := writeBatchFile(t, filepath.Join(root, "plan.json"), signedKnowledgePlan([]Item{{ID: "bad", Kind: "cncf", Project: "kyverno", From: "1.12.5", To: "1.13.0", InputPath: "bad.json"}}))
	opens := 0
	open := func(knowledge.SelectionRequest, []string) (knowledge.VerifiedRevision, error) {
		opens++
		return knowledge.VerifiedRevision{}, nil
	}
	if _, exit, err := evaluate(planPath, root, time.Time{}, filepath.Join(root, "must-not-open"), currentbundle.OpenDirectoryNoFollow, open); err == nil || exit != 2 || opens != 0 {
		t.Fatalf("store opened before preflight: exit=%d err=%v opens=%d", exit, err, opens)
	}
}

func TestEvaluateRejectsPublicHardlinkAndFIFOInputs(t *testing.T) {
	root := t.TempDir()
	valid := mustJSON(canonical("pkg:github/thanos-io/thanos", "0.41.0", "0.42.0", []any{}, []any{}))
	base := filepath.Join(root, "base.json")
	if err := os.WriteFile(base, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(base, filepath.Join(root, "hard.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public.json"), valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "public.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, inputPath := range []string{"hard.json", "public.json", "pipe.json"} {
		plan := Plan{Schema: PlanSchema, Authority: PlanAuthority, Knowledge: KnowledgeSelection{Mode: "embedded_only"}, Items: []Item{{ID: "unsafe", Kind: "cncf", Project: "thanos", From: "0.41.0", To: "0.42.0", InputPath: inputPath}}}
		planPath := writeBatchFile(t, filepath.Join(root, inputPath+".plan"), plan)
		if _, exit, err := Evaluate(planPath, root, time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC)); err == nil || exit != 2 {
			t.Fatalf("unsafe %s accepted: exit=%d err=%v", inputPath, exit, err)
		}
	}
}
