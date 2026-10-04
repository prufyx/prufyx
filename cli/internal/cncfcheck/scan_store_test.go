// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"testing"
	"time"
)

// TestStoreScanKnowledgeReadsOnlyOpenedProjects: knowledge selected from a
// store holds the opened projects' rules and nothing of the embedded pack.
// An unopened project has no rule, no evaluation, no review and no policy.
func TestStoreScanKnowledgeReadsOnlyOpenedProjects(t *testing.T) {
	_, targets, err := BuildEmbeddedExternalTargets("3", nil)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := LoadScanKnowledge()
	if err != nil {
		t.Fatal(err)
	}
	var kubernetes ExternalBundle
	for _, target := range targets {
		if project, _ := ProjectFromTargetPath(target.Path); project == "kubernetes" {
			if kubernetes, err = ParseExternalBundle(target.Bytes); err != nil {
				t.Fatal(err)
			}
		}
	}
	store, err := NewStoreScanKnowledge(map[string]ExternalBundle{"kubernetes": kubernetes})
	if err != nil {
		t.Fatal(err)
	}
	if store.Origin() != "external_signed_local" || embedded.Origin() != "embedded" || store.Revision() != "" || store.PackDigest() != "" {
		t.Fatalf("origin %s revision %q digest %q", store.Origin(), store.Revision(), store.PackDigest())
	}
	if len(store.Rules("kubernetes")) != len(embedded.Rules("kubernetes")) || len(store.Rules("kyverno")) != 0 || len(embedded.Rules("kyverno")) == 0 {
		t.Fatalf("rules: store %d/%d embedded %d/%d", len(store.Rules("kubernetes")), len(store.Rules("kyverno")), len(embedded.Rules("kubernetes")), len(embedded.Rules("kyverno")))
	}
	if len(store.Projects()) != len(embedded.Projects()) {
		t.Fatal("catalog differs")
	}
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	input := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[]},"proposed":{"components":[]}}`)
	if _, err := store.CheckFactsWithPolicy(TrustPolicy{}, "kyverno", []string{"x"}, input, now); err != ErrIntegrity {
		t.Fatalf("unopened project evaluated: %v", err)
	}
	if _, err := store.CheckFacts("kyverno", []string{"x"}, input, now); err != ErrIntegrity {
		t.Fatalf("unopened project evaluated: %v", err)
	}
	component, _ := store.Component("kyverno")
	if store.AttestationsFor(component, "1.0", "f", now) != nil || store.PathPolicyFor(component, now).Found {
		t.Fatal("unopened project has records")
	}
	// A single-target envelope serves only the opened project's rules.
	raw, err := ExportEmbeddedExternalBundle("3")
	if err != nil {
		t.Fatal(err)
	}
	single, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := NewStoreScanKnowledge(map[string]ExternalBundle{"kubernetes": single})
	if err != nil {
		t.Fatal(err)
	}
	if len(whole.Rules("kubernetes")) != len(embedded.Rules("kubernetes")) || len(whole.Rules("kyverno")) != 0 {
		t.Fatalf("single-target rules %d/%d", len(whole.Rules("kubernetes")), len(whole.Rules("kyverno")))
	}
	for i, rule := range whole.Rules("kubernetes") {
		if rule.Scope.ID != embedded.Rules("kubernetes")[i].Scope.ID {
			t.Fatalf("rule %d: %s", i, rule.Scope.ID)
		}
	}
	// An envelope changed after admission is refused.
	changed := kubernetes
	changed.pack.Entries = changed.pack.Entries[1:]
	if _, err := NewStoreScanKnowledge(map[string]ExternalBundle{"kubernetes": changed}); err != ErrIntegrity {
		t.Fatalf("changed envelope accepted: %v", err)
	}
	if _, err := NewStoreScanKnowledge(map[string]ExternalBundle{"kubernetes": {}}); err != ErrIntegrity {
		t.Fatalf("unadmitted envelope accepted: %v", err)
	}
	if _, err := NewStoreScanKnowledge(map[string]ExternalBundle{"no-such-project": kubernetes}); err != ErrIntegrity {
		t.Fatalf("unknown project accepted: %v", err)
	}
	if _, err := NewStoreScanKnowledge(nil); err != ErrInvalid {
		t.Fatalf("no project accepted: %v", err)
	}
}

// TestExternalTargetsFromPack: building from the embedded pack's bytes gives
// exactly the embedded builders' targets, and a pack the embedded checks
// refuse is refused.
func TestExternalTargetsFromPack(t *testing.T) {
	raw, err := packagedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	single, err := ExportExternalBundleFromPack(raw, "4")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ExportEmbeddedExternalBundle("4")
	if err != nil || !bytes.Equal(single, want) {
		t.Fatalf("single target differs: %v", err)
	}
	index, targets, err := BuildExternalTargetsFromPack(raw, "4")
	if err != nil {
		t.Fatal(err)
	}
	wantIndex, wantTargets, err := BuildEmbeddedExternalTargets("4", nil)
	if err != nil || !bytes.Equal(index.Bytes, wantIndex.Bytes) || len(targets) != len(wantTargets) {
		t.Fatalf("index differs: %v", err)
	}
	for i := range targets {
		if targets[i].Path != wantTargets[i].Path || !bytes.Equal(targets[i].Bytes, wantTargets[i].Bytes) {
			t.Fatalf("target %s differs", targets[i].Path)
		}
	}
	broken := bytes.Replace(raw, []byte(`"policyId": "cncf-source-preview-v1"`), []byte(`"policyId": "other"`), 1)
	if bytes.Equal(broken, raw) {
		t.Fatal("edit did not apply")
	}
	if _, err := ExportExternalBundleFromPack(broken, "4"); err == nil {
		t.Fatal("refused pack exported")
	}
	if _, _, err := BuildExternalTargetsFromPack(broken, "4"); err == nil {
		t.Fatal("refused pack split")
	}
	if _, _, err := BuildExternalTargetsFromPack(raw, "0"); err != ErrInvalid {
		t.Fatalf("bad revision: %v", err)
	}
}
