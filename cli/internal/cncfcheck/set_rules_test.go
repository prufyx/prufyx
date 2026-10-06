// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// These tests hold a synthetic forbid_set_member rule to every check the
// packaged knowledge passes. The rule names a gate that does not exist and is
// never published; the embedded pack stays byte-identical.

const (
	syntheticSetFact   = "component.kubernetes.kubelet_feature_gates_set"
	syntheticGate      = "SyntheticRemovedGate"
	syntheticRevision  = "0000000000000000000000000000000000000001"
	syntheticRuleID    = "kubernetes.synthetic-removed-gate.1-36-0-to-1-37-0"
	embeddedPackSHA256 = "78fd08313d2af6823f07b1793cbe44ccc4bee0c32e8a8a116d0d2c0c2951edc2"
)

func syntheticSetDefinition() constraintengine.FactDefinition {
	return constraintengine.FactDefinition{ID: syntheticSetFact, Component: "pkg:github/kubernetes/kubernetes", Type: constraintengine.FactSet}
}

func syntheticSetEntry(t *testing.T) Entry {
	t.Helper()
	rule := `{"id":"` + syntheticRuleID + `","operator":"forbid_set_member","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.36.0","to":"1.37.0"},` +
		`"setCondition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"` + syntheticSetFact + `","members":["` + syntheticGate + `"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"synthetic-gate-declaration","url":"https://github.com/kubernetes/kubernetes/blob/` + syntheticRevision + `/pkg/features/kube_features.go","revision":"` + syntheticRevision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"KUBERNETES_FEATURE_GATE_REMOVED","nextAction":"remove ` + syntheticGate + ` from every kubelet feature-gate setting before upgrading"}`
	return Entry{Project: "kubernetes", Description: "Synthetic test-only removed kubelet feature gate.", RequiredFacts: []Fact{{Side: "proposed", ID: syntheticSetFact, Component: "pkg:github/kubernetes/kubernetes", Type: constraintengine.FactSet, Description: "Feature gates the kubelet sets."}}, Rule: json.RawMessage(rule)}
}

// syntheticPack renders the embedded pack plus entries under schema, with
// the registry digest of the compiled definitions plus extra.
func syntheticPack(t *testing.T, schema string, extra []constraintengine.FactDefinition, entries ...Entry) []byte {
	t.Helper()
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack rulePack
	if err := strictJSON(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack.Entries = append(pack.Entries, entries...)
	sort.SliceStable(pack.Entries, func(i, j int) bool { return ruleID(t, pack.Entries[i]) < ruleID(t, pack.Entries[j]) })
	registry, err := constraintengine.NewCompiledRegistry(append(compiledDefinitions(), extra...))
	if err != nil {
		t.Fatal(err)
	}
	pack.Schema, pack.Revision, pack.RegistryDigest = schema, "synthetic-test-only", registry.Digest()
	encoded, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func ruleID(t *testing.T, entry Entry) string {
	t.Helper()
	var shape struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(entry.Rule, &shape); err != nil {
		t.Fatal(err)
	}
	return shape.ID
}

func assembleSynthetic(packRaw []byte, extra []constraintengine.FactDefinition) (bundle, error) {
	landscape, _ := packagedFiles.ReadFile("data/landscape-projects.json")
	priority, _ := packagedFiles.ReadFile("data/priority-portfolio.json")
	return assemble(landscape, priority, packRaw, append(compiledDefinitions(), extra...))
}

func TestEmbeddedKnowledgeCarriesNoSetFact(t *testing.T) {
	raw, err := packagedFiles.ReadFile("data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != embeddedPackSHA256 {
		t.Fatalf("embedded pack changed: %x", sum)
	}
	// The only set facts of the compiled registry are the custom-resource
	// version sets, one per project of the reviewed custom-resource table.
	crd := map[string]bool{}
	for _, p := range customresources.Projects() {
		crd[p.FactID()] = true
	}
	sets := 0
	for _, definition := range compiledDefinitions() {
		if definition.Type == constraintengine.FactSet {
			if !crd[definition.ID] {
				t.Fatalf("compiled registry registers set fact %s", definition.ID)
			}
			sets++
		}
	}
	if sets != len(crd) {
		t.Fatalf("%d set facts registered, %d custom-resource projects", sets, len(crd))
	}
	for _, fact := range cncfprepare.KubernetesComponentConfigSetFacts() {
		if RegisteredFact(fact) {
			t.Fatalf("%s is registered without a published rule", fact)
		}
	}
	if len(additionalDefinitions()) != 0 {
		t.Fatal("a default build adds fact definitions")
	}
}

func TestSetRulePackSchemaGating(t *testing.T) {
	extra := []constraintengine.FactDefinition{syntheticSetDefinition()}
	entry := syntheticSetEntry(t)
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSet, extra, entry), extra); err != nil {
		t.Fatalf("set pack under the set schema refused: %v", err)
	}
	for _, schema := range []string{packSchema, packSchemaRanged, "prufyx.io/cncf-source-rule-pack/v1alpha4"} {
		if _, err := assembleSynthetic(syntheticPack(t, schema, extra, entry), extra); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("set pack under %s accepted: %v", schema, err)
		}
	}
	// The set schema is never used without a set rule.
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSet, extra), extra); !errors.Is(err, ErrIntegrity) {
		t.Fatal("set schema without a set rule accepted")
	}
	// The set fact must be registered and declared with its type.
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSet, nil, entry), nil); !errors.Is(err, ErrIntegrity) {
		t.Fatal("set rule over an unregistered fact accepted")
	}
	undeclared := entry
	undeclared.RequiredFacts = nil
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSet, extra, undeclared), extra); !errors.Is(err, ErrIntegrity) {
		t.Fatal("set condition fact missing from requiredFacts accepted")
	}
	mistyped := entry
	mistyped.RequiredFacts = []Fact{entry.RequiredFacts[0]}
	mistyped.RequiredFacts[0].Type = constraintengine.FactBool
	if _, err := assembleSynthetic(syntheticPack(t, packSchemaSet, extra, mistyped), extra); !errors.Is(err, ErrIntegrity) {
		t.Fatal("set fact declared as bool accepted")
	}
}

// TestSyntheticRemovedGateThroughAdapterAndKnowledge runs the component
// configuration adapter and the fact-family selection the command route
// uses, against knowledge holding one synthetic set rule.
func TestSyntheticRemovedGateThroughAdapterAndKnowledge(t *testing.T) {
	extra := []constraintengine.FactDefinition{syntheticSetDefinition()}
	b, err := assembleSynthetic(syntheticPack(t, packSchemaSet, extra, syntheticSetEntry(t)), extra)
	if err != nil {
		t.Fatal(err)
	}
	registered := func(id string) bool { return id == syntheticSetFact }
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	kubeletConfig := "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nfeatureGates:\n  KeptGate: true\n"
	for _, tc := range []struct {
		name, args string
		complete   bool
		status     string
		exit       int
	}{
		{"gate set to false blocks", "--config=/var/lib/kubelet/config.yaml --feature-gates=" + syntheticGate + "=false", true, "BLOCKED", 10},
		{"gate on an incomplete scope still blocks", "--config=/var/lib/kubelet/config.yaml --feature-gates=" + syntheticGate + "=true", false, "BLOCKED", 10},
		{"complete scope without the gate passes", "--config=/var/lib/kubelet/config.yaml --feature-gates=OtherGate=true", true, "PASS", 0},
		{"incomplete scope without the gate is unknown", "--config=/var/lib/kubelet/config.yaml --feature-gates=OtherGate=true", false, "UNKNOWN", 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			complete := ""
			if tc.complete {
				complete = "complete: [kubelet]\n"
			}
			selectionRaw := []byte("apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: ComponentConfigSelection\n" + complete + "sources:\n- {scope: kubelet, format: kubelet-env, path: /private/selected/flags.env}\n- {scope: kubelet, format: kubelet-config, path: /private/selected/config.yaml}\n")
			selection, err := cncfprepare.ParseKubernetesComponentSelection(selectionRaw)
			if err != nil {
				t.Fatal(err)
			}
			contents := [][]byte{[]byte("KUBELET_KUBEADM_ARGS=\"" + tc.args + "\"\n"), []byte(kubeletConfig)}
			prepared, err := cncfprepare.PrepareKubernetesComponentConfig(selection, contents, "1.36.0", "1.37.0", "official_upstream", registered)
			if err != nil {
				t.Fatal(err)
			}
			input, err := constraintengine.ParseInput(prepared.CanonicalInputJSON, b.registry)
			if err != nil {
				t.Fatalf("prepared input refused: %v: %s", err, prepared.CanonicalInputJSON)
			}
			rules, err := b.factFamilyRuleSet("kubernetes", cncfprepare.KubernetesComponentConfigAllFacts(), prepared.CanonicalInputJSON)
			if err != nil {
				t.Fatal(err)
			}
			report, err := b.report("kubernetes", "", true, input, rules, prepared.CanonicalInputJSON, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Check.Claims) != 1 || report.Check.Claims[0].RuleID != syntheticRuleID || report.Check.Claims[0].Status != tc.status || ClaimExit(report) != tc.exit {
				t.Fatalf("claims=%+v exit=%d", report.Check.Claims, ClaimExit(report))
			}
			if report.Check.EngineContractDigest != constraintengine.EngineContractDigestSet() || report.Assessment != "UNKNOWN" {
				t.Fatalf("report=%+v", report)
			}
			raw, err := MarshalReport(report)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "OtherGate") || strings.Contains(string(raw), "KeptGate") || strings.Contains(string(raw), "/private/selected") {
				t.Fatalf("report leaked a declared value: %s", raw)
			}
			if blocked := tc.status == "BLOCKED"; blocked != strings.Contains(string(raw), `"matchedMembers":["`+syntheticGate+`"]`) {
				t.Fatalf("matched members disclosure wrong: %s", raw)
			}
		})
	}
}

// TestReleaseBuildsNeverUseSyntheticKnowledge: the synthetic knowledge seam
// exists only under a build tag that the release workflow never sets.
func TestReleaseBuildsNeverUseSyntheticKnowledge(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "prufyx_synthetic_knowledge") || strings.Contains(string(raw), "-tags") {
		t.Fatal("the release workflow sets build tags")
	}
}
