// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package communityapp

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/communityapp/
//
// The command route is exercised end to end against synthetic, never
// published knowledge: one forbid_set_member rule over the kubelet
// feature-gate set naming a gate that does not exist.

const (
	syntheticGateFact = "component.kubernetes.kubelet_feature_gates_set"
	syntheticGate     = "SyntheticRemovedGate"
	syntheticGateRule = "kubernetes.synthetic-removed-gate.1-36-0-to-1-37-0"
)

func useSyntheticGateKnowledge(t *testing.T) {
	t.Helper()
	revision := "0000000000000000000000000000000000000001"
	rule := `{"id":"` + syntheticGateRule + `","operator":"forbid_set_member","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.36.0","to":"1.37.0"},` +
		`"setCondition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"` + syntheticGateFact + `","members":["` + syntheticGate + `"]},` +
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"synthetic-gate-declaration","url":"https://github.com/kubernetes/kubernetes/blob/` + revision + `/pkg/features/kube_features.go","revision":"` + revision + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"KUBERNETES_FEATURE_GATE_REMOVED","nextAction":"remove ` + syntheticGate + ` from every kubelet feature-gate setting before upgrading"}`
	entry := cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only removed kubelet feature gate.", RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: syntheticGateFact, Component: "pkg:github/kubernetes/kubernetes", Type: constraintengine.FactSet, Description: "Feature gates the kubelet sets."}}, Rule: json.RawMessage(rule)}
	restore, err := cncfcheck.UseSyntheticKnowledge([]constraintengine.FactDefinition{{ID: syntheticGateFact, Component: "pkg:github/kubernetes/kubernetes", Type: constraintengine.FactSet}}, []cncfcheck.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
}

func writeGateFixture(t *testing.T, args string, complete bool) string {
	t.Helper()
	dir := t.TempDir()
	flags, config := filepath.Join(dir, "kubeadm-flags.env"), filepath.Join(dir, "config.yaml")
	writeCNCFFileAt(t, flags, []byte("KUBELET_KUBEADM_ARGS=\""+args+"\"\n"))
	writeCNCFFileAt(t, config, []byte("apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nfeatureGates:\n  KeptGate: true\n"))
	completeLine := ""
	if complete {
		completeLine = "complete: [kubelet]\n"
	}
	selection := filepath.Join(dir, "selection.yaml")
	writeCNCFFileAt(t, selection, []byte("apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: ComponentConfigSelection\n"+completeLine+"sources:\n- {scope: kubelet, format: kubelet-env, path: "+flags+"}\n- {scope: kubelet, format: kubelet-config, path: "+config+"}\n"))
	return selection
}

func gateArgs(selection string, extra ...string) []string {
	return append([]string{"check", "cncf", "--project", "kubernetes", "--component-config", selection, "--from", "1.36.0", "--to", "1.37.0", "--distribution", "official_upstream", "--now", "2026-10-01T00:00:00Z"}, extra...)
}

func TestSyntheticRemovedGateThroughTheCommandRoute(t *testing.T) {
	useSyntheticGateKnowledge(t)
	for _, tc := range []struct {
		name, args string
		complete   bool
		exit       int
		status     string
		reason     string
	}{
		{"removed gate set to false blocks", "--config=/var/lib/kubelet/config.yaml --feature-gates=" + syntheticGate + "=false", true, ExitBlocked, "BLOCKED", "KUBERNETES_FEATURE_GATE_REMOVED"},
		{"removed gate blocks on an incomplete scope", "--config=/var/lib/kubelet/config.yaml --feature-gates=" + syntheticGate + "=true", false, ExitBlocked, "BLOCKED", "KUBERNETES_FEATURE_GATE_REMOVED"},
		{"complete scope without the gate passes", "--config=/var/lib/kubelet/config.yaml --feature-gates=OtherGate=true", true, 0, "PASS", "KUBERNETES_FEATURE_GATE_REMOVED"},
		{"incomplete scope without the gate is unknown", "--config=/var/lib/kubelet/config.yaml --feature-gates=OtherGate=true", false, ExitUnknown, "UNKNOWN", "RULE_SET_FACT_INCOMPLETE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selection := writeGateFixture(t, tc.args, tc.complete)
			code, stdout, stderr := runCNCFCLI(t, gateArgs(selection, "--format", "json")...)
			if code != tc.exit || stderr != "" {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			var report struct {
				KnowledgeRevision string `json:"knowledgeRevision"`
				Check             struct {
					Assessment           string                   `json:"assessment"`
					EngineContractDigest string                   `json:"engineContractDigest"`
					Claims               []constraintengine.Claim `json:"claims"`
				} `json:"check"`
			}
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatal(err)
			}
			if report.KnowledgeRevision != "synthetic-test-only" || report.Check.Assessment != "UNKNOWN" || report.Check.EngineContractDigest != constraintengine.EngineContractDigestSet() || len(report.Check.Claims) != 1 {
				t.Fatalf("report=%s", stdout)
			}
			claim := report.Check.Claims[0]
			if claim.RuleID != syntheticGateRule || claim.Status != tc.status || claim.ReasonCode != tc.reason || (tc.status == "BLOCKED") != (strings.Join(claim.MatchedMembers, ",") == syntheticGate) {
				t.Fatalf("claim=%+v", claim)
			}
			for _, private := range []string{"OtherGate", "KeptGate", "kubeadm-flags.env", "/var/lib/kubelet", filepath.Dir(selection)} {
				if strings.Contains(stdout, private) {
					t.Fatalf("private input crossed the output boundary: %q in %s", private, stdout)
				}
			}

			code, human, stderr := runCNCFCLI(t, gateArgs(selection)...)
			if code != tc.exit || stderr != "" || !strings.Contains(human, syntheticGateRule+": "+tc.status+" ("+tc.reason+")") || strings.Contains(human, "forbidden members present:") != (tc.status == "BLOCKED") {
				t.Fatalf("human code=%d stdout=%s stderr=%s", code, human, stderr)
			}
			if tc.status == "BLOCKED" && !strings.Contains(human, "forbidden members present: "+syntheticGate+"\n") {
				t.Fatalf("human output does not name the forbidden member: %s", human)
			}
		})
	}
	// Outside the rule's reviewed transition the family is still evaluated
	// and the claim says why it does not apply.
	selection := writeGateFixture(t, "--config=/var/lib/kubelet/config.yaml --feature-gates="+syntheticGate+"=true", true)
	args := gateArgs(selection, "--format", "json")
	for index, value := range args {
		if value == "1.36.0" {
			args[index] = "1.37.0"
		} else if value == "1.37.0" {
			args[index] = "1.38.0"
		}
	}
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"reasonCode":"RULE_TRANSITION_NOT_REVIEWED"`) || strings.Contains(stdout, "matchedMembers") {
		t.Fatalf("unreviewed transition code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
