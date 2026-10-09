// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestScanNeverDecidesAFeatureGateSetRule: scan supplies no component
// configuration, so a forbid_set_member rule over a registered feature-gate
// set fact is neither evaluated nor counted as covered. It changes no exit,
// gap, finding or pass, and in particular never produces a PASS. The rule is
// decided only by `check cncf --kubernetes-component-config`, where the caller
// supplies the configuration.
func TestScanNeverDecidesAFeatureGateSetRule(t *testing.T) {
	const factID = "component.kubernetes.kubelet_feature_gates_set"
	rule := `{"id":"kubernetes.synthetic-removed-gate.1-24-0-to-1-25-0","operator":"forbid_set_member","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` +
		`"setCondition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"` + factID + `","members":["SyntheticRemovedGate"]},` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},"reasonCode":"KUBERNETES_FEATURE_GATE_REMOVED","nextAction":"Remove the gate."}`
	entry := cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only removed kubelet feature gate. Never published.", RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: factID, Component: kubernetesKey, Type: constraintengine.FactSet, Description: "Synthetic."}}, Rule: json.RawMessage(rule)}
	type outcome struct {
		exit     int
		gaps     []string
		findings []string
		passes   []string
	}
	run := func() []outcome {
		var out []outcome
		for _, manifest := range []string{cronjobV1, cronjobV1beta1} {
			_, paths := files(t, map[string]string{"applyset.yaml": manifest})
			result := mustScan(t, newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"}), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
			o := outcome{exit: result.Exit, gaps: gapReasons(result.Report)}
			for _, finding := range result.Report.Findings {
				o.findings = append(o.findings, finding.RuleID)
			}
			for _, pass := range result.Report.Passes {
				o.passes = append(o.passes, pass.RuleID+" "+pass.Hop.To)
			}
			out = append(out, o)
		}
		return out
	}
	plain := run()
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, []cncfcheck.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	// Positive control: the synthetic rule is part of the loaded knowledge,
	// so an unchanged answer is not an override that silently failed.
	identities, err := cncfcheck.EmbeddedRuleIdentities()
	if err != nil {
		t.Fatal(err)
	}
	loaded := false
	for _, identity := range identities {
		loaded = loaded || identity.RuleID == "kubernetes.synthetic-removed-gate.1-24-0-to-1-25-0"
	}
	if !loaded {
		t.Fatal("the synthetic feature-gate rule is not in the loaded knowledge")
	}
	with := run()
	if !reflect.DeepEqual(plain, with) {
		t.Fatalf("a feature-gate set rule changed the scan answer:\n%+v\n%+v", plain, with)
	}
	for _, o := range with {
		for _, pass := range o.passes {
			if pass == "kubernetes.synthetic-removed-gate.1-24-0-to-1-25-0 1.25.0" {
				t.Fatalf("scan passed a rule it cannot evaluate: %v", o.passes)
			}
		}
	}
}
