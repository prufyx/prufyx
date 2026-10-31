// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package cncfcheck

import (
	"errors"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// crossingGateInput is the canonical input of a 1.38.0 -> 1.39.0 hop whose
// proposed kubelet feature gates still set the synthetic removed gate.
func crossingGateInput(t *testing.T) []byte {
	t.Helper()
	selection, err := cncfprepare.ParseKubernetesComponentSelection([]byte("apiVersion: prufyx.io/kubernetes-component-config/v1alpha1\nkind: ComponentConfigSelection\ncomplete: [kubelet]\nsources:\n- {scope: kubelet, format: kubelet-env, path: /private/selected/flags.env}\n- {scope: kubelet, format: kubelet-config, path: /private/selected/config.yaml}\n"))
	if err != nil {
		t.Fatal(err)
	}
	contents := [][]byte{[]byte("KUBELET_KUBEADM_ARGS=\"--config=/var/lib/kubelet/config.yaml --feature-gates=" + syntheticGate + "=false\"\n"), []byte("apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nfeatureGates:\n  KeptGate: true\n")}
	prepared, err := cncfprepare.PrepareKubernetesComponentConfig(selection, contents, "1.38.0", "1.39.0", "official_upstream", func(id string) bool { return id == syntheticSetFact })
	if err != nil {
		t.Fatal(err)
	}
	return prepared.CanonicalInputJSON
}

// storeBundleOf is the external bundle a store would hold for the installed
// synthetic knowledge: derived from the embedded pack, so without any
// removal-crossing rule.
func storeBundleOf(t *testing.T) ExternalBundle {
	t.Helper()
	raw, err := ExportEmbeddedExternalBundle("7")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// A store target never carries a removal-crossing rule, yet every store
// evaluation (check cncf, check batch, auto mode with a store chosen, scan)
// must keep the block the embedded pack reaches: exit 10, never 0.
func TestSyntheticStoreEvaluationKeepsEmbeddedCrossingBlock(t *testing.T) {
	restore, err := UseSyntheticKnowledge(nil, []Entry{syntheticCrossingEntry(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	input := crossingGateInput(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	facts := cncfprepare.KubernetesComponentConfigAllFacts()

	embedded, err := CheckFacts("kubernetes", facts, input, now)
	if err != nil || ClaimExit(embedded) != 10 {
		t.Fatalf("embedded: exit %d, %v", ClaimExit(embedded), err)
	}
	store := storeBundleOf(t)

	for name, evaluate := range map[string]func() (Report, error){
		"store check": func() (Report, error) { return store.Evaluate("kubernetes", input, now) },
		"store scan": func() (Report, error) {
			k, err := NewStoreScanKnowledge(map[string]ExternalBundle{"kubernetes": store})
			if err != nil {
				return Report{}, err
			}
			return k.CheckFacts("kubernetes", facts, input, now)
		},
	} {
		report, err := evaluate()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if exit := ClaimExit(report); exit != 10 {
			t.Fatalf("%s: exit %d, claims %+v", name, exit, report.Check.Claims)
		}
	}
	// The selected-rule route names the crossing rule; the store holds no
	// such rule, so the answer is no claim (UNKNOWN), never a pass.
	report, err := store.EvaluateRule("kubernetes", syntheticRuleID, input, now)
	if err != nil || ClaimExit(report) == 0 {
		t.Fatalf("selected-rule route: exit %d, %v", ClaimExit(report), err)
	}
}

// A store rule with the id of an embedded crossing rule would decide in its
// place: check, selected-rule check and scan all refuse it.
func TestSyntheticStoreSameIDShadowOfCrossingRuleRefused(t *testing.T) {
	restoreSet, err := UseSyntheticKnowledge(nil, []Entry{syntheticSetEntry(t)})
	if err != nil {
		t.Fatal(err)
	}
	shadow := storeBundleOf(t) // holds the non-crossing rule under the crossing rule's id
	restoreSet()
	restore, err := UseSyntheticKnowledge(nil, []Entry{syntheticCrossingEntry(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	input := crossingGateInput(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := shadow.Evaluate("kubernetes", input, now); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("check with a shadow rule: %v", err)
	}
	if _, err := shadow.EvaluateRule("kubernetes", syntheticRuleID, input, now); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("selected-rule check with a shadow rule: %v", err)
	}
	if _, err := NewStoreScanKnowledge(map[string]ExternalBundle{"kubernetes": shadow}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("scan with a shadow rule: %v", err)
	}
}
