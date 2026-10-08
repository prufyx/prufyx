// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// The published version-skew rules decide through the adapter's own input:
// a control plane upgrade whose declared lowest kubelet is within three minor
// versions of the target passes, one that is further behind is blocked, and
// no declaration leaves it unknown.
func TestPublishedKubeletSkewRules(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		from, to, kubelet string
		status            string
	}{
		{"1.35.2", "1.36.0", "1.33.2", "PASS"},
		{"1.35.2", "1.36.0", "1.32.7", "BLOCKED"},
		{"1.35.2", "1.36.0", "", "UNKNOWN"},
		{"1.34.1", "1.35.0", "1.32.0", "PASS"},
		{"1.34.1", "1.35.0", "1.31.9", "BLOCKED"},
		{"1.33.3", "1.34.0", "1.31.0", "PASS"},
		{"1.32.4", "1.33.1", "1.29.0", "BLOCKED"},
		{"1.32.4", "1.33.1", "1.30.0", "PASS"},
	} {
		declarations := ""
		if test.kubelet != "" {
			declarations = "declarations: {minimumKubeletVersion: \"" + test.kubelet + "\"}\n"
		}
		raw := "apiVersion: " + cncfprepare.KubernetesComponentSelectionAPIVersion + "\nkind: " + cncfprepare.KubernetesComponentSelectionKind + "\n" + declarations +
			"sources: [{scope: kubelet, format: args, path: /private/selected/kubelet-args}]\n"
		selection, err := cncfprepare.ParseKubernetesComponentSelection([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := cncfprepare.PrepareKubernetesComponentConfig(selection, [][]byte{[]byte("- --node-ip=10.0.0.1\n")}, test.from, test.to, "official_upstream", RegisteredFact)
		if err != nil {
			t.Fatal(err)
		}
		report, err := CheckFacts("kubernetes", cncfprepare.KubernetesComponentConfigAllFacts(), prepared.CanonicalInputJSON, now)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, claim := range report.Check.Claims {
			if len(claim.RuleID) > 33 && claim.RuleID[:33] == "kubernetes.kubelet-version-skew.1" {
				found = true
				if claim.Status != test.status {
					t.Fatalf("%s -> %s kubelet %q: %s %s, want %s", test.from, test.to, test.kubelet, claim.RuleID, claim.Status, test.status)
				}
			}
		}
		if !found {
			t.Fatalf("%s -> %s: no skew claim", test.from, test.to)
		}
	}
}
