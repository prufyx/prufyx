// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const controlPlaneSkipPrefix = "kubernetes.control-plane-no-minor-skip."

func controlPlaneSkipInput(from, to string) []byte {
	component := func(version string) string {
		return `{"components":[{"component":"pkg:github/kubernetes/kubernetes","version":"` + version + `","facts":[]}]}`
	}
	return []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":` + component(from) + `,"proposed":` + component(to) + `}`)
}

// The control-plane no-minor-skip rules read no fact, so the generic check
// (not the native adapters' fact-selected family) decides them. They block a jump over one or more minor
// lines of kube-apiserver and name the order to follow; patch jumps and
// one-minor hops are not theirs.
func TestControlPlaneNoMinorSkipRules(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		from, to string
		blocked  string // the one rule expected to block, "" for none
		action   string
	}{
		{"1.33.2", "1.37.1", "1-33-0-to-1-37-0", "through 1.34, 1.35, 1.36 in order"},
		{"1.29.0", "1.31.0", "1-29-0-to-1-31-0", "through 1.30 in order"},
		{"1.35.9", "1.37.0", "1-35-0-to-1-37-0", "through 1.36 in order"},
		{"1.33.1", "1.33.9", "", ""},
		{"1.33.5", "1.34.2", "", ""},
		{"1.36.0", "1.37.0", "", ""},
		{"1.29.0", "1.30.0", "", ""},
		// Outside the table: not these rules' to decide.
		{"1.28.0", "1.30.0", "", ""},
		{"1.35.0", "1.38.0", "", ""},
		{"1.36.0", "1.38.0", "", ""},
	} {
		report, err := Check("kubernetes", controlPlaneSkipInput(test.from, test.to), now)
		if err != nil {
			t.Fatal(err)
		}
		blocked := ""
		for _, claim := range report.Check.Claims {
			if !strings.HasPrefix(claim.RuleID, controlPlaneSkipPrefix) {
				continue
			}
			if claim.Status == "BLOCKED" {
				if blocked != "" {
					t.Fatalf("%s -> %s: two rules block: %s and %s", test.from, test.to, blocked, claim.RuleID)
				}
				blocked = strings.TrimPrefix(claim.RuleID, controlPlaneSkipPrefix)
				if !strings.Contains(claim.NextAction, test.action) || len(claim.NextAction) > 256 {
					t.Fatalf("%s -> %s: next action %q", test.from, test.to, claim.NextAction)
				}
			}
		}
		if blocked != test.blocked {
			t.Fatal(fmt.Sprintf("%s -> %s: blocked by %q, want %q", test.from, test.to, blocked, test.blocked))
		}
	}
}
