// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type relnotesCase struct {
	project, component, ruleID, from, to, fact string
}

var (
	cortexStoreRule = relnotesCase{"cortex", "pkg:github/cortexproject/cortex", "cortex.relnotes.flag-removed.store-max-look-back-period.1-9", "1.8.1", "1.9.0", factCortexFlags}
	falcoMesosRule  = relnotesCase{"falco", "pkg:github/falcosecurity/falco", "falco.relnotes.flag-removed.mesos-api.0-35", "0.34.1", "0.35.0", factFalcoFlags}
	falcoRateRule   = relnotesCase{"falco", "pkg:github/falcosecurity/falco", "falco.relnotes.config-key-removed.outputs-rate.0-37", "0.36.2", "0.37.0", factFalcoConfigKey}
)

func (c relnotesCase) input(complete bool, to string, members ...string) []byte {
	quoted := make([]string, len(members))
	for i, m := range members {
		quoted[i] = fmt.Sprintf("%q", m)
	}
	return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":%q,"version":%q,"facts":[{"id":%q,"state":"declared","setValue":{"members":[%s],"complete":%t}}]}]},"proposed":{"components":[{"component":%q,"version":%q,"facts":[]}]}}`,
		c.component, c.from, c.fact, strings.Join(quoted, ","), complete, c.component, to))
}

func (c relnotesCase) status(t *testing.T, raw []byte) (string, int, Report) {
	t.Helper()
	report, err := CheckRule(c.project, c.ruleID, raw, time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("%s: %v", c.ruleID, err)
	}
	if len(report.Check.Claims) != 1 {
		t.Fatalf("%s: %d claims", c.ruleID, len(report.Check.Claims))
	}
	return report.Check.Claims[0].Status, ClaimExit(report), report
}

// A removed flag spelled with another case is not a real flag of these
// projects, and an upper-case member never compares equal to the lower-case
// forbidden one: the set is refused, never passed.
func TestEmbeddedRelnotesRulesRefuseNonCanonicalCase(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		c       relnotesCase
		members []string
	}{
		{cortexStoreRule, []string{"Store.max-look-back-period"}},
		{cortexStoreRule, []string{"STORE.MAX-LOOK-BACK-PERIOD"}},
		{falcoMesosRule, []string{"Mesos-API"}},
		{falcoMesosRule, []string{"Pm"}},
		{falcoRateRule, []string{"Outputs.rate"}},
	} {
		if _, err := CheckRule(tc.c.project, tc.c.ruleID, tc.c.input(true, tc.c.to, tc.members...), now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s %v: err=%v, want ErrInvalid", tc.c.ruleID, tc.members, err)
		}
		if err := ValidateCanonicalInput(tc.c.project, tc.c.input(true, tc.c.to, tc.members...)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s %v: ValidateCanonicalInput err=%v", tc.c.ruleID, tc.members, err)
		}
	}
}

// falco's single-letter options differ by case: -M is not -m, so it neither
// blocks nor is refused; -m blocks the 0.35.0 crossing.
func TestFalcoMesosShortAlias(t *testing.T) {
	t.Parallel()
	c := falcoMesosRule
	if status, exit, _ := c.status(t, c.input(true, c.to, "m")); status != "BLOCKED" || exit != 10 {
		t.Fatalf("-m: status=%s exit=%d, want BLOCKED", status, exit)
	}
	if status, _, _ := c.status(t, c.input(true, c.to, "M")); status == "BLOCKED" {
		t.Fatal("-M (a different falco option) blocked")
	}
	if status, exit, _ := c.status(t, c.input(true, c.to, "K")); status != "PASS" || exit != 0 {
		t.Fatalf("-K (removed in 0.37.0, not 0.35.0): status=%s exit=%d, want PASS on the 0.35.0 hop", status, exit)
	}
}

// A complete declared set that holds a flag the same release removed, with no
// rule of its own, is UNKNOWN; a forbidden member still blocks; a set without
// any sibling still passes the rule on its own hop.
func TestEmbeddedRelnotesRulesNeverPassUnreviewedSiblings(t *testing.T) {
	t.Parallel()
	for _, c := range []relnotesCase{cortexStoreRule, falcoRateRule} {
		siblings := relnotesUnreviewedRemovals[c.fact]
		if len(siblings) == 0 {
			t.Fatalf("%s: no siblings recorded", c.ruleID)
		}
		for _, sibling := range siblings {
			status, exit, report := c.status(t, c.input(true, c.to, sibling))
			if status != "UNKNOWN" || exit == 0 {
				t.Fatalf("%s sibling %s: status=%s exit=%d, want UNKNOWN", c.ruleID, sibling, status, exit)
			}
			if report.NextAction != relnotesUnreviewedNextAction {
				t.Fatalf("%s sibling %s: next action %q", c.ruleID, sibling, report.NextAction)
			}
		}
	}
	c := cortexStoreRule
	if status, exit, _ := c.status(t, c.input(true, c.to, "cluster.peer", "store.max-look-back-period")); status != "BLOCKED" || exit != 10 {
		t.Fatalf("forbidden member beside a sibling: status=%s exit=%d, want BLOCKED", status, exit)
	}
	if status, exit, report := c.status(t, c.input(true, c.to, "ingester.max-transfer-retries")); status != "PASS" || exit != 0 || report.NextAction == relnotesUnreviewedNextAction {
		t.Fatalf("unrelated flag: status=%s exit=%d", status, exit)
	}
	// The same flag on a set that is already declared incomplete stays UNKNOWN.
	if status, _, _ := c.status(t, c.input(false, c.to, "cluster.peer")); status != "UNKNOWN" {
		t.Fatalf("incomplete set: status=%s", status)
	}
}

// falco 0.37.0 removed command-line options too, but no shipped rule reads
// falco's flag set across that release: a hop beyond the mesos rule's
// reviewed line is never PASS, whatever the set holds.
func TestFalcoFlagSetBeyondTheReviewedLineNeverPasses(t *testing.T) {
	t.Parallel()
	c := falcoMesosRule
	for _, members := range [][]string{{"userspace"}, {"K", "k"}, {"k8s-node"}, {}} {
		status, exit, _ := c.status(t, c.input(true, "0.37.0", members...))
		if status == "PASS" || exit == 0 {
			t.Fatalf("hop to 0.37.0 with %v: status=%s exit=%d", members, status, exit)
		}
	}
}
