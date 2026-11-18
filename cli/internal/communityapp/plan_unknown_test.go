// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/upgradeplan"
)

func planGap(plan upgradeplan.Plan, component string) (upgradeplan.Gap, bool) {
	for _, g := range plan.Gaps {
		if g.Component == component {
			return g, true
		}
	}
	return upgradeplan.Gap{}, false
}

func TestPlanUnknownComponentDoesNotHideKnownOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applyset.yaml")
	if err := os.WriteFile(path, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3",
		"--from", "cert-manager=1.12.0", "--to", "cert-manager=1.13.0",
		"--from", "external-dns=0.14.0", "--to", "external-dns=0.15.0"}
	code, stdout, stderr := runPlan(t, append(append([]string{}, args...), "--format", "json")...)
	if code != ExitUnknown {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if plan.Verdict == upgradeplan.VerdictPass || len(plan.Stages) == 0 {
		t.Fatalf("verdict %s stages %d", plan.Verdict, len(plan.Stages))
	}
	seen := map[string]bool{}
	for _, s := range plan.Stages {
		seen[s.Component] = true
		if s.Component == "external-dns" {
			t.Fatalf("unknown component planned as a stage: %+v", s)
		}
	}
	if !seen["kubernetes"] {
		t.Fatalf("kubernetes not planned: %+v", plan.Stages)
	}
	gap, ok := planGap(plan, "external-dns")
	if !ok || gap.Reason == "" || gap.Action == "" || gap.Detail == "" {
		t.Fatalf("external-dns gap missing or untyped: %+v", plan.Gaps)
	}
	if code != plan.ExitCode {
		t.Fatalf("exit %d vs plan %d", code, plan.ExitCode)
	}
	_, human, _ := runPlan(t, args...)
	if !strings.Contains(human, "external-dns") || !strings.Contains(human, gap.Reason) || !strings.Contains(human, "Stage 1") {
		t.Fatalf("human output\n%s", human)
	}
}

func TestPlanOnlyUnknownComponentIsUnknown(t *testing.T) {
	code, stdout, stderr := runPlan(t, "--from", "no-such-project=1.0.0", "--to", "no-such-project=1.1.0", "--format", "json")
	if code != ExitUnknown {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatal(err)
	}
	gap, ok := planGap(plan, "no-such-project")
	if plan.Verdict != upgradeplan.VerdictUnknown || !ok || gap.Reason != "COMPONENT_NOT_IN_CATALOG" || gap.Action == "" {
		t.Fatalf("%+v", plan)
	}
}

func TestPlanUnknownComponentStillRefusesMalformedInput(t *testing.T) {
	for _, args := range [][]string{
		{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--to", "external-dns=not a version"},
		{"--from", "kubernetes=1.2", "--to", "kubernetes=1.25.3", "--to", "external-dns=0.15.0"},
		{"--from", "external-dns=0.14.0"},
	} {
		if code, out, _ := runPlan(t, args...); code != ExitUsage {
			t.Fatalf("%v: exit %d\n%s", args, code, out)
		}
	}
}

func TestPlanUnknownComponentWithBlockedStageExits10(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applyset.yaml")
	if err := os.WriteFile(path, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runPlan(t, path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4",
		"--from", "external-dns=0.14.0", "--to", "external-dns=0.15.0", "--format", "json",
		"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", supersedeids.ClockString())
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("%v\n%s\n%s", err, stdout, stderr)
	}
	if _, ok := planGap(plan, "external-dns"); code != ExitBlocked || plan.Verdict != upgradeplan.VerdictBlocked || !ok {
		t.Fatalf("exit %d verdict %s", code, plan.Verdict)
	}
}

func TestPlanUnknownComponentNotCoveredAndTypo(t *testing.T) {
	for _, tc := range []struct{ slug, reason, detail string }{
		{"cass-operator", "COMPONENT_NOT_COVERED", "community"},
		{"cert-manger", "COMPONENT_NOT_IN_CATALOG", "closest:"},
	} {
		code, stdout, stderr := runPlan(t, "--from", tc.slug+"=1.0.0", "--to", tc.slug+"=1.1.0", "--format", "json")
		var plan upgradeplan.Plan
		if err := json.Unmarshal([]byte(stdout), &plan); err != nil || code != ExitUnknown {
			t.Fatalf("%s: exit %d %v\n%s\n%s", tc.slug, code, err, stdout, stderr)
		}
		gap, ok := planGap(plan, tc.slug)
		if !ok || gap.Reason != tc.reason || !strings.Contains(gap.Detail, tc.detail) || gap.Action == "" {
			t.Fatalf("%s: %+v", tc.slug, plan.Gaps)
		}
	}
}

func TestPlanUnknownComponentNewestCovered(t *testing.T) {
	code, stdout, stderr := runPlan(t, "--to", "no-such-project=newest-covered", "--format", "json")
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil || code != ExitUnknown {
		t.Fatalf("exit %d %v\n%s\n%s", code, err, stdout, stderr)
	}
	if gap, ok := planGap(plan, "no-such-project"); !ok || gap.Reason != "COMPONENT_NOT_IN_CATALOG" {
		t.Fatalf("%+v", plan.Gaps)
	}
}
