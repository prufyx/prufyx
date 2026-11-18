// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if code != ExitUnknown && code != ExitBlocked {
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
		{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--to", "external-dns=not-a-version"},
		{"--from", "kubernetes=1.2", "--to", "kubernetes=1.25.3", "--to", "external-dns=0.15.0"},
		{"--from", "external-dns=0.14.0"},
	} {
		if code, out, _ := runPlan(t, args...); code != ExitUsage {
			t.Fatalf("%v: exit %d\n%s", args, code, out)
		}
	}
}
