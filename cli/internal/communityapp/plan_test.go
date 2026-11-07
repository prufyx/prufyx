// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/upgradeplan"
)

func runPlan(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), append([]string{"plan"}, args...), &stdout, &stderr, "test")
	return code, stdout.String(), stderr.String()
}

func TestPlanCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "applyset.yaml")
	if err := os.WriteFile(path, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	declared := []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", supersedeids.ClockString()}
	code, stdout, _ := runPlan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--format", "json"}, declared...)...)
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if code != ExitBlocked || plan.Verdict != upgradeplan.VerdictBlocked || len(plan.Stages) != 6 || plan.Routes[0].Policy != "sequential_minor" {
		t.Fatalf("%d %+v", code, plan)
	}
	for _, s := range plan.Stages {
		if s.Verdict == upgradeplan.VerdictPass {
			t.Fatalf("PASS stage %+v", s)
		}
	}
	code, stdout, _ = runPlan(t, append([]string{path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, declared...)...)
	if code != ExitBlocked || !strings.Contains(stdout, "Stage 6") || !strings.Contains(stdout, "BLOCKED") {
		t.Fatalf("human %d\n%s", code, stdout)
	}
	// latest is not resolved: reported, never guessed.
	code, stdout, _ = runPlan(t, "--to", "kubernetes=latest")
	if code != ExitUnknown || !strings.Contains(stdout, "LATEST_NOT_RESOLVED") {
		t.Fatalf("latest %d\n%s", code, stdout)
	}
	code, stdout, _ = runPlan(t, path, "--from", "kubernetes=1.24.17", "--to=kubernetes=1.25.3", "--to", "cilium=latest", "--format", "markdown")
	if code == ExitUsage || !strings.Contains(stdout, "cilium") || !strings.Contains(stdout, "LATEST_NOT_RESOLVED") {
		t.Fatalf("mixed %d\n%s", code, stdout)
	}
	if code, _, stderr := runPlan(t, path, "--to", "kubernetes=1.30.4", "--format", "sarif"); code != ExitUsage {
		t.Fatalf("sarif %d %s", code, stderr)
	}
	// newest-covered: the newest line with a current reviewed list, labelled.
	code, stdout, stderr := runPlan(t, append([]string{path, "--from", "kubernetes=1.35.2", "--to", "kubernetes=newest-covered", "--format", "json"}, declared...)...)
	var newest upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &newest); err != nil || len(newest.Routes) != 1 || !strings.HasSuffix(newest.Routes[0].To, ".0") || len(newest.Notes) != 1 || !strings.Contains(newest.Notes[0], "not the newest release") {
		t.Fatalf("newest-covered %d %v\n%s\n%s", code, err, stdout, stderr)
	}
	if code, _, _ := runPlan(t, append([]string{path, "--to", "kubernetes=1.30.4", "--to", "kubernetes=newest-covered"}, declared...)...); code != ExitUsage {
		t.Fatalf("newest-covered twice %d", code)
	}
	if code, _, _ := runPlan(t, append([]string{path, "--to", "kubernetes=latest", "--to", "kubernetes=newest-covered"}, declared...)...); code != ExitUsage {
		t.Fatalf("latest and newest-covered %d", code)
	}
	if code, _, _ := runPlan(t, append([]string{path, "--to", "cilium=newest-covered"}, declared...)...); code != ExitUsage {
		t.Fatalf("newest-covered without lines %d", code)
	}
	if code, _, _ := runPlan(t, path, "--to", "kubernetes=1.30.4", "--fail-on", "none"); code != ExitUsage {
		t.Fatalf("fail-on %d", code)
	}
	if code, out, _ := runPlan(t, "--help"); code != ExitOK || !strings.Contains(out, "Usage: prufyx plan") {
		t.Fatalf("help %d %s", code, out)
	}
}

// TestPlanOldToLatestExample pins the hop statuses printed for the
// examples/old-to-latest apply set. A kubelet declaration is one fixed
// version, so no single declaration spans every hop up to the newest covered
// line: each run below is COVERED on every hop, and neither is a PASS.
// The COVERED and PARTIAL counts below depend on knowledge revision
// cncf-2026-09-13.8; a new revision can change them.
func TestPlanOldToLatestExample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "old-to-latest", "rendered.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rendered.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	declared := []string{"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--now", supersedeids.ClockString(), "--format", "json"}
	for _, tc := range []struct {
		name    string
		args    []string
		last    string
		covered int
	}{
		{"1.29.15 to 1.36.0", []string{"--from", "kubernetes=1.29.15", "--to", "kubernetes=1.36.0", "--kubelet-version-min", "1.33.0"}, "1.36.0", 7},
		{"1.33.5 to newest-covered", []string{"--from", "kubernetes=1.33.5", "--to", "kubernetes=newest-covered", "--kubelet-version-min", "1.34.0"}, "1.37.0", 4},
	} {
		code, stdout, stderr := runPlan(t, append(append([]string{path}, tc.args...), declared...)...)
		var plan upgradeplan.Plan
		if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
			t.Fatalf("%s: %v\n%s\n%s", tc.name, err, stdout, stderr)
		}
		if code != ExitUnknown || plan.Verdict != upgradeplan.VerdictUnknown || len(plan.Stages) != tc.covered || plan.Stages[tc.covered-1].To != tc.last {
			t.Fatalf("%s: %d %s stages=%d", tc.name, code, plan.Verdict, len(plan.Stages))
		}
		for _, s := range plan.Stages {
			if s.HopStatus != "COVERED" || s.Verdict != upgradeplan.VerdictUnknown || len(s.Findings) != 0 || len(s.Gaps) != 0 {
				t.Fatalf("%s: stage %d %s: %+v", tc.name, s.Index, s.To, s)
			}
			got := strings.Join(reasonStrings(s.Reasons), ",")
			if got != "HOP_ACTIONS_NOT_CHECKED,NODE_ROLLS_NOT_PLANNED" {
				t.Fatalf("%s: stage %d reasons %s", tc.name, s.Index, got)
			}
		}
	}
	// One kubelet declaration cannot span 1.29 -> 1.37: the skew rule blocks.
	code, stdout, _ := runPlan(t, append([]string{path, "--from", "kubernetes=1.29.15", "--to", "kubernetes=newest-covered", "--kubelet-version-min", "1.33.0"}, declared...)...)
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil || code != ExitBlocked || plan.Verdict != upgradeplan.VerdictBlocked {
		t.Fatalf("full span %d %v", code, err)
	}
	last := plan.Stages[len(plan.Stages)-1]
	if last.To != "1.37.0" {
		t.Fatalf("full span last stage targets %s", last.To)
	}
	skew := false
	for _, f := range last.Findings {
		skew = skew || strings.HasPrefix(f.RuleID, "kubernetes.kubelet-version-skew.")
	}
	if !skew || last.Verdict != upgradeplan.VerdictBlocked {
		t.Fatalf("full span last stage: verdict %s findings %+v", last.Verdict, last.Findings)
	}
	// Without the kubelet declaration the hops that carry a skew rule stay PARTIAL.
	code, stdout, _ = runPlan(t, append([]string{path, "--from", "kubernetes=1.29.15", "--to", "kubernetes=1.36.0"}, declared...)...)
	plan = upgradeplan.Plan{}
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil || code != ExitUnknown || len(plan.Stages) != 7 {
		t.Fatalf("no kubelet %d %v", code, err)
	}
	for i, s := range plan.Stages {
		want := "PARTIAL"
		if i < 3 {
			want = "COVERED"
		}
		if s.HopStatus != want {
			t.Fatalf("no kubelet stage %d %s want %s", s.Index, s.HopStatus, want)
		}
	}
}

func reasonStrings[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, r := range in {
		out[i] = string(r)
	}
	return out
}
