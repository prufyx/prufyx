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
	if code, _, _ := runPlan(t, path, "--to", "kubernetes=1.30.4", "--fail-on", "none"); code != ExitUsage {
		t.Fatalf("fail-on %d", code)
	}
	if code, out, _ := runPlan(t, "--help"); code != ExitOK || !strings.Contains(out, "Usage: prufyx plan") {
		t.Fatalf("help %d %s", code, out)
	}
}
