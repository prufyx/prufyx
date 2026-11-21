// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradeplan"
)

func schemeInput(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "applyset.yaml")
	if err := os.WriteFile(path, []byte(scanCronJob), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanVersionSchemeIsAGapNotAnAbort(t *testing.T) {
	path := schemeInput(t)
	code, stdout, stderr := runPlan(t, path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3",
		"--from", "linkerd=edge-24.10.5", "--to", "linkerd=edge-24.11.8", "--format", "json")
	if code != ExitUnknown {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var plan upgradeplan.Plan
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	planned := false
	for _, s := range plan.Stages {
		planned = planned || s.Component == "kubernetes"
		if s.Component == "linkerd" {
			t.Fatalf("linkerd planned: %+v", s)
		}
	}
	gap, ok := planGap(plan, "linkerd")
	if !planned || !ok || gap.Reason != scanreport.ReasonVersionSchemeUnsupported || gap.Detail == "" || gap.Action == "" {
		t.Fatalf("planned %v gap %+v\n%s", planned, gap, stdout)
	}
}

func TestPlanOnlyVersionSchemeIsUnknown(t *testing.T) {
	code, stdout, stderr := runPlan(t, "--to", "linkerd=edge-24.11.8", "--format", "json")
	if code != ExitUnknown {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestScanVersionSchemeIsAGapNotAnAbort(t *testing.T) {
	path := schemeInput(t)
	code, stdout, stderr := runScan(t, path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3",
		"--to", "linkerd=edge-24.11.8", "--format", "json")
	if code != ExitUnknown && code != ExitBlocked {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var report scanreport.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	found := false
	for _, g := range report.Gaps {
		found = found || g.Component == "linkerd" && g.Reason == scanreport.ReasonVersionSchemeUnsupported && g.Action != ""
	}
	if !found {
		t.Fatalf("no VERSION_SCHEME_UNSUPPORTED gap for linkerd\n%s", stdout)
	}
}

func TestVersionSchemeMalformedStillUsageError(t *testing.T) {
	path := schemeInput(t)
	long := strings.Repeat("a", 65)
	for _, bad := range []string{"edge 24.11.8", "edge-24.11.8\x01", "1.25", "v1.25.4", "-edge", long, "edge/24"} {
		for _, cmd := range []func(*testing.T, ...string) (int, string, string){runPlan, runScan} {
			if code, out, _ := cmd(t, path, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--to", "linkerd="+bad); code != ExitUsage {
				t.Fatalf("%q: exit %d\n%s", bad, code, out)
			}
		}
	}
	if code, _, _ := runPlan(t, path, "--to", "kubernetes=edge-24.11.8"); code != ExitUsage {
		t.Fatalf("kubernetes edge: exit %d", code)
	}
}

func TestScanOnlyVersionSchemeIsUnknown(t *testing.T) {
	path := schemeInput(t)
	code, stdout, stderr := runScan(t, path, "--to", "linkerd=edge-24.11.8", "--format", "json")
	if code != ExitUnknown {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	var report scanreport.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	found := false
	for _, g := range report.Gaps {
		found = found || g.Component == "linkerd" && g.Reason == scanreport.ReasonVersionSchemeUnsupported
	}
	if !found {
		t.Fatalf("no gap\n%s", stdout)
	}
}
