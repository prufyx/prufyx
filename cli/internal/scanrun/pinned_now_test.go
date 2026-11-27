// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// TestScanPinnedNowCannotHideWallClockExpiry: --now pins the evaluation time,
// but knowledge that has expired at the real time must not leave a PASS.
func TestScanPinnedNowCannotHideWallClockExpiry(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
	first := embeddedEarliest(t)
	// The pinned instant follows the rule data: not before the review of any
	// Kubernetes API-removal or kubelet version-skew rule (an earlier clock
	// answers UNKNOWN, see TestScanClockBeforeReviewStaysUnknown) and before
	// the earliest end.
	pinned := supersedeids.Clock()
	if !pinned.Before(first.Add(-24 * time.Hour)) {
		t.Fatalf("pinned instant %s is not before the day that precedes the earliest end %s", pinned.Format(time.RFC3339), first.Format(time.RFC3339))
	}
	argv := append(append([]string{"applyset.yaml"}, declared...), "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--now", pinned.Format(time.RFC3339))
	run := func(wall time.Time) Result {
		request, err := ParseArgs(argv)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Run(request, Options{Build: &testBuild, Clock: func() time.Time { return wall }})
		if err != nil {
			t.Fatal(err)
		}
		checkInvariants(t, result.Report)
		return result
	}
	inDir(t, dir, func() {
		for _, c := range []struct {
			name string
			wall time.Time
		}{
			{"wall clock equals --now", pinned},
			{"wall clock inside the validity window", first.Add(-24 * time.Hour)},
		} {
			result := run(c.wall)
			if result.Exit != scanreport.ExitPass || result.PinnedNowWarning != "" {
				t.Errorf("%s: exit %d warning %q gaps %v", c.name, result.Exit, result.PinnedNowWarning, result.Report.Gaps)
			}
		}
		result := run(first.Add(48 * time.Hour))
		if result.Exit != scanreport.ExitUnknown || result.Report.Verdict == scanreport.VerdictPass {
			t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
		}
		var gap *scanreport.Gap
		for i := range result.Report.Gaps {
			if result.Report.Gaps[i].Reason == scanreport.ReasonEvidenceExpired {
				gap = &result.Report.Gaps[i]
			}
		}
		if gap == nil || !strings.Contains(gap.Detail, pinned.Format(time.RFC3339)) {
			t.Fatalf("no pinned-now gap: %+v", result.Report.Gaps)
		}
		for _, want := range []string{"--now " + pinned.Format(time.RFC3339), "knowledge rules have expired since"} {
			if !strings.Contains(result.PinnedNowWarning, want) {
				t.Errorf("warning %q lacks %q", result.PinnedNowWarning, want)
			}
		}
		for format, want := range map[string]string{"human": "knowledge rules have expired since", "json": "EVIDENCE_EXPIRED"} {
			out, _ := scanreport.Render(result.Report, format, scanreport.RenderOptions{Verbose: true})
			if !strings.Contains(string(out), want) {
				t.Errorf("%s output does not show the gap", format)
			}
		}
	})
}
