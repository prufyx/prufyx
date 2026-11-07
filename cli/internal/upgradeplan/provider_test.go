// SPDX-License-Identifier: AGPL-3.0-only

package upgradeplan

import (
	"flag"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/goldenfile"
	"github.com/prufyx/prufyx/cli/internal/providerfacts"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func bp(b bool) *bool { return &b }

// providerSection evaluates a synthetic EKS record (all rows and dates are
// invented, in the shape of the design example) for 1.29.15 -> 1.33.0.
func providerSection(t *testing.T, withRecord bool) *providerfacts.Section {
	t.Helper()
	rev := "0123456789abcdef0123456789abcdef01234567"
	day := distribution.PrecisionDay
	section := distribution.Section{Applicability: []distribution.Applicability{}, Records: []distribution.Record{{
		Distribution: "eks", ControlPlane: distribution.ControlPlaneManaged,
		Lifecycle: []distribution.Lifecycle{
			{Line: "1.31", StandardEnd: "2025-11-26", ExtendedEnd: "2026-11-26", ExtendedRequiresOptIn: bp(false), Precision: day},
			{Line: "1.32", StandardEnd: "2026-03-23", ExtendedEnd: "2027-03-23", ExtendedRequiresOptIn: bp(false), Precision: day},
			{Line: "1.33", StandardEnd: "2026-07-29", ExtendedEnd: "2027-07-29", ExtendedRequiresOptIn: bp(false), ForcedUpgrade: &distribution.ForcedUpgrade{Date: "2027-07-29", SentenceID: "synthetic-1"}, Precision: day},
		},
		Evidence: distribution.Evidence{State: distribution.StateActive, ReviewedAt: "2026-11-01T00:00:00Z", ValidUntil: "2026-12-01T00:00:00Z",
			Sources: []constraintengine.SourceEvidence{{ID: "table", URL: "https://github.com/example/docs/blob/" + rev + "/eks.md", Revision: rev, ContentDigest: "sha256:" + strings.Repeat("0", 64), StartLine: 1, EndLine: 9}}},
	}}}
	if !withRecord {
		section = distribution.Section{Applicability: []distribution.Applicability{}}
	}
	if withRecord {
		if err := distribution.Validate(section); err != nil {
			t.Fatal(err)
		}
	}
	s, ok := providerfacts.Evaluate(providerfacts.Input{Provider: "eks", Now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Records: distribution.NewIndex(section),
		Current: providerfacts.Endpoint{Version: "1.29.15"}, Target: providerfacts.Endpoint{Version: "1.33.0"}, KnowledgeRevision: "rev-synthetic"})
	if !ok {
		t.Fatal("no section")
	}
	return &s
}

func eksReport(t *testing.T, withRecord bool) scanreport.Report {
	hops := []scanreport.Hop{hop(1, "1.29.15", "1.30", scanreport.HopCovered), hop(2, "1.30", "1.31", scanreport.HopCovered), hop(3, "1.31", "1.32", scanreport.HopCovered), hop(4, "1.32", "1.33.0", scanreport.HopCovered)}
	return scanreport.Report{Verdict: scanreport.VerdictUnknown, Paths: []scanreport.Path{{Component: "kubernetes", From: "1.29.15", To: "1.33.0", Policy: "sequential_minor", Hops: hops}}, Provider: providerSection(t, withRecord)}
}

// TestProviderPlanGolden pins the plan output for a multi-hop plan: per-hop
// provider support dates as advisory lines, the target, the forced upgrade,
// extended support labelled paid and never recommended, and a verdict that
// is not changed by any of it.
func TestProviderPlanGolden(t *testing.T) {
	plan := Build(eksReport(t, true), nil, Capabilities{})
	out, err := Render(plan, "human")
	if err != nil {
		t.Fatal(err)
	}
	goldenfile.Check(t, filepath.Join("testdata", "provider-plan-eks.txt"), out, *update, "")
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(l), "extended") && !strings.Contains(l, "(paid") && !strings.Contains(l, "Extended support is paid") {
			t.Errorf("extended support not labelled paid: %q", l)
		}
		if strings.Contains(l, "available in your region") {
			t.Errorf("region claim: %q", l)
		}
	}
}

func TestProviderFactsDoNotChangeThePlanVerdict(t *testing.T) {
	for _, withRecord := range []bool{true, false} {
		with := Build(eksReport(t, withRecord), nil, Capabilities{})
		r := eksReport(t, withRecord)
		r.Provider = nil
		without := Build(r, nil, Capabilities{})
		if with.Verdict != without.Verdict || with.ExitCode != without.ExitCode || with.Headline != without.Headline || with.Undecided != without.Undecided {
			t.Fatalf("record %v: provider facts changed the plan: %s/%s", withRecord, with.Headline, without.Headline)
		}
		for i := range with.Stages {
			if with.Stages[i].Verdict != without.Stages[i].Verdict || strings.Join(with.Stages[i].Reasons, ",") != strings.Join(without.Stages[i].Reasons, ",") {
				t.Fatalf("stage %d changed", i+1)
			}
			if with.Stages[i].Verdict == VerdictPass {
				t.Fatal("PASS")
			}
		}
		if with.Provider == nil || without.Provider != nil {
			t.Fatal("provider placement")
		}
	}
}

func TestProviderStagesCarryTheHopLine(t *testing.T) {
	plan := Build(eksReport(t, true), nil, Capabilities{})
	want := []string{"provider_version_unknown", "provider_version_unknown", "provider_support_ended", "provider_support_ended"}
	for i, s := range plan.Stages {
		if len(s.Provider) == 0 || s.Provider[0].Rule != want[i] {
			t.Fatalf("stage %d: %+v", i+1, s.Provider)
		}
	}
	if len(plan.Provider.Target) == 0 || plan.Provider.Target[0].Line != "1.33" {
		t.Fatalf("target %+v", plan.Provider.Target)
	}
	// Absent record: every stage says UNKNOWN, none is silent.
	for _, s := range Build(eksReport(t, false), nil, Capabilities{}).Stages {
		if len(s.Provider) != 1 || s.Provider[0].Severity != providerfacts.SeverityUnknown {
			t.Fatalf("absent: %+v", s.Provider)
		}
	}
}
