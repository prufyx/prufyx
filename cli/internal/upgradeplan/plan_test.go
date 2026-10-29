// SPDX-License-Identifier: AGPL-3.0-only

package upgradeplan

import (
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

func hop(i int, from, to, status string) scanreport.Hop {
	return scanreport.Hop{Index: i, From: scanreport.Endpoint{Version: from}, To: scanreport.Endpoint{Line: to}, Status: status}
}

func report() scanreport.Report {
	return scanreport.Report{
		Verdict: scanreport.VerdictUnknown,
		Paths: []scanreport.Path{
			{Component: "cilium", From: "1.14.1", To: "1.16.0", Hops: []scanreport.Hop{hop(1, "1.14.1", "1.15", scanreport.HopCovered), hop(2, "1.15", "1.16.0", scanreport.HopNoData)}},
			{Component: "kubernetes", From: "1.29.1", To: "1.31.0", Policy: "sequential_minor", Hops: []scanreport.Hop{hop(1, "1.29.1", "1.30", scanreport.HopCovered), hop(2, "1.30", "1.31.0", scanreport.HopBlocked)}},
		},
		Findings: []scanreport.Finding{{RuleID: "k.r1", Component: "kubernetes", Hop: scanreport.HopRef{Index: 2}, Title: "removed API", Fix: "migrate"}},
	}
}

func TestOrderAndPlacement(t *testing.T) {
	plan := Build(report(), nil, Capabilities{})
	var got []string
	for _, s := range plan.Stages {
		got = append(got, s.Component+":"+s.To)
	}
	if want := "kubernetes:1.30 kubernetes:1.31.0 cilium:1.15 cilium:1.16.0"; strings.Join(got, " ") != want {
		t.Fatalf("order %v", got)
	}
	if plan.Stages[0].Order.Kind != OrderRequired || plan.Stages[2].Order.Kind != OrderInferred {
		t.Fatalf("order labels %+v", plan.Stages)
	}
	if plan.Stages[1].Verdict != VerdictBlocked || plan.Verdict != VerdictBlocked || plan.ExitCode != ExitBlocked {
		t.Fatalf("blocked %+v", plan)
	}
	if plan.Routes[0].Component != "kubernetes" || len(plan.Routes[0].Stops) != 1 || plan.Routes[0].Stops[0] != "1.30" {
		t.Fatalf("routes %+v", plan.Routes)
	}
}

// TestNoPassWithoutProof: a covered hop is still not PASS while the
// order is inferred, hop actions are unchecked or node rolls are unplanned.
func TestNoPassWithoutProof(t *testing.T) {
	r := scanreport.Report{Verdict: scanreport.VerdictPass, Paths: []scanreport.Path{{Component: "kubernetes", From: "1.29.1", To: "1.30.0", Policy: "sequential_minor", Hops: []scanreport.Hop{hop(1, "1.29.1", "1.30.0", scanreport.HopCovered)}}}}
	full := Capabilities{ActionsChecked: true, NodeRollsPlanned: true}
	if p := Build(r, nil, Capabilities{}); p.Verdict != VerdictUnknown || p.ExitCode != ExitUnknown || p.Undecided != 1 {
		t.Fatalf("default caps: %+v", p)
	}
	for name, caps := range map[string]Capabilities{"actions": {NodeRollsPlanned: true}, "rolls": {ActionsChecked: true}} {
		if p := Build(r, nil, caps); p.Verdict == VerdictPass {
			t.Fatalf("%s: PASS", name)
		}
	}
	if p := Build(r, nil, full); p.Verdict != VerdictPass || p.ExitCode != ExitPass {
		t.Fatalf("all proven: %+v", p)
	}
	r.Paths[0].Policy = ""
	if p := Build(r, nil, full); p.Verdict == VerdictPass {
		t.Fatal("PASS with an inferred order")
	}
	r.Paths[0].Policy = "sequential_minor"
	r.Paths[0].Hops[0].Status = scanreport.HopPartial
	if p := Build(r, nil, full); p.Verdict == VerdictPass {
		t.Fatal("PASS with an uncovered hop")
	}
	r.Paths[0].Hops[0].Status = scanreport.HopCovered
	r.Gaps = []scanreport.Gap{{Component: "kubernetes", Reason: "X", Detail: "d"}}
	if p := Build(r, nil, full); p.Verdict == VerdictPass {
		t.Fatal("PASS with a component gap")
	}
	r.Gaps = []scanreport.Gap{{Component: "", Reason: "Y"}}
	if p := Build(r, nil, full); p.Verdict == VerdictPass {
		t.Fatal("PASS with a plan-level gap")
	}
}

func TestWholeUpgradeFindingInOneStage(t *testing.T) {
	r := report()
	r.Findings = append(r.Findings, scanreport.Finding{RuleID: "c.whole", Component: "cilium", Hop: scanreport.HopRef{WholeUpgrade: true}, Title: "skip", Fix: "f"})
	plan := Build(r, nil, Capabilities{})
	n := 0
	for _, s := range plan.Stages {
		for _, f := range s.Findings {
			if f.RuleID == "c.whole" {
				n++
				if s.Component != "cilium" || s.To != "1.16.0" || !s.WholeUpgrade {
					t.Fatalf("placed in %+v", s)
				}
			}
		}
	}
	if n != 1 {
		t.Fatalf("whole finding shown %d times", n)
	}
}

func TestUnsupportedAndExit(t *testing.T) {
	r := scanreport.Report{Verdict: scanreport.VerdictUnknown, Paths: []scanreport.Path{{Component: "x", From: "1.0.0", To: "1.1.0", Hops: []scanreport.Hop{hop(1, "1.0.0", "1.1.0", scanreport.HopNoData)}}},
		Unsupported: []scanreport.Unsupported{{RuleID: "x.r", Component: "x", Hop: scanreport.HopRef{Index: 1}, Reason: "OUT_OF_RANGE"}}}
	plan := Build(r, nil, Capabilities{ActionsChecked: true, NodeRollsPlanned: true})
	if plan.Verdict != VerdictUnsupported || plan.ExitCode != ExitUnknown {
		t.Fatalf("%+v", plan)
	}
	if plan.Stages[0].Order.Kind != OrderFree {
		t.Fatalf("order %+v", plan.Stages[0].Order)
	}
}

func TestLatestAndUnplannedAreGaps(t *testing.T) {
	r := scanreport.Report{Verdict: scanreport.VerdictUnknown, Paths: []scanreport.Path{{Component: "x", From: "1.0.0", To: "2.0.0", Gap: "PATH_NOT_PLANNABLE"}}}
	plan := Build(r, []string{"cilium"}, Capabilities{})
	if plan.Verdict != VerdictUnknown || len(plan.Stages) != 0 || len(plan.Gaps) != 2 || plan.Gaps[0].Reason != ReasonLatestNotResolved {
		t.Fatalf("%+v", plan)
	}
	if empty := Build(scanreport.Report{}, nil, Capabilities{}); empty.Verdict != VerdictUnknown {
		t.Fatalf("empty plan %s", empty.Verdict)
	}
}

// TestBlockerNeverDropped: a finding that fits no stage still blocks the
// plan and is listed.
func TestBlockerNeverDropped(t *testing.T) {
	r := scanreport.Report{Verdict: scanreport.VerdictBlocked, Findings: []scanreport.Finding{{RuleID: "z.r", Component: "z", Hop: scanreport.HopRef{Index: 9}, Title: "t"}}}
	plan := Build(r, nil, Capabilities{})
	if plan.Verdict != VerdictBlocked || plan.ExitCode != ExitBlocked || len(plan.Gaps) != 1 || plan.Gaps[0].Reason != "FINDING_NOT_PLACED" {
		t.Fatalf("%+v", plan)
	}
}

func TestDeterministicAndRender(t *testing.T) {
	a, _ := Render(Build(report(), nil, Capabilities{}), "json")
	b, _ := Render(Build(report(), nil, Capabilities{}), "json")
	if string(a) != string(b) {
		t.Fatal("not deterministic")
	}
	for _, f := range Formats() {
		out, err := Render(Build(report(), []string{"argo-cd"}, Capabilities{}), f)
		if err != nil || !strings.Contains(string(out), "kubernetes") || !strings.Contains(string(out), "LATEST_NOT_RESOLVED") {
			t.Fatalf("%s: %v\n%s", f, err, out)
		}
	}
	r := report()
	r.Findings[0].Title = "a\nStage 99 PASS"
	out, _ := Render(Build(r, nil, Capabilities{}), "human")
	if strings.Contains(string(out), "\nStage 99") {
		t.Fatal("forged line")
	}
}

func TestGapPlacementAndEarlierBlocker(t *testing.T) {
	r := report()
	r.Paths[1].Hops = append(r.Paths[1].Hops, hop(3, "1.31", "1.32.0", scanreport.HopBlocked))
	r.Gaps = []scanreport.Gap{
		{Component: "kubernetes", Hop: &scanreport.HopRef{WholeUpgrade: true}, Reason: "LINE_NO_RULES", Detail: "whole"},
		{Component: "kubernetes", Hop: &scanreport.HopRef{Index: 42}, Reason: "ORPHAN", Detail: "no such hop"},
	}
	plan := Build(r, nil, Capabilities{ActionsChecked: true, NodeRollsPlanned: true})
	k := plan.Stages[:3]
	if len(k[2].Gaps) != 1 || k[2].Gaps[0].Reason != "LINE_NO_RULES" {
		t.Fatalf("whole gap not in last stage: %+v", k[2])
	}
	if len(plan.Gaps) != 1 || plan.Gaps[0].Reason != "ORPHAN" {
		t.Fatalf("orphan gap lost: %+v", plan.Gaps)
	}
	if k[2].Verdict != VerdictBlocked || !slices.Contains(k[2].Reasons, ReasonBlockedEarlier) {
		t.Fatalf("earlier blocker: %+v", k[2])
	}
	if p := Build(scanreport.Report{Findings: r.Findings}, nil, Capabilities{}); p.Verdict != VerdictBlocked {
		t.Fatalf("findings without verdict: %s", p.Verdict)
	}
}
