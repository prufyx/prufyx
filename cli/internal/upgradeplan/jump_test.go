// SPDX-License-Identifier: AGPL-3.0-only

package upgradeplan

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A route carries the scan's jump and a per-hop table, rendered in text and
// JSON, and neither changes a stage verdict, the plan verdict or the exit.
func TestRouteJumpAndHopTable(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	hops := []scanreport.JumpHop{
		{Index: 1, From: "1.14.5", To: "1.15.3", Status: scanreport.JumpHopUndecided, ObjectSetDigest: digest, Reasons: []string{"LINE_NOT_ATTESTED"}},
		{Index: 2, From: "1.15.3", To: "1.16.0", Status: scanreport.JumpHopBlocked, ObjectSetDigest: digest, RuleIDs: []string{"kyverno.crd-version-removal.updaterequests-kyverno-io.1-15-0-to-1-16-0"}},
	}
	jump := scanreport.NewJump(hops, digest, nil, map[int]string{1: "request coverage of line 1.15"})
	report := scanreport.Report{Verdict: scanreport.VerdictBlocked, Paths: []scanreport.Path{{Component: "kyverno", From: "1.14.5", To: "1.16.0", Hops: []scanreport.Hop{
		{Index: 1, From: scanreport.Endpoint{Version: "1.14.5"}, To: scanreport.Endpoint{Version: "1.15.3"}, Status: scanreport.HopPartial},
		{Index: 2, From: scanreport.Endpoint{Version: "1.15.3"}, To: scanreport.Endpoint{Version: "1.16.0"}, Status: scanreport.HopBlocked},
	}}}}
	without := Build(report, nil, Capabilities{})
	report.Paths[0].Jump = &jump
	with := Build(report, nil, Capabilities{})
	if with.Verdict != without.Verdict || with.ExitCode != without.ExitCode || len(with.Stages) != len(without.Stages) {
		t.Fatalf("the jump changed the plan: %s/%d vs %s/%d", with.Verdict, with.ExitCode, without.Verdict, without.ExitCode)
	}
	for i := range with.Stages {
		if with.Stages[i].Verdict != without.Stages[i].Verdict {
			t.Fatalf("stage %d verdict %s vs %s", i+1, with.Stages[i].Verdict, without.Stages[i].Verdict)
		}
	}
	route := with.Routes[0]
	if route.Jump == nil || route.Jump.Status != scanreport.JumpBlocked || len(route.HopTable) != 2 || route.HopTable[0].Status != "UNDECIDED" {
		t.Fatalf("route %+v", route)
	}
	out, err := Render(with, "human")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"BLOCKED on the stepwise path (hop 2 decides)", "hop 1 1.14.5 -> 1.15.3: UNDECIDED (LINE_NOT_ATTESTED)", "missing for hop 1", "kyverno.crd-version-removal.updaterequests-kyverno-io.1-15-0-to-1-16-0"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("plan lacks %q:\n%s", want, out)
		}
	}
	raw, err := Render(with, "json")
	if err != nil || !strings.Contains(string(raw), `"jump":{"status":"BLOCKED"`) || !strings.Contains(string(raw), `"hopTable":[`) {
		t.Fatalf("json %v %s", err, raw)
	}
}
