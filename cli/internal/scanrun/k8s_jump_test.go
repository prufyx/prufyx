// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

func k8sJumpOf(t *testing.T, manifest string, lines []string, extra ...string) (Result, *scanreport.Jump) {
	t.Helper()
	_, paths := files(t, map[string]string{"applyset.yaml": manifest})
	command := append([]string{"--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4"}, extra...)
	result := mustScan(t, newKnowledge(t, knowledgeOptions{lines: lines, policy: "current"}), args(paths, command...)...)
	for _, path := range result.Report.Paths {
		if path.Component == kubernetesSlug {
			return result, path.Jump
		}
	}
	t.Fatalf("no kubernetes path: %+v", result.Report.Paths)
	return result, nil
}

func TestKubernetesJumpStatus(t *testing.T) {
	t.Run("a blocked hop blocks the jump and is cited", func(t *testing.T) {
		result, jump := k8sJumpOf(t, cronjobV1beta1, allLines)
		if jump == nil || jump.Status != scanreport.JumpBlocked || len(jump.DecidedBy) == 0 || len(jump.Hops) < 2 {
			t.Fatalf("jump %+v", jump)
		}
		cited := false
		for _, hop := range jump.Hops {
			if hop.Status == scanreport.JumpHopBlocked && len(hop.RuleIDs) > 0 {
				cited = true
			}
		}
		if !cited || result.Exit != scanreport.ExitBlocked {
			t.Fatalf("exit %d jump %+v", result.Exit, jump)
		}
	})
	t.Run("every hop covered is a scoped stepwise pass", func(t *testing.T) {
		result, jump := k8sJumpOf(t, cronjobV1, allLines)
		if jump == nil || jump.Status != scanreport.JumpStepwisePass || len(jump.Hops) < 2 || jump.ObjectSetDigest == "" {
			t.Fatalf("jump %+v", jump)
		}
		for _, hop := range jump.Hops {
			if hop.Status != scanreport.JumpHopPass || hop.ObjectSetDigest != jump.ObjectSetDigest {
				t.Fatalf("hop %+v", hop)
			}
		}
		if strings.Contains(jump.Scope, "custom-resource") || !strings.Contains(jump.Scope, "direct skip") || result.Exit != scanreport.ExitPass {
			t.Fatalf("exit %d scope %q", result.Exit, jump.Scope)
		}
	})
	t.Run("the scope says whether kubelet skew was checked", func(t *testing.T) {
		_, none := k8sJumpOf(t, cronjobV1, allLines)
		if none == nil || none.Status != scanreport.JumpStepwisePass || !strings.Contains(none.Scope, "kubelet skew not checked") {
			t.Fatalf("no declaration: %+v", none)
		}
		_, declared := k8sJumpOf(t, cronjobV1, allLines, "--kubelet-version-min", "1.30.0")
		if declared == nil || !strings.Contains(declared.Scope, "kubelet skew was checked against the declared kubelet version 1.30.0") || strings.Contains(declared.Scope, "not checked") {
			t.Fatalf("declared: %+v", declared)
		}
	})
	t.Run("an undecided hop is UNKNOWN with the table and what is missing", func(t *testing.T) {
		result, jump := k8sJumpOf(t, cronjobV1, without(allLines, "1.28", "1.30"))
		if jump == nil || jump.Status != scanreport.JumpUnknown || len(jump.Hops) < 2 || len(jump.Missing) == 0 {
			t.Fatalf("jump %+v", jump)
		}
		undecided := 0
		for _, hop := range jump.Hops {
			if hop.Status == scanreport.JumpHopUndecided {
				undecided++
			}
		}
		if undecided == 0 || result.Exit != scanreport.ExitUnknown {
			t.Fatalf("exit %d jump %+v", result.Exit, jump)
		}
	})
	t.Run("the exit and the verdict do not read the jump", func(t *testing.T) {
		for _, manifest := range []string{cronjobV1, cronjobV1beta1} {
			for _, lines := range [][]string{allLines, without(allLines, "1.28")} {
				result, jump := k8sJumpOf(t, manifest, lines)
				if jump == nil {
					t.Fatal("no jump")
				}
				with := scanreport.Exit(result.Report)
				result.Report.Paths[0].Jump = nil
				if without := scanreport.Exit(result.Report); with != without || with != result.Exit {
					t.Fatalf("exit %d without the jump %d (run %d)", with, without, result.Exit)
				}
			}
		}
	})
	t.Run("an open gap outside the hops never passes", func(t *testing.T) {
		// An object at an API version the target does not serve, on a line
		// that no hop decides, leaves the report UNKNOWN: no hop passes.
		_, jump := k8sJumpOf(t, "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: a}\n", allLines)
		if jump != nil && jump.Status == scanreport.JumpStepwisePass {
			t.Fatalf("jump %+v", jump)
		}
	})
}

// Notices cite ATTENTION, a hop on another object set is not composable, and
// a blocker of the whole upgrade is cited, never passed over.
func TestKubernetesJumpComposition(t *testing.T) {
	hops := []scanreport.Hop{
		{Index: 1, From: scanreport.Endpoint{Version: "1.24.17"}, To: scanreport.Endpoint{Version: "1.25.16"}, Status: scanreport.HopCovered},
		{Index: 2, From: scanreport.Endpoint{Version: "1.25.16"}, To: scanreport.Endpoint{Version: "1.26.15"}, Status: scanreport.HopCovered},
	}
	run := func(report scanreport.Report, digests map[int]string) *scanreport.Jump {
		r := &kubernetesRun{report: &report, hopDigests: digests}
		path := scanreport.Path{Component: kubernetesSlug, From: "1.24.17", To: "1.26.15", Hops: hops}
		r.composeJump(&path)
		return path.Jump
	}
	same := map[int]string{1: "sha256:a", 2: "sha256:a"}
	if j := run(scanreport.Report{}, same); j.Status != scanreport.JumpStepwisePass {
		t.Fatalf("clean %+v", j)
	}
	if j := run(scanreport.Report{}, map[int]string{1: "sha256:a", 2: "sha256:b"}); j.Status != scanreport.JumpUnknown {
		t.Fatalf("other object set %+v", j)
	}
	if j := run(scanreport.Report{}, map[int]string{1: "sha256:a"}); j.Status != scanreport.JumpUnknown {
		t.Fatalf("missing digest %+v", j)
	}
	if j := run(scanreport.Report{}, nil); j.Status != scanreport.JumpUnknown {
		t.Fatalf("no digests %+v", j)
	}
	withNeutral := func(rules ...neutralRule) *scanreport.Jump {
		r := &kubernetesRun{report: &scanreport.Report{}, hopDigests: same, hopNeutral: map[int][]neutralRule{2: rules}}
		path := scanreport.Path{Component: kubernetesSlug, Hops: hops}
		r.composeJump(&path)
		return path.Jump
	}
	if j := withNeutral(neutralRule{id: "kubernetes.note", text: "back up etcd", noticed: true}); j.Status != scanreport.JumpAttention || len(j.DecidedBy) != 1 || j.DecidedBy[0] != 2 || !strings.HasPrefix(j.Hops[1].Entries[0], "kubernetes.note") {
		t.Fatalf("notice %+v", j)
	}
	// A lead, or a notice the engine did not give a claim, decides nothing:
	// its hop is never a pass and the jump is never a stepwise pass.
	for _, rule := range []neutralRule{{id: "kubernetes.lead", noticed: false}} {
		if j := withNeutral(rule, neutralRule{id: "kubernetes.note", noticed: true}); j.Status == scanreport.JumpStepwisePass || j.Status == scanreport.JumpAttention || j.Hops[1].Status != scanreport.JumpHopUndecided {
			t.Fatalf("lead %+v", j)
		}
	}
	wholeNeutral := &kubernetesRun{report: &scanreport.Report{}, hopDigests: same, wholeNeutral: []neutralRule{{id: "kubernetes.note", noticed: true}}}
	wholePath := scanreport.Path{Component: kubernetesSlug, Hops: hops}
	wholeNeutral.composeJump(&wholePath)
	if wholePath.Jump.Status != scanreport.JumpUnknown {
		t.Fatalf("whole-upgrade notice %+v", wholePath.Jump)
	}
	gapped := scanreport.Report{Gaps: []scanreport.Gap{{Component: kubernetesSlug, Reason: "API_VERSION_NOT_SERVED"}}}
	if j := run(gapped, same); j.Status != scanreport.JumpUnknown || len(j.Missing) != 2 {
		t.Fatalf("root gap %+v", j)
	}
	whole := scanreport.Report{Findings: []scanreport.Finding{{RuleID: "kubernetes.whole", Component: kubernetesSlug, Hop: scanreport.HopRef{From: "1.24.17", To: "1.26.15", WholeUpgrade: true}}}}
	if j := run(whole, same); j.Status != scanreport.JumpBlocked || j.Hops[1].RuleIDs[0] != "kubernetes.whole" {
		t.Fatalf("whole-upgrade blocker %+v", j)
	}
	blockedNoRule := append([]scanreport.Hop{}, hops...)
	blockedNoRule[1].Status = scanreport.HopBlocked
	r := &kubernetesRun{report: &scanreport.Report{}, hopDigests: same}
	path := scanreport.Path{Component: kubernetesSlug, Hops: blockedNoRule}
	r.composeJump(&path)
	if path.Jump.Status == scanreport.JumpBlocked || path.Jump.Status == scanreport.JumpStepwisePass {
		t.Fatalf("a blocked hop without a cited rule: %+v", path.Jump)
	}
}
