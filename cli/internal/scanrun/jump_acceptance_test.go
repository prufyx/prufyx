// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/crdbatchids"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradeplan"
)

const (
	kyvernoUpdateRequestV1beta1 = "apiVersion: kyverno.io/v1beta1\nkind: UpdateRequest\nmetadata:\n  name: qa-update-request\n  namespace: kyverno\n"
	kyvernoUpdateRequestV2      = "apiVersion: kyverno.io/v2\nkind: UpdateRequest\nmetadata:\n  name: qa-update-request\n  namespace: kyverno\n"
)

var hopStatuses = map[string]bool{scanreport.JumpHopBlocked: true, scanreport.JumpHopPass: true, scanreport.JumpHopAttention: true, scanreport.JumpHopUndecided: true}

// requireNeverBare holds for every jump answer (owner rule): the jump lists
// every hop with a status of the closed set, every undecided hop is named in
// Missing with its evidence and action, and an UNKNOWN has the table.
func requireNeverBare(t *testing.T, name string, jump *scanreport.Jump, hops int) {
	t.Helper()
	if jump == nil || len(jump.Hops) != hops || hops < 1 {
		t.Fatalf("%s: jump %+v, want %d hops", name, jump, hops)
	}
	missing := map[int]scanreport.JumpMissing{}
	for _, m := range jump.Missing {
		missing[m.Hop] = m
	}
	for _, h := range jump.Hops {
		if !hopStatuses[h.Status] {
			t.Fatalf("%s: hop status %q", name, h.Status)
		}
		if h.Status == scanreport.JumpHopUndecided {
			m, found := missing[h.Index]
			if !found || m.Evidence == "" || m.Action == "" || len(h.Reasons) == 0 {
				t.Fatalf("%s: undecided hop %+v without evidence, action or reason (missing %+v)", name, h, jump.Missing)
			}
		}
	}
	if jump.Status == scanreport.JumpUnknown && len(jump.Missing) == 0 {
		t.Fatalf("%s: bare UNKNOWN", name)
	}
}

// The shape of the QA baseline of jumps that answered a bare UNKNOWN: with
// the embedded knowledge, an application jump, a jump with an undecided hop
// and a Kubernetes multi-minor route all list every hop with its status.
func TestJumpAcceptanceShapes(t *testing.T) {
	t.Run("kyverno 1.14.5 to 1.16.0 blocks on the 1.15 to 1.16 hop", func(t *testing.T) {
		t.Parallel()
		if !crdbatchids.Shipped() {
			t.Skip("the embedded knowledge holds no custom-resource rule yet")
		}
		result := crdScan(t, newKnowledge(t, knowledgeOptions{}), []string{kyvernoUpdateRequestV1beta1}, "--from", "kyverno=1.14.5", "--to", "kyverno=1.16.0", "--resource-scope-complete")
		var path scanreport.Path
		for _, p := range result.Report.Paths {
			if p.Component == "kyverno" {
				path = p
			}
		}
		requireNeverBare(t, "kyverno", path.Jump, 2)
		last := path.Jump.Hops[1]
		if result.Exit != 10 || path.Jump.Status != scanreport.JumpBlocked || last.Status != scanreport.JumpHopBlocked ||
			len(last.RuleIDs) != 1 || last.RuleIDs[0] != "kyverno.crd-version-removal.updaterequests-kyverno-io.1-15-0-to-1-16-0" || last.From == "1.14.5" {
			t.Fatalf("exit %d jump %+v", result.Exit, path.Jump)
		}
		if len(result.Report.Findings) != 1 || result.Report.Findings[0].Hop.Index != 2 || len(result.Report.Findings[0].Citations) == 0 {
			t.Fatalf("findings %+v", result.Report.Findings)
		}
	})
	t.Run("an application jump with an undecided hop is UNKNOWN with the table", func(t *testing.T) {
		t.Parallel()
		k := newKnowledge(t, knowledgeOptions{})
		for _, line := range []string{"1.15", "1.16"} {
			if len(k.AttestationsFor("pkg:github/kyverno/kyverno", line, lineattest.FamilyCustomResourceVersions, parseNow(t))) != 0 {
				t.Skip("the embedded knowledge now reviews these lines")
			}
		}
		result := crdScan(t, k, []string{kyvernoUpdateRequestV2}, "--from", "kyverno=1.14.5", "--to", "kyverno=1.16.0", "--resource-scope-complete")
		var path scanreport.Path
		for _, p := range result.Report.Paths {
			if p.Component == "kyverno" {
				path = p
			}
		}
		requireNeverBare(t, "kyverno served", path.Jump, 2)
		if result.Exit != 11 || path.Jump.Status != scanreport.JumpUnknown || len(path.Jump.Missing) != 2 {
			t.Fatalf("exit %d jump %+v", result.Exit, path.Jump)
		}
	})
	t.Run("a Kubernetes multi-minor route has the per-hop table", func(t *testing.T) {
		dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1})
		var result Result
		inDir(t, dir, func() {
			result = mustScan(t, newKnowledge(t, knowledgeOptions{lines: without(allLines, "1.28", "1.30"), policy: "current"}), args([]string{"applyset.yaml"}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4")...)
		})
		plan := upgradeplan.Build(result.Report, nil, upgradeplan.Capabilities{})
		route := plan.Routes[0]
		if route.Component != "kubernetes" || route.Hops < 2 || len(route.HopTable) != route.Hops {
			t.Fatalf("route %+v", route)
		}
		undecided := 0
		for _, h := range route.HopTable {
			if !hopStatuses[h.Status] {
				t.Fatalf("hop %+v", h)
			}
			if h.Status == "UNDECIDED" {
				undecided++
				if len(h.Reasons) == 0 {
					t.Fatalf("undecided hop without a reason: %+v", h)
				}
			}
		}
		if undecided == 0 {
			t.Fatalf("expected undecided hops: %+v", route.HopTable)
		}
	})
}

func parseNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return now
}
