// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/onecommand"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

// assess with a declared scope exits with the aggregate, in both formats:
// a BLOCKED or UNKNOWN aggregate must never exit 0.
func TestAssessExitFollowsAggregate(t *testing.T) {
	cases := []struct {
		name       string
		scope      bool
		assessment string
		want       int
	}{
		{"pass", true, "SCOPE_COMPLETE_PASS", ExitOK},
		{"blocked", true, "BLOCKED", ExitBlocked},
		{"unknown", true, "UNKNOWN", ExitUnknown},
		{"unrecognised aggregate", true, "SAFE", ExitUnknown},
		{"no scope declaration", false, "UNKNOWN", ExitOK},
	}
	old := runAssessCollect
	t.Cleanup(func() { runAssessCollect = old })
	for _, tc := range cases {
		for _, format := range []string{"human", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				runAssessCollect = func(context.Context, onecommand.Options, io.Writer, io.Writer) (onecommand.Report, int) {
					rep := onecommand.Report{Aggregate: onecommand.AggregateNote{Assessment: tc.assessment, ReasonCode: "r", Note: "n"}}
					if tc.scope {
						rep.ScopeAssessment = &projectcheck.ScopeReport{Assessment: tc.assessment}
					}
					return rep, onecommand.ExitOK
				}
				code, stdout, stderr := runCommunity(t, "assess", "--kubeconfig", "/k", "--acknowledge-kubeconfig-exec-risk", "--format", format, "ctx")
				if code != tc.want {
					t.Fatalf("code=%d want %d stdout=%q", code, tc.want, stdout)
				}
				if gotNote := strings.Contains(stderr, assessNoScopeNote); gotNote != !tc.scope {
					t.Fatalf("no-scope note present=%v, scope=%v, stderr=%q", gotNote, tc.scope, stderr)
				}
				if !strings.Contains(stdout, tc.assessment) {
					t.Fatalf("aggregate %s missing from output: %q", tc.assessment, stdout)
				}
			})
		}
	}
}

// Collection failures keep their own codes.
func TestAssessCollectionFailureCodeKept(t *testing.T) {
	old := runAssessCollect
	t.Cleanup(func() { runAssessCollect = old })
	runAssessCollect = func(context.Context, onecommand.Options, io.Writer, io.Writer) (onecommand.Report, int) {
		return onecommand.Report{}, onecommand.ExitPartial
	}
	code, _, _ := runCommunity(t, "assess", "--kubeconfig", "/k", "--acknowledge-kubeconfig-exec-risk", "ctx")
	if code != onecommand.ExitPartial {
		t.Fatalf("code=%d want %d", code, onecommand.ExitPartial)
	}
}

// A scope assessment that disagrees with the aggregate is never a pass.
func TestAssessExitScopeAggregateMismatch(t *testing.T) {
	for _, tc := range [][2]string{{"SCOPE_COMPLETE_PASS", "BLOCKED"}, {"BLOCKED", "SCOPE_COMPLETE_PASS"}, {"UNKNOWN", "SCOPE_COMPLETE_PASS"}} {
		rep := onecommand.Report{
			Aggregate:       onecommand.AggregateNote{Assessment: tc[0]},
			ScopeAssessment: &projectcheck.ScopeReport{Assessment: tc[1]},
		}
		if got := assessExit(rep); got != ExitUnknown {
			t.Errorf("aggregate=%s scope=%s: exit=%d want %d", tc[0], tc[1], got, ExitUnknown)
		}
	}
}
