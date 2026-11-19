// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// A real scan whose knowledge holds a one-way notice (and a lead) on a hop of
// a Kubernetes route: the jump shows ATTENTION citing the notice, a lead is
// never a pass, and neither changes the exit code. Needs the build tag
// prufyx_synthetic_knowledge.
func TestKubernetesJumpNoticeAndLead(t *testing.T) {
	notice := `{"id":"kubernetes.synthetic-jump-notice.1-24-0-to-1-25-0","operator":"notice_one_way","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` + lineRange("1.24", "1.25", "1.26") +
		`"appliesWhen":[{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.psp_v1beta1_removed_gvk_present","boolValue":false}],` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},"reasonCode":"ONE_WAY_TRANSITION","nextAction":"Back up etcd before you start."}`
	lead := `{"id":"kubernetes.synthetic-jump-lead.1-24-0-to-1-25-0","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` + lineRange("1.24", "1.25", "1.26") +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.flowcontrol_v1beta3_removed_gvk_present","boolValue":true},` +
		`"evidence":{"state":"active","basis":"lead","derivedAt":"` + currentReviewed + `",` + currentWindow + `,"sources":[` + skewSource + `]},"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"Check the FlowSchema objects."}`
	fact := func(id string) cncfcheck.Fact {
		return cncfcheck.Fact{Side: "proposed", ID: id, Component: kubernetesKey, Type: constraintengine.FactBool, Description: "Synthetic."}
	}
	run := func(entries []cncfcheck.Entry) (Result, *scanreport.Jump) {
		restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries)
		if err != nil {
			t.Fatal(err)
		}
		defer restore()
		return k8sJumpOf(t, cronjobV1, allLines, "--require-basis", allBases)
	}
	plainResult, plain := run(nil)
	if plain == nil || plain.Status != scanreport.JumpStepwisePass {
		t.Fatalf("plain %+v", plain)
	}
	noticeEntry := cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only notice. Never published.", RequiredFacts: []cncfcheck.Fact{fact("component.kubernetes.psp_v1beta1_removed_gvk_present")}, Rule: json.RawMessage(notice)}
	leadEntry := cncfcheck.Entry{Project: "kubernetes", Description: "Synthetic test-only lead. Never published.", RequiredFacts: []cncfcheck.Fact{fact("component.kubernetes.flowcontrol_v1beta3_removed_gvk_present")}, Rule: json.RawMessage(lead)}

	result, jump := run([]cncfcheck.Entry{noticeEntry})
	if jump == nil || jump.Status != scanreport.JumpAttention || len(jump.DecidedBy) == 0 || result.Exit != plainResult.Exit {
		t.Fatalf("notice: exit %d/%d jump %+v", result.Exit, plainResult.Exit, jump)
	}
	cited := false
	for _, hop := range jump.Hops {
		for _, entry := range hop.Entries {
			cited = cited || strings.HasPrefix(entry, "kubernetes.synthetic-jump-notice.")
		}
	}
	if !cited {
		t.Fatalf("the notice is not cited: %+v", jump.Hops)
	}

	result, jump = run([]cncfcheck.Entry{leadEntry})
	if jump == nil || jump.Status == scanreport.JumpStepwisePass || result.Exit != plainResult.Exit {
		t.Fatalf("lead: exit %d/%d jump %+v", result.Exit, plainResult.Exit, jump)
	}
}
