// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/scanrun/

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// TestScanPackNoticeAndLeadAreNeutral: a one-way notice and a lead inside
// the published pack's Kubernetes family (so the real selection and the real
// rule document hold them) change no exit, gap, finding or pass. They may
// change the engine contract of the hops that select them.
func TestScanPackNoticeAndLeadAreNeutral(t *testing.T) {
	notice := `{"id":"kubernetes.synthetic-pack-notice.1-24-0-to-1-25-0","operator":"notice_one_way","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` + lineRange("1.24", "1.25", "1.26") +
		`"appliesWhen":[{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.psp_v1beta1_removed_gvk_present","boolValue":false}],` +
		`"evidence":{"state":"active",` + currentWindow + `,"sources":[` + skewSource + `]},"reasonCode":"ONE_WAY_TRANSITION","nextAction":"Back up etcd before you start."}`
	lead := `{"id":"kubernetes.synthetic-pack-lead.1-24-0-to-1-25-0","operator":"forbid_predicate_value","subject":{"component":"pkg:github/kubernetes/kubernetes","from":"1.24.0","to":"1.25.0"},` + lineRange("1.24", "1.25", "1.26") +
		`"condition":{"side":"proposed","component":"pkg:github/kubernetes/kubernetes","factId":"component.kubernetes.flowcontrol_v1beta3_removed_gvk_present","boolValue":true},` +
		`"evidence":{"state":"active","basis":"lead","derivedAt":"` + currentReviewed + `",` + currentWindow + `,"sources":[` + skewSource + `]},"reasonCode":"REVIEWED_SOURCE_CONSTRAINT","nextAction":"Check the FlowSchema objects."}`
	fact := func(id string) cncfcheck.Fact {
		return cncfcheck.Fact{Side: "proposed", ID: id, Component: kubernetesKey, Type: constraintengine.FactBool, Description: "Synthetic."}
	}
	entries := []cncfcheck.Entry{
		{Project: "kubernetes", Description: "Synthetic test-only notice. Never published.", RequiredFacts: []cncfcheck.Fact{fact("component.kubernetes.psp_v1beta1_removed_gvk_present")}, Rule: json.RawMessage(notice)},
		{Project: "kubernetes", Description: "Synthetic test-only lead. Never published.", RequiredFacts: []cncfcheck.Fact{fact("component.kubernetes.flowcontrol_v1beta3_removed_gvk_present")}, Rule: json.RawMessage(lead)},
	}
	type outcome struct {
		exit     int
		gaps     []string
		findings []string
		passes   []string
		contract []string
		notices  int
	}
	runAll := func() []outcome {
		var out []outcome
		for _, manifest := range []string{cronjobV1, cronjobV1beta1} {
			for _, lines := range [][]string{allLines, without(allLines, "1.28")} {
				_, paths := files(t, map[string]string{"applyset.yaml": manifest})
				result := mustScan(t, newKnowledge(t, knowledgeOptions{lines: lines, policy: "current"}), args(paths, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--require-basis", allBases)...)
				o := outcome{exit: result.Exit, gaps: gapReasons(result.Report), notices: len(result.Report.Notices)}
				for _, finding := range result.Report.Findings {
					o.findings = append(o.findings, finding.RuleID)
				}
				for _, pass := range result.Report.Passes {
					o.passes = append(o.passes, pass.RuleID+" "+pass.Hop.To)
				}
				for _, hop := range result.Report.Paths[0].Hops {
					o.contract = append(o.contract, hop.EngineContractDigest)
				}
				out = append(out, o)
			}
		}
		return out
	}
	plain := runAll()
	restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	withNeutral := runAll()
	for index := range plain {
		a, b := plain[index], withNeutral[index]
		if a.exit != b.exit || !reflect.DeepEqual(a.gaps, b.gaps) || !reflect.DeepEqual(a.findings, b.findings) || !reflect.DeepEqual(a.passes, b.passes) {
			t.Fatalf("case %d: neutral rules changed the answer:\n%+v\n%+v", index, a, b)
		}
		if a.notices != 0 || b.notices != 1 {
			t.Fatalf("case %d: notices %d / %d", index, a.notices, b.notices)
		}
		// The hop that selects the notice and the lead (and any hop whose
		// family fallback holds them) runs under another engine contract.
		if a.contract[0] == b.contract[0] {
			t.Fatalf("case %d: contracts %v / %v", index, a.contract, b.contract)
		}
	}
}
