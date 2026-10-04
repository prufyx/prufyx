// SPDX-License-Identifier: AGPL-3.0-only

package cncfknowledge_test

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
)

// TestExternalKnowledgeAppliesTrustPolicy: the request's trust policy
// reaches the external evaluation, for current checks and historical replay.
func TestExternalKnowledgeAppliesTrustPolicy(t *testing.T) {
	state := makeFixture(t)
	importSecond(t, &state)
	req := request(state, "2", state.manifest.Revisions[1].BundleDigest, state.receipt2.TrustReceiptDigest, []byte(kyvernoInputTrue))
	policy, err := cncfcheck.ParseTrustPolicy("mechanical")
	if err != nil {
		t.Fatal(err)
	}
	req.TrustPolicy = policy
	report, err := cncfknowledge.EvaluateCurrent(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Check.Check.Claims) != 0 || report.Check.TrustPolicy == nil || report.Check.TrustPolicy.ExcludedRules != 1 || cncfknowledge.ClaimExit(report) != 11 {
		t.Fatalf("policy not applied: claims=%+v disclosure=%+v", report.Check.Check.Claims, report.Check.TrustPolicy)
	}
	raw := append(mustMarshalReport(t, report), '\n')
	if _, err := cncfknowledge.ReplayHistorical(req, raw); err != nil {
		t.Fatalf("replay under the same policy: %v", err)
	}
	req.TrustPolicy = cncfcheck.TrustPolicy{}
	if _, err := cncfknowledge.ReplayHistorical(req, raw); err == nil {
		t.Fatal("replay under another policy matched")
	}
}
