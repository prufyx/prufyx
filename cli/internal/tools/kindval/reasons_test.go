// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// reasonOf decides one claim on the runs as Evaluate does, before any v1
// clearing, and returns its result.
func reasonOf(runs Runs, claims []Claim, id string) ClaimResult {
	// The CRD fixtures carry no observed digests: take them as proven.
	crd := append([]CRDRun(nil), runs.CRD...)
	for i := range crd {
		if crd[i].ObservedImageDigests == nil {
			crd[i].ObservedImageDigests = []string{"registry.example/node@" + imageDigest(crd[i].Image)}
		}
	}
	runs.CRD = crd
	ev := newEvaluator(runs, Provenance{}, &Results{}, claims)
	for _, c := range claims {
		if c.ID == id {
			return ev.evaluate(c)
		}
	}
	return ClaimResult{}
}

// Every reason code the fakes can produce, one fixture each, with the
// outcome it goes with.
func TestEveryReasonCode(t *testing.T) {
	served := lineSnapshot("1.32", apiDeploy)
	k8s := Runs{Snapshots: map[string]Snapshot{"1.31": lineSnapshot("1.31", apiDeploy, "g.example/v1beta1 K"), "1.32": served}, Verdicts: map[string]VerdictRun{
		"1.31": {Line: "1.31", Cases: []VerdictCase{
			{ID: caseID("g.example/v1beta1 K"), Server: ServerTry{Outcome: ServerAccepted}},
			{ID: caseID("e.example/v1beta1 K"), Server: ServerTry{Outcome: ServerError, Message: "connection refused"}},
		}},
		"1.32": {Line: "1.32", Cases: []VerdictCase{
			{ID: caseID("g.example/v1beta1 K"), Server: ServerTry{Outcome: ServerNotServed}, Scan: &ScanTry{Exit: 2, Error: "no JSON report"}},
			{ID: caseID("e.example/v1beta1 K"), Server: ServerTry{Outcome: ServerNotServed}, Scan: scanTry(exitBlocked, "BLOCKED", nil, gapNotServed)},
		}},
	}}
	unproven := Runs{Snapshots: map[string]Snapshot{"1.32": {Line: "1.32", ServerVersion: "v1.32.0", Image: served.Image, Served: served.Served}}}
	k8sClaims := []Claim{
		{ID: "addon", Kind: KindAddonRule, Subject: Subject{Project: "x"}},
		servedAPIClaim("1.40", "apps", "v1", "Deployment", ExpectServed, "t"),
		servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectNotServed, "t"),
		servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectServed, "t"),
		removalClaim("nocorpus", "n.example", "v1beta1", "K", ""),
		removalClaim("broken", "g.example", "v1beta1", "K", ""),
		removalClaim("noanswer", "e.example", "v1beta1", "K", ""),
	}

	gadgets := gadgetClaims(true).Claims
	pairID := "fixture.v9.0.0-to-v9.1.0"
	failedPair := crdRuns(CRDPairResult{ID: pairID, Project: "fixture", FromTag: "v9.0.0", ToTag: "v9.1.0", From: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}, Error: "kubectl apply: exit 1"}})
	ie := &InstallError{Phase: "apply", Exit: 1, Lines: []string{"Error from server (Invalid): x"}}
	rejectedPair := crdRuns(CRDPairResult{ID: pairID, Project: "fixture", FromTag: "v9.0.0", ToTag: "v9.1.0", From: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}, Error: "kubectl apply: exit 1", InstallError: ie}})
	stoppedPair := crdRuns(CRDPairResult{ID: pairID, Project: "fixture", FromTag: "v9.0.0", ToTag: "v9.1.0", From: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}}})
	gadgetDef := CRDDef{Name: "gadgets.fixture.example", Group: "fixture.example", Kind: "Gadget", Versions: []CRDVersion{{Name: "v1", Served: true, Storage: true}}}
	installed := CRDReleaseState{Files: []FetchedFile{{Path: "x"}}, CRDs: []CRDDef{gadgetDef}}
	noDef := crdRuns(CRDPairResult{ID: pairID, Project: "fixture", FromTag: "v9.0.0", ToTag: "v9.1.0", From: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}}, To: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}}})
	declared := crdRuns(CRDPairResult{ID: pairID, Project: "fixture", FromTag: "v9.0.0", ToTag: "v9.1.0", From: installed, To: installed})
	singles := singleVersionClaims().Claims
	for name, tc := range map[string]struct {
		runs    Runs
		claims  []Claim
		id      string
		outcome string
		reason  string
	}{
		"not evaluated":         {k8s, k8sClaims, "addon", OutcomeUndetermined, ReasonNotEvaluated},
		"no snapshot":           {k8s, k8sClaims, "k8s.1.40.apps_v1_Deployment.served", OutcomeUndetermined, ReasonNoSnapshot},
		"disagreement":          {k8s, k8sClaims, "k8s.1.32.apps_v1_Deployment.not_served", OutcomeRefuted, ReasonDisagreement},
		"no corpus case":        {k8s, k8sClaims, "nocorpus", OutcomeUndetermined, ReasonNoCorpusCase},
		"scan no report":        {k8s, k8sClaims, "broken", OutcomeError, ReasonScanNoReport},
		"server no answer":      {k8s, k8sClaims, "noanswer", OutcomeError, ReasonServerNoAnswer},
		"image digest mismatch": {unproven, k8sClaims, "k8s.1.32.apps_v1_Deployment.served", OutcomeError, ReasonImageDigestMismatch},
		"no run":                {Runs{}, gadgets, "removal", OutcomeUndetermined, ReasonNoRun},
		"install failed":        {failedPair, gadgets, "removal", OutcomeError, ReasonInstallFailed},
		"install rejected":      {rejectedPair, gadgets, "removal", OutcomeError, ReasonInstallRejected},
		"release not installed": {stoppedPair, gadgets, "to.v1", OutcomeError, ReasonReleaseNotInstalled},
		"not probed":            {declared, gadgets, "removal", OutcomeUndetermined, ReasonNotProbed},
		"crd missing":           {noDef, gadgets, "to.v1", OutcomeRefuted, ReasonCRDMissing},
		"version not declared":  {declared, gadgets, "to.v1beta1", OutcomeRefuted, ReasonVersionNotDeclared},
		"release unavailable":   {singleRuns(CRDReleaseResult{ID: "fixture.v9.1.0", Project: "fixture", Tag: "v9.1.0", Unavailable: "no CustomResourceDefinition"}), singles, "v1", OutcomeUndetermined, ReasonReleaseUnavailable},
	} {
		got := reasonOf(tc.runs, tc.claims, tc.id)
		if got.Outcome != tc.outcome || got.Reason != tc.reason {
			t.Errorf("%s: %s %q (%s), want %s %q", name, got.Outcome, got.Reason, got.Detail, tc.outcome, tc.reason)
		}
	}
	// canary-failed and controls-absent come from the v2 evaluation.
	claims := v2Claims(t, lines3132, append(k8sPlainClaims(), servedAPIClaim("1.30", "apps", "v1", "Deployment", ExpectServed, "t"))...)
	runs := k8sRuns()
	runs.Snapshots["1.30"] = lineSnapshot("1.30", apiDeploy)
	runs.Snapshots["1.32"] = lineSnapshot("1.32", apiDS)
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	got := outcomes(res)
	if c := got["k8s.1.32.apps_v1_DaemonSet.not_served"]; c.Reason != ReasonCanaryFailed || c.Verdict != VerdictError {
		t.Errorf("canary-failed: %+v", c)
	}
	if c := got["k8s.1.30.apps_v1_Deployment.served"]; c.Reason != ReasonControlsAbsent || c.Verdict != VerdictUndetermined {
		t.Errorf("controls-absent: %+v", c)
	}
}

// Every result of every fixture of the suite that is not confirmed carries
// a code of the closed list (the evaluator sets the reason for v1 claims
// too, before Evaluate clears it), and the docs table lists exactly that list.
func TestEveryNonConfirmedResultHasAListedReason(t *testing.T) {
	known := map[string]bool{}
	for _, r := range Reasons {
		known[r] = true
	}
	if len(known) != len(Reasons) {
		t.Fatal("duplicate reason code")
	}
	cases := []struct {
		claims Claims
		runs   Runs
	}{
		{goldenV1Claims(), goldenRuns(t, goldenV1Claims())},
		{gadgetClaims(false), goldenRuns(t, gadgetClaims(false))},
		{singleVersionClaims(), singleRuns(CRDReleaseResult{ID: "fixture.v9.1.0", Project: "fixture", Tag: "v9.1.0", Error: "HTTP 503"})},
		{goldenV1Claims(), Runs{}},
	}
	for i, tc := range cases {
		ev := newEvaluator(tc.runs, Provenance{}, &Results{}, tc.claims.Claims)
		for _, c := range tc.claims.Claims {
			cr := ev.evaluate(c)
			if cr.Outcome == OutcomeConfirmed {
				continue
			}
			if !known[cr.Reason] {
				t.Errorf("case %d: %s is %s with reason %q (%s)", i, cr.ID, cr.Outcome, cr.Reason, cr.Detail)
			}
		}
	}
	// The docs table lists exactly the closed list.
	code := append([]string(nil), Reasons...)
	sort.Strings(code)
	if doc := reasonsInDocs(t); strings.Join(doc, ",") != strings.Join(code, ",") {
		t.Fatalf("docs table %v, code %v", doc, code)
	}
}

// reasonsInDocs reads the reason codes of the table in docs/kind-val.md.
func reasonsInDocs(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "kind-val.md"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	in := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "| `reason` |"):
			in = true
		case in && strings.HasPrefix(line, "| `"):
			out = append(out, strings.Trim(strings.Fields(line)[1], "`"))
		case in && !strings.HasPrefix(line, "| ---"):
			in = false
		}
	}
	sort.Strings(out)
	return out
}
