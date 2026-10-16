// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// v2Claims is a v2 claims file of the given lines: the claims plus the
// reviewed controls of their kinds.
func v2Claims(t *testing.T, lines []string, claims ...Claim) Claims {
	t.Helper()
	c := Claims{Schema: ClaimsSchemaV2, Lines: lines, Claims: append([]Claim(nil), claims...)}
	c.Claims = append(c.Claims, ExpandControls(mustControls(), lines, claimKinds(claims))...)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

const (
	apiDeploy = "apps/v1 Deployment"
	apiDS     = "apps/v1 DaemonSet"
	apiFS     = "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema"
	apiPLC    = "flowcontrol.apiserver.k8s.io/v1beta3 PriorityLevelConfiguration"
)

// lineImage is a pinned node image of a line.
func lineImage(line string) string {
	return "kindest/node:v" + line + ".0@sha256:" + strings.Repeat(fmt.Sprint(len(line)%10), 63) + line[len(line)-1:]
}

func lineSnapshot(line string, served ...string) Snapshot {
	img := lineImage(line)
	return Snapshot{Line: line, ServerVersion: "v" + line + ".0", Image: img, ObservedImageDigests: []string{"registry.example/node@" + imageDigest(img)}, Served: served}
}

// k8sRuns are runs on which every Kubernetes control of 1.31 and 1.32 comes
// out as expected: apps/v1 served on both, flow-control v1beta3 served by
// 1.31 only, the removal hop blocked by the scan.
func k8sRuns() Runs {
	accepted := func(api string) VerdictCase {
		return VerdictCase{ID: caseID(api), API: api, Server: ServerTry{Outcome: ServerAccepted}}
	}
	removed := func(api string) VerdictCase {
		return VerdictCase{ID: caseID(api), API: api, Server: ServerTry{Outcome: ServerNotServed}, Scan: scanTry(exitBlocked, "BLOCKED", nil, gapNotServed)}
	}
	kept := func(api string) VerdictCase {
		c := accepted(api)
		c.Scan = scanTry(exitPass, "PASS", nil)
		return c
	}
	return Runs{
		Snapshots: map[string]Snapshot{
			"1.31": lineSnapshot("1.31", apiDeploy, apiDS, apiFS, apiPLC),
			"1.32": lineSnapshot("1.32", apiDeploy, apiDS),
		},
		Verdicts: map[string]VerdictRun{
			"1.31": {Line: "1.31", Cases: []VerdictCase{accepted(apiDeploy), accepted(apiDS), accepted(apiFS), accepted(apiPLC)}},
			"1.32": {Line: "1.32", Cases: []VerdictCase{kept(apiDeploy), kept(apiDS), removed(apiFS), removed(apiPLC)}},
		},
	}
}

// k8sPlainClaims: two confirmed served-API claims, one refuted, a confirmed
// removal and an addon rule.
func k8sPlainClaims() []Claim {
	return []Claim{
		servedAPIClaim("1.32", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ExpectNotServed, "t"),
		servedAPIClaim("1.31", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ExpectServed, "t"),
		servedAPIClaim("1.32", "apps", "v1", "DaemonSet", ExpectNotServed, "t"),
		removalClaim("removal.blocked", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ""),
		{ID: "addon", Kind: KindAddonRule, Subject: Subject{Project: "x", RuleID: "x.y"}},
	}
}

func controlsByID(res Results) map[string]ControlResult {
	out := map[string]ControlResult{}
	for _, c := range res.Controls {
		out[c.ID] = c
	}
	return out
}

func summaryOf(res Results, kind, line string) (ControlSummary, bool) {
	for _, s := range res.Totals.Controls {
		if s.Kind == kind && s.Line == line {
			return s, true
		}
	}
	return ControlSummary{}, false
}

// checkReasons requires a reason of the closed list on every result that is
// not confirmed, none on a confirmed one, and the verdict of the outcome.
func checkReasons(t *testing.T, name string, res Results) {
	t.Helper()
	known := map[string]bool{}
	for _, r := range Reasons {
		known[r] = true
	}
	verdict := map[string]string{OutcomeConfirmed: VerdictConfirmed, OutcomeRefuted: VerdictRefuted, OutcomeError: VerdictError, OutcomeUndetermined: VerdictUndetermined}
	check := func(id, outcome, reason string) {
		if outcome == OutcomeConfirmed && reason != "" {
			t.Errorf("%s: %s is confirmed with reason %q", name, id, reason)
		}
		if outcome != OutcomeConfirmed && !known[reason] {
			t.Errorf("%s: %s is %s with reason %q, not one of the list", name, id, outcome, reason)
		}
	}
	for _, c := range res.Claims {
		check(c.ID, c.Outcome, c.Reason)
		if c.Verdict != verdict[c.Outcome] {
			t.Errorf("%s: %s outcome %s verdict %q", name, c.ID, c.Outcome, c.Verdict)
		}
	}
	for _, c := range res.Controls {
		check(c.ID, c.Outcome, c.Reason)
	}
}

func hasFinding(res Results, id string) (Finding, bool) {
	for _, f := range res.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

var lines3132 = []string{"1.31", "1.32"}

func TestV2AllControlsPass(t *testing.T) {
	plain := k8sPlainClaims()
	claims := v2Claims(t, lines3132, plain...)
	res := Evaluate(claims, k8sRuns(), Provenance{}, time.Unix(0, 0))
	checkReasons(t, "all pass", res)
	if res.Schema != ResultsSchemaV2 || len(res.Claims) != len(plain) {
		t.Fatalf("schema %s, %d claims", res.Schema, len(res.Claims))
	}
	for _, c := range res.Claims {
		if strings.HasPrefix(c.ID, "control.") {
			t.Fatalf("control in claims: %s", c.ID)
		}
	}
	if len(res.Controls) != len(claims.Claims)-len(plain) {
		t.Fatalf("%d controls", len(res.Controls))
	}
	for i, c := range res.Controls {
		if !c.OK {
			t.Errorf("control %s: %s (%s)", c.ID, c.Outcome, c.Detail)
		}
		if i > 0 && res.Controls[i-1].ID >= c.ID {
			t.Errorf("controls not sorted at %s", c.ID)
		}
	}
	got := outcomes(res)
	want := map[string]string{
		"k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served": OutcomeConfirmed,
		"k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served":     OutcomeConfirmed,
		"k8s.1.32.apps_v1_DaemonSet.not_served":                               OutcomeRefuted,
		"removal.blocked":                                                     OutcomeConfirmed,
		"addon":                                                               OutcomeUndetermined,
	}
	for id, outcome := range want {
		if got[id].Outcome != outcome {
			t.Errorf("%s: %s (%s), want %s", id, got[id].Outcome, got[id].Detail, outcome)
		}
	}
	if got["addon"].Reason != ReasonNotEvaluated {
		t.Errorf("addon %+v", got["addon"])
	}
	tt := res.Totals
	if tt.Claims != 5 || tt.Confirmed != 3 || tt.Refuted != 1 || tt.Undetermined != 1 || tt.Error != 0 {
		t.Fatalf("totals %+v", tt)
	}
	if *tt.Verdicts != (VerdictTotals{ConfirmedByExecution: 3, Refuted: 1, Undetermined: 1}) {
		t.Fatalf("verdicts %+v", *tt.Verdicts)
	}
	wantSummary := []ControlSummary{
		{Kind: KindAddonRule, State: ControlStateAbsent},
		{Kind: KindK8sRemoval, Line: "1.32", State: ControlStateOK, True: 2, False: 2},
		{Kind: KindServedAPI, Line: "1.31", State: ControlStateOK, True: 2, False: 2},
		{Kind: KindServedAPI, Line: "1.32", State: ControlStateOK, True: 3, False: 3},
	}
	if fmt.Sprint(tt.Controls) != fmt.Sprint(wantSummary) {
		t.Fatalf("controls summary %+v", tt.Controls)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "canary-failed") || strings.HasPrefix(f.ID, "control.") {
			t.Fatalf("finding %+v", f)
		}
	}
	if tt.Medium != 1 || tt.High != 0 {
		t.Fatalf("findings %+v", res.Findings)
	}
	if s := Summary(res); !strings.Contains(s, "## Controls") || !strings.Contains(s, "- k8s-served-api 1.32: ok (3 true, 3 false)") || !strings.Contains(s, "- addon-rule (all lines): absent") {
		t.Fatalf("summary:\n%s", s)
	}
}

// A v1 file gets no v2 member.
func TestV1HasNoV2Members(t *testing.T) {
	res := Evaluate(Claims{Schema: ClaimsSchema, Claims: k8sPlainClaims()}, k8sRuns(), Provenance{}, time.Unix(0, 0))
	if res.Schema != ResultsSchema || res.Controls != nil || res.Totals.Verdicts != nil || res.Totals.Controls != nil {
		t.Fatalf("v1 results %+v", res)
	}
	for _, c := range res.Claims {
		if c.Reason != "" || c.Verdict != "" {
			t.Fatalf("v1 claim %+v", c)
		}
	}
	if strings.Contains(Summary(res), "## Controls") {
		t.Fatal("v1 summary has controls")
	}
}

// A line that does not serve apps/v1 Deployment fails its controls: every
// served-API claim of that line is void, the other lines and kinds are not.
func TestV2FailedControlVoidsItsGroup(t *testing.T) {
	claims := v2Claims(t, lines3132, k8sPlainClaims()...)
	runs := k8sRuns()
	runs.Snapshots["1.32"] = lineSnapshot("1.32", apiDS)
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "failed", res)
	got := outcomes(res)
	for _, id := range []string{"k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served", "k8s.1.32.apps_v1_DaemonSet.not_served"} {
		c := got[id]
		if c.Outcome != OutcomeError || c.Reason != ReasonCanaryFailed || !strings.HasPrefix(c.Detail, "canary failed: control.served.apps_v1_Deployment.not_served.1.32 (expected refuted, got confirmed), control.served.apps_v1_Deployment.served.1.32 (expected confirmed, got refuted); was: ") {
			t.Errorf("%s: %+v", id, c)
		}
	}
	if got["k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served"].Outcome != OutcomeConfirmed {
		t.Fatalf("other groups: %+v", got)
	}
	// The removal 1.31 -> 1.32 reads the served APIs of 1.32: void too.
	if c := got["removal.blocked"]; c.Reason != ReasonCanaryFailed || !strings.HasPrefix(c.Detail, "canary failed: control.served.apps_v1_Deployment.not_served.1.32 ") {
		t.Fatalf("removal %+v", c)
	}
	if s, _ := summaryOf(res, KindK8sRemoval, "1.32"); s.State != ControlStateOK {
		t.Fatalf("removal summary %+v", s)
	}
	if res.Totals.Refuted != 0 || res.Totals.Error != 3 || res.Totals.Verdicts.Error != 3 {
		t.Fatalf("totals %+v", res.Totals)
	}
	s, _ := summaryOf(res, KindServedAPI, "1.32")
	if s.State != ControlStateFailed || strings.Join(s.Failed, ",") != "control.served.apps_v1_Deployment.not_served.1.32,control.served.apps_v1_Deployment.served.1.32" {
		t.Fatalf("summary %+v", s)
	}
	if s, _ := summaryOf(res, KindServedAPI, "1.31"); s.State != ControlStateOK {
		t.Fatalf("1.31 summary %+v", s)
	}
	f, ok := hasFinding(res, "canary-failed/"+KindServedAPI+"/1.32")
	if !ok || f.Severity != SeverityHigh || !strings.Contains(f.Message, "control.served.apps_v1_Deployment.served.1.32 expected confirmed, got refuted (disagreement): not served by v1.32.0") {
		t.Fatalf("finding %+v in %+v", f, res.Findings)
	}
	// The would-be refutation is no evidence: its finding is dropped too.
	if f, ok := hasFinding(res, "k8s.1.32.apps_v1_DaemonSet.not_served"); ok {
		t.Fatalf("finding of a voided claim kept: %+v", f)
	}
	if len(res.Findings) == 0 || res.Findings[0].Severity != SeverityHigh || res.Totals.High != 1 {
		t.Fatalf("findings %+v", res.Findings)
	}
	if !strings.Contains(Summary(res), "- k8s-served-api 1.32: failed (3 true, 3 false); failed: control.served.apps_v1_Deployment.not_served.1.32, control.served.apps_v1_Deployment.served.1.32") {
		t.Fatalf("summary:\n%s", Summary(res))
	}
}

// A control that cannot be decided (no snapshot of its line) voids its
// group.
func TestV2UndeterminedControlVoids(t *testing.T) {
	plain := append(k8sPlainClaims(), servedAPIClaim("1.33", "apps", "v1", "Deployment", ExpectServed, "t"))
	claims := v2Claims(t, []string{"1.31", "1.32", "1.33"}, plain...)
	res := Evaluate(claims, k8sRuns(), Provenance{}, time.Unix(0, 0))
	checkReasons(t, "undetermined", res)
	c := outcomes(res)["k8s.1.33.apps_v1_Deployment.served"]
	if c.Outcome != OutcomeError || c.Reason != ReasonCanaryFailed || !strings.Contains(c.Detail, "(expected confirmed, got undetermined)") || !strings.HasSuffix(c.Detail, "; was: no snapshot of line 1.33") {
		t.Fatalf("claim %+v", c)
	}
	if ctl := controlsByID(res)["control.served.apps_v1_Deployment.served.1.33"]; ctl.OK || ctl.Reason != ReasonNoSnapshot || ctl.Line != "1.33" || ctl.Expected != ControlTrue {
		t.Fatalf("control %+v", ctl)
	}
	// The removal controls of the hop into 1.33 fail too, with no claim.
	if s, _ := summaryOf(res, KindK8sRemoval, "1.33"); s.State != ControlStateFailed || s.False != 2 {
		t.Fatalf("summary %+v", res.Totals.Controls)
	}
	if _, ok := hasFinding(res, "canary-failed/"+KindK8sRemoval+"/1.33"); !ok {
		t.Fatalf("findings %+v", res.Findings)
	}
	if outcomes(res)["removal.blocked"].Outcome != OutcomeConfirmed {
		t.Fatal("the 1.32 removal is not affected")
	}
}

// A decided claim on a line outside the matrix has no control: it is
// undetermined.
func TestV2ClaimWithoutControlsIsUndetermined(t *testing.T) {
	plain := append(k8sPlainClaims(), servedAPIClaim("1.30", "apps", "v1", "Deployment", ExpectServed, "t"), servedAPIClaim("1.29", "apps", "v1", "Deployment", ExpectServed, "t"))
	claims := v2Claims(t, lines3132, plain...)
	runs := k8sRuns()
	runs.Snapshots["1.30"] = lineSnapshot("1.30", apiDeploy)
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "absent", res)
	got := outcomes(res)
	c := got["k8s.1.30.apps_v1_Deployment.served"]
	if c.Outcome != OutcomeUndetermined || c.Reason != ReasonControlsAbsent || c.Detail != "served by v1.30.0; no control of kind k8s-served-api ran on line 1.30" {
		t.Fatalf("claim %+v", c)
	}
	// Already undetermined: keeps its reason.
	if c := got["k8s.1.29.apps_v1_Deployment.served"]; c.Reason != ReasonNoSnapshot {
		t.Fatalf("claim %+v", c)
	}
	for _, line := range []string{"1.29", "1.30"} {
		if s, ok := summaryOf(res, KindServedAPI, line); !ok || s.State != ControlStateAbsent {
			t.Fatalf("summary %+v", res.Totals.Controls)
		}
	}
	if res.Totals.Controls[2].Line != "1.29" || res.Totals.Controls[3].Line != "1.30" {
		t.Fatalf("summary order %+v", res.Totals.Controls)
	}
	if got["addon"].Outcome != OutcomeUndetermined || got["addon"].Reason != ReasonNotEvaluated {
		t.Fatalf("addon %+v", got["addon"])
	}
}

// A node image that is not proven voids the line's controls; the claim's
// detail keeps the image problem after "was:".
func TestV2ImageMismatchInAVoidGroup(t *testing.T) {
	claims := v2Claims(t, lines3132, k8sPlainClaims()...)
	runs := k8sRuns()
	s := runs.Snapshots["1.32"]
	s.ObservedImageDigests = []string{"kindest/node@sha256:" + strings.Repeat("f", 64)}
	runs.Snapshots["1.32"] = s
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "image", res)
	c := outcomes(res)["k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served"]
	if c.Outcome != OutcomeError || c.Reason != ReasonCanaryFailed || !strings.Contains(c.Detail, "; was: not served by v1.32.0; observed node image digest") {
		t.Fatalf("claim %+v", c)
	}
	if ctl := controlsByID(res)["control.served.apps_v1_Deployment.served.1.32"]; ctl.OK || ctl.Reason != ReasonImageDigestMismatch {
		t.Fatalf("control %+v", ctl)
	}
	if outcomes(res)["k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served"].Outcome != OutcomeConfirmed {
		t.Fatal("1.31 is not affected")
	}
}

// snapshotterTags are the external-snapshotter releases the controls cite.
var snapshotterTags = map[string]string{
	"6fc14b4f219ab9ce11b9f9124751e33f98c2afaa": "v4.2.1",
	"9f6fc893a6ed5c93c06cc6365d2eec9d5a5d3c48": "v5.0.1",
	"83d0e0914f696b6f686f568ce0c2e99d1cbe3269": "v6.0.0",
	"e746d0717a32109d8c57cb76a70b299ec849f54d": "v6.0.1",
}

// snapshotterCRD mirrors the upstream versions: v4.2.1 and v5.0.1 serve v1
// (storage) and v1beta1; v6.0.0 declares only v1; v6.0.1 declares v1
// (storage) and v1beta1 served: false.
func snapshotterCRD(tag, path string) []byte {
	plural, kind, scope := "volumesnapshots", "VolumeSnapshot", "Namespaced"
	if strings.HasSuffix(path, "volumesnapshotclasses.yaml") {
		plural, kind, scope = "volumesnapshotclasses", "VolumeSnapshotClass", "Cluster"
	}
	versions := "  - {name: v1, served: true, storage: true}\n"
	switch tag {
	case "v4.2.1", "v5.0.1":
		versions += "  - {name: v1beta1, served: true, storage: false}\n"
	case "v6.0.1":
		versions += "  - {name: v1beta1, served: false, storage: false}\n"
	}
	return []byte(fmt.Sprintf("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: %s.snapshot.storage.k8s.io\nspec:\n  group: snapshot.storage.k8s.io\n  scope: %s\n  names:\n    kind: %s\n    plural: %s\n  versions:\n%s", plural, scope, kind, plural, versions))
}

func snapshotterFetcher(ctx context.Context, repo, commit, path string) ([]byte, error) {
	if tag, ok := snapshotterTags[commit]; ok {
		return snapshotterCRD(tag, path), nil
	}
	return fixtureFetcher(false)(ctx, repo, commit, path)
}

// crdControlRuns runs every pair and single release the claims need on a
// fake cluster.
func crdControlRuns(claims Claims) Runs {
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	k := kube{run: cluster.runner, kubeconfig: "kc"}
	run := CRDRun{Schema: CRDRunSchema, Line: "1.32", Image: "img@sha256:crd"}
	for _, p := range claims.Pairs() {
		run.Pairs = append(run.Pairs, runPair(context.Background(), k, snapshotterFetcher, p))
	}
	for _, s := range claims.Singles() {
		run.Releases = append(run.Releases, runSingle(context.Background(), k, snapshotterFetcher, s))
	}
	return Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{}, CRD: []CRDRun{run}}
}

// The custom-resource controls pass on releases that match upstream; a
// failed control pair voids its kind only.
func TestV2CRDControls(t *testing.T) {
	quiet := gadgetClaims(false).Claims
	plain := append(gadgetClaims(true).Claims, quiet[len(quiet)-1])
	claims := v2Claims(t, lines3132, plain...)
	runs := crdControlRuns(claims)
	res := evalObserved(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "crd pass", res)
	for _, c := range res.Controls {
		if !c.OK {
			t.Errorf("control %s: %s (%s)", c.ID, c.Outcome, c.Detail)
		}
	}
	got := outcomes(res)
	if got["removal"].Outcome != OutcomeConfirmed || got["to.v1"].Outcome != OutcomeConfirmed || got["quiet"].Outcome != OutcomeRefuted {
		t.Fatalf("claims %+v", res.Claims)
	}
	for _, kind := range []string{KindCRDVersion, KindCRDRemoval, KindCRDPair} {
		if s, _ := summaryOf(res, kind, ""); s.State != ControlStateOK {
			t.Fatalf("summary %+v", res.Totals.Controls)
		}
	}
	// The controls' own findings (missed removals of their pairs) are not
	// reported.
	for _, f := range res.Findings {
		if strings.Contains(f.ID, "control.") || strings.Contains(f.Message, "snapshot.storage.k8s.io") {
			t.Fatalf("control finding %+v", f)
		}
	}

	// A fetch of the v6.0.0 -> v6.0.1 pair fails: the crd-pair control of
	// that pair is an error, so every crd-pair claim is void.
	for i, p := range runs.CRD[0].Pairs {
		if p.ID == "control.external-snapshotter.v6.0.0-to-v6.0.1" {
			runs.CRD[0].Pairs[i].To.Error = "fetch: connection reset"
		}
	}
	res = evalObserved(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "crd failed", res)
	got = outcomes(res)
	if c := got["quiet"]; c.Outcome != OutcomeError || c.Reason != ReasonCanaryFailed || c.Detail != "canary failed: control.crd-pair.external-snapshotter.v6.0.0-to-v6.0.1 (expected confirmed, got error); was: 1 version(s) served at v9.0.0 still served at v9.1.0; no longer served, named by removal claims: fixture.example/v1beta1/Gadget" {
		t.Fatalf("quiet %+v", c)
	}
	if got["to.v1"].Outcome != OutcomeConfirmed || got["removal"].Outcome != OutcomeConfirmed {
		t.Fatalf("other kinds %+v", res.Claims)
	}
	f, ok := hasFinding(res, "canary-failed/"+KindCRDPair)
	if !ok || f.Severity != SeverityHigh || !strings.Contains(f.Message, "(install-failed): fetch: connection reset") {
		t.Fatalf("finding %+v in %+v", f, res.Findings)
	}
	if s, _ := summaryOf(res, KindCRDPair, ""); s.State != ControlStateFailed || len(s.Failed) != 1 || s.True != 2 || s.False != 2 {
		t.Fatalf("summary %+v", s)
	}
	if s, _ := summaryOf(res, KindCRDRemoval, ""); s.State != ControlStateOK {
		t.Fatalf("summary %+v", s)
	}
}

// A removal hop whose removals no upstream guide documents has false
// removal controls only: the group is incomplete and a confirmed removal
// claim on it is undetermined, not confirmed by execution.
func TestV2OneExpectationGroupIsIncomplete(t *testing.T) {
	const cidr = "networking.k8s.io/v1beta1 ServiceCIDR"
	removal := Claim{ID: "removal.cidr", Kind: KindK8sRemoval, Subject: Subject{From: rawString("1.36"), To: rawString("1.37"), Group: "networking.k8s.io", Version: "v1beta1", Kind: "ServiceCIDR"}}
	served := servedAPIClaim("1.37", "apps", "v1", "Deployment", ExpectServed, "t")
	claims := v2Claims(t, []string{"1.36", "1.37"}, removal, served)
	accepted := func(api string) VerdictCase {
		return VerdictCase{ID: caseID(api), API: api, Server: ServerTry{Outcome: ServerAccepted}}
	}
	keptOn37 := func(api string) VerdictCase {
		c := accepted(api)
		c.Scan = &ScanTry{From: "1.36.0", To: "1.37.0", Exit: exitPass, Verdict: "PASS", Gaps: []string{}, Rules: []string{}}
		return c
	}
	runs := Runs{
		Snapshots: map[string]Snapshot{"1.36": lineSnapshot("1.36", apiDeploy, apiDS, cidr), "1.37": lineSnapshot("1.37", apiDeploy, apiDS)},
		Verdicts: map[string]VerdictRun{
			"1.36": {Line: "1.36", Cases: []VerdictCase{accepted(apiDeploy), accepted(apiDS), accepted(cidr)}},
			"1.37": {Line: "1.37", Cases: []VerdictCase{keptOn37(apiDeploy), keptOn37(apiDS), {ID: caseID(cidr), API: cidr, Server: ServerTry{Outcome: ServerNotServed}, Scan: &ScanTry{From: "1.36.0", To: "1.37.0", Exit: exitBlocked, Verdict: "BLOCKED", Gaps: []string{gapNotServed}, Rules: []string{}}}}},
		},
	}
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "incomplete", res)
	for _, c := range res.Controls {
		if !c.OK {
			t.Fatalf("control %s: %s (%s)", c.ID, c.Outcome, c.Detail)
		}
	}
	got := outcomes(res)
	if c := got["removal.cidr"]; c.Outcome != OutcomeUndetermined || c.Reason != ReasonControlsAbsent || !strings.Contains(c.Detail, "all have one expectation") {
		t.Fatalf("removal %+v", c)
	}
	if s, _ := summaryOf(res, KindK8sRemoval, "1.37"); s.State != ControlStateIncomplete || s.True != 0 || s.False != 2 {
		t.Fatalf("summary %+v", res.Totals.Controls)
	}
	if c := got["k8s.1.37.apps_v1_Deployment.served"]; c.Outcome != OutcomeConfirmed || c.Verdict != VerdictConfirmed {
		t.Fatalf("served %+v", c)
	}
}

// Every finding a voided claim raised goes with it, whatever its id
// (here the ".undefined" finding of a crd-pair claim), and the canary
// finding names what was dropped.
func TestV2VoidDropsAllFindingsOfTheClaim(t *testing.T) {
	quiet := gadgetClaims(false)
	claims := v2Claims(t, lines3132, quiet.Claims...)
	runs := crdControlRuns(claims)
	// The fixture's later release no longer defines the Gadget definition.
	dropping := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		if commit == gadgetFrom.Commit {
			return gadget(true, false), nil
		}
		return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: nothing-here\n"), nil
	}
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	for i, p := range runs.CRD[0].Pairs {
		if p.Project == "fixture" {
			runs.CRD[0].Pairs[i] = runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, dropping, quiet.Pairs()[0])
		}
	}
	res := evalObserved(claims, runs, Provenance{}, time.Unix(0, 0))
	if _, ok := hasFinding(res, "quiet.undefined"); !ok {
		t.Fatalf("the fixture raises no .undefined finding: %+v", res.Findings)
	}
	for i, p := range runs.CRD[0].Pairs {
		if p.ID == "control.external-snapshotter.v6.0.0-to-v6.0.1" {
			runs.CRD[0].Pairs[i].To.Error = "fetch: connection reset"
		}
	}
	res = evalObserved(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "void findings", res)
	if c := outcomes(res)["quiet"]; c.Reason != ReasonCanaryFailed {
		t.Fatalf("quiet %+v", c)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "quiet") {
			t.Fatalf("finding of a voided claim kept: %+v", f)
		}
	}
	if f, ok := hasFinding(res, "canary-failed/"+KindCRDPair); !ok || !strings.Contains(f.Message, "dropped: MEDIUM quiet.undefined") {
		t.Fatalf("canary finding %+v", f)
	}
}

// A removal reads the snapshots and dry runs of both its lines: a failed
// served-API control on the from line voids it, while the removal controls
// of the to line pass. Its findings are listed in the canary finding.
func TestV2RemovalVoidedByServedAPIOfFrom(t *testing.T) {
	plain := append(k8sPlainClaims(), removalClaim("removal.ds", "apps", "v1", "DaemonSet", ""))
	claims := v2Claims(t, lines3132, plain...)
	runs := k8sRuns()
	if _, ok := hasFinding(Evaluate(claims, runs, Provenance{}, time.Unix(0, 0)), "removal.ds"); !ok {
		t.Fatal("the refuted removal raises no finding")
	}
	runs.Snapshots["1.31"] = lineSnapshot("1.31", apiDS, apiFS, apiPLC)
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "removal from", res)
	if s, _ := summaryOf(res, KindK8sRemoval, "1.32"); s.State != ControlStateOK {
		t.Fatalf("removal summary %+v", res.Totals.Controls)
	}
	if s, _ := summaryOf(res, KindServedAPI, "1.31"); s.State != ControlStateFailed {
		t.Fatalf("1.31 summary %+v", res.Totals.Controls)
	}
	got := outcomes(res)
	want := "canary failed: control.served.apps_v1_Deployment.not_served.1.31 (expected refuted, got confirmed), control.served.apps_v1_Deployment.served.1.31 (expected confirmed, got refuted); was: "
	for _, id := range []string{"removal.blocked", "removal.ds"} {
		if c := got[id]; c.Outcome != OutcomeError || c.Verdict != VerdictError || c.Reason != ReasonCanaryFailed || !strings.HasPrefix(c.Detail, want) {
			t.Errorf("%s: %+v", id, c)
		}
	}
	if c := got["k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served"]; c.Outcome != OutcomeConfirmed {
		t.Fatalf("1.32 served-API claim %+v", c)
	}
	if _, ok := hasFinding(res, "removal.ds"); ok {
		t.Fatal("finding of a voided removal kept")
	}
	if _, ok := hasFinding(res, "canary-failed/"+KindK8sRemoval+"/1.32"); ok {
		t.Fatal("canary finding for the passing removal group")
	}
	f, ok := hasFinding(res, "canary-failed/"+KindServedAPI+"/1.31")
	if !ok || !strings.Contains(f.Message, "findings of the voided claims dropped: MEDIUM removal.ds") || !strings.Contains(f.Message, "diff 1.31 -> 1.32") {
		t.Fatalf("canary finding %+v in %+v", f, res.Findings)
	}
	// The refuted 1.32 served-API claim keeps its finding.
	if _, ok := hasFinding(res, "k8s.1.32.apps_v1_DaemonSet.not_served"); !ok || len(res.Diffs) != 0 || res.Totals.High != 1 || res.Totals.Medium != 1 {
		t.Fatalf("diffs %+v, totals %+v", res.Diffs, res.Totals)
	}
}

// A served-API difference reads the snapshots of both its lines: a failed
// served-API group drops it and its findings, listed in the canary finding
// and not counted.
func TestV2FailedServedAPIDropsDiff(t *testing.T) {
	plain := k8sPlainClaims()
	runs := k8sRuns()
	runs.Snapshots["1.32"] = lineSnapshot("1.32", apiDS)
	const diffID = "diff.1.32.apps_v1_Deployment"
	v1 := Evaluate(Claims{Schema: ClaimsSchema, Claims: plain}, runs, Provenance{}, time.Unix(0, 0))
	if f, ok := hasFinding(v1, diffID); !ok || f.Severity != SeverityMedium || len(v1.Diffs) != 1 {
		t.Fatalf("the fixture raises no diff finding: %+v", v1.Findings)
	}
	res := Evaluate(v2Claims(t, lines3132, plain...), runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "diff", res)
	if len(res.Diffs) != 0 || res.Diffs == nil {
		t.Fatalf("diffs %+v", res.Diffs)
	}
	if _, ok := hasFinding(res, diffID); ok {
		t.Fatal("diff finding of a void line kept")
	}
	f, ok := hasFinding(res, "canary-failed/"+KindServedAPI+"/1.32")
	if !ok || !strings.Contains(f.Message, "MEDIUM "+diffID) || !strings.HasSuffix(f.Message, ", diff 1.31 -> 1.32") {
		t.Fatalf("canary finding %+v", f)
	}
	if res.Totals.Medium != 0 || res.Totals.High != 1 || res.Totals.Info != 0 {
		t.Fatalf("totals %+v in %+v", res.Totals, res.Findings)
	}
	if strings.Contains(Summary(res), "Served-API changes") {
		t.Fatalf("summary:\n%s", Summary(res))
	}
}

// The removal controls are decided on the API servers only: a scan that
// passes a removed API refutes the plain claim, not the controls.
func TestV2RemovalControlsIgnoreScan(t *testing.T) {
	claims := v2Claims(t, lines3132, k8sPlainClaims()...)
	runs := k8sRuns()
	cases := runs.Verdicts["1.32"].Cases
	for i := range cases {
		if cases[i].ID == caseID(apiFS) {
			cases[i].Scan = scanTry(exitPass, "PASS", nil)
		}
	}
	res := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	checkReasons(t, "scan", res)
	c := outcomes(res)["removal.blocked"]
	if c.Outcome != OutcomeRefuted || c.Verdict != VerdictRefuted || c.Reason != ReasonDisagreement {
		t.Fatalf("removal %+v", c)
	}
	if f, ok := hasFinding(res, "removal.blocked"); !ok || f.Severity != SeverityHigh {
		t.Fatalf("findings %+v", res.Findings)
	}
	ctl := controlsByID(res)["control.removal.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.1.31-to-1.32"]
	if !ctl.OK || ctl.Outcome != OutcomeConfirmed || ctl.Detail != "both servers agree (controls are decided on the API servers only)" {
		t.Fatalf("control %+v", ctl)
	}
	for _, ctl := range res.Controls {
		if !ctl.OK {
			t.Errorf("control %s: %s (%s)", ctl.ID, ctl.Outcome, ctl.Detail)
		}
	}
	if s, _ := summaryOf(res, KindK8sRemoval, "1.32"); s.State != ControlStateOK {
		t.Fatalf("summary %+v", res.Totals.Controls)
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.ID, "canary-failed") {
			t.Fatalf("finding %+v", f)
		}
	}
}
