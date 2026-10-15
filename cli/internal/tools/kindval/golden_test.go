// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateGoldens = flag.Bool("update", false, "rewrite the kindval goldens under testdata/")

// goldenV1Claims mixes every claim kind: served-API claims on two lines, a
// removal hop, the fixture CRD pair and an addon rule.
func goldenV1Claims() Claims {
	claims := []Claim{
		servedAPIClaim("1.32", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ExpectNotServed, "t"),
		servedAPIClaim("1.31", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ExpectServed, "t"),
		servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectNotServed, "t"),
		servedAPIClaim("1.40", "apps", "v1", "Deployment", ExpectServed, "t"),
		removalClaim("removal.blocked", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ""),
		removalClaim("removal.passed", "h.example", "v1beta1", "K", ""),
		{ID: "addon", Kind: KindAddonRule, Subject: Subject{Project: "x", RuleID: "x.y"}},
	}
	claims = append(claims, gadgetClaims(true).Claims...)
	return Claims{Schema: ClaimsSchema, Claims: claims}
}

// goldenRuns are the runs the golden claims are decided on.
func goldenRuns(t *testing.T, claims Claims) Runs {
	t.Helper()
	fs := "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema"
	snapshots := map[string]Snapshot{
		"1.31": {Line: "1.31", ServerVersion: "v1.31.14", Image: "kindest/node:v1.31.14@sha256:prev", Served: []string{"apps/v1 Deployment", fs, "h.example/v1beta1 K", "v1 ConfigMap"}},
		"1.32": {Line: "1.32", ServerVersion: "v1.32.11", Image: "kindest/node:v1.32.11@sha256:next", Served: []string{"apps/v1 Deployment", "v1 ConfigMap"}},
	}
	prev := VerdictRun{Line: "1.31", Cases: []VerdictCase{
		{ID: caseID(fs), API: fs, Server: ServerTry{Outcome: ServerAccepted}},
		{ID: caseID("h.example/v1beta1 K"), API: "h.example/v1beta1 K", Server: ServerTry{Outcome: ServerAccepted}},
	}}
	next := VerdictRun{Line: "1.32", FromVersion: "1.31.14", ToVersion: "1.32.11", Cases: []VerdictCase{
		{ID: caseID(fs), API: fs, Server: ServerTry{Outcome: ServerNotServed}, Scan: scanTry(exitBlocked, "BLOCKED", nil, gapNotServed)},
		{ID: caseID("h.example/v1beta1 K"), API: "h.example/v1beta1 K", Server: ServerTry{Outcome: ServerNotServed}, Scan: scanTry(exitPass, "PASS", nil)},
	}}
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	var pairs []CRDPairResult
	for _, p := range claims.Pairs() {
		pairs = append(pairs, runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fixtureFetcher(false), p))
	}
	return Runs{Snapshots: snapshots, Verdicts: map[string]VerdictRun{"1.31": prev, "1.32": next}, CRD: []CRDRun{{Schema: CRDRunSchema, Line: "1.32", Image: "kindest/node:v1.32.11@sha256:next", Pairs: pairs}}}
}

// checkGolden compares got with testdata/name, or rewrites it with -update.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGoldens {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs from the golden (go test -run %s -update to rewrite):\n%s", path, t.Name(), got)
	}
}

func marshalResults(t *testing.T, res Results) []byte {
	t.Helper()
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// A v1 claims file gives exactly the v1 results it always gave.
func TestGoldenV1ResultsAreUnchanged(t *testing.T) {
	claims := goldenV1Claims()
	if err := claims.Validate(); err != nil {
		t.Fatal(err)
	}
	prov := Provenance{Prufyx: Binary{Commit: "abc", SHA256: "sha256:bin"}, LogDigest: "sha256:log"}
	res := evalObserved(claims, goldenRuns(t, claims), prov, time.Unix(0, 0))
	checkGolden(t, "results-v1.golden.json", marshalResults(t, res))
	checkGolden(t, "summary-v1.golden.md", []byte(Summary(res)))
}
