// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func claimsByID(claims []APIClaim) map[string]APIClaim {
	out := map[string]APIClaim{}
	for _, c := range claims {
		out[c.ID] = c
	}
	return out
}

// The removal table's 1.32 flow-control removal and the 1.37 removals give
// claims on both sides of their line; nothing is claimed about a removed
// version below the previous line.
func TestKubernetesClaimsFollowTheRemovalTable(t *testing.T) {
	claims := KubernetesClaims([]string{"1.30", "1.31", "1.32", "1.36", "1.37"})
	byID := claimsByID(claims)
	want := map[string]string{
		"k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served":                     ExpectServed,
		"k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served":                 ExpectNotServed,
		"k8s.1.37.flowcontrol.apiserver.k8s.io_v1beta3_PriorityLevelConfiguration.not_served": ExpectNotServed,
		"k8s.1.36.networking.k8s.io_v1beta1_ServiceCIDR.served":                               ExpectServed,
		"k8s.1.37.networking.k8s.io_v1beta1_ServiceCIDR.not_served":                           ExpectNotServed,
		"k8s.1.37.networking.k8s.io_v1_ServiceCIDR.served":                                    ExpectServed,
		"k8s.1.37.storage.k8s.io_v1beta1_VolumeAttributesClass.not_served":                    ExpectNotServed,
		"k8s.1.30.batch_v1beta1_CronJob.not_served":                                           ExpectNotServed,
	}
	for id, expect := range want {
		c, ok := byID[id]
		if !ok || c.Expect != expect {
			t.Errorf("claim %s: got %+v, want expect %s", id, c, expect)
		}
	}
	for _, unwanted := range []string{
		"k8s.1.30.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served",
		"k8s.1.30.networking.k8s.io_v1beta1_ServiceCIDR.served",
		"k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served",
	} {
		if _, ok := byID[unwanted]; ok {
			t.Errorf("claim %s must not exist", unwanted)
		}
	}
	for i := 1; i < len(claims); i++ {
		if claims[i-1].ID == claims[i].ID {
			t.Fatalf("duplicate claim %s", claims[i].ID)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		exit    int
		stderr  string
		outcome string
	}{
		{0, "", OutcomeAccepted},
		{1, `error: resource mapping not found for name: "x" namespace: "" from "STDIN": no matches for kind "FlowSchema" in version "flowcontrol.apiserver.k8s.io/v1beta3"`, OutcomeNotServed},
		{1, "error: the server doesn't have a resource type \"cronjobs\"", OutcomeNotServed},
		{1, `The FlowSchema "x" is invalid: spec.rules: Required value`, OutcomeRejected},
		{-1, "exec: kubectl: not found", OutcomeRejected},
	}
	for _, c := range cases {
		if got := classify(c.exit, c.stderr); got.Outcome != c.outcome {
			t.Errorf("classify(%d, %q) = %s, want %s", c.exit, c.stderr, got.Outcome, c.outcome)
		}
	}
}

// fakeKube answers discovery and dry runs from a served set.
func fakeKube(served map[string][]string, version string) runner {
	return func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
		if name != "kubectl" || len(args) < 3 {
			return nil, []byte("unexpected command"), 1
		}
		rest := args[2:]
		switch {
		case len(rest) == 3 && rest[0] == "get" && rest[1] == "--raw":
			path := rest[2]
			switch path {
			case "/version":
				return []byte(`{"gitVersion":"` + version + `"}`), nil, 0
			case "/api":
				return []byte(`{"versions":["v1"]}`), nil, 0
			case "/apis":
				var groups []map[string]any
				for gv := range served {
					if !strings.Contains(gv, "/") {
						continue
					}
					g := strings.Split(gv, "/")[0]
					groups = append(groups, map[string]any{"name": g, "versions": []map[string]string{{"groupVersion": gv}}})
				}
				out, _ := json.Marshal(map[string]any{"groups": groups})
				return out, nil, 0
			}
			gv := strings.TrimPrefix(strings.TrimPrefix(path, "/apis/"), "/api/")
			kinds, ok := served[gv]
			if !ok {
				return nil, []byte("Error from server (NotFound): the server could not find the requested resource"), 1
			}
			var resources []map[string]string
			for _, k := range kinds {
				resources = append(resources, map[string]string{"name": strings.ToLower(k) + "s", "kind": k})
				resources = append(resources, map[string]string{"name": strings.ToLower(k) + "s/status", "kind": k})
			}
			out, _ := json.Marshal(map[string]any{"groupVersion": gv, "resources": resources})
			return out, nil, 0
		case rest[0] == "create":
			var obj struct {
				APIVersion string `yaml:"apiVersion"`
				Kind       string `yaml:"kind"`
			}
			for _, line := range strings.Split(string(stdin), "\n") {
				if strings.HasPrefix(line, "apiVersion: ") {
					obj.APIVersion = strings.TrimPrefix(line, "apiVersion: ")
				}
				if strings.HasPrefix(line, "kind: ") {
					obj.Kind = strings.TrimPrefix(line, "kind: ")
				}
			}
			for _, k := range served[obj.APIVersion] {
				if k == obj.Kind {
					return nil, nil, 0
				}
			}
			return nil, []byte(fmt.Sprintf(`error: resource mapping not found for name: "x" namespace: "" from "STDIN": no matches for kind %q in version %q`, obj.Kind, obj.APIVersion)), 1
		}
		return nil, []byte("unexpected kubectl " + strings.Join(rest, " ")), 1
	}
}

func TestSnapshotReadsDiscovery(t *testing.T) {
	served := map[string][]string{"v1": {"ConfigMap"}, "apps/v1": {"Deployment"}, "flowcontrol.apiserver.k8s.io/v1": {"FlowSchema"}}
	k := kube{run: fakeKube(served, "v1.33.12"), kubeconfig: "kc"}
	s, err := k.snapshot(context.Background(), "1.33", "img", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"apps/v1 Deployment", "flowcontrol.apiserver.k8s.io/v1 FlowSchema", "v1 ConfigMap"}
	if s.ServerVersion != "v1.33.12" || strings.Join(s.Served, ",") != strings.Join(want, ",") {
		t.Fatalf("snapshot %+v", s)
	}
}

func TestEvaluateAPIClaimsAndDiffs(t *testing.T) {
	claims := Claims{Schema: ClaimsSchema, Kubernetes: []APIClaim{
		{ID: "a", Line: "1.32", API: "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema", Expect: ExpectNotServed},
		{ID: "b", Line: "1.31", API: "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema", Expect: ExpectServed},
		{ID: "c", Line: "1.32", API: "flowcontrol.apiserver.k8s.io/v1 FlowSchema", Expect: ExpectServed},
		{ID: "d", Line: "1.32", API: "apps/v1 Deployment", Expect: ExpectNotServed},
		{ID: "e", Line: "1.40", API: "apps/v1 Deployment", Expect: ExpectServed},
	}}
	runs := Runs{Snapshots: map[string]Snapshot{
		"1.31": {Line: "1.31", ServerVersion: "v1.31.14", Served: []string{"apps/v1 Deployment", "example.io/v1alpha1 Gadget", "flowcontrol.apiserver.k8s.io/v1 FlowSchema", "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema", "widgets.example.io/v1beta1 Widget"}},
		"1.32": {Line: "1.32", ServerVersion: "v1.32.11", Served: []string{"apps/v1 Deployment", "flowcontrol.apiserver.k8s.io/v1 FlowSchema", "new.example.io/v1 Thing"}},
	}}
	res := Evaluate(claims, runs, time.Unix(0, 0))
	status := map[string]string{}
	for _, c := range res.Claims {
		status[c.ID] = c.Status
	}
	if status["a"] != StatusConfirmed || status["b"] != StatusConfirmed || status["c"] != StatusConfirmed || status["d"] != StatusRefuted || status["e"] != StatusUnevaluated {
		t.Fatalf("statuses %v", status)
	}
	if res.Totals.Confirmed != 3 || res.Totals.Refuted != 1 || res.Totals.Unevaluated != 1 {
		t.Fatalf("totals %+v", res.Totals)
	}
	if len(res.Diffs) != 1 {
		t.Fatalf("diffs %+v", res.Diffs)
	}
	d := res.Diffs[0]
	if strings.Join(d.Removed, ",") != "example.io/v1alpha1 Gadget,flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema,widgets.example.io/v1beta1 Widget" {
		t.Fatalf("removed %v", d.Removed)
	}
	// The flow-control removal is in the table; the two others are not, and
	// the alpha one is only informational.
	if strings.Join(d.UnknownRemovals, ",") != "example.io/v1alpha1 Gadget,widgets.example.io/v1beta1 Widget" {
		t.Fatalf("unknown removals %v", d.UnknownRemovals)
	}
	severities := map[string]string{}
	for _, f := range res.Findings {
		severities[f.ID] = f.Severity
	}
	if severities["d"] != SeverityMedium || severities["diff.1.32.example-io_v1alpha1_Gadget"] != SeverityInfo || severities["diff.1.32.widgets-example-io_v1beta1_Widget"] != SeverityMedium {
		t.Fatalf("findings %+v", res.Findings)
	}
}

func scanTry(exit int, verdict string, gaps ...string) *ScanTry {
	return &ScanTry{From: "1.31.14", To: "1.32.11", Exit: exit, Verdict: verdict, Gaps: gaps, Rules: []string{}}
}

func TestEvaluateVerdicts(t *testing.T) {
	prev := VerdictRun{Line: "1.31", Cases: []VerdictCase{
		{ID: "removed", Server: ServerTry{Outcome: OutcomeAccepted}},
		{ID: "old", Server: ServerTry{Outcome: OutcomeNotServed}},
		{ID: "kept", Server: ServerTry{Outcome: OutcomeAccepted}},
		{ID: "undecided", Server: ServerTry{Outcome: OutcomeRejected}},
		{ID: "named", Server: ServerTry{Outcome: OutcomeAccepted}},
		{ID: "falseblock", Server: ServerTry{Outcome: OutcomeAccepted}},
		{ID: "broken", Server: ServerTry{Outcome: OutcomeAccepted}},
	}}
	next := VerdictRun{Line: "1.32", FromVersion: "1.31.14", ToVersion: "1.32.11", Cases: []VerdictCase{
		{ID: "removed", API: "g/v1beta3 K", Server: ServerTry{Outcome: OutcomeNotServed}, Scan: scanTry(exitBlocked, "BLOCKED", gapNotServed)},
		{ID: "old", API: "batch/v1beta1 CronJob", Server: ServerTry{Outcome: OutcomeNotServed}, Scan: scanTry(exitPass, "PASS")},
		{ID: "kept", API: "g/v1 K", Server: ServerTry{Outcome: OutcomeAccepted}, Scan: scanTry(exitUnknown, "UNKNOWN", "LINE_NOT_ATTESTED")},
		{ID: "undecided", API: "g/v1beta2 K", Server: ServerTry{Outcome: OutcomeNotServed}, Scan: scanTry(exitUnknown, "UNKNOWN", "LINE_NOT_ATTESTED")},
		{ID: "named", API: "g/v1beta1 K", Server: ServerTry{Outcome: OutcomeNotServed}, Scan: scanTry(exitUnknown, "UNKNOWN", gapNotServed)},
		{ID: "falseblock", API: "apps/v1 Deployment", Server: ServerTry{Outcome: OutcomeAccepted}, Scan: scanTry(exitBlocked, "BLOCKED")},
		{ID: "broken", API: "x/v1 Y", Server: ServerTry{Outcome: OutcomeAccepted}, Scan: &ScanTry{Exit: 2, Error: "no JSON report"}},
		{ID: "unpaired", API: "z/v1 Z", Server: ServerTry{Outcome: OutcomeAccepted}, Scan: scanTry(exitUnknown, "UNKNOWN")},
	}}
	res := Evaluate(Claims{Schema: ClaimsSchema}, Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{"1.31": prev, "1.32": next}}, time.Unix(0, 0))
	status := map[string]string{}
	for _, v := range res.Verdicts {
		status[v.ID] = v.Status
	}
	want := map[string]string{"removed.1.32": StatusConfirmed, "old.1.32": StatusRefuted, "kept.1.32": StatusConfirmed, "undecided.1.32": StatusRefuted, "named.1.32": StatusConfirmed, "falseblock.1.32": StatusRefuted, "broken.1.32": StatusUnevaluated}
	for id, s := range want {
		if status[id] != s {
			t.Errorf("verdict %s: %s, want %s", id, status[id], s)
		}
	}
	if _, ok := status["unpaired.1.32"]; ok {
		t.Error("a case without the previous line's dry run must not be evaluated")
	}
	severities := map[string]string{}
	for _, f := range res.Findings {
		severities[f.ID] = f.Severity
	}
	if severities["verdict.old.1.32"] != SeverityHigh || severities["verdict.undecided.1.32"] != SeverityMedium || severities["verdict.named.1.32"] != SeverityInfo || severities["verdict.falseblock.1.32"] != SeverityMedium || severities["verdict.broken.1.32"] != SeverityInfo {
		t.Fatalf("findings %+v", res.Findings)
	}
	if res.Totals.VerdictsOK != 3 || res.Totals.VerdictsBad != 3 || res.Totals.High != 1 {
		t.Fatalf("totals %+v", res.Totals)
	}
}

const gadgetCRD = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: gadgets.fixture.example
spec:
  group: fixture.example
  scope: Namespaced
  names:
    kind: Gadget
    plural: gadgets
  versions:
  - name: v1beta1
    served: %s
    storage: false
    schema: {openAPIV3Schema: {type: object}}
  - name: v1
    served: true
    storage: true
    schema: {openAPIV3Schema: {type: object}}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: not-a-crd
`

func TestCRDDocumentsKeepOnlyDefinitions(t *testing.T) {
	docs, defs, err := crdDocuments([]byte(fmt.Sprintf(gadgetCRD, "true")))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || len(defs) != 1 || defs[0].Name != "gadgets.fixture.example" || defs[0].Kind != "Gadget" || len(defs[0].Versions) != 2 || !defs[0].Versions[0].Served || !defs[0].Versions[1].Storage {
		t.Fatalf("docs %d defs %+v", len(docs), defs)
	}
}

// fakeCluster is a cluster that holds CRDs applied to it and serves their
// served versions.
type fakeCluster struct {
	crds map[string]CRDDef
}

func (f *fakeCluster) runner(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
	rest := args[2:]
	switch rest[0] {
	case "apply":
		_, defs, err := crdDocuments(stdin)
		if err != nil {
			return nil, []byte(err.Error()), 1
		}
		for _, d := range defs {
			if old, ok := f.crds[d.Name]; ok {
				for _, v := range old.Versions {
					if v.Storage && !hasVersion(d, v.Name) {
						return nil, []byte(fmt.Sprintf("The CustomResourceDefinition %q is invalid: status.storedVersions[0]: Invalid value: %q: must appear in spec.versions", d.Name, v.Name)), 1
					}
				}
			}
			f.crds[d.Name] = d
		}
		return nil, nil, 0
	case "wait":
		return nil, nil, 0
	case "delete":
		for _, name := range rest[5:] {
			delete(f.crds, name)
		}
		return nil, nil, 0
	case "get":
		var items []map[string]any
		for _, name := range rest[4:] {
			d, ok := f.crds[name]
			if !ok {
				return nil, []byte("Error from server (NotFound): customresourcedefinitions.apiextensions.k8s.io " + name + " not found"), 1
			}
			var versions []map[string]any
			for _, v := range d.Versions {
				versions = append(versions, map[string]any{"name": v.Name, "served": v.Served, "storage": v.Storage})
			}
			items = append(items, map[string]any{"kind": "CustomResourceDefinition", "metadata": map[string]any{"name": d.Name}, "spec": map[string]any{"group": d.Group, "scope": d.Scope, "names": map[string]any{"kind": d.Kind}, "versions": versions}})
		}
		out, _ := json.Marshal(map[string]any{"kind": "List", "items": items})
		return out, nil, 0
	case "create":
		var apiVersion, kind string
		for _, line := range strings.Split(string(stdin), "\n") {
			if strings.HasPrefix(line, "apiVersion: ") {
				apiVersion = strings.TrimPrefix(line, "apiVersion: ")
			}
			if strings.HasPrefix(line, "kind: ") {
				kind = strings.TrimPrefix(line, "kind: ")
			}
		}
		for _, d := range f.crds {
			for _, v := range d.Versions {
				if v.Served && d.Group+"/"+v.Name == apiVersion && d.Kind == kind {
					return nil, nil, 0
				}
			}
		}
		return nil, []byte(fmt.Sprintf(`error: resource mapping not found for name: "x" namespace: "" from "STDIN": no matches for kind %q in version %q`, kind, apiVersion)), 1
	}
	return nil, []byte("unexpected kubectl " + strings.Join(rest, " ")), 1
}

func hasVersion(d CRDDef, name string) bool {
	for _, v := range d.Versions {
		if v.Name == name {
			return true
		}
	}
	return false
}

func gadgetPair() CRDPair {
	from := CRDRelease{Tag: "v9.0.0", Commit: strings.Repeat("a", 40), Files: []string{"crds/gadgets.yaml"}, CRDs: []CRDDef{{Name: "gadgets.fixture.example", Group: "fixture.example", Kind: "Gadget", Scope: "Namespaced", Versions: []CRDVersion{{Name: "v1beta1", Served: true}, {Name: "v1", Served: true, Storage: true}}}}}
	to := CRDRelease{Tag: "v9.1.0", Commit: strings.Repeat("b", 40), Files: []string{"crds/gadgets.yaml"}, CRDs: []CRDDef{{Name: "gadgets.fixture.example", Group: "fixture.example", Kind: "Gadget", Scope: "Namespaced", Versions: []CRDVersion{{Name: "v1beta1"}, {Name: "v1", Served: true, Storage: true}}}}}
	return CRDPair{ID: "fixture.9.0.0-to-9.1.0", Project: "fixture", Repo: "github.com/fixture/fixture", From: from, To: to}
}

func fixtureFetcher(ctx context.Context, repo, commit, path string) ([]byte, error) {
	switch commit {
	case strings.Repeat("a", 40):
		return []byte(fmt.Sprintf(gadgetCRD, "true")), nil
	case strings.Repeat("b", 40):
		return []byte(fmt.Sprintf(gadgetCRD, "false")), nil
	}
	return nil, fmt.Errorf("unknown commit %s", commit)
}

func TestRunPairAndEvaluateCRDs(t *testing.T) {
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	k := kube{run: cluster.runner, kubeconfig: "kc"}
	pair := gadgetPair()
	result := runPair(context.Background(), k, fixtureFetcher, pair)
	if result.Error != "" || result.From.Error != "" || result.To.Error != "" {
		t.Fatalf("result %+v", result)
	}
	if !result.InPlace.Attempted || !result.InPlace.Succeeded {
		t.Fatalf("in place %+v", result.InPlace)
	}
	if len(cluster.crds) != 0 {
		t.Fatalf("the pair's CRDs were not removed: %v", cluster.crds)
	}
	if got := removedMembers(pair); strings.Join(got, ",") != "fixture.example/v1beta1/Gadget" {
		t.Fatalf("removed %v", got)
	}
	claims := Claims{Schema: ClaimsSchema, CustomResources: []CRDPair{pair}}
	res := Evaluate(claims, Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{}, CRD: []CRDRun{{Schema: CRDRunSchema, Line: "1.37", Pairs: []CRDPairResult{result}}}}, time.Unix(0, 0))
	if res.Totals.Refuted != 0 || res.Totals.Unevaluated != 0 || res.Totals.Confirmed != 4 {
		t.Fatalf("totals %+v claims %+v", res.Totals, res.Claims)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings %+v", res.Findings)
	}

	// The knowledge says v1beta1 is removed, but the To release still
	// serves it: a HIGH finding.
	stillServed := pair
	stillServed.To.Tag = "v9.1.1"
	stillServed.To.Commit = strings.Repeat("a", 40)
	cluster = &fakeCluster{crds: map[string]CRDDef{}}
	k = kube{run: cluster.runner, kubeconfig: "kc"}
	result = runPair(context.Background(), k, fixtureFetcher, stillServed)
	res = Evaluate(Claims{Schema: ClaimsSchema, CustomResources: []CRDPair{stillServed}}, Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{}, CRD: []CRDRun{{Line: "1.37", Pairs: []CRDPairResult{result}}}}, time.Unix(0, 0))
	if res.Totals.High != 1 || res.Totals.Refuted != 2 {
		t.Fatalf("still served: totals %+v findings %+v", res.Totals, res.Findings)
	}
}

func TestRunPairRecordsRefusedInPlaceUpgrade(t *testing.T) {
	pair := gadgetPair()
	// The From release stores v1beta1; the To release drops it.
	pair.From.CRDs[0].Versions = []CRDVersion{{Name: "v1beta1", Served: true, Storage: true}, {Name: "v1", Served: true}}
	pair.To.CRDs[0].Versions = []CRDVersion{{Name: "v1", Served: true, Storage: true}}
	fetch := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		if commit == pair.From.Commit {
			return []byte(strings.Replace(strings.Replace(fmt.Sprintf(gadgetCRD, "true"), "storage: false", "storage: true", 1), "served: true\n    storage: true\n    schema: {openAPIV3Schema: {type: object}}\n---", "served: true\n    storage: false\n    schema: {openAPIV3Schema: {type: object}}\n---", 1)), nil
		}
		return []byte(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: gadgets.fixture.example
spec:
  group: fixture.example
  scope: Namespaced
  names:
    kind: Gadget
    plural: gadgets
  versions:
  - name: v1
    served: true
    storage: true
    schema: {openAPIV3Schema: {type: object}}
`), nil
	}
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	result := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, pair)
	if result.Error != "" || result.To.Error != "" {
		t.Fatalf("result %+v", result)
	}
	if !result.InPlace.Attempted || result.InPlace.Succeeded || !strings.Contains(result.InPlace.Message, "storedVersions") {
		t.Fatalf("in place %+v", result.InPlace)
	}
	res := Evaluate(Claims{Schema: ClaimsSchema, CustomResources: []CRDPair{pair}}, Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{}, CRD: []CRDRun{{Line: "1.37", Pairs: []CRDPairResult{result}}}}, time.Unix(0, 0))
	if res.Totals.Refuted != 0 || res.Totals.Info != 1 || !strings.Contains(res.Findings[0].Message, "refused") {
		t.Fatalf("totals %+v findings %+v", res.Totals, res.Findings)
	}
}

func TestCorpusHasRemovalsAndControls(t *testing.T) {
	cases := corpus("1.30")
	ids := map[string]corpusCase{}
	for _, c := range cases {
		ids[c.ID] = c
	}
	removed, ok := ids["flowcontrol-apiserver-k8s-io_v1beta3_FlowSchema"]
	if !ok || removed.Removal != "1.32" || !strings.Contains(removed.Manifest, "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3") {
		t.Fatalf("flow-control case %+v", removed)
	}
	if c, ok := ids["apps_v1_Deployment"]; !ok || c.Removal != "" || !strings.Contains(c.Manifest, "namespace: default") {
		t.Fatalf("control case %+v", c)
	}
	if _, ok := ids["rbac-authorization-k8s-io_v1beta1_Role"]; ok {
		t.Fatal("a removal far below the matrix with no body must not be in the corpus")
	}
	if _, ok := ids["batch_v1beta1_CronJob"]; !ok {
		t.Fatal("a removal below the matrix with a body is a probe")
	}
}

func TestCommandsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	crd := filepath.Join(dir, "crd.json")
	data, _ := json.Marshal(Claims{Schema: ClaimsSchema, Kubernetes: []APIClaim{}, CustomResources: []CRDPair{gadgetPair()}})
	if err := os.WriteFile(crd, data, 0o600); err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(dir, "claims.json")
	if code := run([]string{"claims", "--lines", "1.31,1.32", "--crd", crd, "--out", claims}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("claims exit %d", code)
	}
	var c Claims
	if err := readJSON(claims, &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != ClaimsSchema || len(c.Kubernetes) == 0 || len(c.CustomResources) != 1 {
		t.Fatalf("claims %+v", c)
	}
	runs := filepath.Join(dir, "runs")
	if err := os.Mkdir(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(runs, "snapshot-1.32.json"), Snapshot{Schema: SnapshotSchema, Line: "1.32", ServerVersion: "v1.32.11", Served: []string{"flowcontrol.apiserver.k8s.io/v1 FlowSchema"}}); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	results := filepath.Join(dir, "results.json")
	if code := run([]string{"evaluate", "--claims", claims, "--runs", runs, "--out", results, "--summary", filepath.Join(dir, "summary.md")}, &out, os.Stderr); code != 0 {
		t.Fatalf("evaluate exit %d", code)
	}
	var res Results
	if err := readJSON(results, &res); err != nil {
		t.Fatal(err)
	}
	if res.Schema != ResultsSchema || res.Totals.Claims == 0 || !strings.Contains(out.String(), "| 1.32 | v1.32.11 |") {
		t.Fatalf("results %+v\n%s", res.Totals, out.String())
	}
	if code := run([]string{"evaluate", "--claims", crd, "--runs", runs, "--out", results}, &out, os.Stderr); code != 0 {
		t.Fatalf("evaluate with only pairs: exit %d", code)
	}
	if code := run([]string{"bogus"}, &out, &out); code != 1 {
		t.Fatalf("bogus exit %d", code)
	}
}
