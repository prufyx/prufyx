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

func claimsByID(claims []Claim) map[string]Claim {
	out := map[string]Claim{}
	for _, c := range claims {
		out[c.ID] = c
	}
	return out
}

func boolPtr(b bool) *bool { return &b }

// The removal table's 1.32 flow-control removal and the 1.37 removals give
// claims on both sides of their line, a removal claim for the hop when both
// lines are in the matrix, and nothing about a removed version below the
// previous line.
func TestKubernetesClaimsFollowTheRemovalTable(t *testing.T) {
	claims := KubernetesClaims([]string{"1.30", "1.31", "1.32", "1.36", "1.37"})
	if err := (Claims{Schema: ClaimsSchema, Claims: claims}).Validate(); err != nil {
		t.Fatal(err)
	}
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
		if !ok || c.Kind != KindServedAPI || c.Expect != expect {
			t.Errorf("claim %s: got %+v, want expect %s", id, c, expect)
		}
	}
	for _, unwanted := range []string{
		"k8s.1.30.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served",
		"k8s.1.30.networking.k8s.io_v1beta1_ServiceCIDR.served",
		"k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served",
		"k8s.1.32-to-1.33.authentication.k8s.io_v1beta1_SelfSubjectReview.removal",
	} {
		if _, ok := byID[unwanted]; ok {
			t.Errorf("claim %s must not exist", unwanted)
		}
	}
	removal, ok := byID["k8s.1.31-to-1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.removal"]
	if !ok || removal.Kind != KindK8sRemoval || string(removal.Subject.From) != `"1.31"` || string(removal.Subject.To) != `"1.32"` || removal.Subject.Kind != "FlowSchema" {
		t.Fatalf("removal claim %+v", removal)
	}
	for i := 1; i < len(claims); i++ {
		if claims[i-1].ID == claims[i].ID {
			t.Fatalf("duplicate claim %s", claims[i].ID)
		}
	}
}

func TestValidateRefusesBadClaims(t *testing.T) {
	rel := CRDRelease{Tag: "v1.0.0", Commit: strings.Repeat("a", 40), Files: []string{"crds.yaml"}}
	other := CRDRelease{Tag: "v1.0.0", Commit: strings.Repeat("b", 40), Files: []string{"crds.yaml"}}
	cases := map[string]Claims{
		"schema":        {Schema: "x"},
		"repeated id":   {Schema: ClaimsSchema, Claims: []Claim{servedAPIClaim("1.30", "", "v1", "Pod", ExpectServed, "t"), servedAPIClaim("1.30", "", "v1", "Pod", ExpectServed, "t")}},
		"unknown kind":  {Schema: ClaimsSchema, Claims: []Claim{{ID: "a", Kind: "bogus"}}},
		"bad expect":    {Schema: ClaimsSchema, Claims: []Claim{{ID: "a", Kind: KindServedAPI, Subject: Subject{Line: "1.30", Version: "v1", Kind: "Pod"}, Expect: "maybe"}}},
		"bad line":      {Schema: ClaimsSchema, Claims: []Claim{{ID: "a", Kind: KindK8sRemoval, Subject: Subject{From: rawString("1.30.1"), To: rawString("1.31"), Version: "v1", Kind: "Pod"}}}},
		"short commit":  {Schema: ClaimsSchema, Claims: []Claim{{ID: "a", Kind: KindCRDPair, Subject: Subject{Project: "p", Repo: "github.com/p/p", From: rawObject(CRDRelease{Tag: "v1", Commit: "abc", Files: []string{"f"}}), To: rawObject(rel)}}}},
		"two commits":   {Schema: ClaimsSchema, Claims: []Claim{{ID: "a", Kind: KindCRDPair, Subject: Subject{Project: "p", Repo: "github.com/p/p", From: rawObject(rel), To: rawObject(other)}}}},
		"version flags": {Schema: ClaimsSchema, Claims: []Claim{{ID: "a", Kind: KindCRDVersion, Subject: Subject{Project: "p", Repo: "github.com/p/p", Release: &rel, CRD: "x.p.io", Group: "p.io", Version: "v1", Kind: "X"}}}},
	}
	for name, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	good := Claims{Schema: ClaimsSchema, Claims: []Claim{
		{ID: "a", Kind: KindCRDVersion, Subject: Subject{Project: "p", Repo: "github.com/p/p", Release: &rel, CRD: "x.p.io", Group: "p.io", Version: "v1", Kind: "X", Served: boolPtr(true), Storage: boolPtr(true)}},
		{ID: "b", Kind: KindAddonRule, Subject: Subject{Project: "p", RuleID: "p.rule"}},
	}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		exit    int
		stderr  string
		outcome string
	}{
		{0, "", ServerAccepted},
		{1, `error: resource mapping not found for name: "x" namespace: "" from "STDIN": no matches for kind "FlowSchema" in version "flowcontrol.apiserver.k8s.io/v1beta3"`, ServerNotServed},
		{1, "error: the server doesn't have a resource type \"cronjobs\"", ServerNotServed},
		{1, `The FlowSchema "x" is invalid: spec.rules: Required value`, ServerRejected},
		{-1, "exec: kubectl: not found", ServerRejected},
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
			apiVersion, kind := manifestIdentity(stdin)
			for _, k := range served[apiVersion] {
				if k == kind {
					return nil, nil, 0
				}
			}
			return nil, []byte(fmt.Sprintf(`error: resource mapping not found for name: "x" namespace: "" from "STDIN": no matches for kind %q in version %q`, kind, apiVersion)), 1
		}
		return nil, []byte("unexpected kubectl " + strings.Join(rest, " ")), 1
	}
}

func manifestIdentity(manifest []byte) (apiVersion, kind string) {
	for _, line := range strings.Split(string(manifest), "\n") {
		if strings.HasPrefix(line, "apiVersion: ") {
			apiVersion = strings.TrimPrefix(line, "apiVersion: ")
		}
		if strings.HasPrefix(line, "kind: ") {
			kind = strings.TrimPrefix(line, "kind: ")
		}
	}
	return apiVersion, kind
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

func outcomes(res Results) map[string]ClaimResult {
	out := map[string]ClaimResult{}
	for _, c := range res.Claims {
		out[c.ID] = c
	}
	return out
}

func severities(res Results) map[string]string {
	out := map[string]string{}
	for _, f := range res.Findings {
		out[f.ID] = f.Severity
	}
	return out
}

func TestEvaluateServedAPIClaimsAndDiffs(t *testing.T) {
	claims := Claims{Schema: ClaimsSchema, Claims: []Claim{
		servedAPIClaim("1.32", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ExpectNotServed, "t"),
		servedAPIClaim("1.31", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", ExpectServed, "t"),
		servedAPIClaim("1.32", "flowcontrol.apiserver.k8s.io", "v1", "FlowSchema", ExpectServed, "t"),
		servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectNotServed, "t"),
		servedAPIClaim("1.40", "apps", "v1", "Deployment", ExpectServed, "t"),
		servedAPIClaim("1.32", "widgets.example.io", "v1beta1", "Widget", ExpectNotServed, "t"),
		{ID: "addon", Kind: KindAddonRule, Subject: Subject{Project: "x", RuleID: "x.y"}},
	}}
	if err := claims.Validate(); err != nil {
		t.Fatal(err)
	}
	image := "kindest/node:v1.32.11@sha256:" + strings.Repeat("c", 64)
	runs := Runs{Snapshots: map[string]Snapshot{
		"1.31": {Line: "1.31", ServerVersion: "v1.31.14", Image: "kindest/node:v1.31.14@sha256:" + strings.Repeat("b", 64), Served: []string{"apps/v1 Deployment", "example.io/v1alpha1 Gadget", "flowcontrol.apiserver.k8s.io/v1 FlowSchema", "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema", "other.example.io/v1beta1 Other", "widgets.example.io/v1beta1 Widget"}},
		"1.32": {Line: "1.32", ServerVersion: "v1.32.11", Image: image, Served: []string{"apps/v1 Deployment", "flowcontrol.apiserver.k8s.io/v1 FlowSchema", "new.example.io/v1 Thing"}},
	}}
	prov := Provenance{Prufyx: Binary{Commit: "abc"}, LogDigest: "sha256:log"}
	res := Evaluate(claims, runs, prov, time.Unix(0, 0))
	got := outcomes(res)
	want := map[string]string{
		"k8s.1.32.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served": OutcomeConfirmed,
		"k8s.1.31.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.served":     OutcomeConfirmed,
		"k8s.1.32.flowcontrol.apiserver.k8s.io_v1_FlowSchema.served":          OutcomeConfirmed,
		"k8s.1.32.apps_v1_Deployment.not_served":                              OutcomeRefuted,
		"k8s.1.40.apps_v1_Deployment.served":                                  OutcomeUndetermined,
		"k8s.1.32.widgets.example.io_v1beta1_Widget.not_served":               OutcomeConfirmed,
		"addon": OutcomeUndetermined,
	}
	for id, outcome := range want {
		if got[id].Outcome != outcome {
			t.Errorf("%s: %s (%s), want %s", id, got[id].Outcome, got[id].Detail, outcome)
		}
	}
	c := got["k8s.1.32.apps_v1_Deployment.not_served"]
	if c.PrufyxCommit != "abc" || c.LogDigest != "sha256:log" || c.NodeImageDigest != "sha256:"+strings.Repeat("c", 64) || string(c.Evidence) != `{"source":"t"}` {
		t.Fatalf("provenance %+v", c)
	}
	if res.Totals.Confirmed != 4 || res.Totals.Refuted != 1 || res.Totals.Undetermined != 2 || res.Totals.Error != 0 {
		t.Fatalf("totals %+v", res.Totals)
	}
	if len(res.Diffs) != 1 {
		t.Fatalf("diffs %+v", res.Diffs)
	}
	d := res.Diffs[0]
	if strings.Join(d.Removed, ",") != "example.io/v1alpha1 Gadget,flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema,other.example.io/v1beta1 Other,widgets.example.io/v1beta1 Widget" {
		t.Fatalf("removed %v", d.Removed)
	}
	// The flow-control removal is in the table and the widget one in a
	// claim; the gadget (alpha) and the other one are unexplained.
	if strings.Join(d.UnknownRemovals, ",") != "example.io/v1alpha1 Gadget,other.example.io/v1beta1 Other" {
		t.Fatalf("unknown removals %v", d.UnknownRemovals)
	}
	sev := severities(res)
	if sev["k8s.1.32.apps_v1_Deployment.not_served"] != SeverityMedium || sev["diff.1.32.example-io_v1alpha1_Gadget"] != SeverityInfo || sev["diff.1.32.other-example-io_v1beta1_Other"] != SeverityMedium {
		t.Fatalf("findings %+v", res.Findings)
	}
	if !strings.Contains(Summary(res), "| 1.32 | v1.32.11 | 3 | 3 ok / 1 bad | - | - |") {
		t.Fatalf("summary:\n%s", Summary(res))
	}
}

func scanTry(exit int, verdict string, rules []string, gaps ...string) *ScanTry {
	return &ScanTry{From: "1.31.14", To: "1.32.11", Exit: exit, Verdict: verdict, Gaps: gaps, Rules: rules}
}

func removalClaim(id, group, version, kind, ruleID string) Claim {
	return Claim{ID: id, Kind: KindK8sRemoval, Subject: Subject{From: rawString("1.31"), To: rawString("1.32"), Group: group, Version: version, Kind: kind, RuleID: ruleID}}
}

func TestEvaluateRemovalClaims(t *testing.T) {
	type api struct{ group, version, kind string }
	apis := map[string]api{
		"blocked":    {"g", "v1beta3", "K"},
		"withrule":   {"g", "v1beta2", "K"},
		"wrongrule":  {"g", "v1beta1", "K"},
		"passed":     {"h", "v1beta1", "K"},
		"undecided":  {"i", "v1beta1", "K"},
		"named":      {"j", "v1beta1", "K"},
		"stillthere": {"k", "v1beta1", "K"},
		"neverthere": {"l", "v1beta1", "K"},
		"broken":     {"m", "v1beta1", "K"},
		"nocorpus":   {"n", "v1beta1", "K"},
	}
	var claims []Claim
	for id, a := range apis {
		rule := ""
		if id == "withrule" || id == "wrongrule" {
			rule = "rule." + id
		}
		claims = append(claims, removalClaim(id, a.group, a.version, a.kind, rule))
	}
	servedAt := func(ids ...string) []string {
		var out []string
		for _, id := range ids {
			a := apis[id]
			out = append(out, apiPair(a.group, a.version, a.kind))
		}
		return out
	}
	prevServed := servedAt("blocked", "withrule", "wrongrule", "passed", "undecided", "named", "stillthere", "broken", "nocorpus")
	nextServed := servedAt("stillthere")
	snapshots := map[string]Snapshot{
		"1.31": {Line: "1.31", ServerVersion: "v1.31.14", Image: "img@sha256:prev", Served: prevServed},
		"1.32": {Line: "1.32", ServerVersion: "v1.32.11", Image: "img@sha256:next", Served: nextServed},
	}
	caseFor := func(id string, outcome string, scan *ScanTry) VerdictCase {
		a := apis[id]
		return VerdictCase{ID: caseID(apiPair(a.group, a.version, a.kind)), API: apiPair(a.group, a.version, a.kind), Server: ServerTry{Outcome: outcome}, Scan: scan}
	}
	prev := VerdictRun{Line: "1.31"}
	for _, id := range []string{"blocked", "withrule", "wrongrule", "passed", "undecided", "named", "stillthere", "broken"} {
		prev.Cases = append(prev.Cases, caseFor(id, ServerAccepted, nil))
	}
	prev.Cases = append(prev.Cases, caseFor("neverthere", ServerNotServed, nil))
	next := VerdictRun{Line: "1.32", FromVersion: "1.31.14", ToVersion: "1.32.11", Cases: []VerdictCase{
		caseFor("blocked", ServerNotServed, scanTry(exitBlocked, "BLOCKED", nil, gapNotServed)),
		caseFor("withrule", ServerNotServed, scanTry(exitBlocked, "BLOCKED", []string{"rule.withrule"}, gapNotServed)),
		caseFor("wrongrule", ServerNotServed, scanTry(exitBlocked, "BLOCKED", []string{"rule.other"}, gapNotServed)),
		caseFor("passed", ServerNotServed, scanTry(exitPass, "PASS", nil)),
		caseFor("undecided", ServerNotServed, scanTry(exitUnknown, "UNKNOWN", nil, "LINE_NOT_ATTESTED")),
		caseFor("named", ServerNotServed, scanTry(exitUnknown, "UNKNOWN", nil, gapNotServed)),
		caseFor("stillthere", ServerAccepted, scanTry(exitUnknown, "UNKNOWN", nil)),
		caseFor("neverthere", ServerNotServed, scanTry(exitUnknown, "UNKNOWN", nil)),
		caseFor("broken", ServerNotServed, &ScanTry{Exit: 2, Error: "no JSON report"}),
	}}
	res := Evaluate(Claims{Schema: ClaimsSchema, Claims: claims}, Runs{Snapshots: snapshots, Verdicts: map[string]VerdictRun{"1.31": prev, "1.32": next}}, Provenance{}, time.Unix(0, 0))
	got := outcomes(res)
	want := map[string]string{
		"blocked": OutcomeConfirmed, "withrule": OutcomeConfirmed, "wrongrule": OutcomeRefuted, "passed": OutcomeRefuted,
		"undecided": OutcomeRefuted, "named": OutcomeRefuted, "stillthere": OutcomeRefuted, "neverthere": OutcomeRefuted,
		"broken": OutcomeError, "nocorpus": OutcomeUndetermined,
	}
	for id, outcome := range want {
		if got[id].Outcome != outcome {
			t.Errorf("%s: %s (%s), want %s", id, got[id].Outcome, got[id].Detail, outcome)
		}
	}
	if got["blocked"].NodeImageDigest != "sha256:next" {
		t.Errorf("digest %+v", got["blocked"])
	}
	sev := severities(res)
	if sev["passed"] != SeverityHigh || sev["undecided"] != SeverityMedium || sev["named"] != SeverityMedium || sev["wrongrule"] != SeverityMedium || sev["stillthere"] != SeverityMedium || sev["neverthere"] != SeverityMedium || sev["broken"] != SeverityInfo {
		t.Fatalf("findings %+v", res.Findings)
	}
	if res.Totals.High != 1 || res.Totals.Error != 1 {
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
    storage: %s
    schema: {openAPIV3Schema: {type: object}}
  - name: v1
    served: true
    storage: %s
    schema: {openAPIV3Schema: {type: object}}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: not-a-crd
`

func gadget(served, oldStorage bool) []byte {
	return []byte(fmt.Sprintf(gadgetCRD, fmt.Sprint(served), fmt.Sprint(oldStorage), fmt.Sprint(!oldStorage)))
}

func TestCRDDocumentsKeepOnlyDefinitions(t *testing.T) {
	docs, defs, err := crdDocuments(gadget(true, false))
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
		apiVersion, kind := manifestIdentity(stdin)
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

var (
	gadgetFrom = CRDRelease{Tag: "v9.0.0", Commit: strings.Repeat("a", 40), Files: []string{"crds/gadgets.yaml"}}
	gadgetTo   = CRDRelease{Tag: "v9.1.0", Commit: strings.Repeat("b", 40), Files: []string{"crds/gadgets.yaml"}}
)

// gadgetClaims are the claims of the fixture pair: v1beta1 served then
// unserved, v1 stored throughout.
func gadgetClaims(removed bool) Claims {
	version := func(id string, rel CRDRelease, v string, served, storage bool) Claim {
		return Claim{ID: id, Kind: KindCRDVersion, Subject: Subject{Project: "fixture", Repo: "github.com/fixture/fixture", Release: &rel, CRD: "gadgets.fixture.example", Group: "fixture.example", Version: v, Kind: "Gadget", Served: boolPtr(served), Storage: boolPtr(storage)}}
	}
	claims := []Claim{
		version("from.v1beta1", gadgetFrom, "v1beta1", true, false),
		version("from.v1", gadgetFrom, "v1", true, true),
		version("to.v1beta1", gadgetTo, "v1beta1", !removed, false),
		version("to.v1", gadgetTo, "v1", true, true),
	}
	if removed {
		claims = append(claims, Claim{ID: "removal", Kind: KindCRDRemoval, Subject: Subject{Project: "fixture", Repo: "github.com/fixture/fixture", From: rawObject(gadgetFrom), To: rawObject(gadgetTo), Group: "fixture.example", Version: "v1beta1", Kind: "Gadget", RuleID: "fixture.rule"}})
	} else {
		claims = append(claims, Claim{ID: "quiet", Kind: KindCRDPair, Subject: Subject{Project: "fixture", Repo: "github.com/fixture/fixture", From: rawObject(gadgetFrom), To: rawObject(gadgetTo)}})
	}
	return Claims{Schema: ClaimsSchema, Claims: claims}
}

func fixtureFetcher(toServed bool) fetcher {
	return func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		switch commit {
		case gadgetFrom.Commit:
			return gadget(true, false), nil
		case gadgetTo.Commit:
			return gadget(toServed, false), nil
		}
		return nil, fmt.Errorf("unknown commit %s", commit)
	}
}

func crdRuns(result CRDPairResult) Runs {
	return Runs{Snapshots: map[string]Snapshot{}, Verdicts: map[string]VerdictRun{}, CRD: []CRDRun{{Schema: CRDRunSchema, Line: "1.37", Image: "img@sha256:crd", Pairs: []CRDPairResult{result}}}}
}

func TestRunPairAndEvaluateCRDClaims(t *testing.T) {
	claims := gadgetClaims(true)
	if err := claims.Validate(); err != nil {
		t.Fatal(err)
	}
	pairs := claims.Pairs()
	if len(pairs) != 1 || pairs[0].ID != "fixture.v9.0.0-to-v9.1.0" || pairs[0].From.Commit != gadgetFrom.Commit {
		t.Fatalf("pairs %+v", pairs)
	}
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	result := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fixtureFetcher(false), pairs[0])
	if result.Error != "" || result.From.Error != "" || result.To.Error != "" || !result.InPlace.Succeeded {
		t.Fatalf("result %+v", result)
	}
	if len(cluster.crds) != 0 {
		t.Fatalf("the pair's CRDs were not removed: %v", cluster.crds)
	}
	res := Evaluate(claims, crdRuns(result), Provenance{}, time.Unix(0, 0))
	if res.Totals.Confirmed != 5 || res.Totals.Refuted != 0 || res.Totals.Undetermined != 0 || len(res.Findings) != 0 {
		t.Fatalf("totals %+v claims %+v findings %+v", res.Totals, res.Claims, res.Findings)
	}
	if got := outcomes(res)["removal"]; got.NodeImageDigest != "sha256:crd" || !strings.Contains(got.Detail, "not_served at v9.1.0") {
		t.Fatalf("removal %+v", got)
	}

	// The To release still serves v1beta1: the removal claim and the To
	// version claim are refuted, HIGH.
	cluster = &fakeCluster{crds: map[string]CRDDef{}}
	result = runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fixtureFetcher(true), pairs[0])
	res = Evaluate(claims, crdRuns(result), Provenance{}, time.Unix(0, 0))
	got := outcomes(res)
	if got["removal"].Outcome != OutcomeRefuted || got["to.v1beta1"].Outcome != OutcomeRefuted || res.Totals.High != 1 || res.Totals.Medium != 1 {
		t.Fatalf("still served: %+v findings %+v", res.Totals, res.Findings)
	}

	// A quiet pair whose To release drops a version: refuted, HIGH; a
	// claim that keeps v1beta1 served is refuted too.
	quiet := gadgetClaims(false)
	cluster = &fakeCluster{crds: map[string]CRDDef{}}
	result = runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fixtureFetcher(false), quiet.Pairs()[0])
	res = Evaluate(quiet, crdRuns(result), Provenance{}, time.Unix(0, 0))
	got = outcomes(res)
	if got["quiet"].Outcome != OutcomeRefuted || got["to.v1beta1"].Outcome != OutcomeRefuted || res.Totals.High != 2 {
		t.Fatalf("quiet: %+v findings %+v", res.Totals, res.Findings)
	}

	// Without a run of the pair every claim is undetermined.
	res = Evaluate(claims, Runs{Snapshots: map[string]Snapshot{}}, Provenance{}, time.Unix(0, 0))
	if res.Totals.Undetermined != 5 {
		t.Fatalf("no run: %+v", res.Totals)
	}
}

func TestRunPairRecordsRefusedInPlaceUpgrade(t *testing.T) {
	// The From release stores v1beta1; the To release drops it.
	fetch := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		if commit == gadgetFrom.Commit {
			return gadget(true, true), nil
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
	claims := gadgetClaims(true)
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	result := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
	if result.Error != "" || result.To.Error != "" {
		t.Fatalf("result %+v", result)
	}
	if !result.InPlace.Attempted || result.InPlace.Succeeded || !strings.Contains(result.InPlace.Message, "storedVersions") {
		t.Fatalf("in place %+v", result.InPlace)
	}
	res := Evaluate(claims, crdRuns(result), Provenance{}, time.Unix(0, 0))
	got := outcomes(res)
	if got["removal"].Outcome != OutcomeConfirmed || !strings.Contains(got["removal"].Detail, "refused") {
		t.Fatalf("removal %+v", got["removal"])
	}
	if len(result.InPlace.Leftover) != 0 {
		t.Fatalf("leftover %v", result.InPlace.Leftover)
	}
	// The From storage flags differ from the fixture claims (v1beta1 is
	// stored here): those two version claims are refuted, the To one that
	// expects an unserved v1beta1 declaration is refuted (absent).
	if got["from.v1beta1"].Outcome != OutcomeRefuted || got["from.v1"].Outcome != OutcomeRefuted || got["to.v1beta1"].Outcome != OutcomeRefuted || got["to.v1"].Outcome != OutcomeConfirmed {
		t.Fatalf("versions %+v", res.Claims)
	}
}

func TestCorpusHasRemovalsAndControls(t *testing.T) {
	cases := corpus([]Claim{removalClaim("x", "extra.example.io", "v1beta1", "Extra", "")})
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
	if c, ok := ids["rbac-authorization-k8s-io_v1beta1_Role"]; !ok || c.Removal != "1.22" {
		t.Fatalf("an old removal is a probe: %+v", c)
	}
	if c, ok := ids["extra-example-io_v1beta1_Extra"]; !ok || c.Removal != "1.32" {
		t.Fatalf("a claimed removal joins the corpus: %+v", c)
	}
	for i := 1; i < len(cases); i++ {
		if cases[i-1].ID == cases[i].ID {
			t.Fatalf("duplicate case %s", cases[i].ID)
		}
	}
}

func TestCommandsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	crd := filepath.Join(dir, "crd.json")
	data, _ := json.Marshal(gadgetClaims(true))
	if err := os.WriteFile(crd, data, 0o600); err != nil {
		t.Fatal(err)
	}
	claims := filepath.Join(dir, "claims.json")
	if code := run([]string{"claims", "--lines", "1.31,1.32", "--crd", crd, "--out", claims}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("claims exit %d", code)
	}
	c, err := loadClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Claims) < 6 || len(c.Pairs()) != 1 {
		t.Fatalf("claims %d pairs %d", len(c.Claims), len(c.Pairs()))
	}
	runs := filepath.Join(dir, "runs")
	if err := os.Mkdir(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(runs, "snapshot-1.32.json"), Snapshot{Schema: SnapshotSchema, Line: "1.32", ServerVersion: "v1.32.11", Image: "img@sha256:x", Served: []string{"flowcontrol.apiserver.k8s.io/v1 FlowSchema"}}); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "run.log")
	if err := os.WriteFile(log, []byte("log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	results := filepath.Join(dir, "results.json")
	if code := run([]string{"evaluate", "--claims", claims, "--runs", runs, "--out", results, "--summary", filepath.Join(dir, "summary.md"), "--prufyx-commit", "abc", "--prufyx", log, "--log", log}, &out, os.Stderr); code != 0 {
		t.Fatalf("evaluate exit %d", code)
	}
	var res Results
	if err := readJSON(results, &res); err != nil {
		t.Fatal(err)
	}
	if res.Schema != ResultsSchema || res.Totals.Claims != len(c.Claims) || res.Prufyx.Commit != "abc" || !strings.HasPrefix(res.LogDigest, "sha256:") || res.Prufyx.SHA256 != res.LogDigest || !strings.Contains(out.String(), "| 1.32 | v1.32.11 |") {
		t.Fatalf("results %+v\n%s", res, out.String())
	}
	if code := run([]string{"evaluate", "--claims", crd, "--runs", runs, "--out", results}, &out, os.Stderr); code != 0 {
		t.Fatalf("evaluate with only pairs: exit %d", code)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"x","claims":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"evaluate", "--claims", bad, "--runs", runs, "--out", results}, &out, &out); code != 1 {
		t.Fatalf("bad claims exit %d", code)
	}
	if code := run([]string{"bogus"}, &out, &out); code != 1 {
		t.Fatalf("bogus exit %d", code)
	}
}

func TestRunPairRecordsDroppedDefinitions(t *testing.T) {
	claims := gadgetClaims(true)
	fetch := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		if commit == gadgetFrom.Commit {
			return gadget(true, false), nil
		}
		return []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: nothing-here\n"), nil
	}
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	result := runPair(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
	if result.Error != "" || !result.InPlace.Succeeded || strings.Join(result.InPlace.Leftover, ",") != "gadgets.fixture.example" {
		t.Fatalf("result %+v", result)
	}
	// After the fresh install of To nothing is served: the removal is
	// confirmed (and the dropped definition noted), the To version claims
	// are refuted because To declares nothing.
	res := Evaluate(claims, crdRuns(result), Provenance{}, time.Unix(0, 0))
	got := outcomes(res)
	if got["removal"].Outcome != OutcomeConfirmed || !strings.Contains(got["removal"].Detail, "no longer defines gadgets.fixture.example") {
		t.Fatalf("removal %+v", got["removal"])
	}
	if got["to.v1"].Outcome != OutcomeRefuted || severities(res)["removal.leftover"] != SeverityInfo {
		t.Fatalf("claims %+v findings %+v", res.Claims, res.Findings)
	}
}

func TestWaitEstablishedRetriesTheAccessorError(t *testing.T) {
	calls := 0
	run := func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
		calls++
		if calls < 3 {
			return nil, []byte(".status.conditions accessor error: <nil> is of the type <nil>, expected []interface{}"), 1
		}
		return nil, nil, 0
	}
	if err := (kube{run: run, kubeconfig: "kc"}).waitEstablished(context.Background(), []string{"a.example"}); err != nil || calls != 3 {
		t.Fatalf("err %v calls %d", err, calls)
	}
	run = func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
		return nil, []byte("timed out waiting for the condition"), 1
	}
	if err := (kube{run: run, kubeconfig: "kc"}).waitEstablished(context.Background(), []string{"a.example"}); err == nil {
		t.Fatal("a timeout is not retried")
	}
}

// A release whose pair stopped before installing it (the earlier release
// failed) is an error, not a refuted claim; another pair that installed the
// same release decides it.
func TestReleaseStateComesFromACompletedPair(t *testing.T) {
	claims := gadgetClaims(true)
	failed := CRDPairResult{ID: "fixture.v9.0.0-to-v9.1.0", Project: "fixture", FromTag: "v9.0.0", ToTag: "v9.1.0", From: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}, Error: "kubectl wait: exit 1: timed out"}}
	res := Evaluate(claims, crdRuns(failed), Provenance{}, time.Unix(0, 0))
	got := outcomes(res)
	if got["from.v1"].Outcome != OutcomeError || got["to.v1"].Outcome != OutcomeError || !strings.Contains(got["to.v1"].Detail, "timed out") || got["removal"].Outcome != OutcomeError {
		t.Fatalf("claims %+v", res.Claims)
	}
	// A second pair (v9.1.0 -> v9.2.0) installed v9.1.0 as its From.
	ok := CRDPairResult{ID: "fixture.v9.1.0-to-v9.2.0", Project: "fixture", FromTag: "v9.1.0", ToTag: "v9.2.0", From: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}, CRDs: []CRDDef{{Name: "gadgets.fixture.example", Group: "fixture.example", Kind: "Gadget", Versions: []CRDVersion{{Name: "v1beta1"}, {Name: "v1", Served: true, Storage: true}}}}}, To: CRDReleaseState{Files: []FetchedFile{{Path: "x"}}}}
	runs := crdRuns(failed)
	runs.CRD[0].Pairs = append(runs.CRD[0].Pairs, ok)
	got = outcomes(Evaluate(claims, runs, Provenance{}, time.Unix(0, 0)))
	if got["to.v1"].Outcome != OutcomeConfirmed || got["to.v1beta1"].Outcome != OutcomeConfirmed || got["from.v1"].Outcome != OutcomeError {
		t.Fatalf("claims %+v", got)
	}
}
