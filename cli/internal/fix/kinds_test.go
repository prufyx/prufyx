// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	promID = "pkg:oci/prometheus/prometheus"
	cmID   = "pkg:oci/cert-manager/cert-manager"
)

func kindParams(t testing.TB, fields map[string]string) Params {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// planKind plans one request and, when it succeeds, applies it in memory.
func planKind(t *testing.T, src, kind string, params Params) (FilePlan, string, error) {
	t.Helper()
	plan, err := Plan(display, []byte(src), []Request{{Kind: kind, Params: params}}, Options{})
	if err != nil {
		return plan, "", err
	}
	after, err := ApplyInMemory([]byte(src), plan, Options{})
	if err != nil {
		t.Fatalf("a plan that was produced does not apply: %v", err)
	}
	return plan, string(after), nil
}

// onlyTokensChanged proves the edited bytes differ from the original only
// inside the edited spans.
func onlyTokensChanged(t *testing.T, src, after string, edits []Edit) {
	t.Helper()
	var rebuilt strings.Builder
	cursor := 0
	for _, e := range edits {
		if e.StartByte < cursor {
			t.Fatalf("overlapping edits")
		}
		rebuilt.WriteString(src[cursor:e.StartByte])
		rebuilt.WriteString(e.Replacement)
		cursor = e.EndByte
	}
	rebuilt.WriteString(src[cursor:])
	if rebuilt.String() != after {
		t.Fatalf("bytes outside the edited tokens changed:\n%q\n%q", rebuilt.String(), after)
	}
	if len(edits) > 0 {
		first, last := edits[0], edits[len(edits)-1]
		if after[:first.StartByte] != src[:first.StartByte] || !strings.HasSuffix(after, src[last.EndByte:]) {
			t.Fatal("prefix or suffix outside the edits changed")
		}
	}
}

type kindCase struct {
	name   string
	src    string
	params Params
	want   string // expected output; empty means no edits
	edits  int
}

func runPositive(t *testing.T, kind string, cases []kindCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, after, err := planKind(t, tc.src, kind, tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Edits) != tc.edits {
				t.Fatalf("edits %d, want %d: %+v", len(plan.Edits), tc.edits, plan.Edits)
			}
			wantAfter := tc.want
			if tc.edits == 0 {
				wantAfter = tc.src
			}
			if after != wantAfter {
				t.Fatalf("after:\n%s\nwant:\n%s", after, wantAfter)
			}
			onlyTokensChanged(t, tc.src, after, plan.Edits)
			// Idempotence: the edited bytes plan nothing further.
			again, err := Plan(display, []byte(after), []Request{{Kind: kind, Params: tc.params}}, Options{})
			if err != nil || len(again.Edits) != 0 {
				t.Fatalf("second plan: %v %+v", err, again.Edits)
			}
			if tc.edits == 0 && plan.Diff != "" {
				t.Fatalf("diff for no edits: %q", plan.Diff)
			}
			golden := filepath.Join("testdata", "kinds", kind+"-"+strings.ReplaceAll(tc.name, " ", "-")+".golden")
			if *update {
				if err := os.WriteFile(golden, []byte(plan.Diff), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Diff != string(want) {
				t.Fatalf("diff differs from %s:\n%s", golden, plan.Diff)
			}
		})
	}
}

func runRefusals(t *testing.T, kind string, params Params, cases map[string]string) {
	t.Helper()
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			plan, _, err := planKind(t, src, kind, params)
			if ReasonOf(err) != ReasonKindRefused {
				t.Fatalf("got %v, plan %+v", err, plan.Edits)
			}
		})
	}
}

func runInvalidParams(t *testing.T, kind string, params []string) {
	t.Helper()
	for _, raw := range params {
		t.Run(raw, func(t *testing.T) {
			_, err := Plan(display, []byte("a: b\n"), []Request{{Kind: kind, Params: Params(raw)}}, Options{})
			if ReasonOf(err) != ReasonInvalidParams && ReasonOf(err) != ReasonLimit {
				t.Fatalf("got %v", err)
			}
		})
	}
}

var _ = flag.Bool // the update flag lives in diff_test.go

func TestKindsAreRegistered(t *testing.T) {
	ids := Kinds()
	for _, want := range []string{"set_api_version", "rename_flag", "remove_feature_gate"} {
		found := false
		for _, id := range ids {
			found = found || id == want
		}
		if !found {
			t.Fatalf("%s is not registered: %v", want, ids)
		}
	}
}

// ---- set_api_version ----

func TestSetAPIVersion(t *testing.T) {
	params := kindParams(t, map[string]string{"from": "batch/v1beta1", "to": "batch/v1", "kind": "CronJob"})
	cron := func(api string) string {
		return "apiVersion: " + api + "\nkind: CronJob\nmetadata:\n  name: x\nspec:\n  schedule: \"* * * * *\"\n"
	}
	runPositive(t, "set_api_version", []kindCase{
		{name: "plain", src: cron("batch/v1beta1"), params: params, want: cron("batch/v1"), edits: 1},
		{name: "double quoted", src: cron(`"batch/v1beta1"`), params: params, want: cron(`"batch/v1"`), edits: 1},
		{name: "single quoted", src: cron(`'batch/v1beta1'`), params: params, want: cron(`'batch/v1'`), edits: 1},
		{name: "comment and crlf", src: "# keep\r\napiVersion: batch/v1beta1 # why\r\nkind: CronJob\r\n", params: params,
			want: "# keep\r\napiVersion: batch/v1 # why\r\nkind: CronJob\r\n", edits: 1},
		{name: "flow mapping", src: "{apiVersion: batch/v1beta1, kind: CronJob}\n", params: params,
			want: "{apiVersion: batch/v1, kind: CronJob}\n", edits: 1},
		{name: "only the matching document", params: params,
			src:  "apiVersion: apps/v1\nkind: Deployment\n---\n" + cron("batch/v1beta1") + "---\n" + cron("batch/v1beta1"),
			want: "apiVersion: apps/v1\nkind: Deployment\n---\n" + cron("batch/v1") + "---\n" + cron("batch/v1"), edits: 2},
		{name: "other version untouched", src: "apiVersion: batch/v2alpha1\nkind: CronJob\n", params: params},
		{name: "already migrated", src: cron("batch/v1"), params: params},
		{name: "other group untouched", src: "apiVersion: example.com/batch/v1beta1\nkind: CronJob\n", params: params},
		{name: "core group", params: kindParams(t, map[string]string{"from": "v1", "to": "v1beta1", "kind": "Widget"}),
			src: "apiVersion: v1\nkind: Widget\n", want: "apiVersion: v1beta1\nkind: Widget\n", edits: 1},
		{name: "no apiVersion", src: "kind: CronJob\nname: x\n", params: params},
	})
}

func TestSetAPIVersionRefusals(t *testing.T) {
	params := kindParams(t, map[string]string{"from": "batch/v1beta1", "to": "batch/v1", "kind": "CronJob"})
	runRefusals(t, "set_api_version", params, map[string]string{
		"wrong kind":            "apiVersion: batch/v1beta1\nkind: Job\n",
		"kind in other case":    "apiVersion: batch/v1beta1\nkind: cronjob\n",
		"list with a match":     "apiVersion: v1\nkind: List\nitems:\n- apiVersion: batch/v1beta1\n  kind: CronJob\n",
		"no kind":               "apiVersion: batch/v1beta1\nname: x\n",
		"match among documents": "apiVersion: batch/v1beta1\nkind: CronJob\n---\napiVersion: batch/v1beta1\nkind: Job\n",
	})
	for name, src := range map[string]string{
		"block scalar":   "apiVersion: >-\n  batch/v1beta1\nkind: CronJob\n",
		"templated file": "apiVersion: batch/v1beta1\nkind: CronJob\nname: {{ .x }}\n",
		"secret file":    "apiVersion: batch/v1beta1\nkind: CronJob\n---\napiVersion: v1\nkind: Secret\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := planKind(t, src, "set_api_version", params); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
	runInvalidParams(t, "set_api_version", []string{
		``, `{}`, `[]`, `null`,
		`{"from":"batch/v1beta1","to":"batch/v1"}`,
		`{"from":"batch/v1","to":"batch/v1","kind":"CronJob"}`,
		`{"from":"batch/v1beta1","to":"batch/v1","kind":"CronJob","extra":1}`,
		`{"from":"Batch/v1beta1","to":"batch/v1","kind":"CronJob"}`,
		`{"from":"batch/1","to":"batch/v1","kind":"CronJob"}`,
		`{"from":"batch/v1beta1","to":"batch/v1/x","kind":"CronJob"}`,
		`{"from":"batch/v1beta1","to":"batch/v1","kind":"cronjob"}`,
		`{"from":"batch/v1beta1","to":"batch/v1","kind":"Secret"}`,
		`{"from":"batch/v1beta1","to":"batch/v1","kind":"List"}`,
		`{"from":"batch/v1beta1","to":"batch/v1","kind":"Cron Job"}`,
		`{"from":"batch/v1beta1","to":"batch/v1\n","kind":"CronJob"}`,
		`{"from":1,"to":"batch/v1","kind":"CronJob"}`,
	})
}

// ---- rename_flag ----

func workload(kind, containers string) string {
	return "apiVersion: apps/v1\nkind: " + kind + "\nmetadata:\n  name: x\nspec:\n  template:\n    spec:\n      containers:\n" + containers
}

func container(image, body string) string {
	return "      - name: c\n        image: " + image + "\n" + body
}

func TestRenameFlag(t *testing.T) {
	params := kindParams(t, map[string]string{"component": promID, "from": "--storage.tsdb.retention", "to": "--storage.tsdb.retention.time"})
	prom := "prom/prometheus:v3.1.0"
	args := func(list string) string { return container(prom, "        args:\n"+list) }
	runPositive(t, "rename_flag", []kindCase{
		{name: "bare flag", params: params,
			src:  workload("Deployment", args("        - --storage.tsdb.retention\n        - 15d\n")),
			want: workload("Deployment", args("        - --storage.tsdb.retention.time\n        - 15d\n")), edits: 1},
		{name: "equals form", params: params,
			src:  workload("StatefulSet", args("        - --storage.tsdb.retention=15d\n        - --web.enable-lifecycle\n")),
			want: workload("StatefulSet", args("        - --storage.tsdb.retention.time=15d\n        - --web.enable-lifecycle\n")), edits: 1},
		{name: "double quoted", params: params,
			src:  workload("Deployment", args("        - \"--storage.tsdb.retention=15d\"\n")),
			want: workload("Deployment", args("        - \"--storage.tsdb.retention.time=15d\"\n")), edits: 1},
		{name: "single quoted with comment", params: params,
			src:  workload("Deployment", args("        - '--storage.tsdb.retention=15d' # keep\n")),
			want: workload("Deployment", args("        - '--storage.tsdb.retention.time=15d' # keep\n")), edits: 1},
		{name: "escape after the flag is kept", params: params,
			src:  workload("Deployment", args("        - \"--storage.tsdb.retention\\x3d15d\"\n")),
			want: workload("Deployment", args("        - \"--storage.tsdb.retention.time\\x3d15d\"\n")), edits: 1},
		{name: "flow list", params: params,
			src:  workload("Deployment", container(prom, "        args: [--a, --storage.tsdb.retention=1d, --b]\n")),
			want: workload("Deployment", container(prom, "        args: [--a, --storage.tsdb.retention.time=1d, --b]\n")), edits: 1},
		{name: "command list", params: params,
			src:  workload("Deployment", container(prom, "        command:\n        - /bin/prometheus\n        - --storage.tsdb.retention=1d\n")),
			want: workload("Deployment", container(prom, "        command:\n        - /bin/prometheus\n        - --storage.tsdb.retention.time=1d\n")), edits: 1},
		{name: "cron job", params: params,
			src:  "apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - image: " + prom + "\n            args: [--storage.tsdb.retention=1d]\n",
			want: "apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - image: " + prom + "\n            args: [--storage.tsdb.retention.time=1d]\n", edits: 1},
		{name: "pod", params: params,
			src:  "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - image: " + prom + "\n    args:\n    - --storage.tsdb.retention=1d\n",
			want: "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - image: " + prom + "\n    args:\n    - --storage.tsdb.retention.time=1d\n", edits: 1},
		{name: "image with digest and registry", params: params,
			src:  workload("Deployment", container("docker.io/prom/prometheus@sha256:"+strings.Repeat("a", 64), "        args: [--storage.tsdb.retention=1d]\n")),
			want: workload("Deployment", container("docker.io/prom/prometheus@sha256:"+strings.Repeat("a", 64), "        args: [--storage.tsdb.retention.time=1d]\n")), edits: 1},
		{name: "two matching containers", params: params,
			src:  workload("Deployment", args("        - --storage.tsdb.retention=1d\n")+args("        - --storage.tsdb.retention=2d\n")),
			want: workload("Deployment", args("        - --storage.tsdb.retention.time=1d\n")+args("        - --storage.tsdb.retention.time=2d\n")), edits: 2},
		{name: "other component untouched", params: params,
			src: workload("DaemonSet", container("quay.io/cilium/cilium:v1.16.0", "        args: [--storage.tsdb.retention=1d]\n"))},
		{name: "unknown image without the flag", params: params,
			src: workload("Deployment", container("nginx:1.27", "        args: [--other]\n"))},
		{name: "similar flag untouched", params: params,
			src: workload("Deployment", args("        - --storage.tsdb.retention.time=1d\n        - --storage.tsdb.retention.size=1GB\n"))},
		{name: "already renamed", params: params,
			src: workload("Deployment", args("        - --storage.tsdb.retention.time=1d\n"))},
		{name: "no args", params: params, src: workload("Deployment", container(prom, ""))},
		{name: "flag in an init container is left alone", params: params,
			src: "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      initContainers:\n      - image: " + prom + "\n        args: [--storage.tsdb.retention=1d]\n"},
		{name: "not a workload", params: params, src: "apiVersion: v1\nkind: ConfigMap\ndata:\n  args: --storage.tsdb.retention=1d\n"},
	})
}

func TestRenameFlagRefusals(t *testing.T) {
	params := kindParams(t, map[string]string{"component": promID, "from": "--storage.tsdb.retention", "to": "--storage.tsdb.retention.time"})
	prom := "prom/prometheus:v3.1.0"
	runRefusals(t, "rename_flag", params, map[string]string{
		"flag twice in args":       workload("Deployment", container(prom, "        args: [--storage.tsdb.retention=1d, --storage.tsdb.retention=2d]\n")),
		"flag in command and args": workload("Deployment", container(prom, "        command: [--storage.tsdb.retention]\n        args: [--storage.tsdb.retention=2d]\n")),
		"old and new together":     workload("Deployment", container(prom, "        args: [--storage.tsdb.retention=1d, --storage.tsdb.retention.time=2d]\n")),
		"unknown image":            workload("Deployment", container("registry.example.com/team/prom:v3", "        args: [--storage.tsdb.retention=1d]\n")),
		"no image":                 "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - args: [--storage.tsdb.retention=1d]\n",
		"unknown beside known":     workload("Deployment", container(prom, "        args: [--storage.tsdb.retention=1d]\n")+container("nginx", "        args: [--storage.tsdb.retention=1d]\n")),
		"escaped flag token":       workload("Deployment", container(prom, "        args: [\"\\x2d-storage.tsdb.retention=1d\"]\n")),
		"list of workloads":        "apiVersion: v1\nkind: List\nitems:\n- apiVersion: apps/v1\n  kind: Deployment\n",
	})
	runInvalidParams(t, "rename_flag", []string{
		``, `{}`, `{"component":"pkg:oci/prometheus/prometheus","from":"--a"}`,
		`{"component":"pkg:oci/unknown/unknown","from":"--a","to":"--b"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"-a","to":"--b"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--a","to":"b"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--a","to":"--a"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--a=1","to":"--b"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--A","to":"--b"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--a","to":"--b","x":1}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--a","to":"--b c"}`,
	})
}

// ---- remove_feature_gate ----

func TestRemoveFeatureGate(t *testing.T) {
	params := kindParams(t, map[string]string{"component": cmID, "gate": "ServerSideApply"})
	img := "quay.io/jetstack/cert-manager-controller:v1.16.2"
	args := func(list string) string { return container(img, "        args:\n"+list) }
	runPositive(t, "remove_feature_gate", []kindCase{
		{name: "middle", params: params,
			src:  workload("Deployment", args("        - --feature-gates=A=true,ServerSideApply=true,B=false\n")),
			want: workload("Deployment", args("        - --feature-gates=A=true,B=false\n")), edits: 1},
		{name: "first", params: params,
			src:  workload("Deployment", args("        - --feature-gates=ServerSideApply=false,B=false\n")),
			want: workload("Deployment", args("        - --feature-gates=B=false\n")), edits: 1},
		{name: "last", params: params,
			src:  workload("Deployment", args("        - --feature-gates=A=true,ServerSideApply=true\n")),
			want: workload("Deployment", args("        - --feature-gates=A=true\n")), edits: 1},
		{name: "separate value", params: params,
			src:  workload("Deployment", args("        - --feature-gates\n        - A=true,ServerSideApply=true\n")),
			want: workload("Deployment", args("        - --feature-gates\n        - A=true\n")), edits: 1},
		{name: "double quoted", params: params,
			src:  workload("Deployment", args("        - \"--feature-gates=A=true,ServerSideApply=true\"\n")),
			want: workload("Deployment", args("        - \"--feature-gates=A=true\"\n")), edits: 1},
		{name: "single quoted value with comment", params: params,
			src:  workload("Deployment", args("        - --feature-gates\n        - 'ServerSideApply=true,A=true' # c\n")),
			want: workload("Deployment", args("        - --feature-gates\n        - 'A=true' # c\n")), edits: 1},
		{name: "flow list", params: params,
			src:  workload("Deployment", container(img, "        args: [--v=2, \"--feature-gates=A=true,ServerSideApply=true\"]\n")),
			want: workload("Deployment", container(img, "        args: [--v=2, \"--feature-gates=A=true\"]\n")), edits: 1},
		{name: "gate in the second of two flags", params: params,
			src:  workload("Deployment", args("        - --feature-gates=A=true\n        - --feature-gates=ServerSideApply=true,B=true\n")),
			want: workload("Deployment", args("        - --feature-gates=A=true\n        - --feature-gates=B=true\n")), edits: 1},
		{name: "command list", params: params,
			src:  workload("Deployment", container(img, "        command:\n        - /app\n        - --feature-gates=ServerSideApply=true,A=true\n")),
			want: workload("Deployment", container(img, "        command:\n        - /app\n        - --feature-gates=A=true\n")), edits: 1},
		{name: "gate absent", params: params,
			src: workload("Deployment", args("        - --feature-gates=A=true,B=false\n"))},
		{name: "longer gate name untouched", params: params,
			src: workload("Deployment", args("        - --feature-gates=ServerSideApplyX=true,A=true\n"))},
		{name: "malformed list without the gate", params: params,
			src: workload("Deployment", args("        - --feature-gates=A=yes\n"))},
		{name: "no gates flag", params: params, src: workload("Deployment", args("        - --v=2\n"))},
		{name: "other component untouched", params: params,
			src: workload("DaemonSet", container("quay.io/cilium/cilium:v1.16.0", "        args: [--feature-gates=ServerSideApply=true]\n"))},
		{name: "map absent", params: params,
			src: "apiVersion: config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\nfeatureGates:\n  A: true\n"},
		{name: "map of an unrelated document", params: params,
			src: "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nfeatureGates:\n  ServerSideApply: true\n"},
	})
}

func TestRemoveFeatureGateRefusals(t *testing.T) {
	params := kindParams(t, map[string]string{"component": cmID, "gate": "ServerSideApply"})
	img := "quay.io/jetstack/cert-manager-controller:v1.16.2"
	runRefusals(t, "remove_feature_gate", params, map[string]string{
		"only gate in the list":      workload("Deployment", container(img, "        args: [--feature-gates=ServerSideApply=true]\n")),
		"only gate in separate form": workload("Deployment", container(img, "        args: [--feature-gates, ServerSideApply=false]\n")),
		"gate twice in a list":       workload("Deployment", container(img, "        args: [\"--feature-gates=ServerSideApply=true,ServerSideApply=false,A=true\"]\n")),
		"gate in two flags":          workload("Deployment", container(img, "        args: [\"--feature-gates=ServerSideApply=true,A=true\", \"--feature-gates=ServerSideApply=true,B=true\"]\n")),
		"malformed entry":            workload("Deployment", container(img, "        args: [\"--feature-gates=ServerSideApply=yes,A=true\"]\n")),
		"spaces in the list":         workload("Deployment", container(img, "        args: [\"--feature-gates=A=true, ServerSideApply=true\"]\n")),
		"unknown image":              workload("Deployment", container("example.com/x:1", "        args: [\"--feature-gates=ServerSideApply=true,A=true\"]\n")),
		"escaped token":              workload("Deployment", container(img, "        args: [\"--feature-gates=ServerSideApply=true,A=true\\x21\"]\n")),
		"gate map entry":             "apiVersion: config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\nfeatureGates:\n  ServerSideApply: true\n  A: true\n",
		"gate map only entry":        "apiVersion: config.cert-manager.io/v1alpha1\nkind: WebhookConfiguration\nfeatureGates: {ServerSideApply: true}\n",
		"list of workloads":          "apiVersion: v1\nkind: List\nitems:\n- kind: Pod\n",
		"junk in a flow list":        workload("Deployment", container(img, "        args: [--v=2, \"--feature-gates=ServerSideApply=true;x\"]\n")),
	})
	runInvalidParams(t, "remove_feature_gate", []string{
		``, `{}`, `{"component":"pkg:oci/cert-manager/cert-manager"}`,
		`{"component":"pkg:oci/cert-manager/cert-manager","gate":"A=true"}`,
		`{"component":"pkg:oci/cert-manager/cert-manager","gate":"A,B"}`,
		`{"component":"pkg:oci/cert-manager/cert-manager","gate":""}`,
		`{"component":"pkg:oci/nope/nope","gate":"A"}`,
		`{"component":"pkg:oci/cert-manager/cert-manager","gate":"A","gates":["B"]}`,
		`{"component":"pkg:oci/cert-manager/cert-manager","gate":1}`,
	})
}

// A kind's plan is the same on every call (it is replayed at apply time).
func TestKindsArePlannedDeterministically(t *testing.T) {
	src := workload("Deployment", container("quay.io/jetstack/cert-manager-controller:v1.16.2", "        args: [\"--feature-gates=ServerSideApply=true,A=true\"]\n")+
		container("prom/prometheus:v3.1.0", "        args: [--storage.tsdb.retention=1d]\n"))
	requests := []Request{
		{Kind: "remove_feature_gate", Params: kindParams(t, map[string]string{"component": cmID, "gate": "ServerSideApply"})},
		{Kind: "rename_flag", Params: kindParams(t, map[string]string{"component": promID, "from": "--storage.tsdb.retention", "to": "--storage.tsdb.retention.time"})},
	}
	first, err := Plan(display, []byte(src), requests, Options{})
	if err != nil || len(first.Edits) != 2 {
		t.Fatalf("%v %+v", err, first.Edits)
	}
	for i := 0; i < 20; i++ {
		again, err := Plan(display, []byte(src), requests, Options{})
		if err != nil || !bytes.Equal([]byte(again.Diff), []byte(first.Diff)) {
			t.Fatalf("plans differ: %v", err)
		}
	}
	after, err := ApplyInMemory([]byte(src), first, Options{})
	if err != nil || !strings.Contains(string(after), "--feature-gates=A=true") || !strings.Contains(string(after), "retention.time=1d") {
		t.Fatalf("%v\n%s", err, after)
	}
}

// ---- fuzz ----

func FuzzKindValidate(f *testing.F) {
	for _, seed := range []string{
		`{"from":"batch/v1beta1","to":"batch/v1","kind":"CronJob"}`,
		`{"component":"pkg:oci/prometheus/prometheus","from":"--a","to":"--b"}`,
		`{"component":"pkg:oci/cert-manager/cert-manager","gate":"A"}`,
		`{}`, ``, `[`, `{"from":"\u0000"}`,
	} {
		f.Add([]byte(seed))
	}
	src := []byte("apiVersion: batch/v1beta1\nkind: CronJob\n")
	f.Fuzz(func(t *testing.T, params []byte) {
		for _, id := range []string{"set_api_version", "rename_flag", "remove_feature_gate"} {
			plan, err := Plan(display, src, []Request{{Kind: id, Params: params}}, Options{})
			if err != nil {
				r, ok := err.(*Refusal)
				if !ok || !knownReasons[r.Reason] || len(r.Detail) > maxDetail {
					t.Fatalf("not a bounded refusal: %v", err)
				}
				continue
			}
			if after, err := ApplyInMemory(src, plan, Options{}); err != nil || len(after) == 0 {
				t.Fatalf("a plan does not apply: %v", err)
			}
		}
	})
}

func FuzzKindPlan(f *testing.F) {
	requests := []Request{
		{Kind: "set_api_version", Params: Params(`{"from":"batch/v1beta1","to":"batch/v1","kind":"CronJob"}`)},
		{Kind: "rename_flag", Params: Params(`{"component":"pkg:oci/prometheus/prometheus","from":"--storage.tsdb.retention","to":"--storage.tsdb.retention.time"}`)},
		{Kind: "remove_feature_gate", Params: Params(`{"component":"pkg:oci/cert-manager/cert-manager","gate":"ServerSideApply"}`)},
	}
	for _, seed := range []string{
		"apiVersion: batch/v1beta1\nkind: CronJob\n",
		"apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: prom/prometheus:v3.1.0\n        args: [--storage.tsdb.retention=1d]\n",
		"apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - image: quay.io/jetstack/cert-manager-controller:v1\n        args: [\"--feature-gates=ServerSideApply=true,A=true\"]\n",
		"apiVersion: config.cert-manager.io/v1alpha1\nkind: ControllerConfiguration\nfeatureGates: {ServerSideApply: true}\n",
		"apiVersion: v1\nkind: List\nitems: []\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		for _, request := range requests {
			plan, err := Plan(display, src, []Request{request}, Options{})
			if err != nil {
				r, ok := err.(*Refusal)
				if !ok || !knownReasons[r.Reason] || len(r.Detail) > maxDetail {
					t.Fatalf("not a bounded refusal: %v", err)
				}
				continue
			}
			after, err := ApplyInMemory(src, plan, Options{})
			if err != nil {
				t.Fatalf("a plan does not apply: %v", err)
			}
			again, err := Plan(display, after, []Request{request}, Options{})
			if err != nil || len(again.Edits) != 0 {
				t.Fatalf("not idempotent: %v %+v", err, again.Edits)
			}
		}
	})
}
