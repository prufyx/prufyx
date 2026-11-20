// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/bundlechart"
)

const (
	canaryReleaseSecret = "CANARY-RELEASE-RECORD-SECRET-VALUE"
	canaryConfigMap     = "CANARY-CONFIGMAP-CHART-VALUES"
	canaryAnnotation    = "CANARY-ANNOTATION-VALUE"
	canaryOtherLabel    = "CANARY-OTHER-LABEL-VALUE"
)

type chartObject struct {
	kind, namespace, name, chartLabel string
}

// chartRunner serves workloads carrying the given chart labels. It records
// every request. A request for Secrets or ConfigMaps is served a canary so a
// read would be visible in the output, and is also recorded so the test can
// prove it never happened.
type chartRunner struct {
	fakeRunner
	objects []chartObject
}

func (r *chartRunner) Run(ctx context.Context, argv, env []string, timeout time.Duration) (CommandResult, error) {
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "secrets") {
		raw, _ := json.Marshal(map[string]any{"items": []any{map[string]any{
			"kind": "Secret", "metadata": map[string]any{"name": "sh.release.v1.app.v1", "labels": map[string]any{"owner": "helm"}},
			"data": map[string]any{"release": canaryReleaseSecret}}}})
		r.calls = append(r.calls, append([]string(nil), argv...))
		return CommandResult{Stdout: raw}, nil
	}
	if strings.Contains(joined, "configmaps") {
		raw, _ := json.Marshal(map[string]any{"items": []any{map[string]any{
			"kind": "ConfigMap", "metadata": map[string]any{"name": "values"}, "data": map[string]any{"values.yaml": canaryConfigMap}}}})
		r.calls = append(r.calls, append([]string(nil), argv...))
		return CommandResult{Stdout: raw}, nil
	}
	resource := ""
	for _, want := range []string{"deployments.apps", "daemonsets.apps", "statefulsets.apps", "replicasets.apps", "jobs.batch", "cronjobs.batch", "replicationcontrollers"} {
		if strings.Contains(joined, " "+want+" ") {
			resource = want
		}
	}
	kind := map[string]string{"deployments.apps": "Deployment", "daemonsets.apps": "DaemonSet", "statefulsets.apps": "StatefulSet", "replicasets.apps": "ReplicaSet", "jobs.batch": "Job", "cronjobs.batch": "CronJob", "replicationcontrollers": "ReplicationController"}[resource]
	if kind == "" {
		return r.fakeRunner.Run(ctx, argv, env, timeout)
	}
	items := []any{}
	for _, o := range r.objects {
		if o.kind != kind {
			continue
		}
		labels := map[string]any{"other": canaryOtherLabel}
		if o.chartLabel != "" {
			labels[bundlechart.ChartLabel] = o.chartLabel
		}
		podTemplate := map[string]any{"spec": map[string]any{"containers": []any{
			map[string]any{"image": "registry.example.invalid/private/app:1.2.3", "env": []any{map[string]any{"name": "TOKEN", "value": canaryAnnotation}}}}}}
		spec := map[string]any{"template": podTemplate}
		if o.kind == "CronJob" {
			spec = map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": podTemplate}}}
		}
		items = append(items, map[string]any{
			"kind":     o.kind,
			"metadata": map[string]any{"name": o.name, "namespace": o.namespace, "labels": labels, "annotations": map[string]any{"meta.example/note": canaryAnnotation}},
			"spec":     spec,
		})
	}
	r.calls = append(r.calls, append([]string(nil), argv...))
	raw, _ := json.Marshal(map[string]any{"items": items})
	return CommandResult{Stdout: raw}, nil
}

type collected struct {
	dir    string
	set    bundlechart.Set
	stdout string
	files  map[string][]byte
	runner *chartRunner
}

func collectCharts(t *testing.T, objects []chartObject, declared []bundlechart.Declared) collected {
	t.Helper()
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &chartRunner{fakeRunner: fakeRunner{t: t, private: "chart-context"}, objects: objects}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: runner}).Collect(context.Background(), Options{
		OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: kubeconfig, Contexts: []string{runner.private},
		AcknowledgeExecRisk: true, Kubectl: os.Args[0], ExecEnv: proxyEnvironmentNames, ChartDeclaration: declared,
		Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("c", 32)),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("collect exit=%d stderr=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "000", bundlechart.FileName))
	if err != nil {
		t.Fatal(err)
	}
	set, err := bundlechart.Decode(raw)
	if err != nil {
		t.Fatalf("persisted set does not validate: %v", err)
	}
	files := map[string][]byte{}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files[path], _ = os.ReadFile(path)
		}
		return nil
	})
	return collected{dir: dir, set: set, stdout: stdout.String(), files: files, runner: runner}
}

func TestChartIdentityLabelOnly(t *testing.T) {
	c := collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", "widget-1.4.2"}}, nil)
	if c.set.Status != bundlechart.StatusIdentified || len(c.set.Entries) != 1 {
		t.Fatalf("set = %+v", c.set)
	}
	want := bundlechart.Entry{ChartName: "widget", ChartVersion: "1.4.2", Source: "label", SourceKind: "Deployment", SourceNamespace: "ns-a", SourceName: "web", State: "resolved"}
	if c.set.Entries[0] != want {
		t.Fatalf("entry = %+v, want %+v", c.set.Entries[0], want)
	}
}

func TestChartIdentityDeclarationOnly(t *testing.T) {
	c := collectCharts(t, nil, []bundlechart.Declared{{Name: "widget", Version: "1.4.2"}})
	if c.set.Status != bundlechart.StatusIdentified || len(c.set.Entries) != 1 {
		t.Fatalf("set = %+v", c.set)
	}
	want := bundlechart.Entry{ChartName: "widget", ChartVersion: "1.4.2", Source: "declared", State: "resolved"}
	if c.set.Entries[0] != want {
		t.Fatalf("entry = %+v, want %+v", c.set.Entries[0], want)
	}
}

func TestChartIdentityDeclarationAndLabelAgree(t *testing.T) {
	c := collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", "widget-1.4.2"}}, []bundlechart.Declared{{Name: "widget", Version: "1.4.2"}})
	if c.set.Status != bundlechart.StatusIdentified || len(c.set.Entries) != 2 {
		t.Fatalf("both sources must be shown and agree: %+v", c.set)
	}
	for _, e := range c.set.Entries {
		if e.State != bundlechart.StateResolved {
			t.Fatalf("agreeing entry not resolved: %+v", e)
		}
	}
}

func TestChartIdentityDeclarationLabelConflictIsUnknown(t *testing.T) {
	c := collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", "widget-1.4.2"}}, []bundlechart.Declared{{Name: "widget", Version: "1.5.0"}})
	if c.set.Status != bundlechart.StatusAmbiguous || c.set.NextAction != bundlechart.NextActionDisambiguate || len(c.set.Entries) != 2 {
		t.Fatalf("conflict must keep both and be ambiguous: %+v", c.set)
	}
	for _, e := range c.set.Entries {
		if e.State != bundlechart.StateAmbiguous {
			t.Fatalf("conflicting entry not ambiguous: %+v", e)
		}
	}
}

func TestChartIdentityTwoVersionsOneNamespaceAmbiguous(t *testing.T) {
	c := collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", "widget-1.4.2"}, {"StatefulSet", "ns-a", "db", "widget-1.5.0"}}, nil)
	if c.set.Status != bundlechart.StatusAmbiguous || len(c.set.Entries) != 2 {
		t.Fatalf("set = %+v", c.set)
	}
	// Different namespaces are separate installs, not a conflict.
	c = collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", "widget-1.4.2"}, {"Deployment", "ns-b", "web", "widget-1.5.0"}}, nil)
	if c.set.Status != bundlechart.StatusIdentified {
		t.Fatalf("separate namespaces were treated as a conflict: %+v", c.set)
	}
}

func TestChartIdentityMalformedLabelDroppedWithOmission(t *testing.T) {
	c := collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", "not-a-chart-label"}, {"Deployment", "ns-a", "web2", "widget-1.0.0-1.2.3"}}, nil)
	if c.set.Status != bundlechart.StatusNotDeclared || len(c.set.Entries) != 0 {
		t.Fatalf("malformed or ambiguous labels must yield no identity: %+v", c.set)
	}
	if len(c.set.Omissions) != 1 || c.set.Omissions[0].Code != bundlechart.OmissionLabelMalformed || c.set.Omissions[0].Count != 2 {
		t.Fatalf("omissions = %+v", c.set.Omissions)
	}
}

func TestChartIdentityMissingIsNotDeclaredWithNextAction(t *testing.T) {
	c := collectCharts(t, []chartObject{{"Deployment", "ns-a", "web", ""}}, nil)
	if c.set.Status != bundlechart.StatusNotDeclared || c.set.NextAction != "declare the chart name and version" {
		t.Fatalf("set = %+v", c.set)
	}
	if !strings.Contains(c.stdout, "next: declare the chart name and version") {
		t.Fatalf("next action not shown: %q", c.stdout)
	}
}

func TestChartIdentityUnreadWorkloadSourceFailsClosed(t *testing.T) {
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &oneFailureRunner{fakeRunner: fakeRunner{t: t, private: "chart-context"}}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: runner}).Collect(context.Background(), Options{
		OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: kubeconfig, Contexts: []string{"chart-context"}, AllowPartial: true,
		AcknowledgeExecRisk: true, Kubectl: os.Args[0], ExecEnv: proxyEnvironmentNames,
		ChartDeclaration: []bundlechart.Declared{{Name: "widget", Version: "1.4.2"}},
		Now:              func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("c", 32)),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("collect exit=%d stderr=%q", code, stderr.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "000", bundlechart.FileName))
	set, err := bundlechart.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	// oneFailureRunner fails one read; if that read was a workload the set must
	// be ambiguous, otherwise the declaration stands. Either is fail-closed;
	// what must never happen is an identified set with an unread source.
	unread := false
	for _, o := range set.Omissions {
		unread = unread || o.Code == bundlechart.OmissionSourceUnread
	}
	if unread && set.Status != bundlechart.StatusAmbiguous {
		t.Fatalf("unread source with status %q", set.Status)
	}
}

func TestChartIdentityNeverReadsSecretsOrConfigMapsAndEchoesNothingElse(t *testing.T) {
	c := collectCharts(t, []chartObject{
		{"Deployment", "ns-a", "web", "widget-1.4.2"},
		{"DaemonSet", "ns-a", "agent", "widget-1.4.2"},
		{"CronJob", "ns-b", "job", "other-chart-2.0.0"},
	}, []bundlechart.Declared{{Name: "widget", Version: "1.4.2"}})
	// The read list is exactly the pre-existing fixed list plus the CRD read:
	// nothing was added for chart identity.
	if len(c.runner.calls) != len(baseQueries)+1 {
		t.Fatalf("kubectl calls=%d want=%d", len(c.runner.calls), len(baseQueries)+1)
	}
	for _, call := range c.runner.calls {
		joined := strings.ToLower(strings.Join(call, " "))
		for _, forbidden := range []string{"secret", "configmap", "release", "sh.helm", "helm"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("forbidden resource %q requested: %q", forbidden, joined)
			}
		}
	}
	for path, raw := range c.files {
		for _, canary := range []string{canaryReleaseSecret, canaryConfigMap, canaryAnnotation, canaryOtherLabel, "registry.example.invalid", "sh.release"} {
			if bytes.Contains(raw, []byte(canary)) {
				t.Fatalf("%q escaped into %s", canary, path)
			}
		}
	}
	if strings.Contains(c.stdout, canaryReleaseSecret) || strings.Contains(c.stdout, "widget") || strings.Contains(c.stdout, "ns-a") {
		t.Fatalf("status output echoed identity content: %q", c.stdout)
	}
	// The persisted file has exactly the kept fields and nothing else.
	var doc struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(c.files[filepath.Join(c.dir, "000", bundlechart.FileName)], &doc); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"chartName": true, "chartVersion": true, "source": true, "sourceKind": true, "sourceNamespace": true, "sourceName": true, "state": true}
	for _, e := range doc.Entries {
		for k := range e {
			if !allowed[k] {
				t.Fatalf("unexpected kept field %q", k)
			}
		}
	}
}

func TestChartIdentityMetadataDeclaresSchemaAndDisclosure(t *testing.T) {
	c := collectCharts(t, nil, nil)
	var metadata map[string]any
	if err := json.Unmarshal(c.files[filepath.Join(c.dir, "000", "snapshot-metadata.json")], &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["chartIdentitySchema"] != bundlechart.Schema {
		t.Fatalf("metadata does not declare the field: %v", metadata["chartIdentitySchema"])
	}
	if !strings.Contains(string(c.files[filepath.Join(c.dir, "000", "snapshot-metadata.json")]), "chart identity") {
		t.Fatal("retained list does not disclose the field")
	}
}
