// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/bundlechart"
)

func readDoc(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestLocalCollectionDocListsChartIdentity keeps the disclosure honest: every
// source, every kept field, every forbidden source, every omission code and the
// fixed next action of the chart identity field must be written in the docs,
// and the workload kinds its label path reads must be the workload kinds the
// collector already lists.
func TestLocalCollectionDocListsChartIdentity(t *testing.T) {
	collection := readDoc(t, "local-collection.md")
	for _, want := range []string{
		"## Chart identity", "--chart-declaration", bundlechart.ChartLabel, bundlechart.DeclarationSchema, bundlechart.DeclarationKind,
		"chart name", "chart version", "`source`", "`declared`", "`label`", "namespace and name", "`state`",
		"253 bytes", "128 bytes", bundlechart.OmissionLabelMalformed, bundlechart.OmissionSourceUnread,
		"`ambiguous`", "`not_declared`", bundlechart.NextActionDeclare,
		"only for workloads carrying the chart label", "there is no `prufyx.yaml` path yet",
		"release records", "Secret", "ConfigMap", "values", "rendered manifests", "adds no request",
	} {
		if !strings.Contains(collection, want) {
			t.Errorf("local-collection.md does not mention %q", want)
		}
	}
	section := collection[strings.Index(collection, "## Chart identity"):]
	for _, q := range baseQueries {
		if !isWorkload(q.name) {
			continue
		}
		kind := workloadKindOf(t, q.args[1])
		if !strings.Contains(section, kind) {
			t.Errorf("chart identity section does not list the workload kind %s the label path reads", kind)
		}
	}
	if !strings.Contains(nameOmission, "except the source workload kind, namespace and name kept by chart identity, only for workloads carrying the chart label") {
		t.Error("omittedByPolicy name omission lacks the chart identity exception")
	}
	handling := readDoc(t, "data-handling.md")
	for _, want := range []string{"chart identity", "--chart-declaration", bundlechart.ChartLabel, "Secrets", "ConfigMaps", "never read", "no `prufyx.yaml` path yet", "chart identity exception"} {
		if !strings.Contains(handling, want) {
			t.Errorf("data-handling.md does not mention %q", want)
		}
	}
	if !strings.Contains(readDoc(t, "declarations.md"), "--chart-declaration") {
		t.Error("declarations.md does not document the declaration file")
	}
}

// workloadKindOf maps a listed resource to its documented plural kind name. An
// unmapped resource fails the test, so a new workload read cannot slip in
// without the disclosure being looked at.
func workloadKindOf(t *testing.T, resource string) string {
	t.Helper()
	kinds := map[string]string{
		"deployments.apps": "Deployments", "daemonsets.apps": "DaemonSets", "statefulsets.apps": "StatefulSets",
		"replicasets.apps": "ReplicaSets", "jobs.batch": "Jobs", "cronjobs.batch": "CronJobs", "replicationcontrollers": "ReplicationControllers",
	}
	kind, ok := kinds[resource]
	if !ok {
		t.Fatalf("workload resource %q is not mapped to a documented kind", resource)
	}
	return kind
}

// TestChartLabelPathReadsOnlyTheNamedLabelOfListedWorkloads proves the label
// reader reads one label key of an object it is handed and nothing else.
func TestChartLabelPathReadsOnlyTheNamedLabelOfListedWorkloads(t *testing.T) {
	item := map[string]any{
		"kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "ns", "labels": map[string]any{
			"app": "other", bundlechart.ChartLabel: "widget-1.0.0", "app.kubernetes.io/version": "9.9.9"},
			"annotations": map[string]any{"meta.helm.sh/release-name": "x"}},
	}
	got, ok := chartLabelOf(item, "Deployment")
	if !ok || got != (bundlechart.LabelObservation{Kind: "Deployment", Namespace: "ns", Name: "web", Label: "widget-1.0.0"}) {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	for _, item := range []any{nil, "x", map[string]any{}, map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "x"}}},
		map[string]any{"metadata": map[string]any{"labels": map[string]any{bundlechart.ChartLabel: 7}}}} {
		if _, ok := chartLabelOf(item, "Deployment"); ok {
			t.Fatalf("label read from %v", item)
		}
	}
}
