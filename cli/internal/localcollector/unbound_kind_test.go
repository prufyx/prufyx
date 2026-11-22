// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// kindRunner serves one workload of the given kind carrying image.
type kindRunner struct {
	resource, kind, image, owner string
}

func (r kindRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (CommandResult, error) {
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, " "+r.resource+" ") {
		meta := map[string]any{}
		if r.owner != "" {
			meta["ownerReferences"] = []any{map[string]any{"kind": r.owner, "apiVersion": ownerAPIVersions[r.owner], "controller": true, "name": "x"}}
		}
		raw, _ := json.Marshal(map[string]any{"items": []any{map[string]any{
			"kind": r.kind, "metadata": meta,
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"image": r.image}}}}},
		}}})
		return CommandResult{Stdout: raw}, nil
	}
	return CommandResult{Stdout: fakeResponse(argv)}, nil
}

func collectOmissions(t *testing.T, r Runner, components bool) string {
	t.Helper()
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "kc")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: r}).Collect(context.Background(), Options{
		OutputRoot: filepath.Join(tmp, "out"), Kubeconfig: kubeconfig, Contexts: []string{"ctx"},
		AcknowledgeExecRisk: true, AllowPartial: true, Kubectl: os.Args[0],
		IncludeComponentConfiguration: components, ComponentConfigurationProfile: "v3",
		Now:    func() time.Time { return time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC) },
		Random: strings.NewReader(strings.Repeat("r", 32)),
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Collect exit=%d stderr=%q", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "000", "omissions.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestUnboundWorkloadKindOrFormMarksPartialInBothPaths(t *testing.T) {
	for _, components := range []bool{true, false} {
		// A DaemonSet running the image of a Deployment-only adapter.
		got := collectOmissions(t, kindRunner{"daemonsets.apps", "DaemonSet", "quay.io/argoproj/workflow-controller:v4.1.2", ""}, components)
		if strings.Count(got, OmissionComponentVersionUnbound) != 1 {
			t.Fatalf("components=%v daemonset: omissions=%q", components, got)
		}
		got = collectOmissions(t, kindRunner{"deployments.apps", "Deployment", "index.docker.io/argoproj/workflow-controller:v4.1.2", ""}, components)
		if strings.Count(got, OmissionComponentVersionUnbound) != 1 {
			t.Fatalf("components=%v index.docker.io: omissions=%q", components, got)
		}
	}
}

func TestStandaloneDerivedKindsAreUnbound(t *testing.T) {
	img := "quay.io/argoproj/workflow-controller:v4.1.2"
	for _, r := range []kindRunner{
		{"replicasets.apps", "ReplicaSet", img, ""},
		{"replicasets.apps", "ReplicaSet", img, "StatefulSet"},
		{"jobs.batch", "Job", img, ""},
	} {
		if got := collectOmissions(t, r, true); strings.Count(got, OmissionComponentVersionUnbound) != 1 {
			t.Fatalf("standalone %s owner=%q: omissions=%q", r.kind, r.owner, got)
		}
	}
}

func TestHealthyDeploymentAndItsReplicaSetDoNotTriggerUnbound(t *testing.T) {
	img := "quay.io/argoproj/workflow-controller:v4.1.2"
	for _, r := range []kindRunner{
		{"deployments.apps", "Deployment", img, ""},
		{"deployments.apps", "Deployment", "registry.example/other/app:v1.0.0", ""},
		{"replicasets.apps", "ReplicaSet", "registry.example/other/app:v1.0.0", ""},
	} {
		if got := collectOmissions(t, r, true); strings.Contains(got, OmissionComponentVersionUnbound) {
			t.Fatalf("%s: unexpected %q", r.kind, got)
		}
	}
}
