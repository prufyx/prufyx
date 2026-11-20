// SPDX-License-Identifier: AGPL-3.0-only

package currentbundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/bundlechart"
	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

type chartBridgeRunner struct{ label string }

func (r chartBridgeRunner) Run(ctx context.Context, argv, env []string, timeout time.Duration) (localcollector.CommandResult, error) {
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, "get deployments.apps") && r.label != "" {
		item := map[string]any{"kind": "Deployment",
			"metadata": map[string]any{"name": "web", "namespace": "ns-a", "labels": map[string]any{bundlechart.ChartLabel: r.label}},
			"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"image": "registry.example.invalid/x:1.0.0"}}}}}}
		raw, _ := json.Marshal(map[string]any{"items": []any{item}})
		return localcollector.CommandResult{Stdout: raw}, nil
	}
	return collectorBridgeRunner{mode: "server-version-clean"}.Run(ctx, argv, env, timeout)
}

func collectChartBundle(t *testing.T, label string, declared []bundlechart.Declared) (Artifact, string) {
	t.Helper()
	root := t.TempDir()
	kubeconfig := filepath.Join(root, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range testProxyNames {
		t.Setenv(name, "")
	}
	var out, errb bytes.Buffer
	path, code := (localcollector.Collector{Runner: chartBridgeRunner{label: label}}).Collect(context.Background(), localcollector.Options{
		OutputRoot: filepath.Join(root, "output"), Kubeconfig: kubeconfig, Contexts: []string{"synthetic-context"}, AcknowledgeExecRisk: true,
		ChartDeclaration: declared, Kubectl: os.Args[0], ExecEnv: testProxyNames,
		Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("k", 32)),
	}, &out, &errb)
	if code != 0 {
		t.Fatalf("collector exit=%d stderr=%q", code, errb.String())
	}
	artifact, err := buildTestPath(t, path, Options{})
	if err != nil {
		t.Fatalf("bundle rejected collector output: %v", err)
	}
	return artifact, out.String()
}

func TestBundleCarriesChartIdentity(t *testing.T) {
	artifact, _ := collectChartBundle(t, "widget-1.4.2", []bundlechart.Declared{{Name: "widget", Version: "1.4.2"}})
	set := artifact.Bundle.ChartIdentity
	if set == nil || set.Status != bundlechart.StatusIdentified || len(set.Entries) != 2 {
		t.Fatalf("chart identity = %+v", set)
	}
	if err := ValidateArtifact(artifact); err != nil {
		t.Fatalf("artifact does not validate: %v", err)
	}
	if bytes.Contains(artifact.Bytes, []byte("registry.example.invalid")) {
		t.Fatal("image reference escaped")
	}
}

func TestBundleChartIdentityMissingAndConflictAreUnknownWithNextAction(t *testing.T) {
	artifact, stdout := collectChartBundle(t, "", nil)
	set := artifact.Bundle.ChartIdentity
	if set == nil || set.Status != bundlechart.StatusNotDeclared || set.NextAction != "declare the chart name and version" || len(set.Entries) != 0 {
		t.Fatalf("missing identity = %+v", set)
	}
	if !strings.Contains(stdout, "declare the chart name and version") {
		t.Fatalf("next action not shown: %q", stdout)
	}
	artifact, _ = collectChartBundle(t, "widget-1.4.2", []bundlechart.Declared{{Name: "widget", Version: "2.0.0"}})
	set = artifact.Bundle.ChartIdentity
	if set == nil || set.Status != bundlechart.StatusAmbiguous || len(set.Entries) != 2 {
		t.Fatalf("conflict = %+v", set)
	}
}

func TestBundleRejectsTamperedChartIdentity(t *testing.T) {
	artifact, _ := collectChartBundle(t, "widget-1.4.2", []bundlechart.Declared{{Name: "widget", Version: "2.0.0"}})
	bundle := artifact.Bundle
	forged := *bundle.ChartIdentity
	forged.Entries = append([]bundlechart.Entry(nil), forged.Entries...)
	forged.Entries[0].State = bundlechart.StateResolved
	forged.Status, forged.NextAction = bundlechart.StatusIdentified, ""
	bundle.ChartIdentity = &forged
	if err := validateBundle(bundle); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged chart identity accepted: %v", err)
	}
}
