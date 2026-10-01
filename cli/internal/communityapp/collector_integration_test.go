// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/localcollector"
	"github.com/prufyx/prufyx/cli/internal/observation"
)

func TestOfflineCollectorOutputsImportIntoCurrentBundle(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
		args []string
	}{
		{name: "default-typed-public-images", mode: "pod-private-images"},
		{name: "producer-v3", mode: "component-v3-prom", args: []string{"--include-component-configuration", "--component-configuration-profile", "v3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			kubeconfig := filepath.Join(work, "kubeconfig")
			if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(work, "output")
			for _, name := range integrationProxyNames {
				t.Setenv(name, "")
			}
			profile := "v2"
			components := false
			for i := range tc.args {
				if tc.args[i] == "--include-component-configuration" {
					components = true
				}
				if tc.args[i] == "--component-configuration-profile" && i+1 < len(tc.args) {
					profile = tc.args[i+1]
				}
			}
			var stdout, stderr bytes.Buffer
			rootPath, code := (localcollector.Collector{Runner: integrationRunner{mode: tc.mode}}).Collect(context.Background(), localcollector.Options{
				OutputRoot: output, Kubeconfig: kubeconfig, Contexts: []string{"synthetic-context"}, AcknowledgeExecRisk: true,
				AllowPartial: true, IncludeComponentConfiguration: components, ComponentConfigurationProfile: profile,
				Kubectl: os.Args[0], ExecEnv: integrationProxyNames, Now: func() time.Time { return time.Unix(1, 0) }, Random: strings.NewReader(strings.Repeat("i", 32)),
			}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("collector exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			assertCollectorTreeOmitsPrivateCanaries(t, rootPath)
			root, err := observation.OpenPath(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := currentbundle.BuildObservation(context.Background(), root, currentbundle.Options{})
			closeErr := root.Close()
			if err != nil {
				t.Fatalf("build current bundle: %v", err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			raw, err := json.Marshal(artifact.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"pkg:oci/prometheus/prometheus", `"value":"2.55.1"`} {
				if !bytes.Contains(raw, []byte(required)) {
					t.Fatalf("current bundle missing %q: %s", required, raw)
				}
			}
			if tc.name == "producer-v3" {
				for _, required := range []string{`"predicateRegistryVersion":"v2"`, `"version":"current-bundle-v3"`, `"id":"component.prometheus.agent_mode"`, `"value":true`} {
					if !bytes.Contains(raw, []byte(required)) {
						t.Fatalf("v3 current bundle missing %q: %s", required, raw)
					}
				}
			}
		})
	}
}

var integrationProxyNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}

type integrationRunner struct{ mode string }

func (r integrationRunner) Run(_ context.Context, argv, _ []string, _ time.Duration) (localcollector.CommandResult, error) {
	joined := strings.Join(argv, " ")
	var value any = map[string]any{"items": []any{}}
	switch {
	case strings.Contains(joined, "--raw=/version"):
		value = map[string]any{"gitVersion": "v1.34.0", "goVersion": "go1.26.8", "compiler": "gc", "platform": "linux/amd64"}
	case strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{}}
	case strings.Contains(joined, "--raw=/apis"):
		value = map[string]any{"groups": []any{}}
	case strings.Contains(joined, "--raw=/api"):
		value = map[string]any{"versions": []any{"v1"}}
	case strings.Contains(joined, "get deployments.apps"):
		image := "docker.io/prom/prometheus:v2.55.1"
		container := map[string]any{"image": image, "args": []any{}}
		if r.mode == "component-v3-prom" {
			image = "docker.io/prom/prometheus:v2.55.1@sha256:f4def6b3b61109a6eeea59945d578bb7e926c36cb0e036a23e3ceb8b6de024ad"
			container = map[string]any{"image": image, "command": []any{"/bin/prometheus"}, "args": []any{"--enable-feature=native-histograms,agent"}}
		}
		value = integrationWorkload(container)
	}
	raw, _ := json.Marshal(value)
	return localcollector.CommandResult{Stdout: raw, Exit: 0}, nil
}

func integrationWorkload(container map[string]any) any {
	podSpec := map[string]any{"containers": []any{container}, "initContainers": []any{}}
	template := map[string]any{"spec": podSpec}
	item := map[string]any{"kind": "Deployment", "spec": map[string]any{"template": template}}
	return map[string]any{"items": []any{item}}
}

func assertCollectorTreeOmitsPrivateCanaries(t *testing.T, root string) {
	t.Helper()
	forbidden := [][]byte{
		[]byte("private.invalid"),
		[]byte("PRIVATE_OBJECT_NAME_NEVER_RETAIN"),
		[]byte("PRIVATE_COMMAND_NEVER_RETAIN"),
		[]byte("PRIVATE_ENV_NEVER_RETAIN"),
		[]byte("PRIVATE_TAG_CANARY"),
		[]byte("PRIVATE_CONTROL_CANARY"),
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, canary := range forbidden {
			if bytes.Contains(raw, canary) {
				t.Fatalf("collector retained private canary in %s", filepath.Base(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
