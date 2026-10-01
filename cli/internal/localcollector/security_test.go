// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorEnvironmentRequiresExplicitProxy(t *testing.T) {
	for _, name := range proxyEnvironmentNames {
		t.Setenv(name, "")
	}
	t.Setenv("HTTPS_PROXY", "http://private.invalid")
	if _, err := collectorEnvironment("/private/kubeconfig", nil); err == nil {
		t.Fatal("ambient proxy accepted without explicit forwarding")
	}
	env, err := collectorEnvironment("/private/kubeconfig", proxyEnvironmentNames)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "HTTPS_PROXY=http://private.invalid") {
		t.Fatal("selected proxy missing")
	}
}

func TestCollectorEnvironmentRejectsLoaderAndPythonVariables(t *testing.T) {
	for _, name := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "BASH_ENV", "PATH"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "private")
			if _, err := collectorEnvironment("/private/kubeconfig", []string{name}); err == nil {
				t.Fatalf("controlled environment %s accepted", name)
			}
		})
	}
}

func TestContextDigestIsRunScopedAndDoesNotEchoName(t *testing.T) {
	t.Parallel()
	a := contextDigest([]byte(strings.Repeat("a", 32)), "private-context")
	b := contextDigest([]byte(strings.Repeat("b", 32)), "private-context")
	if a == b || strings.Contains(a, "private") || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("unexpected context digests %q %q", a, b)
	}
}

func TestResolveKubectlAcceptsPackageManagerStyleSymlinks(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "Cellar", "kubectl")
	if err := os.Mkdir(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(tmp, "kubectl-explicit")
	if err := os.Symlink(target, explicit); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveKubectl(explicit); err != nil || got != want {
		t.Fatalf("explicit symlink resolved to %q, err=%v", got, err)
	}

	bin := filepath.Join(tmp, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(bin, "kubectl")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if got, err := resolveKubectl(""); err != nil || got != want {
		t.Fatalf("PATH symlink resolved to %q, err=%v", got, err)
	}
}

func TestResolveKubectlRejectsNonExecutableFilesWithoutPathDisclosure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-invalid-kubectl")
	if err := os.WriteFile(path, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveKubectl(path); err == nil || strings.Contains(err.Error(), path) {
		t.Fatalf("non-executable path error = %v", err)
	}
}

type countingRunner struct{ calls int }

func (r *countingRunner) Run(context.Context, []string, []string, time.Duration) (CommandResult, error) {
	r.calls++
	return CommandResult{}, nil
}

func TestCollectRejectsInvalidKubectlBeforeExecutionOrOutput(t *testing.T) {
	tmp := t.TempDir()
	kubeconfig := filepath.Join(tmp, "config")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(tmp, "private-invalid-kubectl")
	if err := os.WriteFile(invalid, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &countingRunner{}
	output := filepath.Join(tmp, "out")
	var stdout, stderr bytes.Buffer
	dir, code := (Collector{Runner: runner}).Collect(context.Background(), Options{
		OutputRoot: output, Kubeconfig: kubeconfig, Contexts: []string{"context"},
		AcknowledgeExecRisk: true, Kubectl: invalid,
	}, &stdout, &stderr)
	if dir != "" || code != 2 || runner.calls != 0 {
		t.Fatalf("dir=%q code=%d runner calls=%d", dir, code, runner.calls)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("invalid kubectl created output: %v", err)
	}
	if strings.Contains(stderr.String(), invalid) || stdout.Len() != 0 {
		t.Fatalf("unbounded invalid kubectl result stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
