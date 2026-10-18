// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Each usage error names the missing or bad item and exits 2.
func TestUsageErrorsNameTheProblem(t *testing.T) {
	dir := privateDir(t)
	yaml := filepath.Join(dir, "kafka.yaml")
	if err := os.WriteFile(yaml, []byte("apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const now = "2026-10-18T00:00:00Z"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"assess no kubeconfig", []string{"assess", "--acknowledge-kubeconfig-exec-risk", "ctx"}, "missing --kubeconfig"},
		{"assess no acknowledge", []string{"assess", "--kubeconfig", "/nonexistent", "ctx"}, "missing --acknowledge-kubeconfig-exec-risk"},
		{"assess no context", []string{"assess", "--kubeconfig", "/nonexistent", "--acknowledge-kubeconfig-exec-risk"}, "missing CONTEXT"},
		{"assess bad format", []string{"assess", "--kubeconfig", "/nonexistent", "--acknowledge-kubeconfig-exec-risk", "--format", "markdown", "ctx"}, `unsupported --format "markdown"; use human or json`},
		{"assess flag after context", []string{"assess", "--kubeconfig", "/nonexistent", "--acknowledge-kubeconfig-exec-risk", "ctx", "--format", "json"}, "flags must come before CONTEXT"},
		{"assess kubeconfig after context", []string{"assess", "ctx", "--kubeconfig", "/nonexistent"}, "flags must come before CONTEXT"},
		{"check cncf bad format", []string{"check", "cncf", "--project", "kubernetes", "--format", "markdown"}, `unsupported --format "markdown" for check; use human or json`},
		{"check project bad format", []string{"check", "project", "--project", "grafana", "--effective-config", yaml, "--from", "10.0.0", "--to", "11.0.0", "--effective-config-complete", "--precedence-resolved", "--now", now, "--format", "markdown"}, `unsupported --format "markdown" for check; use human or json`},
		{"check cncf yaml to json-only flag", []string{"check", "cncf", "--project", "strimzi", "--kafka-resource", yaml, "--strimzi-distribution", "official_upstream", "--target-kafka-crd-admission-required", "--from", "0.51.0", "--to", "1.0.0", "--now", now}, "--kafka-resource must be JSON"},
		{"unknown command", []string{"--kubeconfig", "x", "assess"}, "flags go after the command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runCommunity(t, tc.args...)
			if code != ExitUsage || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q; want %q", code, stdout, stderr, tc.want)
			}
		})
	}
}
