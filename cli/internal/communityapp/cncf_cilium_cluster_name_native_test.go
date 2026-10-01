// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

func TestCiliumClusterNameNativeAndPrepareRoutes(t *testing.T) {
	valid := []byte("apiVersion: v1\nkind: ConfigMap\nimmutable: false\nmetadata:\n  name: cilium-config\n  creationTimestamp: null\ndata:\n  cluster-name: mesh-1\n")
	blocked := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: Mesh\n")
	for _, tc := range []struct {
		name   string
		raw    []byte
		status string
		code   int
	}{
		{"valid", valid, "PASS", ExitOK},
		{"invalid", blocked, "BLOCKED", ExitBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "cilium-config.yaml", tc.raw, 0o600)
			args := []string{"check", "cncf", "--project", "cilium", "--cilium-config-map", path, "--from", "1.16.19", "--to", "1.17.18", "--cilium-distribution", "official_upstream", "--cilium-config-complete", "--cilium-config-precedence-resolved", "--now", "2026-09-12T10:00:00Z", "--format", "json"}
			code, output, stderr := runCNCFCLI(t, args...)
			if code != tc.code || stderr != "" || !strings.Contains(output, `"status":"`+tc.status+`"`) || strings.Contains(output, "mesh-1") || strings.Contains(output, "Mesh") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
			}
			prepareArgs := []string{"prepare", "cncf", "--project", "cilium", "--cilium-config-map", path, "--from", "1.16.19", "--to", "1.17.18", "--cilium-distribution", "official_upstream", "--cilium-config-complete", "--cilium-config-precedence-resolved", "--format", "input"}
			prepareCode, canonical, prepareStderr := runCNCFCLI(t, prepareArgs...)
			if prepareCode != ExitOK || prepareStderr != "" || !strings.Contains(canonical, cncfprepare.CiliumInvalidEffectiveClusterNameFact) || strings.Contains(canonical, "mesh-1") || strings.Contains(canonical, "Mesh") {
				t.Fatalf("prepare code=%d stdout=%q stderr=%q", prepareCode, canonical, prepareStderr)
			}
			prepared := writeCNCFFile(t, "cilium-canonical.json", []byte(canonical), 0o600)
			checkCode, report, checkStderr := runCNCFCLI(t, "check", "cncf", "--project", "cilium", "--input", prepared, "--input-digest", cncfDigest([]byte(canonical)), "--now", "2026-09-12T10:00:00Z", "--format", "json")
			if checkCode != tc.code || checkStderr != "" || !strings.Contains(report, `"status":"`+tc.status+`"`) {
				t.Fatalf("batch code=%d stdout=%q stderr=%q", checkCode, report, checkStderr)
			}
		})
	}
}

func TestCiliumClusterNameExternalStoreHasNoEmbeddedFallback(t *testing.T) {
	fixture := makeExternalCLIFixture(t)
	raw := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cilium-config\ndata:\n  cluster-name: private-mesh\n")
	path := writeCNCFFile(t, "cilium-config.yaml", raw, 0o600)
	code, output, stderr := runCNCFCLI(t,
		"check", "cncf", "--project", "cilium", "--cilium-config-map", path, "--cilium-config-map-digest", cncfDigest(raw), "--from", "1.16.19", "--to", "1.17.18", "--cilium-distribution", "official_upstream", "--cilium-config-complete", "--cilium-config-precedence-resolved",
		"--knowledge-db", fixture.store, "--knowledge-revision", "1", "--knowledge-bundle-digest", fixture.manifest.Revisions[0].BundleDigest, "--knowledge-trust-receipt-digest", fixture.receipt1.TrustReceiptDigest, "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"knowledgeOrigin":"external_declared"`) || strings.Contains(output, "private-mesh") || strings.Contains(output, path) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, output, stderr)
	}
}

func TestCiliumClusterNameFlagsAreClosedToCiliumCheckMode(t *testing.T) {
	privateInput := filepath.Join(t.TempDir(), "private-not-read.json")
	for _, extra := range [][]string{
		{"--cilium-config-map", privateInput},
		{"--cilium-config-map-digest", "sha256:" + strings.Repeat("0", 64)},
		{"--cilium-config-complete=false"},
		{"--cilium-config-precedence-resolved=false"},
		{"--cilium-distribution", "custom_build"},
	} {
		code, stdout, stderr := runCNCFCLI(t, append([]string{"check", "cncf", "--project", "thanos", "--input", privateInput, "--now", "2026-09-12T10:00:00Z"}, extra...)...)
		if code != ExitUsage || stdout != "" || strings.Contains(stderr, privateInput) {
			t.Fatalf("wrong-project flags accepted: args=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
}
