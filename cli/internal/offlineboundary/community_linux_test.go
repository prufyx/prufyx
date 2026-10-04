// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package offlineboundary

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// TestOfflineBoundaryLinuxCommunityJourneys is the Go-owned replacement for
// the retired shell matrix. It is deliberately opt-in: it needs the explicit
// Linux namespace and strace prerequisites documented by Requirements.
func TestOfflineBoundaryLinuxCommunityJourneys(t *testing.T) {
	if os.Getenv("PRUFYX_OFFLINE_BOUNDARY_ENABLE") != "1" {
		t.Skip("requires explicit Linux namespace boundary execution")
	}
	cli := offlineCLIRoot(t)
	work := t.TempDir()
	mustPrivateDir(t, work)
	binary := offlineBuild(t, cli, work, "prufyx", "./cmd/prufyx-community")
	control := offlineBuild(t, cli, work, "positive-control", "./cmd/prufyx-offline-boundary")

	run := func(name string, want int, argv ...string) Result {
		t.Helper()
		trace := filepath.Join(work, "trace-"+name)
		mustPrivateDir(t, trace)
		results, err := Run(t.Context(), Config{Binary: binary, PositiveControl: []string{control, "positive-control"}, WorkDir: trace, UID: os.Getuid(), GID: os.Getgid(), Scenarios: []Scenario{{Name: name, Argv: argv, ExpectedExit: want}}})
		if err != nil || len(results) != 2 || !results[0].NetworkObserved || results[1].NetworkObserved {
			t.Fatalf("%s boundary result=%#v err=%v", name, results, err)
		}
		return results[1]
	}
	assertJSON := func(name, output string, want map[string]string) {
		t.Helper()
		var value map[string]any
		if err := json.Unmarshal([]byte(output), &value); err != nil {
			t.Fatalf("%s JSON: %v", name, err)
		}
		for key, expected := range want {
			if got, _ := value[key].(string); got != expected {
				t.Fatalf("%s %s=%q want=%q", name, key, got, expected)
			}
		}
	}

	if got := run("help", 0, "--help"); !strings.Contains(got.Stdout, "prufyx Community") {
		t.Fatal("help output missing Community usage")
	}
	assertJSON("version", run("version", 0, "version").Stdout, map[string]string{"command": "version"})

	karmada := offlineCopyFixture(t, cli, work, "karmada-input.json")
	karmadaRaw := mustRead(t, karmada)
	check := run("karmada-check", 10, "check", "cncf", "--project", "karmada", "--input", karmada, "--input-digest", offlineDigest(karmadaRaw), "--now", "2026-09-09T06:00:00Z", "--format", "json")
	assertJSON("karmada check", check.Stdout, map[string]string{"assessment": "UNKNOWN"})

	policy := offlineCopyFixture(t, cli, work, "proposed-karmada-propagation-policy.json")
	prepared := run("karmada-prepare", 0, "prepare", "cncf", "--project", "karmada", "--input", policy, "--from", "1.18.3", "--to", "1.19.0", "--distribution", "official_upstream", "--target-policy-crd-admission", "required", "--input-digest", offlineDigest(mustRead(t, policy)), "--format", "input")
	preparedPath := offlineWrite(t, work, "karmada-prepared.json", []byte(prepared.Stdout))
	if !json.Valid([]byte(prepared.Stdout)) || strings.Contains(prepared.Stdout, "OFFLINE-BOUNDARY") {
		t.Fatal("Karmada preparation did not produce a redacted canonical declaration")
	}
	_ = preparedPath

	ciliumRaw := []byte(`{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"OFFLINE-BOUNDARY-CILIUM-CANARY"},"spec":{"ingress":[{"fromRequires":[{"matchLabels":{"prufyx.io/offline-boundary":"OFFLINE-BOUNDARY-CILIUM-CANARY"}}]}]}}`)
	cilium := offlineWrite(t, work, "cilium.json", ciliumRaw)
	ciliumPrepared := run("cilium-prepare", 0, "prepare", "cncf", "--project", "cilium", "--input", cilium, "--from", "1.18.6", "--to", "1.19.0", "--input-digest", offlineDigest(ciliumRaw), "--format", "input")
	ciliumInput := offlineWrite(t, work, "cilium-prepared.json", []byte(ciliumPrepared.Stdout))
	if strings.Contains(ciliumPrepared.Stdout, "OFFLINE-BOUNDARY-CILIUM-CANARY") {
		t.Fatal("Cilium private canary escaped canonical input")
	}
	run("cilium-check", 10, "check", "cncf", "--project", "cilium", "--input", ciliumInput, "--input-digest", offlineDigest([]byte(ciliumPrepared.Stdout)), "--now", "2026-09-09T06:00:00Z", "--format", "json")

	scanInput := offlineWrite(t, work, "scan-applyset.yaml", []byte("apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: OFFLINE-BOUNDARY-SCAN-CANARY\n"))
	scanned := run("scan", 10, "scan", scanInput, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--redact", "--now", "2026-10-04T00:00:00Z", "--format", "json")
	assertJSON("scan", scanned.Stdout, map[string]string{"verdict": "BLOCKED"})
	if strings.Contains(scanned.Stdout, "OFFLINE-BOUNDARY-SCAN-CANARY") || !strings.Contains(scanned.Stdout, `"networkUsed":false`) {
		t.Fatal("redacted scan leaked an object name or claimed network use")
	}

	// The subprocess verifies TUF expiry against its real clock. Generate the
	// ephemeral fixture now so this boundary test does not expire with its seed.
	artifacts, err := knowledgefixture.GenerateConstraints(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root := offlineWrite(t, work, knowledgefixture.RootName, artifacts.Root)
	packagePath := offlineWrite(t, work, knowledgefixture.Revision1Name, artifacts.Revision1)
	var manifest knowledgefixture.Manifest
	if err := json.Unmarshal(artifacts.Manifest, &manifest); err != nil || len(manifest.Revisions) == 0 {
		t.Fatalf("fixture manifest: %v", err)
	}
	revision := manifest.Revisions[0]
	verify := run("knowledge-verify", 0, "db", "verify", packagePath, "--profile", "cncf", "--bootstrap-root", root, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest, "--expected-package-digest", revision.PackageDigest, "--expected-revision", revision.Revision, "--expected-bundle-digest", revision.BundleDigest, "--format", "json")
	assertJSON("knowledge verify", verify.Stdout, map[string]string{"status": "VERIFIED"})
	store := filepath.Join(work, "store")
	mustPrivateDir(t, store)
	imported := run("knowledge-import", 0, "db", "import", packagePath, "--profile", "cncf", "--db-root", store, "--bootstrap-root", root, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest, "--expected-revision", revision.Revision, "--expected-bundle-digest", revision.BundleDigest, "--format", "json")
	assertJSON("knowledge import", imported.Stdout, map[string]string{"status": "IMPORTED"})
	var importDoc struct {
		TrustReceiptDigest string `json:"trustReceiptDigest"`
	}
	if err := json.Unmarshal([]byte(imported.Stdout), &importDoc); err != nil || importDoc.TrustReceiptDigest == "" {
		t.Fatalf("import receipt: %v", err)
	}
	inputRaw := []byte(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.12.5","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/kyverno/kyverno","version":"1.13.0","facts":[{"id":"component.kyverno.reports_chunk_size_flag_present","state":"declared","boolValue":true}]}]}}`)
	input := offlineWrite(t, work, "kyverno-input.json", inputRaw)
	external := run("knowledge-external", 11, "check", "cncf", "--project", "kyverno", "--input", input, "--input-digest", offlineDigest(inputRaw), "--knowledge-db", store, "--knowledge-revision", revision.Revision, "--knowledge-bundle-digest", revision.BundleDigest, "--knowledge-trust-receipt-digest", importDoc.TrustReceiptDigest, "--format", "json")
	assertJSON("knowledge external", external.Stdout, map[string]string{"status": "CANDIDATE_ONLY", "assessment": "UNKNOWN"})
	run("knowledge-status", 0, "db", "status", "--profile", "cncf", "--db-root", store, "--format", "json")
	replay := offlineWrite(t, work, "external-report.json", []byte(external.Stdout))
	matched := run("knowledge-replay", 11, "check", "cncf", "--project", "kyverno", "--input", input, "--input-digest", offlineDigest(inputRaw), "--knowledge-db", store, "--knowledge-revision", revision.Revision, "--knowledge-bundle-digest", revision.BundleDigest, "--knowledge-trust-receipt-digest", importDoc.TrustReceiptDigest, "--replay-report", replay, "--format", "json")
	assertJSON("knowledge replay", matched.Stdout, map[string]string{"mode": "historical", "status": "MATCH"})
}

func offlineCLIRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && info.Mode().IsRegular() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func offlineBuild(t *testing.T, cli, work, name, target string) string {
	t.Helper()
	path := filepath.Join(work, name)
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", path, target)
	command.Dir = cli
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", target, err, output)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func offlineCopyFixture(t *testing.T, cli, work, name string) string {
	t.Helper()
	raw := mustRead(t, filepath.Join(cli, "examples", "cncf", name))
	return offlineWrite(t, work, name, raw)
}

func offlineWrite(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustPrivateDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func offlineDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
