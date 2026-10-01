// SPDX-License-Identifier: AGPL-3.0-only

package localkind

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	switch os.Getenv("PRUFYX_LOCAL_KIND_TEST_HELPER") {
	case "exit0":
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	case "stderr0":
		_, _ = os.Stderr.WriteString("private helper diagnostic")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateRejectsUnsafeManualInputs(t *testing.T) {
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "tool")
	if err := os.WriteFile(bin, []byte("tool"), 0700); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(tmp, "fixtures")
	if err := os.Mkdir(fixture, 0700); err != nil {
		t.Fatal(err)
	}
	base := Options{Prufyx: bin, Collector: bin, FixtureDir: fixture, Evidence: filepath.Join(tmp, "evidence")}
	if err := validate(&base); err != nil {
		t.Fatalf("validate admitted options: %v", err)
	}
	for name, mutate := range map[string]func(*Options){
		"relative binary":   func(o *Options) { o.Prufyx = "tool" },
		"existing evidence": func(o *Options) { _ = os.Mkdir(o.Evidence, 0700) },
		"relative evidence": func(o *Options) { o.Evidence = "evidence" },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			mutate(&o)
			if err := validate(&o); err == nil {
				t.Fatal("validate accepted unsafe manual input")
			}
		})
	}
}

func TestRunRejectsNonzeroExit(t *testing.T) {
	env := append(os.Environ(), "PRUFYX_LOCAL_KIND_TEST_HELPER=exit7")
	if err := run(t.Context(), helperExecutable(t), nil, env); err == nil {
		t.Fatal("run accepted a nonzero command exit")
	}
}

func TestKindOutputRejectsNonzeroExit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := kindOutput(t.Context(), "get", "clusters"); err == nil {
		t.Fatal("kind output accepted an unavailable command")
	}
}

func TestKindRejectsNonzeroExit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kind")
	if err := os.Symlink(helperExecutable(t), path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("PRUFYX_LOCAL_KIND_TEST_HELPER", "exit7")
	if err := kind(t.Context(), "get", "clusters"); err == nil {
		t.Fatal("kind accepted a nonzero command exit")
	}
}

func TestRunExitPropagatesDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	env := append(os.Environ(), "PRUFYX_LOCAL_KIND_TEST_HELPER=exit0")
	if _, _, _, err := runExit(ctx, helperExecutable(t), nil, env); err == nil {
		t.Fatal("runExit hid a cancelled context")
	}
}

func TestRunExitCapturesSuccessfulStderr(t *testing.T) {
	env := append(os.Environ(), "PRUFYX_LOCAL_KIND_TEST_HELPER=stderr0")
	_, stderr, exit, err := runExit(t.Context(), helperExecutable(t), nil, env)
	if err != nil || exit != 0 || string(stderr) != "private helper diagnostic" {
		t.Fatalf("runExit stderr=%q exit=%d err=%v", stderr, exit, err)
	}
}

func TestZeroReplicaProof(t *testing.T) {
	if !zeroReplicas([]byte("0\n")) || zeroReplicas([]byte("1")) || zeroReplicas(nil) {
		t.Fatal("replica proof admitted the wrong value")
	}
}

func TestClusterOwnershipRequiresProvenAbsence(t *testing.T) {
	deleteOK := func() error { return nil }
	if err := verifyClusterDeleted(deleteOK, func() (string, error) { return "other\n", nil }, "owned"); err != nil {
		t.Fatal(err)
	}
	if err := verifyClusterDeleted(deleteOK, func() (string, error) { return "owned\n", nil }, "owned"); err == nil {
		t.Fatal("accepted a cluster that remained after deletion")
	}
	if err := verifyClusterDeleted(deleteOK, func() (string, error) { return "", context.Canceled }, "owned"); err == nil {
		t.Fatal("accepted an unverified cluster inventory")
	}
}

func TestIdentityEvidenceRequiresStrictDevelopmentOrReleaseShape(t *testing.T) {
	valid := []byte(`{"result":{"status":"OK","reasonCode":"build_identity_reported"},"data":{"version":"dev","releaseState":"development","sourceRevision":"unbound","sourceTreeDigest":"unbound","allowlistDigest":"unbound","buildProfile":"development","goVersion":"go1.26.8","candidateOnly":true}}`)
	identity, err := validIdentity(valid)
	if err != nil || identity.ReleaseState != "development" || !identity.CandidateOnly {
		t.Fatalf("validIdentity=%+v err=%v", identity, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"result":{"status":"OK","reasonCode":"other"},"data":{"candidateOnly":true}}`),
		[]byte(`{"result":{"status":"OK","reasonCode":"build_identity_reported"},"data":{"version":"v1.2.3","releaseState":"release","sourceRevision":"abc1234","sourceTreeDigest":"bad","allowlistDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","buildProfile":"linux-arm64","goVersion":"go1.26.8","candidateOnly":true}}`),
	} {
		if _, err := validIdentity(invalid); err == nil {
			t.Fatal("accepted malformed identity evidence")
		}
	}
}

// TestIdentityEvidenceRejectsCommunityProfile proves that a well-formed
// community-release identity (as produced by .github/workflows/release.yml
// and accepted by buildidentity for `prufyx version`) is still refused here,
// where only the strict signed-release profile is trusted. A community
// profile must never pass a check that requires a signed release.
func TestIdentityEvidenceRejectsCommunityProfile(t *testing.T) {
	community := []byte(`{"result":{"status":"OK","reasonCode":"build_identity_reported"},"data":{"version":"v1.2.3","releaseState":"release","sourceRevision":"abc1234567","sourceTreeDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowlistDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","buildProfile":"community-darwin-arm64","goVersion":"go1.26.8","candidateOnly":true}}`)
	if _, err := validIdentity(community); err == nil {
		t.Fatal("accepted a community-release profile where a signed-release profile is required")
	}
}

func TestProofReceiptRetainsLegacyEvidenceBindings(t *testing.T) {
	identity := identityEvidence{Version: "dev", ReleaseState: "development", SourceRevision: "unbound", SourceTreeDigest: "unbound", AllowlistDigest: "unbound", BuildProfile: "development", GoVersion: "go1.26.8", CandidateOnly: true}
	receipt := proofReceipt("2026-09-11T00:00:00Z", "sha256:binary", "2026-09-11T00:00:01Z", "sha256:replay", identity)
	fixture, ok := receipt["fixture"].(map[string]any)
	if !ok || fixture["replicas"] != 0 {
		t.Fatal("receipt lost the zero-replica proof")
	}
	evaluator, ok := receipt["evaluator"].(map[string]any)
	if !ok || evaluator["identity"] != identity {
		t.Fatal("receipt lost minimized evaluator identity")
	}
	evaluation, ok := receipt["evaluation"].(map[string]any)
	if !ok || evaluation["replayDigest"] != "sha256:replay" || evaluation["sameInputReplayByteEqual"] != true {
		t.Fatal("receipt lost replay evidence")
	}
}

func TestTaskWorkspaceIsGoneBeforeCleanupReceipt(t *testing.T) {
	work := filepath.Join(t.TempDir(), "work")
	kube := filepath.Join(work, "kubeconfig")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kube, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeTaskWorkspace(work, kube); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(work); !os.IsNotExist(err) {
		t.Fatal("task workspace still exists")
	}
}
