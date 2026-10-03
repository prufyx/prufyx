// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releaseworkflow"
	"golang.org/x/sys/unix"
)

func TestMaintainerCLI_Help(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"help"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("out=%q err=%q", out.String(), errOut.String())
	}
}

func TestMaintainerCLI_ProjectExactTagsAreTheOnlyNewRepeatableOption(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(parent, "request.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"project", "init", "--repository", "https://github.com/acme/sample", "--exact-tag", "v1.0.0", "--exact-tag", "v2.0.0", "--license-anchor-tag", "v2.0.0", "--output", request}, &out, &errOut); err != nil {
		t.Fatalf("repeatable exact tag rejected: %v %s", err, errOut.String())
	}
	if _, err := os.Stat(request); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"project", "init", "--repository", "https://github.com/acme/sample", "--repository", "https://github.com/acme/other", "--output", filepath.Join(parent, "bad.json")}, &out, &errOut); err == nil {
		t.Fatal("unrelated duplicate accepted")
	}
	if err := run([]string{"project", "init", "--repository", "https://github.com/acme/sample", "--exact-tag", "v1.0.0", "--license-anchor-tag", "v1.0.0", "--license-anchor-tag", "v1.0.0", "--output", filepath.Join(parent, "bad-exact.json")}, &out, &errOut); err == nil || err.Error() != "prufyx-maintainer: duplicate option rejected" {
		t.Fatalf("exact-tag singleton duplicate not rejected: %v", err)
	}
}

func TestMaintainerCLI_ReviewRecordHelpAndOptionErrorsAreSanitized(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"review-record", "verify", "--help"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "usage: prufyx-maintainer review-record verify") || !strings.Contains(out.String(), "--source-manifest") || errOut.Len() != 0 {
		t.Fatalf("out=%q err=%q", out.String(), errOut.String())
	}

	tests := [][]string{
		{"review-record", "verify", "--record", "PRIVATE_PATH_CANARY"},
		{"review-record", "verify", "--record", "PRIVATE_PATH_CANARY", "--record", "second"},
		{"review-record", "verify", "--unknown", "PRIVATE_PATH_CANARY"},
		{"review-record", "verify", "PRIVATE_PATH_CANARY"},
	}
	for _, args := range tests {
		out.Reset()
		errOut.Reset()
		err := run(args, &out, &errOut)
		if err == nil || out.Len() != 0 || errOut.Len() != 0 || strings.Contains(err.Error(), "PRIVATE_PATH_CANARY") {
			t.Fatalf("unsafe option failure: args=%v stdout=%q stderr=%q err=%q", args, out.String(), errOut.String(), err)
		}
	}
}

func TestMaintainerCLI_FlagErrorsAreSanitized(t *testing.T) {
	tests := [][]string{{"export-knowledge", "--PRIVATE_ARGUMENT_CANARY"}, {"package-knowledge", "--PRIVATE_ARGUMENT_CANARY"}, {"knowledge-publish", "--PRIVATE_ARGUMENT_CANARY"}, {"knowledge-sign", "--PRIVATE_ARGUMENT_CANARY"}, {"support-inventory", "--PRIVATE_ARGUMENT_CANARY"}, {"contribution", "validate", "--PRIVATE_ARGUMENT_CANARY"}, {"review-record", "verify", "--record", "PRIVATE_ARGUMENT_CANARY"}, {"release-gate", "generate", "--PRIVATE_ARGUMENT_CANARY"}, {"release-metadata", "--PRIVATE_ARGUMENT_CANARY"}, {"staging-receipt", "create", "--PRIVATE_ARGUMENT_CANARY"}}
	for _, args := range tests {
		var out, errOut bytes.Buffer
		err := run(args, &out, &errOut)
		if err == nil {
			t.Fatalf("expected rejection for %v", args)
		}
		if strings.Contains(err.Error(), "PRIVATE_ARGUMENT_CANARY") || strings.Contains(errOut.String(), "PRIVATE_ARGUMENT_CANARY") || errOut.Len() != 0 {
			t.Fatalf("argument leaked: error=%q stderr=%q", err, errOut.String())
		}
	}
}

func TestMaintainerCLIRejectsDuplicateLongOption(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"release-gate", "generate", "--source-root", "one", "--source-root=two"}, &out, &errOut); err == nil {
		t.Fatal("duplicate singleton option accepted")
	}
	if err := run([]string{"knowledge-publish", "finalize-role", "--signatures", "one", "--signatures=two"}, &out, &errOut); err == nil || err.Error() != "prufyx-maintainer: duplicate option rejected" {
		t.Fatalf("repeated signature option escaped its exact route: %v", err)
	}
	if err := run([]string{"knowledge-publish", "finalize-root-transition", "--output", "one", "--output=two"}, &out, &errOut); err == nil || err.Error() != "prufyx-maintainer: duplicate option rejected" {
		t.Fatalf("duplicate singleton accepted on root-transition route: %v", err)
	}
}

func TestMaintainerCLIFinalizesRootTransitionWithRepeatedSignatures(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("operator passphrase 123")
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	trustedDir := filepath.Join(parent, "trusted-keys")
	templateDir := filepath.Join(parent, "template-keys")
	trusted, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: trustedDir, RootExpires: expires, Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	template, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: templateDir, RootExpires: expires, Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := knowledgepublish.PrepareRootTransition(knowledgepublish.RootTransitionOptions{TrustedRoot: trusted.Root, TrustedRootDigest: trusted.RootDigest, SuccessorTemplate: template.Root, SuccessorTemplateDigest: template.RootDigest})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture := func(name string, raw []byte) string {
		t.Helper()
		fixture := filepath.Join(parent, name)
		if err := os.WriteFile(fixture, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return fixture
	}
	trustedPath := writeFixture("trusted.root.json", trusted.Root)
	templatePath := writeFixture("template.root.json", template.Root)
	unsignedPath := writeFixture("unsigned.root.json", prepared.UnsignedMetadata)
	requestPath := writeFixture("request.json", prepared.Request)
	payloadDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(prepared.Payload))
	sign := func(authority, keyPath string) []byte {
		t.Helper()
		encryptedKey, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := knowledgesign.SignRootTransition(knowledgesign.RootTransitionSignOptions{
			TrustedRoot: trusted.Root, TrustedRootDigest: trusted.RootDigest,
			SuccessorTemplate: template.Root, SuccessorTemplateDigest: template.RootDigest,
			UnsignedMetadata: prepared.UnsignedMetadata, Request: prepared.Request,
			ExpectedPayloadDigest: payloadDigest, Authority: authority,
			EncryptedKey: encryptedKey, Passphrase: append([]byte(nil), passphrase...),
		})
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	trustedEnvelope := writeFixture("trusted-signature.json", sign("trusted", filepath.Join(trustedDir, "root.key.pem")))
	successorEnvelope := writeFixture("successor-signature.json", sign("successor", filepath.Join(templateDir, "root.key.pem")))
	output := filepath.Join(parent, "2.root.json")
	var stdout, stderr bytes.Buffer
	err = run([]string{
		"knowledge-publish", "finalize-root-transition",
		"--trusted-root", trustedPath,
		"--trusted-root-digest", trusted.RootDigest,
		"--successor-template", templatePath,
		"--successor-template-digest", template.RootDigest,
		"--unsigned", unsignedPath,
		"--request", requestPath,
		"--signatures", trustedEnvelope,
		"--signatures", successorEnvelope,
		"--output", output,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"FINALIZED"`) {
		t.Fatalf("unexpected finalization output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if raw, readErr := os.ReadFile(output); readErr != nil || len(raw) == 0 {
		t.Fatalf("finalized root missing: bytes=%d err=%v", len(raw), readErr)
	}
}

func TestMaintainerCLIFinalizesRotatedPackage(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("rotated cli test passphrase 123")
	expires := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	oldDir, successorDir := filepath.Join(parent, "old-keys"), filepath.Join(parent, "successor-keys")
	old, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: oldDir, RootExpires: expires, Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	successorTemplate, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: successorDir, RootExpires: expires, Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	transitionOptions := knowledgepublish.RootTransitionOptions{TrustedRoot: old.Root, TrustedRootDigest: old.RootDigest, SuccessorTemplate: successorTemplate.Root, SuccessorTemplateDigest: successorTemplate.RootDigest}
	transition, err := knowledgepublish.PrepareRootTransition(transitionOptions)
	if err != nil {
		t.Fatal(err)
	}
	transitionPayloadDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(transition.Payload))
	signTransition := func(authority, keyPath string) []byte {
		t.Helper()
		key, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			for i := range key {
				key[i] = 0
			}
		}()
		raw, err := knowledgesign.SignRootTransition(knowledgesign.RootTransitionSignOptions{TrustedRoot: old.Root, TrustedRootDigest: old.RootDigest, SuccessorTemplate: successorTemplate.Root, SuccessorTemplateDigest: successorTemplate.RootDigest, UnsignedMetadata: transition.UnsignedMetadata, Request: transition.Request, ExpectedPayloadDigest: transitionPayloadDigest, Authority: authority, EncryptedKey: key, Passphrase: append([]byte(nil), passphrase...)})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	successor, _, err := knowledgepublish.FinalizeRootTransition(knowledgepublish.RootTransitionFinalizeOptions{RootTransitionOptions: transitionOptions, UnsignedMetadata: transition.UnsignedMetadata, Request: transition.Request, Signatures: [][]byte{signTransition("trusted", filepath.Join(oldDir, "root.key.pem")), signTransition("successor", filepath.Join(successorDir, "root.key.pem"))}})
	if err != nil {
		t.Fatal(err)
	}
	successorDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(successor))
	target, err := cncfcheck.ExportEmbeddedExternalBundle("94")
	if err != nil {
		t.Fatal(err)
	}
	signRole := func(role string, preparation knowledgepublish.Preparation) []byte {
		t.Helper()
		key, err := os.ReadFile(filepath.Join(successorDir, role+".key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			for i := range key {
				key[i] = 0
			}
		}()
		envelope, err := knowledgesign.SignRole(knowledgesign.SignOptions{Root: successor, RootDigest: successorDigest, Role: role, Unsigned: preparation.UnsignedMetadata, ExpectedPayloadDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(preparation.Payload)), EncryptedKey: key, Passphrase: append([]byte(nil), passphrase...)})
		if err != nil {
			t.Fatal(err)
		}
		result, err := knowledgepublish.FinalizeRole(successor, successorDigest, role, preparation.UnsignedMetadata, envelope)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	targetsPreparation, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: successor, RootDigest: successorDigest, Target: target, Version: 1, Expires: time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	targets := signRole("targets", targetsPreparation)
	snapshotPreparation, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: successor, RootDigest: successorDigest, Target: target, Targets: targets, Version: 1, Expires: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := signRole("snapshot", snapshotPreparation)
	timestampPreparation, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: successor, RootDigest: successorDigest, Target: target, Targets: targets, Snapshot: snapshot, Version: 1, Expires: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	timestamp := signRole("timestamp", timestampPreparation)
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	output := filepath.Join(parent, "rotated.tar")
	var stdout, stderr bytes.Buffer
	err = run([]string{"knowledge-publish", "finalize-rotated-package", "--initial-root", write("1.root.json", old.Root), "--initial-root-digest", old.RootDigest, "--successor-root", write("2.root.json", successor), "--target", write("constraints.json", target), "--targets", write("targets.json", targets), "--snapshot", write("snapshot.json", snapshot), "--timestamp", write("timestamp.json", timestamp), "--output", output}, &stdout, &stderr)
	if err != nil || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"VERIFIED_FOR_PACKAGING"`) || !strings.Contains(stdout.String(), `"rootDigest":"`+old.RootDigest+`"`) {
		t.Fatalf("route stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
	if raw, readErr := os.ReadFile(output); readErr != nil || len(raw) == 0 {
		t.Fatalf("rotated output bytes=%d err=%v", len(raw), readErr)
	}
	stdout.Reset()
	err = run([]string{"knowledge-publish", "finalize-rotated-package", "--initial-root", filepath.Join(parent, "1.root.json"), "--initial-root-digest", old.RootDigest, "--successor-root", filepath.Join(parent, "2.root.json"), "--target", filepath.Join(parent, "constraints.json"), "--targets", filepath.Join(parent, "targets.json"), "--snapshot", filepath.Join(parent, "snapshot.json"), "--timestamp", filepath.Join(parent, "timestamp.json"), "--output", output}, &stdout, &stderr)
	if err == nil || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("existing output accepted: stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
	for i := range passphrase {
		passphrase[i] = 0
	}
}

func TestMaintainerCLI_OutputPairRejectsUnsafeTargets(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "inventory.json")
	second := filepath.Join(parent, "inventory.md")
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("PRIVATE_CANARY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", first); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected symlink rejection")
	}
	raw, _ := os.ReadFile(victim)
	if string(raw) != "PRIVATE_CANARY" {
		t.Fatal("symlink target changed")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected FIFO rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, first); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected hard-link rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeOutputPair(first, []byte("json"), second, []byte("markdown")); err == nil {
		t.Fatal("expected directory rejection")
	}
}

func TestMaintainerCLIKnowledgeReleasePlanSecondOutputFailureRetainsPackageAndExistingPlan(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(dir, "package.tar")
	planPath := filepath.Join(dir, "plan.json")
	oldPlan := []byte("existing-plan")
	if err := os.WriteFile(planPath, oldPlan, 0o600); err != nil {
		t.Fatal(err)
	}
	packageRaw := []byte("verified-package")
	if err := writePackageAndPlan(packagePath, packageRaw, planPath, []byte("new-plan")); err == nil {
		t.Fatal("pre-existing plan did not fail ordered publication")
	}
	gotPackage, packageErr := os.ReadFile(packagePath)
	gotPlan, planErr := os.ReadFile(planPath)
	if packageErr != nil || planErr != nil || !bytes.Equal(gotPackage, packageRaw) || !bytes.Equal(gotPlan, oldPlan) {
		t.Fatalf("ordered failure package=%q packageErr=%v plan=%q planErr=%v", gotPackage, packageErr, gotPlan, planErr)
	}
}

func TestMaintainerCLI_OutputPairRollsBackSecondRenameFailure(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "inventory.json")
	second := filepath.Join(parent, "inventory.md")
	if err := os.WriteFile(first, []byte("old-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("old-markdown"), 0o644); err != nil {
		t.Fatal(err)
	}
	original := renameAt
	calls := 0
	renameAt = func(oldFD int, old string, newFD int, new string) error {
		calls++
		if calls == 2 {
			return errors.New("injected second rename failure")
		}
		return original(oldFD, old, newFD, new)
	}
	defer func() { renameAt = original }()
	if err := writeOutputPair(first, []byte("new-json"), second, []byte("new-markdown")); err == nil {
		t.Fatal("expected injected failure")
	}
	firstRaw, _ := os.ReadFile(first)
	secondRaw, _ := os.ReadFile(second)
	if string(firstRaw) != "old-json" || string(secondRaw) != "old-markdown" {
		t.Fatalf("mixed output: %q %q", firstRaw, secondRaw)
	}
}

func TestMaintainerCLI_ReadOutputPairRejectsUnsafeTargets(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "inventory.json")
	second := filepath.Join(parent, "inventory.md")
	victim := filepath.Join(parent, "victim")
	if err := os.WriteFile(victim, []byte("json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("markdown"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOutputPair(first, second); err == nil {
		t.Fatal("expected symlink rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(first, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOutputPair(first, second); err == nil {
		t.Fatal("expected FIFO rejection")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readOutputPair(first, second); err == nil {
		t.Fatal("expected hard-link rejection")
	}
}

func TestMaintainerCLI_SupportInventory_CheckAcceptedFiles(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"support-inventory", "--selected-source-manifest", filepath.Join(root, "docs/data/selected-source-records-v1.json"), "--json-output", filepath.Join(root, "docs/generated/community-support-inventory.json"), "--markdown-output", filepath.Join(root, "docs/generated/community-support-inventory.md"), "--check"}
	var out, errOut bytes.Buffer
	if err = run(args, &out, &errOut); err != nil {
		t.Fatalf("check failed: %v stderr=%q", err, errOut.String())
	}
}

func TestMaintainerCLIExportKnowledgeWritesNewTarget(t *testing.T) {
	output := filepath.Join(t.TempDir(), "constraints.v1.json")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"export-knowledge", "--profile", "cncf", "--revision", "73", "--output", output}, &stdout, &stderr); err != nil {
		t.Fatalf("export failed: %v stderr=%q", err, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("output info=%v err=%v", info, err)
	}
	if err := run([]string{"export-knowledge", "--profile", "cncf", "--revision", "73", "--output", output}, &stdout, &stderr); err == nil {
		t.Fatal("existing output accepted")
	}
}

func TestMaintainerCLIKnowledgeSignRejectsNonTTYWithoutEchoingArguments(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "PRIVATE_PATH_CANARY")
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = readEnd
	defer func() {
		os.Stdin = originalStdin
		_ = readEnd.Close()
		_ = writeEnd.Close()
	}()
	var stdout, stderr bytes.Buffer
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	err = run([]string{"knowledge-sign", "init", "--key-dir", keyDir, "--root-expires", expires}, &stdout, &stderr)
	if err == nil {
		t.Fatal("non-TTY signing initialization accepted")
	}
	if strings.Contains(err.Error(), "PRIVATE_PATH_CANARY") || strings.Contains(stdout.String()+stderr.String(), "PRIVATE_PATH_CANARY") || strings.Contains(stderr.String(), "Passphrase") {
		t.Fatalf("path or prompt leaked err=%q stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if _, statErr := os.Stat(keyDir); !os.IsNotExist(statErr) {
		t.Fatalf("key directory changed stat=%v", statErr)
	}
}

func TestMaintainerCLIKnowledgeSignVerifyKeyRejectsNonTTYWithoutEchoingArguments(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "keys")
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	initialized, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: keyDir, RootExpires: expires, Passphrase: []byte("operator passphrase 123")})
	if err != nil {
		t.Fatal(err)
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdin := os.Stdin
	os.Stdin = readEnd
	defer func() {
		os.Stdin = originalStdin
		_ = readEnd.Close()
		_ = writeEnd.Close()
	}()
	var stdout, stderr bytes.Buffer
	err = run([]string{"knowledge-sign", "verify-key", "--root", filepath.Join(keyDir, "root.json"), "--root-digest", initialized.RootDigest, "--role", "targets", "--key", filepath.Join(keyDir, "targets.key.pem")}, &stdout, &stderr)
	if err == nil {
		t.Fatal("non-TTY restored-key verification accepted")
	}
	for _, canary := range []string{"keys", initialized.RootDigest, "Passphrase"} {
		if strings.Contains(err.Error(), canary) || strings.Contains(stdout.String()+stderr.String(), canary) {
			t.Fatalf("sensitive value leaked: error=%q stdout=%q stderr=%q", err, stdout.String(), stderr.String())
		}
	}
}

func TestMaintainerCLISignerKeyRequiresAbsolutePath(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "keys")
	if _, err := knowledgesign.Init(knowledgesign.InitOptions{
		KeyDir: keyDir, RootExpires: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339),
		Passphrase: []byte("operator passphrase 123"),
	}); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(keyDir, "targets.key.pem")
	if raw, err := signerKey(abs); err != nil || len(raw) == 0 {
		t.Fatalf("absolute encrypted key rejected: bytes=%d err=%v", len(raw), err)
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(keyDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := signerKey("targets.key.pem"); err == nil {
		t.Fatal("relative encrypted key accepted")
	}
}

func TestMaintainerCLIRootTransitionBindingFailurePrecedesPassphraseAndOutput(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	trustedDir := filepath.Join(parent, "trusted-keys")
	templateDir := filepath.Join(parent, "template-keys")
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	trusted, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: trustedDir, RootExpires: expires, Passphrase: []byte("operator passphrase 123")})
	if err != nil {
		t.Fatal(err)
	}
	template, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: templateDir, RootExpires: expires, Passphrase: []byte("operator passphrase 123")})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := knowledgepublish.PrepareRootTransition(knowledgepublish.RootTransitionOptions{TrustedRoot: trusted.Root, TrustedRootDigest: trusted.RootDigest, SuccessorTemplate: template.Root, SuccessorTemplateDigest: template.RootDigest})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	trustedPath := writeFixture("trusted.root.json", trusted.Root)
	templatePath := writeFixture("template.root.json", template.Root)
	unsignedPath := writeFixture("unsigned.root.json", prepared.UnsignedMetadata)
	tamperedRequest := append([]byte(nil), prepared.Request...)
	tamperedRequest[len(tamperedRequest)-2] ^= 1
	requestPath := writeFixture("tampered.request.json", tamperedRequest)
	output := filepath.Join(parent, "must-not-exist.envelope.json")
	prompted := false
	originalPrompt := promptRootTransitionPassphrase
	promptRootTransitionPassphrase = func(io.Writer, bool) ([]byte, error) {
		prompted = true
		return []byte("operator passphrase 123"), nil
	}
	defer func() { promptRootTransitionPassphrase = originalPrompt }()
	var stdout, stderr bytes.Buffer
	err = runKnowledgeSignRootTransition([]string{
		"--trusted-root", trustedPath,
		"--trusted-root-digest", trusted.RootDigest,
		"--successor-template", templatePath,
		"--successor-template-digest", template.RootDigest,
		"--unsigned", unsignedPath,
		"--request", requestPath,
		"--payload-digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--authority", "trusted",
		"--key", filepath.Join(trustedDir, "root.key.pem"),
		"--output", output,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("tampered transition binding accepted")
	}
	if prompted {
		t.Fatal("tampered transition binding prompted for a passphrase")
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("binding failure wrote output: %v", statErr)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("binding failure wrote command output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestMaintainerCLIKnowledgeSignHelpDoesNotPromptOrWrite(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"knowledge-sign", "init", "--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "knowledge-sign init") || stderr.Len() != 0 {
		t.Fatalf("unexpected help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if err := run([]string{"knowledge-sign", "sign-role", "--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "knowledge-sign sign-role") || stderr.Len() != 0 {
		t.Fatalf("unexpected help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if err := run([]string{"knowledge-sign", "verify-key", "--help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "knowledge-sign verify-key") || stderr.Len() != 0 {
		t.Fatalf("unexpected help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestMaintainerCLI_RootTransitionCommandsRouteAndRedact(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"knowledge-publish", "prepare-root-transition", "--help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "prepare-root-transition") || errOut.Len() != 0 {
		t.Fatalf("publisher help out=%q err=%q stderr=%q", out.String(), err, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if err := run([]string{"knowledge-publish", "finalize-root-transition", "--help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "finalize-root-transition") || !strings.Contains(out.String(), "--signatures") || errOut.Len() != 0 {
		t.Fatalf("publisher finalizer help out=%q err=%q stderr=%q", out.String(), err, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if err := run([]string{"knowledge-sign", "sign-root-transition", "--help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "sign-root-transition") || errOut.Len() != 0 {
		t.Fatalf("sign help out=%q err=%q stderr=%q", out.String(), err, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	err := run([]string{"knowledge-publish", "prepare-root-transition", "--trusted-root", "PRIVATE_ROOT_CANARY"}, &out, &errOut)
	if err == nil || strings.Contains(err.Error(), "PRIVATE_ROOT_CANARY") || strings.Contains(errOut.String(), "PRIVATE_ROOT_CANARY") {
		t.Fatalf("publisher rejection leaked: err=%q stderr=%q", err, errOut.String())
	}
}

func TestMaintainerCLI_RotatedPackageRouteAllowsOnlySuccessorRepetition(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"knowledge-publish", "finalize-rotated-package", "--help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "finalize-rotated-package") || !strings.Contains(out.String(), "--successor-root") || !strings.Contains(out.String(), "N+1..K") || !strings.Contains(out.String(), "currently trusting N") || !strings.Contains(out.String(), "not store eligibility") || errOut.Len() != 0 {
		t.Fatalf("help out=%q err=%v stderr=%q", out.String(), err, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	err := run([]string{"knowledge-publish", "finalize-rotated-package", "--successor-root", "one", "--successor-root=two", "--output", "one", "--output=two"}, &out, &errOut)
	if err == nil || err.Error() != "prufyx-maintainer: duplicate option rejected" || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("singleton duplicate escaped: out=%q err=%v stderr=%q", out.String(), err, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	err = run([]string{"knowledge-publish", "finalize-rotated-package", "--successor-root", "one", "--successor-root=two"}, &out, &errOut)
	if err == nil || err.Error() == "prufyx-maintainer: duplicate option rejected" || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("repeatable successor rejected by global duplicate guard: out=%q err=%v stderr=%q", out.String(), err, errOut.String())
	}
}

func TestReleaseSignRejectsMalformedInvocations(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{
		{"release-sign"},
		{"release-sign", "unknown"},
		{"release-sign", "init"},
		{"release-sign", "init", "--key-dir", "relative/path", "--expires", "2099-01-01T00:00:00Z"},
		{"release-sign", "init", "--key-dir", "/tmp/prufyx-release-keys", "--expires", "not-a-time"},
		{"release-sign", "init", "--key-dir", "/tmp/prufyx-release-keys", "--expires", "2099-01-01T00:00:00Z", "extra"},
	} {
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatalf("accepted malformed invocation %v", args)
		}
	}
}

func TestReleaseSignHelpIsAvailableWithoutTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"release-sign", "help"}, &stdout, &stderr); err != nil {
		t.Fatalf("release-sign help: %v", err)
	}
	if !strings.Contains(stdout.String(), "release-sign init") {
		t.Fatalf("release-sign help did not describe init: %q", stdout.String())
	}
}

func TestReleaseSigningPassphraseReaderIsInstalled(t *testing.T) {
	// The workflow package must receive a real prompt from the command layer,
	// not keep its refusing default.
	if releaseworkflow.ReadSigningPassphrase == nil {
		t.Fatal("no release signing passphrase reader was installed")
	}
	// Without a terminal on stdin the installed reader must refuse.
	if _, err := releaseworkflow.ReadSigningPassphrase(io.Discard); err == nil {
		t.Fatal("release signing passphrase was read without a terminal")
	}
}

func TestGateCommandIsWired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"gate", "help"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "gate verify") {
		t.Fatalf("gate help: %v %q", err, stdout.String())
	}
	if code := exitCode(run([]string{"gate", "classify"}, &stdout, &stderr)); code != 2 {
		t.Fatalf("gate classify without trees: exit %d", code)
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := run([]string{"gate", "classify", "--base", root, "--head", root}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "0 tightening, 0 loosening") {
		t.Fatalf("gate classify: %v %q", err, stdout.String())
	}
}
