// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package communityapp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestRotatedPackage_InitializedStoreImportsAndContinuesAtSuccessor(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	private, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o700); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("rotated package test passphrase 123")
	oldDir, nextDir := filepath.Join(private, "old-keys"), filepath.Join(private, "next-keys")
	old, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: oldDir, RootExpires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339), Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	next, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: nextDir, RootExpires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339), Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	initialTarget := exportedRotatedTarget(t, "91")
	initialPackage, initialReceipt := signedRotatedPackage(t, old, oldDir, passphrase, initialTarget, 1)
	store := filepath.Join(private, "store")
	initialPath := writeKnowledgeReleaseFile(t, private, "initial.tar", initialPackage)
	rootPath := writeKnowledgeReleaseFile(t, private, "1.root.json", old.Root)
	initialImport, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: initialPath, StoreRoot: store, BootstrapRootPath: rootPath, BootstrapRootDigest: old.RootDigest, ExpectedPackageDigest: releaseDigest(initialPackage), ExpectedRevision: initialReceipt.KnowledgeRevision, ExpectedBundleDigest: initialReceipt.TargetDigest})
	if err != nil || initialImport.Status != "IMPORTED" || initialImport.TrustReceipt.Root.Version != 1 {
		t.Fatalf("initial import=%+v err=%v", initialImport, err)
	}

	transition := finalizeRotatedTestTransition(t, old, oldDir, next, nextDir, passphrase)
	successorAuthority := next
	successorAuthority.Root = transition
	successorAuthority.RootDigest = releaseDigest(transition)
	rotatedTarget := exportedRotatedTarget(t, "92")
	rotatedPackage, rotatedReceipt := signedRotatedPackageWithChain(t, old.Root, old.RootDigest, [][]byte{transition}, successorAuthority, nextDir, passphrase, rotatedTarget, 2)
	rotatedPath := writeKnowledgeReleaseFile(t, private, "rotated.tar", rotatedPackage)
	rotatedImport, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: rotatedPath, StoreRoot: store, ExpectedPackageDigest: releaseDigest(rotatedPackage), ExpectedRevision: rotatedReceipt.KnowledgeRevision, ExpectedBundleDigest: rotatedReceipt.TargetDigest})
	if err != nil || rotatedImport.Status != "IMPORTED" || !rotatedImport.TrustStateAdvanced || rotatedImport.TrustReceipt.Root.Version != 2 || len(rotatedImport.TrustReceipt.RootHistory) != 2 || rotatedImport.TrustReceipt.RootHistory[0].Digest != old.RootDigest || rotatedImport.TrustReceipt.RootHistory[1].Digest != releaseDigest(transition) {
		t.Fatalf("rotated import=%+v err=%v", rotatedImport, err)
	}
	assertRotatedKyvernoOutcomes(t, store, rotatedImport, mustParseReleaseTime(t, kyvernoReportsValidUntil))

	// A package that redundantly includes the already consumed successor is not
	// an update for this store; the rejected attempt must preserve its prefix.
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: rotatedPath, StoreRoot: store, ExpectedPackageDigest: releaseDigest(rotatedPackage), ExpectedRevision: rotatedReceipt.KnowledgeRevision, ExpectedBundleDigest: rotatedReceipt.TargetDigest}); err == nil {
		t.Fatal("starting-root-specific package was accepted after its successor")
	}
	status, err := knowledge.InspectConstraints(store)
	if err != nil || status.RootVersion != 2 || status.SelectedRevision != "92" || status.TrustReceiptDigest != rotatedImport.TrustReceiptDigest {
		t.Fatalf("rejected repeated package lost trusted prefix or selection: status=%+v err=%v", status, err)
	}

	continuedTarget := exportedRotatedTarget(t, "93")
	continuedPackage, continuedReceipt := signedRotatedPackage(t, successorAuthority, nextDir, passphrase, continuedTarget, 3)
	continuedPath := writeKnowledgeReleaseFile(t, private, "continued.tar", continuedPackage)
	continuedImport, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: continuedPath, StoreRoot: store, ExpectedPackageDigest: releaseDigest(continuedPackage), ExpectedRevision: continuedReceipt.KnowledgeRevision, ExpectedBundleDigest: continuedReceipt.TargetDigest})
	if err != nil || continuedImport.Status != "IMPORTED" || continuedImport.TrustReceipt.Root.Version != 2 || continuedImport.TrustReceipt.KnowledgeRevision != "93" {
		t.Fatalf("continued import=%+v err=%v", continuedImport, err)
	}
	for i := range passphrase {
		passphrase[i] = 0
	}
}

func assertRotatedKyvernoOutcomes(t *testing.T, store string, receipt knowledge.ImportReceipt, validUntil time.Time) {
	t.Helper()
	for _, test := range []struct {
		input string
		want  string
	}{
		{kyvernoInputFalse, "PASS"},
		{kyvernoInputTrue, "BLOCKED"},
		{kyvernoInputUnknown, "UNKNOWN"},
	} {
		result, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: store, ExpectedRevision: "92", ExpectedBundleDigest: receipt.TrustReceipt.TargetDigest, ExpectedTrustReceiptDigest: receipt.TrustReceiptDigest}, Project: "kyverno", SelectedRuleID: kyvernoReportsChunkSizeRuleID, Input: []byte(test.input), InputDigest: releaseDigest([]byte(test.input))})
		if err != nil || result.Knowledge.Origin != "external_signed_local" || result.Knowledge.Revision != "92" || result.Knowledge.BundleDigest != receipt.TrustReceipt.TargetDigest || result.Knowledge.TrustReceiptDigest != receipt.TrustReceiptDigest || result.Check.KnowledgeOrigin != "external_declared" || result.Check.KnowledgeRevision != "92" || result.Check.KnowledgePackDigest != receipt.TrustReceipt.TargetDigest || len(result.Check.Check.Claims) != 1 || result.Check.Check.Claims[0].RuleID != kyvernoReportsChunkSizeRuleID {
			t.Fatalf("selected evaluation=%+v err=%v", result, err)
		}
		claim := result.Check.Check.Claims[0]
		if !time.Now().UTC().Before(validUntil) {
			if claim.Status != "UNKNOWN" || claim.ReasonCode != "RULE_EVIDENCE_STALE" {
				t.Fatalf("stale selected evaluation=%+v", claim)
			}
		} else if claim.Status != test.want {
			t.Fatalf("selected status=%q want=%q claim=%+v", claim.Status, test.want, claim)
		}
	}
}

func exportedRotatedTarget(t *testing.T, revision string) []byte {
	t.Helper()
	raw, err := cncfcheck.ExportEmbeddedExternalBundle(revision)
	if err != nil {
		t.Fatal(err)
	}
	assertExportedKyvernoReviewIdentity(t, raw)
	return raw
}

func finalizeRotatedTestTransition(t *testing.T, old knowledgesign.InitResult, oldDir string, next knowledgesign.InitResult, nextDir string, passphrase []byte) []byte {
	t.Helper()
	opts := knowledgepublish.RootTransitionOptions{TrustedRoot: old.Root, TrustedRootDigest: old.RootDigest, SuccessorTemplate: next.Root, SuccessorTemplateDigest: next.RootDigest}
	prepared, err := knowledgepublish.PrepareRootTransition(opts)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(prepared.Payload))
	sign := func(authority, keyPath string) []byte {
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
		envelope, err := knowledgesign.SignRootTransition(knowledgesign.RootTransitionSignOptions{TrustedRoot: old.Root, TrustedRootDigest: old.RootDigest, SuccessorTemplate: next.Root, SuccessorTemplateDigest: next.RootDigest, UnsignedMetadata: prepared.UnsignedMetadata, Request: prepared.Request, ExpectedPayloadDigest: payloadDigest, Authority: authority, EncryptedKey: key, Passphrase: append([]byte(nil), passphrase...)})
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	result, _, err := knowledgepublish.FinalizeRootTransition(knowledgepublish.RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: prepared.UnsignedMetadata, Request: prepared.Request, Signatures: [][]byte{sign("trusted", filepath.Join(oldDir, "root.key.pem")), sign("successor", filepath.Join(nextDir, "root.key.pem"))}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func signedRotatedPackage(t *testing.T, initialized knowledgesign.InitResult, keyDir string, passphrase, target []byte, version int64) ([]byte, knowledgepublish.FinalizationReceipt) {
	t.Helper()
	return signedRotatedPackageWithChain(t, initialized.Root, initialized.RootDigest, nil, initialized, keyDir, passphrase, target, version)
}

func signedRotatedPackageWithChain(t *testing.T, initial []byte, initialDigest string, successors [][]byte, authority knowledgesign.InitResult, keyDir string, passphrase, target []byte, version int64) ([]byte, knowledgepublish.FinalizationReceipt) {
	t.Helper()
	expires := time.Now().UTC().Truncate(time.Second)
	targetsPrep, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: authority.Root, RootDigest: authority.RootDigest, Target: target, Version: version, Expires: expires.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	targets := finalizeRotatedTestRole(t, authority, keyDir, passphrase, metadata.TARGETS, targetsPrep)
	snapshotPrep, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: authority.Root, RootDigest: authority.RootDigest, Target: target, Targets: targets, Version: version, Expires: expires.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := finalizeRotatedTestRole(t, authority, keyDir, passphrase, metadata.SNAPSHOT, snapshotPrep)
	timestampPrep, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: authority.Root, RootDigest: authority.RootDigest, Target: target, Targets: targets, Snapshot: snapshot, Version: version, Expires: expires.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	timestamp := finalizeRotatedTestRole(t, authority, keyDir, passphrase, metadata.TIMESTAMP, timestampPrep)
	if len(successors) == 0 {
		packageRaw, receipt, err := knowledgepublish.FinalizePackage(knowledgepublish.FinalizePackageOptions{Root: initial, RootDigest: initialDigest, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp})
		if err != nil {
			t.Fatal(err)
		}
		return packageRaw, receipt
	}
	packageRaw, receipt, err := knowledgepublish.FinalizeRotatedPackage(knowledgepublish.RotatedFinalizePackageOptions{InitialRoot: initial, InitialRootDigest: initialDigest, SuccessorRoots: successors, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	return packageRaw, receipt
}

func finalizeRotatedTestRole(t *testing.T, initialized knowledgesign.InitResult, keyDir string, passphrase []byte, role string, preparation knowledgepublish.Preparation) []byte {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(keyDir, role+".key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	envelope, err := knowledgesign.SignRole(knowledgesign.SignOptions{Root: initialized.Root, RootDigest: initialized.RootDigest, Role: role, Unsigned: preparation.UnsignedMetadata, ExpectedPayloadDigest: releaseDigest(preparation.Payload), EncryptedKey: key, Passphrase: append([]byte(nil), passphrase...)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := knowledgepublish.FinalizeRole(initialized.Root, initialized.RootDigest, role, preparation.UnsignedMetadata, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
