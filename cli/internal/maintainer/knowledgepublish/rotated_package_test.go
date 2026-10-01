// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestFinalizeRotatedPackage_OrderedChainAndEmptyWithdrawal(t *testing.T) {
	opts := rotatedPackageOptions(t, emptyReplacementTarget(t, "81"))
	packageRaw, receipt, err := FinalizeRotatedPackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(packageRaw) == 0 || receipt.RootDigest != opts.InitialRootDigest || receipt.Verification.InitialRootDigest != opts.InitialRootDigest || len(receipt.Verification.RootHistory) != 2 || receipt.Verification.RootHistory[0].Digest != opts.InitialRootDigest || receipt.Verification.RootHistory[1].Digest != digest(opts.SuccessorRoots[0]) || receipt.Verification.HasRule {
		t.Fatalf("unexpected rotated receipt: %+v", receipt)
	}
	second, secondReceipt, err := FinalizeRotatedPackage(opts)
	if err != nil || !bytes.Equal(packageRaw, second) || secondReceipt.PackageDigest != receipt.PackageDigest {
		t.Fatalf("rotated package was not deterministic: equal=%t receipt=%+v err=%v", bytes.Equal(packageRaw, second), secondReceipt, err)
	}
}

func TestFinalizeRotatedPackage_ExportsNonemptyTarget(t *testing.T) {
	target, err := cncfcheck.ExportEmbeddedExternalBundle("82")
	if err != nil {
		t.Fatal(err)
	}
	opts := rotatedPackageOptions(t, target)
	_, receipt, err := FinalizeRotatedPackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Verification.HasRule || receipt.KnowledgeRevision != "82" || receipt.Verification.InitialRootDigest != opts.InitialRootDigest {
		t.Fatalf("nonempty rotated receipt=%+v", receipt)
	}
}

func TestFinalizeRotatedPackage_TwoSuccessorsRequireContiguousOrder(t *testing.T) {
	opts := twoSuccessorRotatedPackageOptions(t, emptyReplacementTarget(t, "821"))
	packageRaw, receipt, err := FinalizeRotatedPackage(opts)
	if err != nil || len(packageRaw) == 0 || len(receipt.Verification.RootHistory) != 3 || receipt.Verification.RootHistory[2].Digest != digest(opts.SuccessorRoots[1]) {
		t.Fatalf("two-successor package=%d receipt=%+v err=%v", len(packageRaw), receipt, err)
	}
	for _, test := range []struct {
		name  string
		roots [][]byte
	}{
		{"reversed", [][]byte{opts.SuccessorRoots[1], opts.SuccessorRoots[0]}},
		{"gap", [][]byte{opts.SuccessorRoots[1]}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := cloneRotatedOptions(opts)
			invalid.SuccessorRoots = test.roots
			packageRaw, receipt, err := FinalizeRotatedPackage(invalid)
			if !errors.Is(err, ErrRejected) || len(packageRaw) != 0 || receipt.Schema != "" || receipt.Status != "" {
				t.Fatalf("package=%d receipt=%+v err=%v", len(packageRaw), receipt, err)
			}
		})
	}
}

func TestFinalizeRotatedPackage_RejectsInvalidChainBeforePackaging(t *testing.T) {
	opts := rotatedPackageOptions(t, emptyReplacementTarget(t, "83"))
	cases := []struct {
		name string
		edit func(*RotatedFinalizePackageOptions)
	}{
		{"missing successor", func(o *RotatedFinalizePackageOptions) { o.SuccessorRoots = nil }},
		{"too many successors", func(o *RotatedFinalizePackageOptions) {
			o.SuccessorRoots = append(o.SuccessorRoots, o.SuccessorRoots[0], o.SuccessorRoots[0], o.SuccessorRoots[0], o.SuccessorRoots[0], o.SuccessorRoots[0], o.SuccessorRoots[0], o.SuccessorRoots[0], o.SuccessorRoots[0])
		}},
		{"duplicate successor", func(o *RotatedFinalizePackageOptions) {
			o.SuccessorRoots = append(o.SuccessorRoots, o.SuccessorRoots[0])
		}},
		{"wrong initial digest", func(o *RotatedFinalizePackageOptions) {
			o.InitialRootDigest = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
		}},
		{"malformed successor", func(o *RotatedFinalizePackageOptions) { o.SuccessorRoots[0] = []byte(`{}`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copyOpts := cloneRotatedOptions(opts)
			tc.edit(&copyOpts)
			packageRaw, receipt, err := FinalizeRotatedPackage(copyOpts)
			if !errors.Is(err, ErrRejected) || len(packageRaw) != 0 || receipt.Schema != "" || receipt.Status != "" {
				t.Fatalf("package=%d receipt=%+v err=%v", len(packageRaw), receipt, err)
			}
		})
	}
}

func TestFinalizeRotatedPackage_RejectsFinalAuthorityFailureWithoutPackage(t *testing.T) {
	opts := rotatedPackageOptions(t, emptyReplacementTarget(t, "84"))
	opts.Timestamp = append([]byte(nil), opts.Timestamp...)
	opts.Timestamp[len(opts.Timestamp)-2] ^= 1
	packageRaw, receipt, err := FinalizeRotatedPackage(opts)
	if !errors.Is(err, ErrRejected) || len(packageRaw) != 0 || receipt.Schema != "" || receipt.Status != "" {
		t.Fatalf("downstream failure emitted package=%d receipt=%+v err=%v", len(packageRaw), receipt, err)
	}
}

func TestFinalizeRotatedPackage_RejectsValidOldAuthorityMetadata(t *testing.T) {
	rotated, oldAuthority := rotatedPackageFixture(t, emptyReplacementTarget(t, "85"))
	rotated.Targets, rotated.Snapshot, rotated.Timestamp = oldAuthority.Targets, oldAuthority.Snapshot, oldAuthority.Timestamp
	packageRaw, receipt, err := FinalizeRotatedPackage(rotated)
	if !errors.Is(err, ErrRejected) || len(packageRaw) != 0 || receipt.Schema != "" || receipt.Status != "" {
		t.Fatalf("old-authority metadata emitted package=%d receipt=%+v err=%v", len(packageRaw), receipt, err)
	}
}

func rotatedPackageOptions(t *testing.T, target []byte) RotatedFinalizePackageOptions {
	t.Helper()
	opts, _ := rotatedPackageFixture(t, target)
	return opts
}

func rotatedPackageFixture(t *testing.T, target []byte) (RotatedFinalizePackageOptions, FinalizePackageOptions) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	initial, initialDigest, oldKeys := testRoot(t, now)
	oldTargetsPrep, err := PrepareTargets(TargetsOptions{Root: initial, RootDigest: initialDigest, Target: target, Version: 5, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	oldTargets := finalizeTestRole(t, initial, initialDigest, oldTargetsPrep, oldKeys[metadata.TARGETS])
	oldSnapshotPrep, err := PrepareSnapshot(SnapshotOptions{Root: initial, RootDigest: initialDigest, Target: target, Targets: oldTargets, Version: 6, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot := finalizeTestRole(t, initial, initialDigest, oldSnapshotPrep, oldKeys[metadata.SNAPSHOT])
	oldTimestampPrep, err := PrepareTimestamp(TimestampOptions{Root: initial, RootDigest: initialDigest, Target: target, Targets: oldTargets, Snapshot: oldSnapshot, Version: 7, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	oldTimestamp := finalizeTestRole(t, initial, initialDigest, oldTimestampPrep, oldKeys[metadata.TIMESTAMP])
	oldAuthority := FinalizePackageOptions{Root: initial, RootDigest: initialDigest, Target: target, Targets: oldTargets, Snapshot: oldSnapshot, Timestamp: oldTimestamp}
	template, templateDigest, newKeys := testRoot(t, now)
	transition, err := PrepareRootTransition(RootTransitionOptions{TrustedRoot: initial, TrustedRootDigest: initialDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest})
	if err != nil {
		t.Fatal(err)
	}
	successor, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: RootTransitionOptions{TrustedRoot: initial, TrustedRootDigest: initialDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}, UnsignedMetadata: transition.UnsignedMetadata, Request: transition.Request, Signatures: [][]byte{rootContribution(t, transition, oldKeys[metadata.ROOT]), rootContribution(t, transition, newKeys[metadata.ROOT])}})
	if err != nil {
		t.Fatal(err)
	}
	successorDigest := digest(successor)
	targetsPrep, err := PrepareTargets(TargetsOptions{Root: successor, RootDigest: successorDigest, Target: target, Version: 7, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	targets := finalizeTestRole(t, successor, successorDigest, targetsPrep, newKeys[metadata.TARGETS])
	snapshotPrep, err := PrepareSnapshot(SnapshotOptions{Root: successor, RootDigest: successorDigest, Target: target, Targets: targets, Version: 8, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := finalizeTestRole(t, successor, successorDigest, snapshotPrep, newKeys[metadata.SNAPSHOT])
	timestampPrep, err := PrepareTimestamp(TimestampOptions{Root: successor, RootDigest: successorDigest, Target: target, Targets: targets, Snapshot: snapshot, Version: 9, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	timestamp := finalizeTestRole(t, successor, successorDigest, timestampPrep, newKeys[metadata.TIMESTAMP])
	return RotatedFinalizePackageOptions{InitialRoot: initial, InitialRootDigest: initialDigest, SuccessorRoots: [][]byte{successor}, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp}, oldAuthority
}

func twoSuccessorRotatedPackageOptions(t *testing.T, target []byte) RotatedFinalizePackageOptions {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	initial, initialDigest, initialKeys := testRoot(t, now)
	templateOne, templateOneDigest, firstKeys := testRoot(t, now)
	firstPreparation, err := PrepareRootTransition(RootTransitionOptions{TrustedRoot: initial, TrustedRootDigest: initialDigest, SuccessorTemplate: templateOne, SuccessorTemplateDigest: templateOneDigest})
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: RootTransitionOptions{TrustedRoot: initial, TrustedRootDigest: initialDigest, SuccessorTemplate: templateOne, SuccessorTemplateDigest: templateOneDigest}, UnsignedMetadata: firstPreparation.UnsignedMetadata, Request: firstPreparation.Request, Signatures: [][]byte{rootContribution(t, firstPreparation, initialKeys[metadata.ROOT]), rootContribution(t, firstPreparation, firstKeys[metadata.ROOT])}})
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := digest(first)
	templateTwo, templateTwoDigest, secondKeys := testRoot(t, now)
	secondPreparation, err := PrepareRootTransition(RootTransitionOptions{TrustedRoot: first, TrustedRootDigest: firstDigest, SuccessorTemplate: templateTwo, SuccessorTemplateDigest: templateTwoDigest})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: RootTransitionOptions{TrustedRoot: first, TrustedRootDigest: firstDigest, SuccessorTemplate: templateTwo, SuccessorTemplateDigest: templateTwoDigest}, UnsignedMetadata: secondPreparation.UnsignedMetadata, Request: secondPreparation.Request, Signatures: [][]byte{rootContribution(t, secondPreparation, firstKeys[metadata.ROOT]), rootContribution(t, secondPreparation, secondKeys[metadata.ROOT])}})
	if err != nil {
		t.Fatal(err)
	}
	secondDigest := digest(second)
	targetsPreparation, err := PrepareTargets(TargetsOptions{Root: second, RootDigest: secondDigest, Target: target, Version: 7, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	targets := finalizeTestRole(t, second, secondDigest, targetsPreparation, secondKeys[metadata.TARGETS])
	snapshotPreparation, err := PrepareSnapshot(SnapshotOptions{Root: second, RootDigest: secondDigest, Target: target, Targets: targets, Version: 8, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := finalizeTestRole(t, second, secondDigest, snapshotPreparation, secondKeys[metadata.SNAPSHOT])
	timestampPreparation, err := PrepareTimestamp(TimestampOptions{Root: second, RootDigest: secondDigest, Target: target, Targets: targets, Snapshot: snapshot, Version: 9, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	timestamp := finalizeTestRole(t, second, secondDigest, timestampPreparation, secondKeys[metadata.TIMESTAMP])
	return RotatedFinalizePackageOptions{InitialRoot: initial, InitialRootDigest: initialDigest, SuccessorRoots: [][]byte{first, second}, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp}
}

func cloneRotatedOptions(opts RotatedFinalizePackageOptions) RotatedFinalizePackageOptions {
	clone := opts
	clone.InitialRoot = bytes.Clone(opts.InitialRoot)
	clone.Target = bytes.Clone(opts.Target)
	clone.Targets = bytes.Clone(opts.Targets)
	clone.Snapshot = bytes.Clone(opts.Snapshot)
	clone.Timestamp = bytes.Clone(opts.Timestamp)
	clone.SuccessorRoots = make([][]byte, len(opts.SuccessorRoots))
	for i := range opts.SuccessorRoots {
		clone.SuccessorRoots[i] = bytes.Clone(opts.SuccessorRoots[i])
	}
	return clone
}
