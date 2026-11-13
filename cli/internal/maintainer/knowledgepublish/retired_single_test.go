// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"errors"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestSingleProducerAPIsRejectLegacyContent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootDigest, keys := testRoot(t, now)
	legacy := recordsOnlyTarget(t, "73").projects[0].Raw
	expires := now.Add(time.Hour).Format(time.RFC3339)
	if prep, err := PrepareTargets(TargetsOptions{Root: root, RootDigest: rootDigest, Target: legacy, Version: 1, Expires: expires}); !errors.Is(err, ErrRejected) || len(prep.Request) != 0 {
		t.Fatalf("single targets preparation: %+v %v", prep, err)
	}
	// Sign legacy metadata independently as a historical fixture. Neither the
	// role finalizer nor timestamp-refresh preparation may revive its producer.
	role := metadata.Targets(now.Add(time.Hour))
	role.Signed.Version = 1
	info, err := metadata.TargetFile().FromBytes(knowledge.ConstraintsTargetPath, legacy, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	role.Signed.Targets[knowledge.ConstraintsTargetPath] = info
	unsigned, err := role.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cjson.EncodeCanonical(role.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := FinalizeRole(root, rootDigest, metadata.TARGETS, unsigned, signatureEnvelope(t, Preparation{Role: metadata.TARGETS, Payload: payload}, keys[metadata.TARGETS])); !errors.Is(err, ErrRejected) || len(raw) != 0 {
		t.Fatalf("single role: %d %v", len(raw), err)
	}
	if _, err := role.Sign(keys[metadata.TARGETS].signer); err != nil {
		t.Fatal(err)
	}
	signed, err := role.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := metadata.Snapshot(now.Add(time.Hour))
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = metaIdentity(1, signed)
	if _, err := snapshot.Sign(keys[metadata.SNAPSHOT].signer); err != nil {
		t.Fatal(err)
	}
	snapshotRaw, err := snapshot.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := metadata.Timestamp(now.Add(time.Hour))
	timestamp.Signed.Version = 1
	timestamp.Signed.Meta["snapshot.json"] = metaIdentity(1, snapshotRaw)
	if _, err := timestamp.Sign(keys[metadata.TIMESTAMP].signer); err != nil {
		t.Fatal(err)
	}
	timestampRaw, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	// These inputs form a valid signed legacy chain; missing downstream
	// metadata must not be the reason the producer rejects them.
	trusted, _, err := admitRoot(root, rootDigest)
	if err != nil || trusted.VerifyDelegate(metadata.TARGETS, role) != nil || trusted.VerifyDelegate(metadata.SNAPSHOT, snapshot) != nil || trusted.VerifyDelegate(metadata.TIMESTAMP, timestamp) != nil || validateSnapshot(snapshot, signed, 1) != nil || validateTimestamp(timestamp, snapshotRaw, 1) != nil {
		t.Fatalf("invalid legacy positive control: %v", err)
	}
	if prep, err := PrepareSnapshot(SnapshotOptions{Root: root, RootDigest: rootDigest, Target: legacy, Targets: signed, Version: 1, Expires: expires}); !errors.Is(err, ErrRejected) || len(prep.Request) != 0 {
		t.Fatalf("single snapshot preparation: %+v %v", prep, err)
	}
	if prep, err := PrepareTimestamp(TimestampOptions{Root: root, RootDigest: rootDigest, Target: legacy, Targets: signed, Snapshot: snapshotRaw, Version: 1, Expires: expires}); !errors.Is(err, ErrRejected) || len(prep.Request) != 0 {
		t.Fatalf("single timestamp preparation: %+v %v", prep, err)
	}
	if raw, _, err := FinalizePackage(FinalizePackageOptions{Root: root, RootDigest: rootDigest, Target: legacy, Targets: signed, Snapshot: snapshotRaw, Timestamp: timestampRaw}); !errors.Is(err, ErrRejected) || len(raw) != 0 {
		t.Fatalf("single package: %d %v", len(raw), err)
	}
	if prep, err := PrepareTimestampRefresh(TimestampRefreshOptions{Root: root, RootDigest: rootDigest, Targets: signed, Snapshot: snapshotRaw, TargetDigest: digest(legacy), PreviousVersion: 1, Version: 2, Expires: expires}); !errors.Is(err, ErrRejected) || len(prep.Request) != 0 {
		t.Fatalf("single refresh: %+v %v", prep, err)
	}
}
