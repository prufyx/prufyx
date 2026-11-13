// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type testKey struct {
	private ed25519.PrivateKey
	signer  signature.Signer
	id      string
}

func TestExternallySignedRecordsOnlyProjectFinalizesThroughConsumerVerifier(t *testing.T) {
	target := recordsOnlyTarget(t, "41")
	packageRaw, receipt := exerciseSignedPackage(t, target, "41")
	if len(packageRaw) == 0 || receipt.KnowledgeRevision != "41" {
		t.Fatalf("empty replacement finalization receipt=%+v bytes=%d", receipt, len(packageRaw))
	}
}

func TestExternallySignedExportedFullCNCFPackFinalizesThroughConsumerVerifier(t *testing.T) {
	opts := signedProjectOptions(t, "51")
	if raw, receipt, err := FinalizePackage(opts); err != nil || len(raw) == 0 || !receipt.Verification.HasRule {
		t.Fatalf("full project export receipt=%+v err=%v", receipt, err)
	}
}

func TestRetiredReleasePlanProducesNoOutput(t *testing.T) {
	opts := signedPackageOptions(t, recordsOnlyTarget(t, "52"))
	raw, plan, _, err := FinalizePackageWithReleasePlan(opts, "https://metadata.example.test/cncf-52.tar")
	if !errors.Is(err, ErrRejected) || len(raw) != 0 || len(plan) != 0 {
		t.Fatalf("retired plan emitted output: %v", err)
	}
}

func exerciseSignedPackage(t *testing.T, target publicationTarget, revision string) ([]byte, FinalizationReceipt) {
	t.Helper()
	opts := signedPackageOptions(t, target)
	packageRaw, receipt, err := FinalizePackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.Profile != "cncf-projects" || receipt.NetworkUsed || receipt.KeysHandled || receipt.KnowledgeRevision != revision || receipt.TargetDigest != digest(target.raw) || receipt.PackageDigest != digest(packageRaw) || receipt.Verification.Status != "VERIFIED" || receipt.Verification.NetworkUsed || receipt.Verification.StoreUsed {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	second, _, err := FinalizePackage(opts)
	if err != nil || !bytes.Equal(packageRaw, second) {
		t.Fatalf("canonical package changed: equal=%t err=%v", bytes.Equal(packageRaw, second), err)
	}
	return packageRaw, receipt
}

func signedPackageOptions(t *testing.T, target publicationTarget) FinalizePackageOptions {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, rootDigest, keys := testRoot(t, now)

	targetsPreparation, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, RootDigest: rootDigest, Version: 7, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, targetsPreparation, metadata.TARGETS, rootDigest, digest(target.raw), 7)
	targets := finalizeTestRole(t, rootRaw, rootDigest, targetsPreparation, keys[metadata.TARGETS])

	snapshotPreparation, err := PrepareSnapshot(SnapshotOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, Targets: targets, RootDigest: rootDigest, Version: 8, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, snapshotPreparation, metadata.SNAPSHOT, rootDigest, digest(target.raw), 8)
	snapshot := finalizeTestRole(t, rootRaw, rootDigest, snapshotPreparation, keys[metadata.SNAPSHOT])

	timestampPreparation, err := PrepareTimestamp(TimestampOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, Targets: targets, Snapshot: snapshot, RootDigest: rootDigest, Version: 9, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, timestampPreparation, metadata.TIMESTAMP, rootDigest, digest(target.raw), 9)
	timestamp := finalizeTestRole(t, rootRaw, rootDigest, timestampPreparation, keys[metadata.TIMESTAMP])

	return FinalizePackageOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, Targets: targets, Snapshot: snapshot, Timestamp: timestamp, RootDigest: rootDigest}
}

func TestFinalizationRejectsWrongPayloadSignatureAndExpiredMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, rootDigest, keys := testRoot(t, now)
	target := recordsOnlyTarget(t, "42")
	prepared, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, RootDigest: rootDigest, Version: 1, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	envelope := signatureEnvelope(t, prepared, keys[metadata.TARGETS])
	var decoded SignatureEnvelope
	if json.Unmarshal(envelope, &decoded) != nil {
		t.Fatal("decode test envelope")
	}
	decoded.PayloadDigest = "sha256:" + strings.Repeat("0", 64)
	wrong, _ := json.Marshal(decoded)
	if _, err := FinalizeRole(rootRaw, rootDigest, metadata.TARGETS, prepared.UnsignedMetadata, wrong); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong payload signature accepted: %v", err)
	}
	if _, err := FinalizeRole(rootRaw, "sha256:"+strings.Repeat("0", 64), metadata.TARGETS, prepared.UnsignedMetadata, envelope); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong root digest accepted: %v", err)
	}

	expiredTargetsPreparation, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, RootDigest: rootDigest, Version: 2, Expires: now.Add(-time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	expiredTargets := finalizeTestRole(t, rootRaw, rootDigest, expiredTargetsPreparation, keys[metadata.TARGETS])
	snapshotPreparation, _ := PrepareSnapshot(SnapshotOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, Targets: expiredTargets, RootDigest: rootDigest, Version: 2, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	snapshot := finalizeTestRole(t, rootRaw, rootDigest, snapshotPreparation, keys[metadata.SNAPSHOT])
	timestampPreparation, _ := PrepareTimestamp(TimestampOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, Targets: expiredTargets, Snapshot: snapshot, RootDigest: rootDigest, Version: 2, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	timestamp := finalizeTestRole(t, rootRaw, rootDigest, timestampPreparation, keys[metadata.TIMESTAMP])
	if _, _, err := FinalizePackage(FinalizePackageOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, Targets: expiredTargets, Snapshot: snapshot, Timestamp: timestamp, RootDigest: rootDigest}); err == nil {
		t.Fatal("expired targets metadata reached successful package output")
	}
}

func TestFinalizeRoleRejectsWrongOrOpenRoleShape(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, rootDigest, keys := testRoot(t, now)
	target := recordsOnlyTarget(t, "44")
	prepared, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target.raw, Projects: target.projects, RootDigest: rootDigest, Version: 1, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"wrong type": func(signed map[string]any) { signed["_type"] = metadata.SNAPSHOT },
		"open shape": func(signed map[string]any) { signed["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(prepared.UnsignedMetadata, &document); err != nil {
				t.Fatal(err)
			}
			signed, ok := document["signed"].(map[string]any)
			if !ok {
				t.Fatal("missing signed object")
			}
			mutate(signed)
			unsigned, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := cjson.EncodeCanonical(signed)
			if err != nil {
				t.Fatal(err)
			}
			envelope := signatureEnvelope(t, Preparation{Role: metadata.TARGETS, Payload: payload}, keys[metadata.TARGETS])
			if _, err := FinalizeRole(rootRaw, rootDigest, metadata.TARGETS, unsigned, envelope); !errors.Is(err, ErrRejected) {
				t.Fatalf("invalid role shape accepted: %v", err)
			}
		})
	}
}

func TestCanonicalRoleProfileBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	hash := metadata.HexBytes(make([]byte, 32))

	targets := metadata.Targets(now.Add(time.Hour))
	targets.Signed.Version = 1
	targets.Signed.Targets[cncfcheck.ProjectTargetPath("kubernetes")] = &metadata.TargetFiles{Length: 1, Hashes: metadata.Hashes{"sha256": hash}}
	targets.Signed.Targets[cncfcheck.ExternalIndexTargetPath] = &metadata.TargetFiles{Length: 1, Hashes: metadata.Hashes{"sha256": hash}}
	if err := validateTargetsShape(targets); err != nil {
		t.Fatalf("valid targets shape: %v", err)
	}
	targets.Signed.Version = int64(^uint32(0)>>1) + 1
	if err := validateTargetsShape(targets); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized targets version=%v", err)
	}
	targets.Signed.Version = 1
	targets.Signed.Targets[cncfcheck.ExternalIndexTargetPath].Length = MaxTargetBytes + 1
	if err := validateTargetsShape(targets); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized target length=%v", err)
	}

	snapshot := metadata.Snapshot(now.Add(time.Hour))
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta["targets.json"] = &metadata.MetaFiles{Version: 1, Length: 1, Hashes: metadata.Hashes{"sha256": hash}}
	if err := validateSnapshotShape(snapshot); err != nil {
		t.Fatalf("valid snapshot shape: %v", err)
	}
	snapshot.Signed.Meta["targets.json"].Version = int64(^uint32(0)>>1) + 1
	if err := validateSnapshotShape(snapshot); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized referenced version=%v", err)
	}
	snapshot.Signed.Meta["targets.json"].Version = 1
	snapshot.Signed.Meta["targets.json"].Length = MaxRoleBytes + 1
	if err := validateSnapshotShape(snapshot); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized metadata length=%v", err)
	}

	timestamp := metadata.Timestamp(now.Add(time.Hour))
	timestamp.Signed.Version = int64(^uint32(0)>>1) + 1
	timestamp.Signed.Meta["snapshot.json"] = &metadata.MetaFiles{Version: 1, Length: 1, Hashes: metadata.Hashes{"sha256": hash}}
	if err := validateTimestampShape(timestamp); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized timestamp version=%v", err)
	}

	rootRaw, _, keys := testRoot(t, now)
	root, err := metadata.Root().FromBytes(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = nil
	root.Signed.Version = int64(^uint32(0)>>1) + 1
	if _, err := root.Sign(keys[metadata.ROOT].signer); err != nil {
		t.Fatal(err)
	}
	oversizedRoot, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := admitRoot(oversizedRoot, digest(oversizedRoot)); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized root version=%v", err)
	}
}

func TestOutputArtifactsArePrivateExclusiveAndFailureDoesNotOverwrite(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootDigest, _ := testRoot(t, now)
	target := recordsOnlyTarget(t, "43")
	prepared, err := PrepareTargets(TargetsOptions{Root: root, Target: target.raw, Projects: target.projects, RootDigest: rootDigest, Version: 1, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "targets-step")
	if err := WritePreparation(directory, prepared); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(directory)
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%o", info.Mode().Perm())
	}
	for _, suffix := range []string{"unsigned.json", "payload.json", "request.json"} {
		path := filepath.Join(directory, "targets."+suffix)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s mode=%v err=%v", suffix, info.Mode().Perm(), err)
		}
	}
	if err := WritePreparation(directory, prepared); err == nil {
		t.Fatal("existing preparation directory overwritten")
	}
	file := filepath.Join(parent, "signed.json")
	if err := WriteExclusive(file, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusive(file, []byte("second")); err == nil {
		t.Fatal("existing artifact overwritten")
	}
	raw, _ := os.ReadFile(file)
	if string(raw) != "first" {
		t.Fatalf("existing bytes changed: %q", raw)
	}

	held, err := openPrivateRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusiveAtWith(held, "partial.json", []byte("complete"), func(file *os.File, _ []byte) error {
		_, writeErr := file.Write([]byte("partial"))
		if writeErr != nil {
			return writeErr
		}
		return errors.New("injected failure")
	}); !errors.Is(err, ErrRejected) {
		t.Fatalf("injected output failure=%v", err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	partial, err := os.ReadFile(filepath.Join(parent, "partial.json"))
	if err != nil || string(partial) != "partial" {
		t.Fatalf("failed output was removed or changed: raw=%q err=%v", partial, err)
	}
	if err := WriteExclusive(filepath.Join(parent, "partial.json"), []byte("replacement")); !errors.Is(err, ErrRejected) {
		t.Fatalf("partial output overwritten: %v", err)
	}

	partialDirectory := filepath.Join(parent, "partial-step")
	oversized := prepared
	oversized.Request = bytes.Repeat([]byte{'x'}, maxOutputBytes+1)
	if err := WritePreparation(partialDirectory, oversized); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized preparation error=%v", err)
	}
	if info, err := os.Stat(partialDirectory); err != nil || !info.IsDir() {
		t.Fatalf("failed preparation directory was removed: info=%v err=%v", info, err)
	}
}

func assertPreparation(t *testing.T, preparation Preparation, role, rootDigest, targetDigest string, version int64) {
	t.Helper()
	if preparation.Role != role || len(preparation.Payload) == 0 || len(preparation.UnsignedMetadata) == 0 {
		t.Fatalf("incomplete preparation: %+v", preparation)
	}
	var request signingRequest
	if json.Unmarshal(preparation.Request, &request) != nil || request.Schema != SigningRequestSchema || request.Role != role || request.PayloadDigest != digest(preparation.Payload) || request.UnsignedMetadataDigest != digest(preparation.UnsignedMetadata) || request.RootDigest != rootDigest || request.TargetDigest != targetDigest || request.RoleVersion != version || request.Threshold != 1 || len(request.AuthorizedKeyIDs) != 1 {
		t.Fatalf("invalid request: %+v", request)
	}
}

func finalizeTestRole(t *testing.T, root []byte, rootDigest string, preparation Preparation, key testKey) []byte {
	t.Helper()
	result, err := FinalizeRole(root, rootDigest, preparation.Role, preparation.UnsignedMetadata, signatureEnvelope(t, preparation, key))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func signatureEnvelope(t *testing.T, preparation Preparation, key testKey) []byte {
	t.Helper()
	sig := ed25519.Sign(key.private, preparation.Payload)
	raw, err := json.Marshal(SignatureEnvelope{Schema: SignatureEnvelopeSchema, Role: preparation.Role, PayloadDigest: digest(preparation.Payload), Signatures: []SignatureInput{{KeyID: key.id, Sig: hex.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testRoot(t *testing.T, now time.Time) ([]byte, string, map[string]testKey) {
	t.Helper()
	keys := map[string]testKey{}
	root := metadata.Root(now.Add(7 * 24 * time.Hour))
	root.Signed.Version = 1
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := signature.LoadSigner(private, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			t.Fatal(err)
		}
		id, err := key.ID()
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(key, role); err != nil {
			t.Fatal(err)
		}
		keys[role] = testKey{private: private, signer: signer, id: id}
	}
	if _, err := root.Sign(keys[metadata.ROOT].signer); err != nil {
		t.Fatal(err)
	}
	raw, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, key := range keys {
			for index := range key.private {
				key.private[index] = 0
			}
		}
	})
	return raw, digest(raw), keys
}

type publicationTarget struct {
	raw      []byte
	projects []Target
}

// A small project fixture exercises the real publisher without a global
// single envelope. A records-only project has no rules but retains evidence.
func recordsOnlyTarget(t *testing.T, revision string) publicationTarget {
	t.Helper()
	index, projects := embeddedProjectTargets(t, revision)
	var document struct {
		Schema     string                         `json:"schema"`
		Revision   string                         `json:"revision"`
		Purpose    string                         `json:"purpose"`
		Capability string                         `json:"engineCapabilityDigest"`
		Projects   []cncfcheck.ExternalIndexEntry `json:"projects"`
	}
	if err := json.Unmarshal(index, &document); err != nil {
		t.Fatal(err)
	}
	var selected Target
	var entry cncfcheck.ExternalIndexEntry
	for i, p := range projects {
		if p.Path == cncfcheck.ProjectTargetPath("kubernetes") {
			selected = p
			entry = document.Projects[i]
			break
		}
	}
	if len(selected.Raw) == 0 {
		t.Fatal("missing Kubernetes fixture")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(selected.Raw, &envelope); err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(envelope["pack"], &pack); err != nil {
		t.Fatal(err)
	}
	pack["entries"] = json.RawMessage("[]")
	delete(pack, "lineAttestations")
	delete(pack, "pathPolicies")
	envelope["pack"], _ = json.Marshal(pack)
	selected.Raw, _ = json.Marshal(envelope)
	bundle, err := cncfcheck.ParseExternalBundle(selected.Raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil {
		t.Fatal(err)
	}
	entry.Length, entry.Digest, entry.RuleDigest = int64(len(selected.Raw)), digest(selected.Raw), admission.RuleDigest
	entry.EvidenceExpiresAt, entry.Records = admission.EvidenceExpiresAt, admission.HasRecords
	document.Schema = cncfcheck.ExternalIndexSchemaRecords
	document.Projects = []cncfcheck.ExternalIndexEntry{entry}
	index, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalIndex(index); err != nil {
		t.Fatal(err)
	}
	return publicationTarget{index, []Target{selected}}
}
