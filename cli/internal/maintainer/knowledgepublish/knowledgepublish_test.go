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
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgereleaseplan"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type testKey struct {
	private ed25519.PrivateKey
	signer  signature.Signer
	id      string
}

func TestExternallySignedCompleteEmptyReplacementFinalizesThroughConsumerVerifier(t *testing.T) {
	target := emptyReplacementTarget(t, "41")
	packageRaw, receipt := exerciseSignedPackage(t, target, "41")
	if len(packageRaw) == 0 || receipt.KnowledgeRevision != "41" {
		t.Fatalf("empty replacement finalization receipt=%+v bytes=%d", receipt, len(packageRaw))
	}
}

func TestExternallySignedExportedFullCNCFPackFinalizesThroughConsumerVerifier(t *testing.T) {
	target, err := cncfcheck.ExportEmbeddedExternalBundle("51")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Pack struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(target, &envelope); err != nil || len(envelope.Pack.Entries) == 0 {
		t.Fatalf("exported target entries=%d err=%v", len(envelope.Pack.Entries), err)
	}
	packageRaw, receipt := exerciseSignedPackage(t, target, "51")
	if len(packageRaw) == 0 || receipt.KnowledgeRevision != "51" || !receipt.Verification.HasRule {
		t.Fatalf("full export finalization receipt=%+v bytes=%d", receipt, len(packageRaw))
	}
}

func TestSuccessfulFinalizationGeneratesDeterministicReleasePlan(t *testing.T) {
	target := emptyReplacementTarget(t, "52")
	opts := signedPackageOptions(t, target)
	const packageURL = "https://metadata.example.test/cncf-52.tar"
	firstPackage, firstPlan, _, err := FinalizePackageWithReleasePlan(opts, packageURL)
	if err != nil {
		t.Fatal(err)
	}
	secondPackage, secondPlan, _, err := FinalizePackageWithReleasePlan(opts, packageURL)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstPackage, secondPackage) || !bytes.Equal(firstPlan, secondPlan) {
		t.Fatal("identical verified publisher inputs did not produce identical package and plan")
	}
	plan, err := knowledgereleaseplan.Parse(firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Package.URL != packageURL || plan.Package.Digest != digest(firstPackage) ||
		plan.Target.Revision != "52" || plan.Target.Digest != digest(target) ||
		plan.PublisherVerification.PublisherInitialRootDigest != opts.RootDigest ||
		len(plan.PublisherVerification.RootHistory) != 1 || plan.PublisherVerification.RootHistory[0].Digest != opts.RootDigest {
		t.Fatalf("release plan lost verified identities: %+v", plan)
	}
	badPackage, badPlan, _, err := FinalizePackageWithReleasePlan(opts, packageURL+"?credential=canary")
	if !errors.Is(err, ErrRejected) || len(badPackage) != 0 || len(badPlan) != 0 {
		t.Fatalf("invalid plan routing escaped finalization: package=%d plan=%d err=%v", len(badPackage), len(badPlan), err)
	}
}

func exerciseSignedPackage(t *testing.T, target []byte, revision string) ([]byte, FinalizationReceipt) {
	t.Helper()
	opts := signedPackageOptions(t, target)
	packageRaw, receipt, err := FinalizePackage(opts)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "VERIFIED_FOR_PACKAGING" || receipt.Profile != "cncf" || receipt.NetworkUsed || receipt.KeysHandled || receipt.KnowledgeRevision != revision || receipt.TargetDigest != digest(target) || receipt.PackageDigest != digest(packageRaw) || receipt.Verification.Status != "VERIFIED" || receipt.Verification.NetworkUsed || receipt.Verification.StoreUsed {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	second, _, err := FinalizePackage(opts)
	if err != nil || !bytes.Equal(packageRaw, second) {
		t.Fatalf("canonical package changed: equal=%t err=%v", bytes.Equal(packageRaw, second), err)
	}
	return packageRaw, receipt
}

func signedPackageOptions(t *testing.T, target []byte) FinalizePackageOptions {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, rootDigest, keys := testRoot(t, now)

	targetsPreparation, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 7, Expires: now.Add(72 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, targetsPreparation, metadata.TARGETS, rootDigest, digest(target), 7)
	targets := finalizeTestRole(t, rootRaw, rootDigest, targetsPreparation, keys[metadata.TARGETS])

	snapshotPreparation, err := PrepareSnapshot(SnapshotOptions{Root: rootRaw, Target: target, Targets: targets, RootDigest: rootDigest, Version: 8, Expires: now.Add(48 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, snapshotPreparation, metadata.SNAPSHOT, rootDigest, digest(target), 8)
	snapshot := finalizeTestRole(t, rootRaw, rootDigest, snapshotPreparation, keys[metadata.SNAPSHOT])

	timestampPreparation, err := PrepareTimestamp(TimestampOptions{Root: rootRaw, Target: target, Targets: targets, Snapshot: snapshot, RootDigest: rootDigest, Version: 9, Expires: now.Add(24 * time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	assertPreparation(t, timestampPreparation, metadata.TIMESTAMP, rootDigest, digest(target), 9)
	timestamp := finalizeTestRole(t, rootRaw, rootDigest, timestampPreparation, keys[metadata.TIMESTAMP])

	return FinalizePackageOptions{Root: rootRaw, Target: target, Targets: targets, Snapshot: snapshot, Timestamp: timestamp, RootDigest: rootDigest}
}

func TestFinalizationRejectsWrongPayloadSignatureAndExpiredMetadata(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, rootDigest, keys := testRoot(t, now)
	target := emptyReplacementTarget(t, "42")
	prepared, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 1, Expires: now.Add(time.Hour).Format(time.RFC3339)})
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

	expiredTargetsPreparation, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 2, Expires: now.Add(-time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	expiredTargets := finalizeTestRole(t, rootRaw, rootDigest, expiredTargetsPreparation, keys[metadata.TARGETS])
	snapshotPreparation, _ := PrepareSnapshot(SnapshotOptions{Root: rootRaw, Target: target, Targets: expiredTargets, RootDigest: rootDigest, Version: 2, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	snapshot := finalizeTestRole(t, rootRaw, rootDigest, snapshotPreparation, keys[metadata.SNAPSHOT])
	timestampPreparation, _ := PrepareTimestamp(TimestampOptions{Root: rootRaw, Target: target, Targets: expiredTargets, Snapshot: snapshot, RootDigest: rootDigest, Version: 2, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	timestamp := finalizeTestRole(t, rootRaw, rootDigest, timestampPreparation, keys[metadata.TIMESTAMP])
	if _, _, err := FinalizePackage(FinalizePackageOptions{Root: rootRaw, Target: target, Targets: expiredTargets, Snapshot: snapshot, Timestamp: timestamp, RootDigest: rootDigest}); err == nil {
		t.Fatal("expired targets metadata reached successful package output")
	}
}

func TestFinalizeRoleRejectsWrongOrOpenRoleShape(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootRaw, rootDigest, keys := testRoot(t, now)
	target := emptyReplacementTarget(t, "44")
	prepared, err := PrepareTargets(TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 1, Expires: now.Add(time.Hour).Format(time.RFC3339)})
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
	targets.Signed.Targets[knowledge.ConstraintsTargetPath] = &metadata.TargetFiles{Length: 1, Hashes: metadata.Hashes{"sha256": hash}}
	if err := validateTargetsShape(targets); err != nil {
		t.Fatalf("valid targets shape: %v", err)
	}
	targets.Signed.Version = int64(^uint32(0)>>1) + 1
	if err := validateTargetsShape(targets); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized targets version=%v", err)
	}
	targets.Signed.Version = 1
	targets.Signed.Targets[knowledge.ConstraintsTargetPath].Length = MaxTargetBytes + 1
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
	prepared, err := PrepareTargets(TargetsOptions{Root: root, Target: emptyReplacementTarget(t, "43"), RootDigest: rootDigest, Version: 1, Expires: now.Add(time.Hour).Format(time.RFC3339)})
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

func emptyReplacementTarget(t *testing.T, revision string) []byte {
	t.Helper()
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	packRaw, err := json.Marshal(struct {
		Schema              string `json:"schema"`
		Revision            string `json:"revision"`
		PolicyID            string `json:"policyId"`
		PolicyDigest        string `json:"policyDigest"`
		LandscapeFileDigest string `json:"landscapeFileDigest"`
		RegistryDigest      string `json:"registryDigest"`
		Entries             []any  `json:"entries"`
	}{requirements.PackSchema, revision, requirements.PolicyID, requirements.PolicyDigest, requirements.LandscapeFileDigest, requirements.RegistryDigest, []any{}})
	if err != nil {
		t.Fatal(err)
	}
	document := struct {
		Schema                 string          `json:"schema"`
		Revision               string          `json:"revision"`
		Purpose                string          `json:"purpose"`
		EngineCapabilityDigest string          `json:"engineCapabilityDigest"`
		Pack                   json.RawMessage `json:"pack"`
	}{requirements.Schema, revision, "operator_provided", requirements.EngineCapabilityDigest, packRaw}
	target, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalBundle(target); err != nil {
		t.Fatal(err)
	}
	return target
}
