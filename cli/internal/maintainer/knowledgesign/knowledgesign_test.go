// SPDX-License-Identifier: AGPL-3.0-only

package knowledgesign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestKnowledgeSign_InitProducesFourEncryptedRoleKeys(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "operator-keys")
	passphrase := []byte("operator passphrase 123")
	result, err := Init(InitOptions{KeyDir: keyDir, RootExpires: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339), Passphrase: passphrase})
	if err != nil || result.RootDigest == "" || len(result.Root) == 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !allZero(passphrase) {
		t.Fatal("owned passphrase buffer not wiped")
	}
	info, err := os.Stat(keyDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("key directory info=%v err=%v", info, err)
	}
	root, err := metadata.Root().FromBytes(result.Root)
	if err != nil || root.VerifyDelegate(metadata.ROOT, root) != nil || len(root.Signed.Keys) != 4 {
		t.Fatalf("root err=%v keys=%d", err, len(root.Signed.Keys))
	}
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		if len(root.Signed.Roles[role].KeyIDs) != 1 {
			t.Fatalf("role %s policy=%+v", role, root.Signed.Roles[role])
		}
		keyPath := filepath.Join(keyDir, role+".key.pem")
		raw, err := os.ReadFile(keyPath)
		if err != nil || !bytes.Contains(raw, []byte(EncryptedPEMType)) {
			t.Fatalf("role %s encrypted key missing err=%v", role, err)
		}
		info, err := os.Stat(keyPath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("role %s mode=%v err=%v", role, info.Mode(), err)
		}
		key, err := decryptPrivateKey(raw, []byte("operator passphrase 123"))
		if err != nil || len(key) != ed25519.PrivateKeySize {
			t.Fatalf("role %s decrypt err=%v", role, err)
		}
		wipe(key)
	}
}

func TestKnowledgeSign_SignRoleBindsAuthorizedRoleAndExactPayload(t *testing.T) {
	rootRaw, rootDigest, keyDir := initialized(t)
	target := targetFixture(t, "71")
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	prepared, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 1, Expires: expires})
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := os.ReadFile(filepath.Join(keyDir, "targets.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignRole(SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: keyRaw, Passphrase: []byte("operator passphrase 123")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := knowledgepublish.FinalizeRole(rootRaw, rootDigest, metadata.TARGETS, prepared.UnsignedMetadata, envelope); err != nil {
		t.Fatal(err)
	}
	wrongKey, err := os.ReadFile(filepath.Join(keyDir, "snapshot.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRole(SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: wrongKey, Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong role key accepted: %v", err)
	}
	if _, err := SignRole(SignOptions{Root: rootRaw, RootDigest: "sha256:" + strings.Repeat("0", 64), Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: keyRaw, Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong root accepted: %v", err)
	}
	tampered := append([]byte(nil), prepared.UnsignedMetadata...)
	tampered[len(tampered)-2] ^= 1
	if _, err := SignRole(SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: tampered, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: keyRaw, Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("tampered unsigned accepted: %v", err)
	}
}

func TestKnowledgeSign_RejectsPlaintextWrongPassphraseAndOverwrite(t *testing.T) {
	rootRaw, rootDigest, keyDir := initialized(t)
	target := targetFixture(t, "72")
	prepared, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 1, Expires: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := os.ReadFile(filepath.Join(keyDir, "targets.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRole(SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: keyRaw, Passphrase: []byte("wrong operator passphrase")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong passphrase accepted: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := SignRole(SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: plaintext, Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("plaintext key accepted: %v", err)
	}
	outputParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outputParent, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(outputParent, "envelope.json")
	options := SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: keyRaw, Passphrase: []byte("operator passphrase 123")}
	if err := SignRoleToFile(options, output); err != nil {
		t.Fatal(err)
	}
	options.Passphrase = []byte("operator passphrase 123")
	if err := SignRoleToFile(options, output); !errors.Is(err, ErrRejected) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	if raw, _ := os.ReadFile(output); len(raw) == 0 {
		t.Fatal("output was removed or changed to empty")
	}
}

func TestKnowledgeSign_RejectsUnsafeDirectoryExpiryAndNonCanonicalPEM(t *testing.T) {
	privateParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(InitOptions{KeyDir: filepath.Join(privateParent, "keys"), RootExpires: time.Now().UTC().Add(367 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339), Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("overlong expiry accepted: %v", err)
	}
	nonPrivate := filepath.Join(privateParent, "nonprivate")
	if err := os.Mkdir(nonPrivate, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nonPrivate, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(InitOptions{KeyDir: filepath.Join(nonPrivate, "keys"), RootExpires: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339), Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("non-private parent accepted: %v", err)
	}
	linked := filepath.Join(privateParent, "linked")
	if err := os.Symlink(privateParent, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(InitOptions{KeyDir: filepath.Join(linked, "keys"), RootExpires: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339), Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("symlink ancestor accepted: %v", err)
	}
	if err := os.Mkdir(filepath.Join(privateParent, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(InitOptions{KeyDir: filepath.Join(privateParent, "git-keys"), RootExpires: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339), Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("Git checkout parent accepted: %v", err)
	}
	rootRaw, rootDigest, keyDir := initialized(t)
	target := targetFixture(t, "73")
	prepared, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: rootRaw, Target: target, RootDigest: rootDigest, Version: 1, Expires: time.Now().UTC().Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	keyRaw, err := os.ReadFile(filepath.Join(keyDir, "targets.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	badPEM := append([]byte("garbage\n"), keyRaw...)
	if _, err := SignRole(SignOptions{Root: rootRaw, RootDigest: rootDigest, Role: metadata.TARGETS, Unsigned: prepared.UnsignedMetadata, ExpectedPayloadDigest: digest(prepared.Payload), EncryptedKey: badPEM, Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
		t.Fatalf("noncanonical PEM accepted: %v", err)
	}
}

func initialized(t *testing.T) ([]byte, string, string) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(parent, "keys")
	result, err := Init(InitOptions{KeyDir: keyDir, RootExpires: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339), Passphrase: []byte("operator passphrase 123")})
	if err != nil {
		t.Fatal(err)
	}
	return result.Root, result.RootDigest, keyDir
}

func targetFixture(t *testing.T, revision string) []byte {
	t.Helper()
	requirements, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	pack, err := json.Marshal(struct {
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
	raw, err := json.Marshal(struct {
		Schema                 string          `json:"schema"`
		Revision               string          `json:"revision"`
		Purpose                string          `json:"purpose"`
		EngineCapabilityDigest string          `json:"engineCapabilityDigest"`
		Pack                   json.RawMessage `json:"pack"`
	}{requirements.Schema, revision, "operator_provided", requirements.EngineCapabilityDigest, pack})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalBundle(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func allZero(value []byte) bool {
	for _, v := range value {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestEncryptedKeyPEMRoundTripAndRejections(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("operator passphrase 123")
	encoded, err := EncryptedKeyPEM(private, passphrase)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Contains(encoded, []byte(EncryptedPEMType)) {
		t.Fatal("encrypted key is not in the shared PEM container")
	}
	recovered, err := DecryptPrivateKey(encoded, passphrase)
	if err != nil || !bytes.Equal(recovered, private) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := DecryptPrivateKey(encoded, []byte("wrong passphrase abc")); err == nil {
		t.Fatal("decrypted with a wrong passphrase")
	}
	if _, err := DecryptPrivateKey(append(append([]byte(nil), encoded...), 'x'), passphrase); err == nil {
		t.Fatal("accepted trailing bytes after the PEM block")
	}
	if _, err := EncryptedKeyPEM(private, []byte("short")); err == nil {
		t.Fatal("accepted a passphrase below the minimum length")
	}
	if _, err := EncryptedKeyPEM(ed25519.PrivateKey("truncated"), passphrase); err == nil {
		t.Fatal("accepted a malformed private key")
	}
}
