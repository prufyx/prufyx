// SPDX-License-Identifier: AGPL-3.0-only

package knowledgesign

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestVerifyKeyMatchesEveryTopLevelRole(t *testing.T) {
	rootRaw, rootDigest, keyDir := initialized(t)
	root, err := metadata.Root().FromBytes(rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		t.Run(role, func(t *testing.T) {
			keyRaw, err := os.ReadFile(filepath.Join(keyDir, role+".key.pem"))
			if err != nil {
				t.Fatal(err)
			}
			passphrase := []byte("operator passphrase 123")
			receipt, err := VerifyKey(VerifyKeyOptions{Root: rootRaw, RootDigest: rootDigest, Role: role, EncryptedKey: keyRaw, Passphrase: passphrase})
			if err != nil || !allZero(passphrase) || receipt.Schema != "prufyx.io/local-tuf-key-verification/v1" || receipt.Status != "KEY_MATCHES_SELECTED_ROLE" || receipt.RootDigest != rootDigest || receipt.Role != role || receipt.KeyID == "" || !receipt.KeyMatchesSelectedRole || receipt.RootExpiryAssessed || receipt.NetworkUsed || receipt.TrustActivated || !containsKeyID(root.Signed.Roles[role].KeyIDs, receipt.KeyID) {
				t.Fatalf("receipt=%+v passphraseWiped=%t err=%v", receipt, allZero(passphrase), err)
			}
		})
	}
}

func TestVerifyKeyRejectsWrongRolePassphraseRootAndPlaintext(t *testing.T) {
	rootRaw, rootDigest, keyDir := initialized(t)
	targetsKey, err := os.ReadFile(filepath.Join(keyDir, "targets.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, test := range []struct {
		name   string
		role   string
		root   []byte
		digest string
		key    []byte
		pass   string
	}{
		{name: "wrong-role", role: metadata.SNAPSHOT, root: rootRaw, digest: rootDigest, key: targetsKey, pass: "operator passphrase 123"},
		{name: "wrong-passphrase", role: metadata.TARGETS, root: rootRaw, digest: rootDigest, key: targetsKey, pass: "wrong operator passphrase"},
		{name: "wrong-root-digest", role: metadata.TARGETS, root: rootRaw, digest: "sha256:" + strings.Repeat("0", 64), key: targetsKey, pass: "operator passphrase 123"},
		{name: "unknown-role", role: "delegated", root: rootRaw, digest: rootDigest, key: targetsKey, pass: "operator passphrase 123"},
		{name: "plaintext", role: metadata.TARGETS, root: rootRaw, digest: rootDigest, key: plaintext, pass: "operator passphrase 123"},
	} {
		t.Run(test.name, func(t *testing.T) {
			passphrase := []byte(test.pass)
			if _, err := VerifyKey(VerifyKeyOptions{Root: test.root, RootDigest: test.digest, Role: test.role, EncryptedKey: test.key, Passphrase: passphrase}); !errors.Is(err, ErrRejected) || !allZero(passphrase) {
				t.Fatalf("err=%v passphraseWiped=%t", err, allZero(passphrase))
			}
		})
	}
}

func TestVerifyKeyRejectsMissingOrMismatchedRootRoleKey(t *testing.T) {
	rootRaw, _, keyDir := initialized(t)
	targetsKey, err := os.ReadFile(filepath.Join(keyDir, "targets.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := os.ReadFile(filepath.Join(keyDir, "root.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*metadata.RootType)
	}{
		{name: "missing-selected-key", mutate: func(root *metadata.RootType) {
			delete(root.Keys, root.Roles[metadata.TARGETS].KeyIDs[0])
		}},
		{name: "mismatched-selected-key", mutate: func(root *metadata.RootType) {
			targetID := root.Roles[metadata.TARGETS].KeyIDs[0]
			snapshotID := root.Roles[metadata.SNAPSHOT].KeyIDs[0]
			root.Keys[targetID] = root.Keys[snapshotID]
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := resignRoot(t, rootRaw, rootKey, test.mutate)
			if _, err := VerifyKey(VerifyKeyOptions{Root: mutated, RootDigest: digest(mutated), Role: metadata.TARGETS, EncryptedKey: targetsKey, Passphrase: []byte("operator passphrase 123")}); !errors.Is(err, ErrRejected) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestVerifyKeyDoesNotAssessRootExpiryOrRoleThreshold(t *testing.T) {
	rootRaw, _, keyDir := initialized(t)
	targetsKey, err := os.ReadFile(filepath.Join(keyDir, "targets.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := os.ReadFile(filepath.Join(keyDir, "root.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := resignRoot(t, rootRaw, rootKey, func(root *metadata.RootType) {
		root.Expires = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		root.Roles[metadata.TARGETS].KeyIDs = append(root.Roles[metadata.TARGETS].KeyIDs, root.Roles[metadata.SNAPSHOT].KeyIDs[0])
		root.Roles[metadata.TARGETS].Threshold = 2
	})
	receipt, err := VerifyKey(VerifyKeyOptions{Root: mutated, RootDigest: digest(mutated), Role: metadata.TARGETS, EncryptedKey: targetsKey, Passphrase: []byte("operator passphrase 123")})
	if err != nil || receipt.Status != "KEY_MATCHES_SELECTED_ROLE" || !receipt.KeyMatchesSelectedRole || receipt.RootExpiryAssessed || receipt.TrustActivated {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if strings.Contains(strings.ToLower(receipt.Status), "threshold") || strings.Contains(strings.ToLower(receipt.Status), "ready") {
		t.Fatalf("single-key receipt overstates threshold readiness: %+v", receipt)
	}
}

func resignRoot(t *testing.T, raw, rootKeyRaw []byte, mutate func(*metadata.RootType)) []byte {
	t.Helper()
	root, err := metadata.Root().FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&root.Signed)
	private, err := decryptPrivateKey(rootKeyRaw, []byte("operator passphrase 123"))
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(private)
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	root.ClearSignatures()
	if _, err := root.Sign(signer); err != nil {
		t.Fatal(err)
	}
	result, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
