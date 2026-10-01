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
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func rootContribution(t *testing.T, p RootTransitionPreparation, key testKey) []byte {
	t.Helper()
	sig := ed25519.Sign(key.private, p.Payload)
	raw, err := json.Marshal(SignatureEnvelope{Schema: SignatureEnvelopeSchema, Role: metadata.ROOT, PayloadDigest: digest(p.Payload), Signatures: []SignatureInput{{KeyID: key.id, Sig: hex.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRootTransition_DualAuthorizationAndClosedBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, oldDigest, oldKeys := testRoot(t, now)
	template, templateDigest, newKeys := testRoot(t, now)
	opts := RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}
	p, err := PrepareRootTransition(opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, receipt, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, newKeys[metadata.ROOT])}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := metadata.Root().FromBytes(raw)
	if err != nil || parsed.Signed.Version != 2 || receipt.TrustedVersion != 1 || receipt.SuccessorVersion != 2 || receipt.NetworkUsed || receipt.KeysHandled {
		t.Fatalf("result=%+v root=%v err=%v", receipt, parsed, err)
	}
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT])}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("old-only accepted: %v", err)
	}
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{rootContribution(t, p, newKeys[metadata.ROOT])}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("new-only accepted: %v", err)
	}
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, newKeys[metadata.ROOT])}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("duplicate contribution accepted: %v", err)
	}
	tampered := append([]byte(nil), p.Request...)
	tampered[len(tampered)-2] ^= 1
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: tampered, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, newKeys[metadata.ROOT])}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("tampered request accepted: %v", err)
	}
	unknown := append(append([]byte(nil), p.Request[:len(p.Request)-1]...), []byte(`,"unknown":true}`)...)
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: unknown, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, newKeys[metadata.ROOT])}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown request field accepted: %v", err)
	}
	unauthorized := newTransitionTestKey(t)
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, newKeys[metadata.ROOT]), rootContribution(t, p, unauthorized)}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("unauthorized extra contribution accepted: %v", err)
	}
}

func TestRootTransitionReceiptUsesCanonicalLowerCamelCase(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, oldDigest, oldKeys := testRoot(t, now)
	template, templateDigest, newKeys := testRoot(t, now)
	opts := RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}
	p, err := PrepareRootTransition(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{rootContribution(t, p, oldKeys[metadata.ROOT]), rootContribution(t, p, newKeys[metadata.ROOT])}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"schema"`, `"trustedContributingKeyIDs"`, `"successorContributingKeyIDs"`, `"networkUsed"`} {
		if !bytes.Contains(raw, []byte(required)) {
			t.Fatalf("missing %s: %s", required, raw)
		}
	}
	for _, forbidden := range []string{`"Schema"`, `"TrustedKeyIDs"`, `"SuccessorKeyIDs"`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("legacy/capitalized key %s: %s", forbidden, raw)
		}
	}
	if len(receipt.TrustedContributingKeyIDs) != 1 || len(receipt.SuccessorContributingKeyIDs) != 1 {
		t.Fatalf("contributors=%+v", receipt)
	}
}

func TestRootTransition_SharedKeyTwoOfThreeUsesExactContributors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, _, oldKeys := testRoot(t, now)
	template, _, newKeys := testRoot(t, now)
	oldExtra := newTransitionTestKey(t)
	oldSpare := newTransitionTestKey(t)
	newExtra := newTransitionTestKey(t)
	old = thresholdRoot(t, old, []testKey{oldExtra, oldSpare}, []testKey{oldKeys[metadata.ROOT], oldExtra})
	oldDigest := digest(old)
	template = thresholdRoot(t, template, []testKey{oldKeys[metadata.ROOT], newExtra}, []testKey{newKeys[metadata.ROOT], newExtra})
	templateDigest := digest(template)
	opts := RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}
	p, err := PrepareRootTransition(opts)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := metadata.Root().FromBytes(old)
	if err != nil {
		t.Fatal(err)
	}
	successor, err := metadata.Root().FromBytes(template)
	if err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]*metadata.Metadata[metadata.RootType]{"trusted": trusted, "successor": successor} {
		policy := root.Signed.Roles[metadata.ROOT]
		if policy == nil || policy.Threshold != 2 || len(policy.KeyIDs) != 3 {
			t.Fatalf("%s root policy=%+v", name, policy)
		}
	}
	oldPrimary := rootContribution(t, p, oldKeys[metadata.ROOT])
	oldSecond := rootContribution(t, p, oldExtra)
	newPrimary := rootContribution(t, p, newKeys[metadata.ROOT])
	_, receipt, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldPrimary, oldSecond, newPrimary}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(receipt.TrustedContributingKeyIDs, sortedTransitionIDs(oldKeys[metadata.ROOT].id, oldExtra.id)) || !reflect.DeepEqual(receipt.SuccessorContributingKeyIDs, sortedTransitionIDs(oldKeys[metadata.ROOT].id, newKeys[metadata.ROOT].id)) {
		t.Fatalf("contributors=%+v", receipt)
	}
	for _, id := range append(append([]string(nil), receipt.TrustedContributingKeyIDs...), receipt.SuccessorContributingKeyIDs...) {
		if id == oldSpare.id || id == newExtra.id {
			t.Fatalf("unused authorized key appeared as contributor: %+v", receipt)
		}
	}
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldPrimary, newPrimary}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("old threshold shortfall accepted: %v", err)
	}
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldPrimary, oldSecond}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("successor threshold shortfall accepted: %v", err)
	}
	invalidExtra := rootContribution(t, p, newExtra)
	var invalidEnvelope SignatureEnvelope
	if err := json.Unmarshal(invalidExtra, &invalidEnvelope); err != nil {
		t.Fatal(err)
	}
	invalidEnvelope.Signatures[0].Sig = strings.Repeat("00", ed25519.SignatureSize)
	invalidExtra, err = json.Marshal(invalidEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldPrimary, oldSecond, newPrimary, invalidExtra}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("invalid authorized extra contribution accepted: %v", err)
	}
}

func TestRootTransition_RejectsConsumerInadmissibleTemplatePolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, oldDigest, _ := testRoot(t, now)
	template, _, templateKeys := testRoot(t, now)
	noncanonical, err := metadata.Root().FromBytes(template)
	if err != nil {
		t.Fatal(err)
	}
	extra := newTransitionTestKey(t)
	extraPublic, err := metadata.KeyFromPublicKey(extra.private.Public())
	if err != nil {
		t.Fatal(err)
	}
	noncanonicalID := strings.Repeat("0", 64)
	if computed, err := extraPublic.ID(); err != nil || computed == noncanonicalID {
		t.Fatalf("test key identity=%q err=%v", computed, err)
	}
	noncanonical.Signatures = nil
	noncanonical.Signed.Keys[noncanonicalID] = extraPublic
	if _, err := noncanonical.Sign(templateKeys[metadata.ROOT].signer); err != nil {
		t.Fatal(err)
	}
	noncanonicalRaw, err := noncanonical.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRootTransition(RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: noncanonicalRaw, SuccessorTemplateDigest: digest(noncanonicalRaw)}); !errors.Is(err, ErrRejected) {
		t.Fatalf("unreferenced noncanonical root key accepted: %v", err)
	}

	additions := make([]testKey, 32)
	for i := range additions {
		additions[i] = newTransitionTestKey(t)
	}
	tooMany := rootWithRootPolicy(t, template, additions, 1, []testKey{templateKeys[metadata.ROOT]})
	if _, err := PrepareRootTransition(RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: tooMany, SuccessorTemplateDigest: digest(tooMany)}); !errors.Is(err, ErrRejected) {
		t.Fatalf("33-key root role accepted: %v", err)
	}
}

func TestRootTransition_RejectsBoundedOrMismatchedInputsAndPreservesExistingOutput(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, oldDigest, oldKeys := testRoot(t, now)
	template, templateDigest, newKeys := testRoot(t, now)
	opts := RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}
	p, err := PrepareRootTransition(opts)
	if err != nil {
		t.Fatal(err)
	}
	oldContribution := rootContribution(t, p, oldKeys[metadata.ROOT])
	newContribution := rootContribution(t, p, newKeys[metadata.ROOT])
	tooMany := make([][]byte, 33)
	for i := range tooMany {
		tooMany[i] = oldContribution
	}
	if _, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: tooMany}); !errors.Is(err, ErrRejected) {
		t.Fatalf("too many contributions accepted: %v", err)
	}
	var wrongPayload SignatureEnvelope
	if err := json.Unmarshal(newContribution, &wrongPayload); err != nil {
		t.Fatal(err)
	}
	wrongPayload.PayloadDigest = "sha256:" + strings.Repeat("0", 64)
	wrongPayloadRaw, err := json.Marshal(wrongPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldContribution, wrongPayloadRaw}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong payload contribution accepted: %v", err)
	}
	wrongVersion, err := metadata.Root().FromBytes(p.UnsignedMetadata)
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion.Signed.Version++
	wrongVersion.Signatures = nil
	wrongUnsigned, err := wrongVersion.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: wrongUnsigned, Request: p.Request, Signatures: [][]byte{oldContribution, newContribution}}); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong successor version accepted: %v", err)
	}
	finalized, _, err := FinalizeRootTransition(RootTransitionFinalizeOptions{RootTransitionOptions: opts, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldContribution, newContribution}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	output := filepath.Join(dir, "successor.root.json")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteExclusive(output, finalized); !errors.Is(err, ErrRejected) {
		t.Fatalf("existing finalized-root output replaced: %v", err)
	}
	if got, err := os.ReadFile(output); err != nil || string(got) != "existing" {
		t.Fatalf("existing output changed: %q err=%v", got, err)
	}
}

func sortedTransitionIDs(ids ...string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

func newTransitionTestKey(t *testing.T) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(priv, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	key, err := metadata.KeyFromPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.ID()
	if err != nil {
		t.Fatal(err)
	}
	return testKey{private: priv, signer: signer, id: id}
}
func thresholdRoot(t *testing.T, raw []byte, additions []testKey, signers []testKey) []byte {
	return rootWithRootPolicy(t, raw, additions, 2, signers)
}

func rootWithRootPolicy(t *testing.T, raw []byte, additions []testKey, threshold int, signers []testKey) []byte {
	t.Helper()
	root, err := metadata.Root().FromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = nil
	for _, add := range additions {
		key, e := metadata.KeyFromPublicKey(add.private.Public())
		if e != nil {
			t.Fatal(e)
		}
		if e = root.Signed.AddKey(key, metadata.ROOT); e != nil {
			t.Fatal(e)
		}
	}
	root.Signed.Roles[metadata.ROOT].Threshold = threshold
	for _, s := range signers {
		if _, e := root.Sign(s.signer); e != nil {
			t.Fatal(e)
		}
	}
	out, e := root.ToBytes(false)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
