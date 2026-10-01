// SPDX-License-Identifier: AGPL-3.0-only

package knowledgesign

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestSignRootTransition_ReconstructsTemplateAndAuthorities(t *testing.T) {
	old, oldDigest, oldDir := initialized(t)
	template, templateDigest, newDir := initialized(t)
	p, err := knowledgepublish.PrepareRootTransition(knowledgepublish.RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest})
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(filepath.Join(oldDir, "root.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := os.ReadFile(filepath.Join(newDir, "root.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	base := RootTransitionSignOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, ExpectedPayloadDigest: digest(p.Payload), Authority: "trusted", EncryptedKey: oldKey, Passphrase: []byte("operator passphrase 123")}
	oldEnv, err := SignRootTransition(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Authority = "successor"
	base.EncryptedKey = newKey
	base.Passphrase = []byte("operator passphrase 123")
	newEnv, err := SignRootTransition(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = knowledgepublish.FinalizeRootTransition(knowledgepublish.RootTransitionFinalizeOptions{RootTransitionOptions: knowledgepublish.RootTransitionOptions{TrustedRoot: old, TrustedRootDigest: oldDigest, SuccessorTemplate: template, SuccessorTemplateDigest: templateDigest}, UnsignedMetadata: p.UnsignedMetadata, Request: p.Request, Signatures: [][]byte{oldEnv, newEnv}}); err != nil {
		t.Fatal(err)
	}
	base.Authority = "trusted"
	base.EncryptedKey = newKey
	base.Passphrase = []byte("operator passphrase 123")
	if _, err = SignRootTransition(base); !errors.Is(err, ErrRejected) {
		t.Fatalf("new key accepted as old authority: %v", err)
	}
	base.EncryptedKey = oldKey
	base.SuccessorTemplateDigest = "sha256:" + string(make([]byte, 64))
	base.Passphrase = []byte("operator passphrase 123")
	if _, err = SignRootTransition(base); !errors.Is(err, ErrRejected) {
		t.Fatalf("bad template identity accepted: %v", err)
	}
	_ = metadata.ROOT
}
