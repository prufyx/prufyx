// SPDX-License-Identifier: AGPL-3.0-only

package knowledgesign

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type RootTransitionSignOptions struct {
	TrustedRoot, SuccessorTemplate, UnsignedMetadata, Request, EncryptedKey      []byte
	TrustedRootDigest, SuccessorTemplateDigest, ExpectedPayloadDigest, Authority string
	Passphrase                                                                   []byte
}

func SignRootTransition(opts RootTransitionSignOptions) ([]byte, error) {
	defer wipe(opts.Passphrase)
	if !validPassphrase(opts.Passphrase) || (opts.Authority != "trusted" && opts.Authority != "successor") || !validDigest(opts.TrustedRootDigest) || !validDigest(opts.SuccessorTemplateDigest) || !validDigest(opts.ExpectedPayloadDigest) || len(opts.EncryptedKey) == 0 || len(opts.EncryptedKey) > MaxKeyBytes {
		return nil, ErrRejected
	}
	p, err := knowledgepublish.ValidateRootTransition(knowledgepublish.RootTransitionOptions{TrustedRoot: opts.TrustedRoot, TrustedRootDigest: opts.TrustedRootDigest, SuccessorTemplate: opts.SuccessorTemplate, SuccessorTemplateDigest: opts.SuccessorTemplateDigest}, opts.UnsignedMetadata, opts.Request)
	if err != nil || digest(p.Payload) != opts.ExpectedPayloadDigest {
		return nil, ErrRejected
	}
	var request struct {
		Trusted struct {
			AuthorizedKeyIDs []string `json:"authorizedKeyIDs"`
		} `json:"trusted"`
		Successor struct {
			AuthorizedKeyIDs []string `json:"authorizedKeyIDs"`
		} `json:"successor"`
	}
	if json.Unmarshal(p.Request, &request) != nil {
		return nil, ErrRejected
	}
	private, err := decryptPrivateKey(opts.EncryptedKey, opts.Passphrase)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(private)
	key, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		return nil, ErrRejected
	}
	id, err := key.ID()
	if err != nil {
		return nil, ErrRejected
	}
	ids := request.Trusted.AuthorizedKeyIDs
	if opts.Authority == "successor" {
		ids = request.Successor.AuthorizedKeyIDs
	}
	found := false
	for _, v := range ids {
		if v == id {
			found = true
		}
	}
	if !found {
		return nil, ErrRejected
	}
	sig := ed25519.Sign(private, p.Payload)
	defer wipe(sig)
	raw, err := json.Marshal(knowledgepublish.SignatureEnvelope{Schema: knowledgepublish.SignatureEnvelopeSchema, Role: metadata.ROOT, PayloadDigest: digest(p.Payload), Signatures: []knowledgepublish.SignatureInput{{KeyID: id, Sig: hex.EncodeToString(sig)}}})
	if err != nil {
		return nil, ErrRejected
	}
	return raw, nil
}
func SignRootTransitionToFile(opts RootTransitionSignOptions, output string) error {
	raw, err := SignRootTransition(opts)
	if err != nil {
		return ErrRejected
	}
	defer wipe(raw)
	return writeNew(output, raw)
}
