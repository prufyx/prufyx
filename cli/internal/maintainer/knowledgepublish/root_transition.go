// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

const RootTransitionRequestSchema = "prufyx.io/tuf-root-transition-signing-request/v1"
const RootTransitionReceiptSchema = "prufyx.io/tuf-root-transition-finalization/v1"

type RootTransitionOptions struct {
	TrustedRoot, SuccessorTemplate             []byte
	TrustedRootDigest, SuccessorTemplateDigest string
}
type RootTransitionPreparation struct{ UnsignedMetadata, Payload, Request []byte }
type RootTransitionFinalizeOptions struct {
	RootTransitionOptions
	UnsignedMetadata, Request []byte
	Signatures                [][]byte
}
type RootTransitionReceipt struct {
	Schema                      string   `json:"schema"`
	Status                      string   `json:"status"`
	TrustedRootDigest           string   `json:"trustedRootDigest"`
	SuccessorRootDigest         string   `json:"successorRootDigest"`
	PayloadDigest               string   `json:"payloadDigest"`
	RequestDigest               string   `json:"requestDigest"`
	TrustedVersion              int64    `json:"trustedVersion"`
	SuccessorVersion            int64    `json:"successorVersion"`
	TrustedThreshold            int      `json:"trustedThreshold"`
	SuccessorThreshold          int      `json:"successorThreshold"`
	TrustedContributingKeyIDs   []string `json:"trustedContributingKeyIDs"`
	SuccessorContributingKeyIDs []string `json:"successorContributingKeyIDs"`
	NetworkUsed                 bool     `json:"networkUsed"`
	KeysHandled                 bool     `json:"keysHandled"`
}

type rootTransitionRequest struct {
	Schema                 string                  `json:"schema"`
	Role                   string                  `json:"role"`
	PayloadFormat          string                  `json:"payloadFormat"`
	PayloadDigest          string                  `json:"payloadDigest"`
	UnsignedMetadataDigest string                  `json:"unsignedMetadataDigest"`
	PayloadLength          int                     `json:"payloadLength"`
	Trusted                rootTransitionAuthority `json:"trusted"`
	Successor              rootTransitionAuthority `json:"successor"`
	TemplateDigest         string                  `json:"templateDigest"`
}
type rootTransitionAuthority struct {
	Version          int64    `json:"version"`
	Digest           string   `json:"digest"`
	AuthorizedKeyIDs []string `json:"authorizedKeyIDs"`
	Threshold        int      `json:"threshold"`
}

func PrepareRootTransition(opts RootTransitionOptions) (RootTransitionPreparation, error) {
	return prepareRootTransition(opts)
}

// ValidateRootTransition reconstructs the exact unsigned root, payload and closed request.
func ValidateRootTransition(opts RootTransitionOptions, unsigned, request []byte) (RootTransitionPreparation, error) {
	p, err := prepareRootTransition(opts)
	if err != nil || !bytes.Equal(p.UnsignedMetadata, unsigned) || !bytes.Equal(p.Request, request) {
		return RootTransitionPreparation{}, ErrRejected
	}
	return p, nil
}

func prepareRootTransition(opts RootTransitionOptions) (RootTransitionPreparation, error) {
	trusted, trustedDigest, err := admitRoot(opts.TrustedRoot, opts.TrustedRootDigest)
	if err != nil {
		return RootTransitionPreparation{}, err
	}
	templateDigest := opts.SuccessorTemplateDigest
	if !digestRE.MatchString(templateDigest) || digest(opts.SuccessorTemplate) != templateDigest {
		return RootTransitionPreparation{}, ErrRejected
	}
	if _, _, err := admitRoot(opts.SuccessorTemplate, templateDigest); err != nil {
		return RootTransitionPreparation{}, ErrRejected
	}
	candidate, err := metadata.Root().FromBytes(opts.SuccessorTemplate)
	if err != nil {
		return RootTransitionPreparation{}, ErrRejected
	}
	candidate.Signatures = []metadata.Signature{}
	candidate.Signed.Version = trusted.Signed.Version + 1
	if rootPolicy(candidate, false) != nil {
		return RootTransitionPreparation{}, ErrRejected
	}
	unsigned, err := candidate.ToBytes(false)
	if err != nil {
		return RootTransitionPreparation{}, ErrRejected
	}
	payload, err := cjson.EncodeCanonical(candidate.Signed)
	if err != nil {
		return RootTransitionPreparation{}, ErrRejected
	}
	old := authority(trusted, trustedDigest)
	next := authority(candidate, digest(unsigned))
	raw, err := json.Marshal(rootTransitionRequest{Schema: RootTransitionRequestSchema, Role: metadata.ROOT, PayloadFormat: "olpc_canonical_json_signed", PayloadDigest: digest(payload), PayloadLength: len(payload), UnsignedMetadataDigest: digest(unsigned), Trusted: old, Successor: next, TemplateDigest: templateDigest})
	if err != nil {
		return RootTransitionPreparation{}, ErrRejected
	}
	return RootTransitionPreparation{UnsignedMetadata: unsigned, Payload: payload, Request: raw}, nil
}

func authority(root *metadata.Metadata[metadata.RootType], d string) rootTransitionAuthority {
	r := root.Signed.Roles[metadata.ROOT]
	ids := append([]string(nil), r.KeyIDs...)
	sort.Strings(ids)
	return rootTransitionAuthority{Version: root.Signed.Version, Digest: d, AuthorizedKeyIDs: ids, Threshold: r.Threshold}
}

func FinalizeRootTransition(opts RootTransitionFinalizeOptions) ([]byte, RootTransitionReceipt, error) {
	p, err := ValidateRootTransition(opts.RootTransitionOptions, opts.UnsignedMetadata, opts.Request)
	if err != nil {
		return nil, RootTransitionReceipt{}, err
	}
	trusted, td, err := admitRoot(opts.TrustedRoot, opts.TrustedRootDigest)
	if err != nil {
		return nil, RootTransitionReceipt{}, err
	}
	candidate, err := metadata.Root().FromBytes(opts.UnsignedMetadata)
	if err != nil || rootPolicy(candidate, false) != nil {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	if len(opts.Signatures) == 0 || len(opts.Signatures) > 32 {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	var all []SignatureInput
	seen := map[string]string{}
	for _, raw := range opts.Signatures {
		env, e := parseSignatureEnvelope(raw, metadata.ROOT)
		if e != nil || env.PayloadDigest != digest(p.Payload) {
			return nil, RootTransitionReceipt{}, ErrRejected
		}
		for _, s := range env.Signatures {
			_, exists := seen[s.KeyID]
			if exists {
				return nil, RootTransitionReceipt{}, ErrRejected
			}
			seen[s.KeyID] = s.Sig
			all = append(all, s)
		}
	}
	if len(all) == 0 || len(all) > 32 {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	sort.Slice(all, func(i, j int) bool { return all[i].KeyID < all[j].KeyID })
	old, next := authority(trusted, td), authority(candidate, digest(opts.UnsignedMetadata))
	trustedContributors, successorContributors, err := validateRootContributions(trusted, candidate, p.Payload, all, old, next)
	if err != nil {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	candidate.Signatures = tufSignatures(SignatureEnvelope{Signatures: all})
	signed, err := candidate.ToBytes(false)
	if err != nil || len(signed) > MaxRootBytes {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	tm, err := trustedmetadata.New(opts.TrustedRoot)
	if err != nil {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	if _, err = tm.UpdateRoot(signed); err != nil || rootPolicy(tm.Root, true) != nil {
		return nil, RootTransitionReceipt{}, ErrRejected
	}
	return signed, RootTransitionReceipt{Schema: RootTransitionReceiptSchema, Status: "FINALIZED", TrustedRootDigest: td, SuccessorRootDigest: digest(signed), PayloadDigest: digest(p.Payload), RequestDigest: digest(opts.Request), TrustedVersion: old.Version, SuccessorVersion: tm.Root.Signed.Version, TrustedThreshold: old.Threshold, SuccessorThreshold: next.Threshold, TrustedContributingKeyIDs: trustedContributors, SuccessorContributingKeyIDs: successorContributors, NetworkUsed: false, KeysHandled: false}, nil
}

func validateRootContributions(trusted, successor *metadata.Metadata[metadata.RootType], payload []byte, inputs []SignatureInput, old, next rootTransitionAuthority) ([]string, []string, error) {
	allowed := map[string]*metadata.Key{}
	for _, id := range old.AuthorizedKeyIDs {
		allowed[id] = trusted.Signed.Keys[id]
	}
	for _, id := range next.AuthorizedKeyIDs {
		allowed[id] = successor.Signed.Keys[id]
	}
	oldSet, nextSet := map[string]bool{}, map[string]bool{}
	for _, id := range old.AuthorizedKeyIDs {
		oldSet[id] = true
	}
	for _, id := range next.AuthorizedKeyIDs {
		nextSet[id] = true
	}
	for _, input := range inputs {
		key := allowed[input.KeyID]
		if key == nil {
			return nil, nil, ErrRejected
		}
		public, e := key.ToPublicKey()
		if e != nil {
			return nil, nil, ErrRejected
		}
		ed, ok := public.(ed25519.PublicKey)
		if !ok {
			return nil, nil, ErrRejected
		}
		sig, e := hex.DecodeString(input.Sig)
		if e != nil || !ed25519.Verify(ed, payload, sig) {
			return nil, nil, ErrRejected
		}
	}
	var oldIDs, nextIDs []string
	for _, input := range inputs {
		if oldSet[input.KeyID] {
			oldIDs = append(oldIDs, input.KeyID)
		}
		if nextSet[input.KeyID] {
			nextIDs = append(nextIDs, input.KeyID)
		}
	}
	if len(oldIDs) < old.Threshold || len(nextIDs) < next.Threshold {
		return nil, nil, ErrRejected
	}
	sort.Strings(oldIDs)
	sort.Strings(nextIDs)
	return oldIDs, nextIDs, nil
}

func rootPolicy(root *metadata.Metadata[metadata.RootType], signed bool) error {
	if root == nil || root.Signed.Type != metadata.ROOT || root.Signed.Version < 1 || !validVersion(root.Signed.Version) || root.Signed.Expires.IsZero() || !root.Signed.ConsistentSnapshot || len(root.UnrecognizedFields) != 0 || len(root.Signed.UnrecognizedFields) != 0 || len(root.Signed.Roles) != 4 || !bytes.HasPrefix([]byte(root.Signed.SpecVersion), []byte("1.0.")) {
		return ErrRejected
	}
	for _, name := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		role := root.Signed.Roles[name]
		if role == nil || role.Threshold < 1 || role.Threshold > len(role.KeyIDs) || len(role.KeyIDs) > 32 || len(role.UnrecognizedFields) != 0 {
			return ErrRejected
		}
		ids := map[string]bool{}
		for _, id := range role.KeyIDs {
			key := root.Signed.Keys[id]
			if ids[id] || !keyIDRE.MatchString(id) || key == nil || key.Type != metadata.KeyTypeEd25519 || key.Scheme != metadata.KeySchemeEd25519 || len(key.UnrecognizedFields) != 0 || len(key.Value.UnrecognizedFields) != 0 {
				return ErrRejected
			}
			got, e := key.ID()
			if e != nil || got != id {
				return ErrRejected
			}
			ids[id] = true
		}
	}
	for id, key := range root.Signed.Keys {
		if key == nil || !keyIDRE.MatchString(id) || key.Type != metadata.KeyTypeEd25519 || key.Scheme != metadata.KeySchemeEd25519 || len(key.UnrecognizedFields) != 0 || len(key.Value.UnrecognizedFields) != 0 {
			return ErrRejected
		}
		computed, err := key.ID()
		if err != nil || computed != id {
			return ErrRejected
		}
	}
	if signed && root.VerifyDelegate(metadata.ROOT, root) != nil {
		return ErrRejected
	}
	return nil
}
