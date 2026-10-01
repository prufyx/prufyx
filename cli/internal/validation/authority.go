// SPDX-License-Identifier: AGPL-3.0-only

package validation

// Parser-issued capabilities for the exact proposed bundle and policy
// documents. Ordinary ProposedBundle and PolicyReference values remain
// intentionally usable for candidate/report plumbing but do not cross into
// compatibility authority.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrUnverifiedInput = errors.New("validation input is not parser-verified")

type VerifiedProposedBundle struct {
	bundle ProposedBundle
	// raw is the exact descriptor accepted by the strict parser. Authority
	// digests bind these bytes, not a reconstructed Go value.
	raw    []byte
	digest string
	seal   *proposedBundleSeal
}

type proposedBundleSeal struct{}

func ReadVerifiedProposedBundle(path string) (VerifiedProposedBundle, error) {
	var b ProposedBundle
	raw, err := readStrictJSON(path, "proposed bundle", &b)
	if err != nil {
		return VerifiedProposedBundle{}, err
	}
	if err := b.validate(); err != nil {
		return VerifiedProposedBundle{}, err
	}
	b.PolicyRef = normalizedPolicy(b.PolicyRef)
	return VerifiedProposedBundle{bundle: cloneProposedBundle(b), raw: append([]byte(nil), raw...), digest: DigestBytes(raw), seal: &proposedBundleSeal{}}, nil
}

// ParseVerifiedProposedBundle admits an already-retained canonical document
// without reopening a pathname. It is the owner-side bridge for local
// synthetic factories; the exact bytes remain bound to the issued capability.
func ParseVerifiedProposedBundle(raw []byte) (VerifiedProposedBundle, error) {
	var b ProposedBundle
	if len(raw) == 0 {
		return VerifiedProposedBundle{}, ErrUnverifiedInput
	}
	parsed, err := parseStrictJSONBytes(raw, "proposed bundle", &b)
	if err != nil {
		return VerifiedProposedBundle{}, err
	}
	if err := b.validate(); err != nil {
		return VerifiedProposedBundle{}, err
	}
	b.PolicyRef = normalizedPolicy(b.PolicyRef)
	return VerifiedProposedBundle{bundle: cloneProposedBundle(b), raw: append([]byte(nil), parsed...), digest: DigestBytes(parsed), seal: &proposedBundleSeal{}}, nil
}

func (v VerifiedProposedBundle) Valid() bool {
	return v.seal != nil && len(v.raw) > 0 && v.digest == DigestBytes(v.raw) && v.bundle.validate() == nil
}

func (v VerifiedProposedBundle) Bundle() (ProposedBundle, error) {
	if !v.Valid() {
		return ProposedBundle{}, ErrUnverifiedInput
	}
	return cloneProposedBundle(v.bundle), nil
}

func (v VerifiedProposedBundle) Digest() (string, error) {
	if !v.Valid() {
		return "", ErrUnverifiedInput
	}
	return v.digest, nil
}

type VerifiedPolicyReference struct {
	policy PolicyReference
	// Keep the exact accepted bytes private. The normalized typed value is for
	// semantic checks; it is never used to reconstruct the authority digest.
	raw    []byte
	digest string
	seal   *policyReferenceSeal
}

type policyReferenceSeal struct{}

func ReadVerifiedPolicyReference(path string) (VerifiedPolicyReference, error) {
	var p PolicyReference
	raw, err := readStrictJSON(path, "trust policy reference", &p)
	if err != nil {
		return VerifiedPolicyReference{}, err
	}
	if err := p.validate(); err != nil {
		return VerifiedPolicyReference{}, err
	}
	p = normalizedPolicy(p)
	return VerifiedPolicyReference{policy: p, raw: append([]byte(nil), raw...), digest: DigestBytes(raw), seal: &policyReferenceSeal{}}, nil
}

// ParseVerifiedPolicyReference is the descriptor-free counterpart used when
// an owner has already retained exact policy bytes. It performs the same
// closed-schema and duplicate-key checks as the path-based reader.
func ParseVerifiedPolicyReference(raw []byte) (VerifiedPolicyReference, error) {
	var p PolicyReference
	parsed, err := parseStrictJSONBytes(raw, "trust policy reference", &p)
	if err != nil {
		return VerifiedPolicyReference{}, err
	}
	if err := p.validate(); err != nil {
		return VerifiedPolicyReference{}, err
	}
	p = normalizedPolicy(p)
	return VerifiedPolicyReference{policy: p, raw: append([]byte(nil), parsed...), digest: DigestBytes(parsed), seal: &policyReferenceSeal{}}, nil
}

func (v VerifiedPolicyReference) Valid() bool {
	return v.seal != nil && len(v.raw) > 0 && v.digest == DigestBytes(v.raw) && v.policy.validate() == nil
}

func (v VerifiedPolicyReference) Policy() (PolicyReference, error) {
	if !v.Valid() {
		return PolicyReference{}, ErrUnverifiedInput
	}
	return normalizedPolicy(v.policy), nil
}

func (v VerifiedPolicyReference) Digest() (string, error) {
	if !v.Valid() {
		return "", ErrUnverifiedInput
	}
	return v.digest, nil
}

func cloneProposedBundle(in ProposedBundle) ProposedBundle {
	out := in
	out.PolicyRef = normalizedPolicy(in.PolicyRef)
	out.Components = make([]ProposedTarget, len(in.Components))
	for i, target := range in.Components {
		out.Components[i] = target
		if target.Configuration != nil {
			out.Components[i].Configuration = make(map[string]json.RawMessage, len(target.Configuration))
			for key, raw := range target.Configuration {
				out.Components[i].Configuration[key] = append(json.RawMessage(nil), raw...)
			}
		}
	}
	return out
}

func parseStrictJSONBytes(raw []byte, label string, destination any) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxInputBytes || !utf8.Valid(raw) {
		return nil, ErrUnverifiedInput
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return nil, ErrUnverifiedInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return nil, ErrUnverifiedInput
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrUnverifiedInput
	}
	if err := validateJSONValue(raw, 0); err != nil {
		return nil, err
	}
	return append([]byte(nil), raw...), nil
}
