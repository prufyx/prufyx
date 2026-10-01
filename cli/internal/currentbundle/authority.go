// SPDX-License-Identifier: AGPL-3.0-only

package currentbundle

// This file exposes the narrow capability boundary used by compatibility
// evaluators. Artifact itself remains a useful value type for planners and
// tests, but it is intentionally not an authority token: callers must obtain
// this type from the strict persisted-artifact parser.

import (
	"bytes"
	"errors"
)

var ErrUnverifiedArtifact = errors.New("current bundle artifact is not parser-verified")

// VerifiedArtifact is an opaque, defensive capability issued only by
// ReadVerifiedArtifact. Its zero value and values assembled by external
// callers are unusable by downstream authority code.
type VerifiedArtifact struct {
	artifact Artifact
	seal     *artifactSeal
}

type artifactSeal struct{}

// ReadVerifiedArtifact performs one strict descriptor-relative read and
// returns a capability bound to the exact canonical bytes accepted by that
// parser. The path is deliberately confined to this ingestion boundary.
func ReadVerifiedArtifact(path string) (VerifiedArtifact, error) {
	a, err := ReadArtifact(path)
	if err != nil {
		return VerifiedArtifact{}, err
	}
	return VerifiedArtifact{artifact: a, seal: &artifactSeal{}}, nil
}

// IssueVerifiedArtifact issues the same narrow capability for an artifact
// that was produced by an owner-side importer in the current process. The
// artifact must already carry its canonical bytes and self-consistent digest;
// this function never opens a path, reconstructs bytes, or accepts a digest
// supplied separately by the caller. It exists for descriptor-owned factory
// adapters that have retained the exact result of BuildObservation.
func IssueVerifiedArtifact(a Artifact) (VerifiedArtifact, error) {
	if err := ValidateArtifact(a); err != nil {
		return VerifiedArtifact{}, err
	}
	// Artifact.Digest is the content digest of the canonical bundle with
	// bundleDigest omitted, not the digest of the serialized envelope (which
	// includes the bundleDigest field).  ValidateArtifact already checks both
	// bindings; repeat the content-digest check here before minting authority.
	if len(a.Bytes) == 0 || DigestBytesWithoutBundleDigest(a.Bundle) != a.Digest {
		return VerifiedArtifact{}, ErrUnverifiedArtifact
	}
	canonical, err := Marshal(a.Bundle)
	if err != nil || !bytes.Equal(canonical, a.Bytes) {
		return VerifiedArtifact{}, ErrUnverifiedArtifact
	}
	copy := a
	copy.Bytes = append([]byte(nil), a.Bytes...)
	copy.Bundle = cloneBundle(a.Bundle)
	copy.Disclosure.SourcePaths = append([]string(nil), a.Disclosure.SourcePaths...)
	copy.Disclosure.SourceDigests = append([]string(nil), a.Disclosure.SourceDigests...)
	return VerifiedArtifact{artifact: copy, seal: &artifactSeal{}}, nil
}

func (v VerifiedArtifact) Valid() bool {
	return v.seal != nil && ValidateArtifact(v.artifact) == nil
}

// Artifact returns a defensive value copy. The returned value is not itself
// an authority capability and mutations to it cannot change v.
func (v VerifiedArtifact) Artifact() (Artifact, error) {
	if !v.Valid() {
		return Artifact{}, ErrUnverifiedArtifact
	}
	a := v.artifact
	a.Bytes = append([]byte(nil), a.Bytes...)
	a.Bundle = cloneBundle(a.Bundle)
	a.Disclosure.SourcePaths = append([]string(nil), a.Disclosure.SourcePaths...)
	a.Disclosure.SourceDigests = append([]string(nil), a.Disclosure.SourceDigests...)
	return a, nil
}

func (v VerifiedArtifact) Digest() (string, error) {
	if !v.Valid() {
		return "", ErrUnverifiedArtifact
	}
	return v.artifact.Digest, nil
}
