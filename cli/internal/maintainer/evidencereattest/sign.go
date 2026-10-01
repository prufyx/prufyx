// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/sigstore/sigstore/pkg/signature"
)

// SignOptions signs one exact, already-prepared statement. It owns
// Passphrase and wipes it before returning.
//
// SignOptions does not itself check for a terminal: that check belongs to
// the CLI adapter, which must refuse to acquire a passphrase at all off a
// TTY (see cmd/prufyx-maintainer's promptPassphrase). This package's own
// refusal is checkSampleReviewed: a statement whose sampled rules are
// missing a recorded individual review is refused regardless of how the
// passphrase was obtained.
type SignOptions struct {
	Statement, TrustRoot, EncryptedKey []byte
	Passphrase                         []byte
	// ExpectedTrustRootDigest is the trust root's digest as the caller
	// independently knows it (from a pinned configuration value, never
	// computed from TrustRoot itself). Required: Sign refuses to run
	// without it, and refuses when it does not match sourcecorpus.SHA of
	// the supplied TrustRoot bytes. Computing the expected digest from the
	// same bytes being checked would accept any self-consistent trust
	// root an attacker hands in, which is not pinning at all.
	ExpectedTrustRootDigest string
	// Now is the signer's clock; zero means time.Now(). Sign refuses a
	// statement whose attestedAt is later than Now, so a future-dated
	// statement can never enter a pack's chain.
	Now time.Time
}

// checkSampleReviewed refuses to sign a statement carrying any
// sampled-for-full-review entry with no recorded review: the seeded sample
// must be reviewed, and Prepare can only record that a review happened,
// never that signing may proceed without one.
func checkSampleReviewed(statement Statement) error {
	if len(statement.SampledForFullReview) == 0 && len(statement.Rules) > 0 {
		// A non-empty batch with zero sampled rules can only happen if the
		// 10% seed genuinely rounds to zero, which sampleRuleIDs already
		// guarantees never happens for a non-empty batch (ceil of a
		// positive fraction is always >= 1). Treat an empty sample list on
		// a non-empty batch as a tampered statement.
		return fmt.Errorf("%w: sampled-for-full-review is empty on a non-empty batch", ErrRejected)
	}
	for _, sample := range statement.SampledForFullReview {
		if sample.ReviewRecordDigest == "" || !validDigest(sample.ReviewRecordDigest) {
			return fmt.Errorf("%w: sampled rule %s has no recorded individual review", ErrRejected, sample.RuleID)
		}
	}
	return nil
}

// Sign produces a detached envelope over the exact statement bytes. It
// refuses a statement that does not already parse, a statement attested
// after the signer's clock, a statement whose sampled rules lack a
// recorded review, a signer outside the trust root,
// and any statement bound to a different trust root than the one supplied.
func Sign(options SignOptions) ([]byte, error) {
	defer wipe(options.Passphrase)
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	statement, err := ParseStatement(options.Statement)
	if err != nil {
		return nil, ErrRejected
	}
	if attestedAt, err := parseUTC(statement.AttestedAt); err != nil || attestedAt.After(now) {
		return nil, fmt.Errorf("%w: attestedAt is in the future", ErrRejected)
	}
	if err := checkSampleReviewed(statement); err != nil {
		return nil, err
	}
	if !validDigest(options.ExpectedTrustRootDigest) {
		return nil, fmt.Errorf("%w: an expected trust root digest is required", ErrRejected)
	}
	root, err := ParseTrustRoot(options.TrustRoot, options.ExpectedTrustRootDigest, now)
	if err != nil {
		return nil, ErrRejected
	}
	if len(options.EncryptedKey) == 0 || len(options.EncryptedKey) > knowledgesign.MaxKeyBytes {
		return nil, ErrRejected
	}
	private, err := knowledgesign.DecryptPrivateKey(options.EncryptedKey, options.Passphrase)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(private)
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrRejected
	}
	keyID, err := keyIdentity(public)
	if err != nil {
		return nil, ErrRejected
	}
	authorized := false
	for _, key := range root.Keys {
		if key.KeyID == keyID {
			authorized = true
		}
	}
	if !authorized {
		return nil, ErrRejected
	}
	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		return nil, ErrRejected
	}
	produced, err := signer.SignMessage(bytes.NewReader(options.Statement))
	if err != nil || len(produced) != ed25519.SignatureSize {
		return nil, ErrRejected
	}
	defer wipe(produced)
	envelopeRaw, err := canonicalBytes(Envelope{
		SchemaVersion: EnvelopeSchema, StatementDigest: sourcecorpus.SHA(options.Statement),
		Signatures: []SignatureLine{{KeyID: keyID, Sig: hex.EncodeToString(produced)}},
	})
	if err != nil {
		return nil, ErrRejected
	}
	// Verify what will be written before returning it: a signer must never
	// emit an envelope its own verifier would reject.
	if _, err := VerifySignature(VerifySignatureOptions{
		Statement: options.Statement, Envelope: envelopeRaw, TrustRoot: options.TrustRoot,
		ExpectedTrustRootDigest: options.ExpectedTrustRootDigest, Now: now,
	}); err != nil {
		return nil, ErrRejected
	}
	return envelopeRaw, nil
}

// VerifySignatureOptions verifies one exact statement and envelope against
// a trust root pinned by digest.
type VerifySignatureOptions struct {
	Statement, Envelope, TrustRoot []byte
	// ExpectedTrustRootDigest is required for the same reason it is
	// required on SignOptions: it must come from the caller's own pinned
	// knowledge of the root, never be derived from TrustRoot itself.
	ExpectedTrustRootDigest string
	Now                     time.Time
}

// VerifySignatureResult reports what a successful signature verification
// established. It is deliberately separate from the V1-V7 structural
// invariants in verify.go: a statement can be structurally valid and
// unsigned (useful in early CI stages before a human has signed), and a
// signature check never substitutes for the structural checks.
type VerifySignatureResult struct {
	SignerKeyIDs    []string
	TrustRootDigest string
}

// VerifySignature checks a re-attestation statement's detached signature
// against a pinned trust root. It fails closed on an unknown signer, a
// wrong or expired root, a digest mismatch, a duplicate signer, or too few
// signatures.
func VerifySignature(options VerifySignatureOptions) (VerifySignatureResult, error) {
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	if !validDigest(options.ExpectedTrustRootDigest) {
		return VerifySignatureResult{}, fmt.Errorf("%w: an expected trust root digest is required", ErrRejected)
	}
	root, err := ParseTrustRoot(options.TrustRoot, options.ExpectedTrustRootDigest, now)
	if err != nil {
		return VerifySignatureResult{}, ErrRejected
	}
	trustRootDigest := options.ExpectedTrustRootDigest
	if _, err := ParseStatement(options.Statement); err != nil {
		return VerifySignatureResult{}, ErrRejected
	}
	envelope, err := decodeExact[Envelope](options.Envelope, MaxEnvelopeBytes)
	if err != nil || envelope.SchemaVersion != EnvelopeSchema {
		return VerifySignatureResult{}, ErrRejected
	}
	if envelope.StatementDigest != sourcecorpus.SHA(options.Statement) {
		return VerifySignatureResult{}, ErrRejected
	}
	if len(envelope.Signatures) < root.Threshold || len(envelope.Signatures) > len(root.Keys) {
		return VerifySignatureResult{}, ErrRejected
	}
	keys := make(map[string]ed25519.PublicKey, len(root.Keys))
	for _, key := range root.Keys {
		decoded, decodeErr := hex.DecodeString(key.PublicKey)
		if decodeErr != nil {
			return VerifySignatureResult{}, ErrRejected
		}
		keys[key.KeyID] = ed25519.PublicKey(decoded)
	}
	accepted := make([]string, 0, len(envelope.Signatures))
	seen := make(map[string]bool, len(envelope.Signatures))
	for _, line := range envelope.Signatures {
		public, known := keys[line.KeyID]
		if !known || seen[line.KeyID] || !validHex(line.Sig, 2*ed25519.SignatureSize) {
			return VerifySignatureResult{}, ErrRejected
		}
		raw, decodeErr := hex.DecodeString(line.Sig)
		if decodeErr != nil || !ed25519.Verify(public, options.Statement, raw) {
			return VerifySignatureResult{}, ErrRejected
		}
		seen[line.KeyID] = true
		accepted = append(accepted, line.KeyID)
	}
	if len(accepted) < root.Threshold {
		return VerifySignatureResult{}, ErrRejected
	}
	return VerifySignatureResult{SignerKeyIDs: accepted, TrustRootDigest: trustRootDigest}, nil
}
