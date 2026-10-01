// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// MigrateTrustRootOptions names everything MigrateTrustRoot needs. It
// performs no I/O and never touches a private key: a trust root holds
// public keys only.
type MigrateTrustRootOptions struct {
	// From is the exact bytes of the current trust root, v1 or v2.
	From []byte
	// ExpectedFromDigest is From's digest as the caller independently knows
	// it (its pinned value), never computed from From itself.
	ExpectedFromDigest string
	// Now is the caller's clock; From must not have expired at Now, and
	// the result's expiry must be after Now.
	Now time.Time
	// Expires is the new root's expiry as exact UTC RFC3339. Empty keeps
	// From's expiry.
	Expires string
	// AddAutomationKeys lists hex-encoded Ed25519 public keys to add with
	// the automation role.
	AddAutomationKeys []string
	// RemoveKeyIDs lists key IDs to drop (key rotation). Each must be in
	// From.
	RemoveKeyIDs []string
}

// MigrateTrustRootResult is the new v2 trust root and its digest.
type MigrateTrustRootResult struct {
	TrustRoot []byte
	Digest    string
	Keys      []TrustKey
}

// MigrateTrustRoot renders a v2 trust root from an existing v1 or v2 root.
// Every key it keeps keeps its effective role: a v1 root's keys become
// human keys, a v2 root's keys keep their declared role, so no key ever
// changes role. It can add automation keys and remove keys; it never adds
// a human key, so a human key can enter a root only through the root that
// first listed it. The threshold is carried over unchanged. The result is
// self-checked with ParseTrustRoot against its own digest.
//
// Statements already signed under From stay verifiable under the result
// with the same keys, provided the signing keys are kept: a v1 statement
// requires a human key, and every v1 root key is a human key in the result.
// Only the pinned trust-root digest changes.
func MigrateTrustRoot(options MigrateTrustRootOptions) (MigrateTrustRootResult, error) {
	if options.Now.IsZero() {
		return MigrateTrustRootResult{}, fmt.Errorf("%w: the caller's current time is required", ErrRejected)
	}
	now := options.Now.UTC()
	from, err := ParseTrustRoot(options.From, options.ExpectedFromDigest, now)
	if err != nil {
		return MigrateTrustRootResult{}, fmt.Errorf("%w: the current trust root does not verify against its pinned digest", ErrRejected)
	}
	remove := map[string]bool{}
	for _, id := range options.RemoveKeyIDs {
		remove[id] = true
	}
	present := map[string]bool{}
	keys := make([]TrustKey, 0, len(from.Keys)+len(options.AddAutomationKeys))
	for _, key := range from.Keys {
		present[key.KeyID] = true
		if remove[key.KeyID] {
			continue
		}
		key.Role = keyRole(from, key)
		keys = append(keys, key)
	}
	for id := range remove {
		if !present[id] {
			return MigrateTrustRootResult{}, fmt.Errorf("%w: key %s to remove is not in the trust root", ErrRejected, id)
		}
	}
	for _, encoded := range options.AddAutomationKeys {
		if !validHex(encoded, 2*ed25519.PublicKeySize) {
			return MigrateTrustRootResult{}, fmt.Errorf("%w: an automation public key must be %d lowercase hex characters", ErrRejected, 2*ed25519.PublicKeySize)
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			return MigrateTrustRootResult{}, ErrRejected
		}
		id, err := keyIdentity(ed25519.PublicKey(decoded))
		if err != nil {
			return MigrateTrustRootResult{}, err
		}
		if present[id] {
			return MigrateTrustRootResult{}, fmt.Errorf("%w: key %s is already in the trust root", ErrRejected, id)
		}
		present[id] = true
		keys = append(keys, TrustKey{KeyID: id, KeyType: "ed25519", Scheme: "ed25519", PublicKey: encoded, Role: RoleAutomation})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	expires := from.Expires
	if options.Expires != "" {
		expires = options.Expires
	}
	root := TrustRoot{SchemaVersion: TrustRootSchema, Purpose: Purpose, Expires: expires, Threshold: from.Threshold, Keys: keys}
	raw, err := canonicalBytes(root)
	if err != nil {
		return MigrateTrustRootResult{}, err
	}
	digest := sourcecorpus.SHA(raw)
	if _, err := ParseTrustRoot(raw, digest, now); err != nil {
		return MigrateTrustRootResult{}, fmt.Errorf("%w: the migrated trust root does not verify (expiry, threshold per role, or keys)", ErrRejected)
	}
	return MigrateTrustRootResult{TrustRoot: raw, Digest: digest, Keys: keys}, nil
}

// StatementSignerRole returns the role a key must have to sign the exact
// statement bytes raw, after the same validation ParseStatement applies.
func StatementSignerRole(raw []byte) (string, error) {
	statement, err := ParseStatement(raw)
	if err != nil {
		return "", err
	}
	return statementRole(statement)
}
