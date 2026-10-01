// SPDX-License-Identifier: AGPL-3.0-only

package knowledgesign

import "github.com/theupdateframework/go-tuf/v2/metadata"

// VerifyKeyOptions contains an owned passphrase buffer: VerifyKey consumes and
// wipes it. Root expiry is deliberately not assessed by this offline key-to-
// role comparison.
type VerifyKeyOptions struct {
	Root, EncryptedKey []byte
	RootDigest, Role   string
	Passphrase         []byte
}

// VerifyKeyReceipt describes only a mathematical restored-key match to one
// role in one independently pinned root. It is not a threshold, custody,
// backup-health, root-freshness, trust-activation, or publishing receipt.
type VerifyKeyReceipt struct {
	Schema                 string `json:"schema"`
	Status                 string `json:"status"`
	RootDigest             string `json:"rootDigest"`
	Role                   string `json:"role"`
	KeyID                  string `json:"keyId"`
	KeyMatchesSelectedRole bool   `json:"keyMatchesSelectedRole"`
	RootExpiryAssessed     bool   `json:"rootExpiryAssessed"`
	NetworkUsed            bool   `json:"networkUsed"`
	TrustActivated         bool   `json:"trustActivated"`
}

// VerifyKey checks one encrypted restored Ed25519 key against exactly one
// top-level role in a canonical self-signed root. It reads no store, signs no
// payload, and changes no trust state.
func VerifyKey(options VerifyKeyOptions) (VerifyKeyReceipt, error) {
	defer wipe(options.Passphrase)
	if !validPassphrase(options.Passphrase) || !validVerificationRole(options.Role) || !validDigest(options.RootDigest) || len(options.Root) == 0 || len(options.Root) > maxRootBytes || len(options.EncryptedKey) == 0 || len(options.EncryptedKey) > MaxKeyBytes {
		return VerifyKeyReceipt{}, ErrRejected
	}
	if err := ValidateRoot(options.Root, options.RootDigest); err != nil {
		return VerifyKeyReceipt{}, ErrRejected
	}
	root, err := metadata.Root().FromBytes(options.Root)
	if err != nil || root == nil {
		return VerifyKeyReceipt{}, ErrRejected
	}
	private, err := decryptPrivateKey(options.EncryptedKey, options.Passphrase)
	if err != nil {
		return VerifyKeyReceipt{}, ErrRejected
	}
	defer wipe(private)
	key, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		return VerifyKeyReceipt{}, ErrRejected
	}
	keyID, err := key.ID()
	if err != nil {
		return VerifyKeyReceipt{}, ErrRejected
	}
	role, ok := root.Signed.Roles[options.Role]
	if !ok || role == nil || !containsKeyID(role.KeyIDs, keyID) {
		return VerifyKeyReceipt{}, ErrRejected
	}
	rootKey, ok := root.Signed.Keys[keyID]
	if !ok || rootKey == nil {
		return VerifyKeyReceipt{}, ErrRejected
	}
	rootKeyID, err := rootKey.ID()
	if err != nil || rootKeyID != keyID || rootKey.Type != key.Type || rootKey.Scheme != key.Scheme || rootKey.Value.PublicKey != key.Value.PublicKey {
		return VerifyKeyReceipt{}, ErrRejected
	}
	return VerifyKeyReceipt{
		Schema: "prufyx.io/local-tuf-key-verification/v1", Status: "KEY_MATCHES_SELECTED_ROLE", RootDigest: options.RootDigest, Role: options.Role, KeyID: keyID,
		KeyMatchesSelectedRole: true, RootExpiryAssessed: false, NetworkUsed: false, TrustActivated: false,
	}, nil
}

func validVerificationRole(value string) bool {
	return value == metadata.ROOT || validRole(value)
}

func containsKeyID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
