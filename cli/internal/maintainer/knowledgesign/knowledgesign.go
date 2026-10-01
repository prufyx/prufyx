// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgesign creates encrypted local role keys and signs one exact
// TUF role payload. It never fetches, publishes, or persists passphrases.
package knowledgesign

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	EncryptedPEMType = "ENCRYPTED SIGSTORE PRIVATE KEY"
	MaxPassphrase    = 1024
	MinPassphrase    = 16
	MaxKeyBytes      = 64 << 10
	maxRootBytes     = 128 << 10
	maxRoleBytes     = 512 << 10
)

var ErrRejected = errors.New("knowledge signer input rejected")

// InitOptions contains an owned passphrase buffer: Init consumes and wipes it.
type InitOptions struct {
	KeyDir, RootExpires string
	Passphrase          []byte
}
type InitResult struct {
	RootDigest string
	Root       []byte
}

// SignOptions contains an owned passphrase buffer: SignRole consumes and wipes it.
type SignOptions struct {
	Root, Unsigned, EncryptedKey            []byte
	RootDigest, Role, ExpectedPayloadDigest string
	Passphrase                              []byte
}

// Init creates four distinct encrypted Ed25519 keys and a self-signed root in
// a new private directory outside a Git checkout. Failures leave that directory
// for deliberate operator inspection or cleanup.
func Init(options InitOptions) (InitResult, error) {
	defer wipe(options.Passphrase)
	if !validPassphrase(options.Passphrase) {
		return InitResult{}, ErrRejected
	}
	expires, err := parseFutureUTC(options.RootExpires)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	parent, name, err := openNewPrivateParent(options.KeyDir)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	defer parent.Close()
	if err := parent.Mkdir(name, 0o700); err != nil {
		return InitResult{}, ErrRejected
	}
	keyRoot, err := parent.OpenRoot(name)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	defer keyRoot.Close()
	if err := verifyPrivateRoot(keyRoot); err != nil {
		return InitResult{}, ErrRejected
	}

	keys := make(map[string]ed25519.PrivateKey, 4)
	defer func() {
		for _, key := range keys {
			wipe(key)
		}
	}()
	root := metadata.Root(expires)
	root.Signed.Version = 1
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return InitResult{}, ErrRejected
		}
		keys[role] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil || root.Signed.AddKey(key, role) != nil {
			return InitResult{}, ErrRejected
		}
	}
	rootSigner, err := signature.LoadSigner(keys[metadata.ROOT], crypto.Hash(0))
	if err != nil {
		return InitResult{}, ErrRejected
	}
	if _, err := root.Sign(rootSigner); err != nil {
		return InitResult{}, ErrRejected
	}
	rootRaw, err := root.ToBytes(false)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	for _, role := range []string{metadata.ROOT, metadata.TARGETS, metadata.SNAPSHOT, metadata.TIMESTAMP} {
		if err := writeEncryptedKeyAt(keyRoot, role+".key.pem", keys[role], options.Passphrase); err != nil {
			return InitResult{}, ErrRejected
		}
	}
	if err := writeNewAt(keyRoot, "root.json", rootRaw); err != nil {
		return InitResult{}, ErrRejected
	}
	if err := syncRoot(keyRoot); err != nil {
		return InitResult{}, ErrRejected
	}
	if err := syncRoot(parent); err != nil {
		return InitResult{}, ErrRejected
	}
	return InitResult{RootDigest: digest(rootRaw), Root: append([]byte(nil), rootRaw...)}, nil
}

// SignRole creates one canonical envelope and verifies it through the publisher
// finalizer before returning it. It accepts only encrypted local role keys.
func SignRole(options SignOptions) ([]byte, error) {
	defer wipe(options.Passphrase)
	if !validPassphrase(options.Passphrase) || !validRole(options.Role) || !validDigest(options.RootDigest) || !validDigest(options.ExpectedPayloadDigest) || len(options.Root) == 0 || len(options.Root) > maxRootBytes || len(options.Unsigned) == 0 || len(options.Unsigned) > maxRoleBytes || len(options.EncryptedKey) == 0 || len(options.EncryptedKey) > MaxKeyBytes {
		return nil, ErrRejected
	}
	if err := ValidateRoot(options.Root, options.RootDigest); err != nil {
		return nil, ErrRejected
	}
	payload, err := rolePayload(options.Role, options.Unsigned)
	if err != nil || digest(payload) != options.ExpectedPayloadDigest {
		return nil, ErrRejected
	}
	private, err := decryptPrivateKey(options.EncryptedKey, options.Passphrase)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(private)
	key, err := metadata.KeyFromPublicKey(private.Public())
	if err != nil {
		return nil, ErrRejected
	}
	keyID, err := key.ID()
	if err != nil {
		return nil, ErrRejected
	}
	signatureBytes := ed25519.Sign(private, payload)
	defer wipe(signatureBytes)
	envelopeRaw, err := json.Marshal(knowledgepublish.SignatureEnvelope{Schema: knowledgepublish.SignatureEnvelopeSchema, Role: options.Role, PayloadDigest: digest(payload), Signatures: []knowledgepublish.SignatureInput{{KeyID: keyID, Sig: hex.EncodeToString(signatureBytes)}}})
	if err != nil {
		return nil, ErrRejected
	}
	if _, err := knowledgepublish.FinalizeRole(options.Root, options.RootDigest, options.Role, options.Unsigned, envelopeRaw); err != nil {
		wipe(envelopeRaw)
		return nil, ErrRejected
	}
	return envelopeRaw, nil
}

// SignRoleToFile verifies the external signature envelope before creating one
// new output. It never removes an output path after a failed write.
func SignRoleToFile(options SignOptions, output string) error {
	envelope, err := SignRole(options)
	if err != nil {
		return ErrRejected
	}
	defer wipe(envelope)
	return writeNew(output, envelope)
}

func writeEncryptedKeyAt(root *os.Root, name string, private ed25519.PrivateKey, passphrase []byte) error {
	encoded, err := EncryptedKeyPEM(private, passphrase)
	if err != nil {
		return ErrRejected
	}
	defer wipe(encoded)
	return writeNewAt(root, name, encoded)
}

// EncryptedKeyPEM encodes one Ed25519 private key as an encrypted PEM block
// using the OWASP KDF parameters. It is the single definition of the local
// key-custody format: every maintainer signing purpose must use it rather than
// choosing its own KDF, cipher, or container.
func EncryptedKeyPEM(private ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize || !validPassphrase(passphrase) {
		return nil, ErrRejected
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(der)
	ciphertext, err := encrypted.EncryptWithCustomKDFParameters(der, passphrase, encrypted.OWASP)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(ciphertext)
	return pem.EncodeToMemory(&pem.Block{Type: EncryptedPEMType, Bytes: ciphertext}), nil
}

// DecryptPrivateKey recovers one Ed25519 private key from an encrypted PEM
// block. It never accepts trailing bytes, PEM headers, or a re-encoded block
// that differs from the exact supplied bytes.
func DecryptPrivateKey(raw, passphrase []byte) (ed25519.PrivateKey, error) {
	return decryptPrivateKey(raw, passphrase)
}

func decryptPrivateKey(raw, passphrase []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || block.Type != EncryptedPEMType || len(block.Headers) != 0 || !bytes.Equal(raw, pem.EncodeToMemory(block)) {
		return nil, ErrRejected
	}
	plaintext, err := encrypted.Decrypt(block.Bytes, passphrase)
	if err != nil {
		return nil, ErrRejected
	}
	defer wipe(plaintext)
	parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return nil, ErrRejected
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, ErrRejected
	}
	defer wipe(private)
	return append(ed25519.PrivateKey(nil), private...), nil
}

func rolePayload(role string, raw []byte) ([]byte, error) {
	switch role {
	case metadata.TARGETS:
		parsed, err := metadata.Targets().FromBytes(raw)
		if err != nil || parsed == nil || len(parsed.Signatures) != 0 {
			return nil, ErrRejected
		}
		canonical, err := parsed.ToBytes(false)
		if err != nil || !bytes.Equal(canonical, raw) || parsed.Signed.Type != metadata.TARGETS {
			return nil, ErrRejected
		}
		return cjson.EncodeCanonical(parsed.Signed)
	case metadata.SNAPSHOT:
		parsed, err := metadata.Snapshot().FromBytes(raw)
		if err != nil || parsed == nil || len(parsed.Signatures) != 0 {
			return nil, ErrRejected
		}
		canonical, err := parsed.ToBytes(false)
		if err != nil || !bytes.Equal(canonical, raw) || parsed.Signed.Type != metadata.SNAPSHOT {
			return nil, ErrRejected
		}
		return cjson.EncodeCanonical(parsed.Signed)
	case metadata.TIMESTAMP:
		parsed, err := metadata.Timestamp().FromBytes(raw)
		if err != nil || parsed == nil || len(parsed.Signatures) != 0 {
			return nil, ErrRejected
		}
		canonical, err := parsed.ToBytes(false)
		if err != nil || !bytes.Equal(canonical, raw) || parsed.Signed.Type != metadata.TIMESTAMP {
			return nil, ErrRejected
		}
		return cjson.EncodeCanonical(parsed.Signed)
	default:
		return nil, ErrRejected
	}
}

// ValidateRoot checks bounded canonical self-signed root bytes and their declared digest.
// It performs no key decryption and is safe to call before an interactive prompt.
func ValidateRoot(raw []byte, expected string) error {
	if !validDigest(expected) || len(raw) == 0 || len(raw) > maxRootBytes {
		return ErrRejected
	}
	return validateRootCandidate(raw, expected)
}

func validateRootCandidate(raw []byte, expected string) error {
	if digest(raw) != expected {
		return ErrRejected
	}
	root, err := metadata.Root().FromBytes(raw)
	if err != nil || root == nil || root.Signed.Type != metadata.ROOT || root.Signed.Version < 1 || root.Signed.Expires.IsZero() {
		return ErrRejected
	}
	canonical, err := root.ToBytes(false)
	if err != nil || !bytes.Equal(canonical, raw) || root.VerifyDelegate(metadata.ROOT, root) != nil {
		return ErrRejected
	}
	return nil
}

func writeNew(path string, raw []byte) error {
	parent, name, err := openNewPrivateParent(path)
	if err != nil {
		return ErrRejected
	}
	defer parent.Close()
	if err := writeNewAt(parent, name, raw); err != nil {
		return ErrRejected
	}
	return syncRoot(parent)
}

func writeNewAt(root *os.Root, name string, raw []byte) error {
	if root == nil || name == "" || filepath.Base(name) != name || len(raw) == 0 {
		return ErrRejected
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrRejected
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return ErrRejected
	}
	if _, err := file.Write(raw); err != nil {
		return ErrRejected
	}
	if err := file.Sync(); err != nil {
		return ErrRejected
	}
	if err := file.Close(); err != nil {
		return ErrRejected
	}
	closed = true
	return nil
}

// ValidateInitRequest checks the non-secret init arguments before a caller
// prompts for a passphrase. It performs no writes.
func ValidateInitRequest(keyDir, rootExpires string) error {
	if _, err := parseFutureUTC(rootExpires); err != nil || !validNewPrivatePath(keyDir) {
		return ErrRejected
	}
	return nil
}

func openNewPrivateParent(path string) (*os.Root, string, error) {
	if !validNewPrivatePath(path) {
		return nil, "", ErrRejected
	}
	parent := filepath.Dir(path)
	before, err := os.Lstat(parent)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm() != 0o700 || !ownedByCurrentUser(before) {
		return nil, "", ErrRejected
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, "", ErrRejected
	}
	if err := verifyPrivateRoot(root); err != nil {
		_ = root.Close()
		return nil, "", ErrRejected
	}
	held, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, "", ErrRejected
	}
	after, statErr := held.Stat()
	closeErr := held.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, "", ErrRejected
	}
	return root, filepath.Base(path), nil
}

func validNewPrivatePath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return false
	}
	parent := filepath.Dir(path)
	return physicalPrivateDirectory(parent) && outsideGitCheckout(parent)
}

func physicalPrivateDirectory(path string) bool {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			return false
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().Perm() == 0o700 && ownedByCurrentUser(info)
}

func verifyPrivateRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return ErrRejected
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedByCurrentUser(info) {
		return ErrRejected
	}
	return nil
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return ErrRejected
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrRejected
	}
	return nil
}

func outsideGitCheckout(path string) bool {
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		gitInfo, gitErr := os.Lstat(filepath.Join(current, ".git"))
		if gitErr == nil {
			_ = gitInfo
			return false
		}
		if !os.IsNotExist(gitErr) {
			return false
		}
		next := filepath.Dir(current)
		if next == current {
			return true
		}
		current = next
	}
}

func parseFutureUTC(value string) (time.Time, error) {
	now := time.Now().UTC()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value || !strings.HasSuffix(value, "Z") || !parsed.After(now) || parsed.After(now.Add(366*24*time.Hour)) {
		return time.Time{}, ErrRejected
	}
	return parsed, nil
}
func validPassphrase(value []byte) bool {
	return len(value) >= MinPassphrase && len(value) <= MaxPassphrase
}
func validRole(value string) bool {
	return value == metadata.TARGETS || value == metadata.SNAPSHOT || value == metadata.TIMESTAMP
}
func validDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[7:], "0123456789abcdef") == ""
}
func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
