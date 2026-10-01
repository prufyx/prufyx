// SPDX-License-Identifier: AGPL-3.0-only

// Package releasesign binds a complete Community release asset set to an
// offline Ed25519 signature and a pinned trust root.
//
// It closes the local half of release gate G2: canonical payload, signature,
// trust root, signer identity, expiry, audience/purpose, and anti-replay and
// anti-rollback binding. It deliberately grants no publication authority: it
// creates and verifies local bytes only, never fetches a root, never contacts
// a transparency log, and never decides that a release may ship.
//
// Key custody is the local encrypted-PEM form defined once in knowledgesign.
// Custody of the resulting private key (hardware token, HSM, or KMS) remains
// an operator and infrastructure decision that this package cannot make.
package releasesign

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	// TrustRootSchema identifies the pinned set of keys that may authorize a
	// Community release asset set.
	TrustRootSchema = "prufyx.io/community-release-trust-root/v1"
	// StatementSchema identifies the canonical signed release payload.
	StatementSchema = "prufyx.io/community-release-statement/v1"
	// EnvelopeSchema identifies the detached signature container.
	EnvelopeSchema = "prufyx.io/community-release-signature/v1"

	// Purpose and Audience are bound into the statement so a signature made for
	// one distribution context cannot be replayed into another.
	Purpose  = "community-release-integrity"
	Audience = "public-community-download"

	// StatementName and EnvelopeName are the two release assets this package
	// adds. Neither is listed in SHA256SUMS: the statement covers SHA256SUMS,
	// and the envelope covers the statement.
	StatementName = "RELEASE-STATEMENT.json"
	EnvelopeName  = "RELEASE-STATEMENT.sig.json"

	// MaxTrustRootBytes, MaxStatementBytes, and MaxEnvelopeBytes bound every
	// parsed input so a hostile file cannot exhaust the verifier.
	MaxTrustRootBytes = 128 << 10
	MaxStatementBytes = 512 << 10
	MaxEnvelopeBytes  = 64 << 10

	// MaxArtifacts bounds the covered asset set.
	MaxArtifacts = 256
	// MaxValidity bounds how far ahead a statement or trust root may expire.
	MaxValidity = 366 * 24 * time.Hour
)

// ErrRejected is the single opaque rejection returned to callers. Detailed
// reasons stay internal so a verifier cannot be used as an oracle.
var ErrRejected = errors.New("release signature input rejected")

// TrustRoot is the pinned set of keys authorized to sign a release statement.
// It is distributed and verified by digest, never fetched by this package.
type TrustRoot struct {
	SchemaVersion string     `json:"schemaVersion"`
	Purpose       string     `json:"purpose"`
	Expires       string     `json:"expires"`
	Threshold     int        `json:"threshold"`
	Keys          []TrustKey `json:"keys"`
}

// TrustKey is one authorized signer identity. KeyID is the TUF key identifier
// derived from the public key, so a release root can later be folded into a
// TUF targets delegation without re-identifying its signers.
type TrustKey struct {
	KeyID     string `json:"keyId"`
	KeyType   string `json:"keyType"`
	Scheme    string `json:"scheme"`
	PublicKey string `json:"publicKey"`
}

// Artifact is one covered release asset.
type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Statement is the canonical signed payload. Its exact canonical bytes are
// what is written to disk and what is signed: there is no second serialization.
type Statement struct {
	SchemaVersion         string     `json:"schemaVersion"`
	Purpose               string     `json:"purpose"`
	Audience              string     `json:"audience"`
	Version               string     `json:"version"`
	SourceRevision        string     `json:"sourceRevision"`
	SourceTreeDigest      string     `json:"sourceTreeDigest"`
	ReleaseManifestDigest string     `json:"releaseManifestDigest"`
	GoVersion             string     `json:"goVersion"`
	BuildEpoch            int64      `json:"buildEpoch"`
	Expires               string     `json:"expires"`
	TrustRootDigest       string     `json:"trustRootDigest"`
	Artifacts             []Artifact `json:"artifacts"`
	// CandidateOnly restates that an integrity signature authorizes nothing
	// about compatibility. A verified statement is not a SAFE decision.
	CandidateOnly bool `json:"candidateOnly"`
}

// Envelope is the detached signature over the exact canonical statement bytes.
type Envelope struct {
	SchemaVersion   string          `json:"schemaVersion"`
	StatementDigest string          `json:"statementDigest"`
	Signatures      []SignatureLine `json:"signatures"`
}

// SignatureLine is one signer's contribution.
type SignatureLine struct {
	KeyID string `json:"keyId"`
	Sig   string `json:"sig"`
}

// InitOptions requests a new release signing key. It owns Passphrase: Init
// consumes and wipes it.
type InitOptions struct {
	KeyDir, Expires string
	Passphrase      []byte
}

// InitResult reports the non-secret outputs of Init.
type InitResult struct {
	KeyID           string `json:"keyId"`
	TrustRootDigest string `json:"trustRootDigest"`
	TrustRoot       []byte `json:"-"`
}

// StatementOptions describes the release identity to bind.
type StatementOptions struct {
	Version, SourceRevision, SourceTreeDigest string
	ReleaseManifestDigest, GoVersion          string
	BuildEpoch                                int64
	Expires                                   string
	TrustRoot                                 []byte
	Artifacts                                 []Artifact
}

// SignOptions signs one exact statement. It owns Passphrase and wipes it.
type SignOptions struct {
	Statement, TrustRoot, EncryptedKey []byte
	Passphrase                         []byte
}

// VerifyOptions verifies one exact statement and envelope against a trust root
// whose digest the caller established independently.
type VerifyOptions struct {
	Statement, Envelope, TrustRoot []byte
	TrustRootDigest                string
	Now                            time.Time
}

// VerifyResult reports what a successful verification established.
type VerifyResult struct {
	Version         string   `json:"version"`
	SourceRevision  string   `json:"sourceRevision"`
	TrustRootDigest string   `json:"trustRootDigest"`
	SignerKeyIDs    []string `json:"signerKeyIds"`
	Artifacts       int      `json:"artifacts"`
	// CompatibilityAuthority is always "none": integrity is not a decision.
	CompatibilityAuthority string `json:"compatibilityAuthority"`
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:") &&
		strings.Trim(value[7:], "0123456789abcdef") == ""
}

func validHex(value string, length int) bool {
	return len(value) == length && strings.Trim(value, "0123456789abcdef") == ""
}

// validAssetName accepts a plain file name only. It rejects any separator,
// relative component, control character, or leading dot so a covered asset can
// never name a path outside the release directory.
func validAssetName(name string) bool {
	if name == "" || len(name) > 255 || name != filepath.Base(name) || name == "." || name == ".." || name[0] == '.' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x21 || c > 0x7e || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}

// parseUTC accepts an exact UTC RFC3339 instant and nothing else.
func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, ErrRejected
	}
	return parsed.UTC(), nil
}

// parseBoundedFutureUTC additionally requires the instant to be ahead of now
// and inside the maximum validity window.
func parseBoundedFutureUTC(value string, now time.Time) (time.Time, error) {
	parsed, err := parseUTC(value)
	if err != nil {
		return time.Time{}, err
	}
	if !parsed.After(now) || parsed.After(now.Add(MaxValidity)) {
		return time.Time{}, ErrRejected
	}
	return parsed, nil
}

// canonicalBytes produces the OLPC canonical JSON form used by TUF. The exact
// returned bytes are both the on-disk form and the signed payload.
func canonicalBytes(value any) ([]byte, error) {
	raw, err := cjson.EncodeCanonical(value)
	if err != nil || len(raw) == 0 {
		return nil, ErrRejected
	}
	return raw, nil
}

// decodeExact decodes strictly and confirms that re-encoding the decoded value
// reproduces the exact supplied bytes. A file that is not already canonical,
// or that carries unknown or duplicate fields, is rejected before use.
func decodeExact[T any](raw []byte, limit int) (T, error) {
	var zero T
	if len(raw) == 0 || len(raw) > limit {
		return zero, ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, ErrRejected
	}
	if decoder.Decode(new(struct{})) != io.EOF {
		return zero, ErrRejected
	}
	encoded, err := canonicalBytes(value)
	if err != nil || !bytes.Equal(encoded, raw) {
		return zero, ErrRejected
	}
	return value, nil
}

func keyIdentity(public ed25519.PublicKey) (string, error) {
	key, err := metadata.KeyFromPublicKey(public)
	if err != nil {
		return "", ErrRejected
	}
	id, err := key.ID()
	if err != nil || !validHex(id, 64) {
		return "", ErrRejected
	}
	return id, nil
}

// ParseTrustRoot validates bounded canonical trust-root bytes against the
// declared digest and the supplied clock. An expired root never verifies.
func ParseTrustRoot(raw []byte, expectedDigest string, now time.Time) (TrustRoot, error) {
	if !validDigest(expectedDigest) || digest(raw) != expectedDigest {
		return TrustRoot{}, ErrRejected
	}
	return parseTrustRoot(raw, now)
}

func parseTrustRoot(raw []byte, now time.Time) (TrustRoot, error) {
	root, err := decodeExact[TrustRoot](raw, MaxTrustRootBytes)
	if err != nil {
		return TrustRoot{}, err
	}
	if root.SchemaVersion != TrustRootSchema || root.Purpose != Purpose {
		return TrustRoot{}, ErrRejected
	}
	expires, err := parseUTC(root.Expires)
	if err != nil || !expires.After(now) {
		return TrustRoot{}, ErrRejected
	}
	if root.Threshold < 1 || len(root.Keys) < root.Threshold || len(root.Keys) > 32 {
		return TrustRoot{}, ErrRejected
	}
	seen := make(map[string]bool, len(root.Keys))
	previous := ""
	for _, key := range root.Keys {
		if key.KeyType != "ed25519" || key.Scheme != "ed25519" || !validHex(key.PublicKey, 2*ed25519.PublicKeySize) {
			return TrustRoot{}, ErrRejected
		}
		decoded, decodeErr := hex.DecodeString(key.PublicKey)
		if decodeErr != nil {
			return TrustRoot{}, ErrRejected
		}
		derived, idErr := keyIdentity(ed25519.PublicKey(decoded))
		if idErr != nil || derived != key.KeyID || seen[key.KeyID] {
			return TrustRoot{}, ErrRejected
		}
		// Sorted key order keeps the canonical root stable across regeneration.
		if previous != "" && key.KeyID <= previous {
			return TrustRoot{}, ErrRejected
		}
		previous = key.KeyID
		seen[key.KeyID] = true
	}
	return root, nil
}

// ValidateInitRequest checks the non-secret init arguments before a caller
// prompts for a passphrase. It performs no writes.
func ValidateInitRequest(keyDir, expires string) error {
	if keyDir == "" || !filepath.IsAbs(keyDir) || filepath.Clean(keyDir) != keyDir {
		return ErrRejected
	}
	if _, err := parseBoundedFutureUTC(expires, time.Now().UTC()); err != nil {
		return ErrRejected
	}
	return nil
}

// Init creates one encrypted Ed25519 release signing key and the matching
// single-key trust root in a new private directory outside a Git checkout.
//
// The generated key lives on the local filesystem under a passphrase. That is
// sufficient for a reproducible, offline, auditable signing step; it is not
// hardware-backed custody, and this package does not claim it is.
func Init(options InitOptions) (InitResult, error) {
	defer wipe(options.Passphrase)
	now := time.Now().UTC()
	if err := ValidateInitRequest(options.KeyDir, options.Expires); err != nil {
		return InitResult{}, ErrRejected
	}
	expires, err := parseBoundedFutureUTC(options.Expires, now)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	defer wipe(private)
	keyID, err := keyIdentity(public)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	rootRaw, err := canonicalBytes(TrustRoot{
		SchemaVersion: TrustRootSchema, Purpose: Purpose,
		Expires:   expires.Format(time.RFC3339),
		Threshold: 1,
		Keys: []TrustKey{{
			KeyID: keyID, KeyType: "ed25519", Scheme: "ed25519",
			PublicKey: hex.EncodeToString(public),
		}},
	})
	if err != nil {
		return InitResult{}, ErrRejected
	}
	// Re-parse the bytes that will be distributed, so Init cannot emit a root
	// that its own verifier would reject.
	if _, err := parseTrustRoot(rootRaw, now); err != nil {
		return InitResult{}, ErrRejected
	}
	encodedKey, err := knowledgesign.EncryptedKeyPEM(private, options.Passphrase)
	if err != nil {
		return InitResult{}, ErrRejected
	}
	defer wipe(encodedKey)
	if err := writePrivateDirectory(options.KeyDir, map[string][]byte{
		"release.key.pem":         encodedKey,
		"release-trust-root.json": rootRaw,
	}); err != nil {
		return InitResult{}, ErrRejected
	}
	return InitResult{KeyID: keyID, TrustRootDigest: digest(rootRaw), TrustRoot: append([]byte(nil), rootRaw...)}, nil
}

// BuildStatement derives the exact canonical statement bytes for one release.
// It validates every identity field before binding it, so a malformed release
// cannot be signed into apparent validity.
func BuildStatement(options StatementOptions) ([]byte, error) {
	now := time.Now().UTC()
	if !strings.HasPrefix(options.Version, "v") || len(options.Version) < 2 || len(options.Version) > 64 {
		return nil, ErrRejected
	}
	if !validHex(options.SourceRevision, 40) || !validDigest(options.SourceTreeDigest) || !validDigest(options.ReleaseManifestDigest) {
		return nil, ErrRejected
	}
	if !strings.HasPrefix(options.GoVersion, "go1.") || options.BuildEpoch <= 0 {
		return nil, ErrRejected
	}
	if _, err := parseBoundedFutureUTC(options.Expires, now); err != nil {
		return nil, ErrRejected
	}
	rootDigest := digest(options.TrustRoot)
	if _, err := parseTrustRoot(options.TrustRoot, now); err != nil {
		return nil, ErrRejected
	}
	artifacts, err := normalizeArtifacts(options.Artifacts)
	if err != nil {
		return nil, err
	}
	raw, err := canonicalBytes(Statement{
		SchemaVersion: StatementSchema, Purpose: Purpose, Audience: Audience,
		Version: options.Version, SourceRevision: options.SourceRevision,
		SourceTreeDigest: options.SourceTreeDigest, ReleaseManifestDigest: options.ReleaseManifestDigest,
		GoVersion: options.GoVersion, BuildEpoch: options.BuildEpoch,
		Expires: options.Expires, TrustRootDigest: rootDigest,
		Artifacts: artifacts, CandidateOnly: true,
	})
	if err != nil {
		return nil, ErrRejected
	}
	if _, err := parseStatement(raw, now); err != nil {
		return nil, ErrRejected
	}
	return raw, nil
}

// normalizeArtifacts sorts by name and rejects duplicates, unsafe names, and
// malformed digests or sizes.
func normalizeArtifacts(input []Artifact) ([]Artifact, error) {
	if len(input) == 0 || len(input) > MaxArtifacts {
		return nil, ErrRejected
	}
	out := make([]Artifact, len(input))
	copy(out, input)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	previous := ""
	for _, artifact := range out {
		if !validAssetName(artifact.Name) || !validHex(artifact.SHA256, 64) || artifact.Size < 0 {
			return nil, ErrRejected
		}
		if artifact.Name == StatementName || artifact.Name == EnvelopeName {
			return nil, ErrRejected
		}
		if previous != "" && artifact.Name <= previous {
			return nil, ErrRejected
		}
		previous = artifact.Name
	}
	return out, nil
}

func parseStatement(raw []byte, now time.Time) (Statement, error) {
	statement, err := decodeExact[Statement](raw, MaxStatementBytes)
	if err != nil {
		return Statement{}, err
	}
	if statement.SchemaVersion != StatementSchema || statement.Purpose != Purpose || statement.Audience != Audience || !statement.CandidateOnly {
		return Statement{}, ErrRejected
	}
	if !validHex(statement.SourceRevision, 40) || !validDigest(statement.SourceTreeDigest) ||
		!validDigest(statement.ReleaseManifestDigest) || !validDigest(statement.TrustRootDigest) {
		return Statement{}, ErrRejected
	}
	if !strings.HasPrefix(statement.Version, "v") || !strings.HasPrefix(statement.GoVersion, "go1.") || statement.BuildEpoch <= 0 {
		return Statement{}, ErrRejected
	}
	expires, err := parseUTC(statement.Expires)
	if err != nil || !expires.After(now) {
		return Statement{}, ErrRejected
	}
	if _, err := normalizeArtifacts(statement.Artifacts); err != nil {
		return Statement{}, ErrRejected
	}
	// normalizeArtifacts sorts a copy; the statement itself must already be in
	// that order so the covered set has exactly one canonical form.
	for i := 1; i < len(statement.Artifacts); i++ {
		if statement.Artifacts[i-1].Name >= statement.Artifacts[i].Name {
			return Statement{}, ErrRejected
		}
	}
	return statement, nil
}

// Sign produces a detached envelope over the exact statement bytes. It refuses
// a statement that does not already verify, a signer outside the trust root,
// and any statement bound to a different trust root.
func Sign(options SignOptions) ([]byte, error) {
	defer wipe(options.Passphrase)
	now := time.Now().UTC()
	statement, err := parseStatement(options.Statement, now)
	if err != nil {
		return nil, ErrRejected
	}
	root, err := parseTrustRoot(options.TrustRoot, now)
	if err != nil || statement.TrustRootDigest != digest(options.TrustRoot) {
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
		SchemaVersion: EnvelopeSchema, StatementDigest: digest(options.Statement),
		Signatures: []SignatureLine{{KeyID: keyID, Sig: hex.EncodeToString(produced)}},
	})
	if err != nil {
		return nil, ErrRejected
	}
	// Verify what will be written before returning it: a signer must never
	// emit an envelope its own verifier would reject.
	if _, err := Verify(VerifyOptions{
		Statement: options.Statement, Envelope: envelopeRaw, TrustRoot: options.TrustRoot,
		TrustRootDigest: statement.TrustRootDigest, Now: now,
	}); err != nil {
		wipe(envelopeRaw)
		return nil, ErrRejected
	}
	return envelopeRaw, nil
}

// Verify checks one release statement and envelope against a pinned trust root.
// It fails closed on an unknown signer, a wrong or expired root, an expired
// statement, a digest mismatch, a duplicate signer, or too few signatures.
func Verify(options VerifyOptions) (VerifyResult, error) {
	now := options.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	root, err := ParseTrustRoot(options.TrustRoot, options.TrustRootDigest, now)
	if err != nil {
		return VerifyResult{}, ErrRejected
	}
	statement, err := parseStatement(options.Statement, now)
	if err != nil || statement.TrustRootDigest != options.TrustRootDigest {
		return VerifyResult{}, ErrRejected
	}
	envelope, err := decodeExact[Envelope](options.Envelope, MaxEnvelopeBytes)
	if err != nil || envelope.SchemaVersion != EnvelopeSchema {
		return VerifyResult{}, ErrRejected
	}
	if envelope.StatementDigest != digest(options.Statement) {
		return VerifyResult{}, ErrRejected
	}
	if len(envelope.Signatures) < root.Threshold || len(envelope.Signatures) > len(root.Keys) {
		return VerifyResult{}, ErrRejected
	}
	keys := make(map[string]ed25519.PublicKey, len(root.Keys))
	for _, key := range root.Keys {
		decoded, decodeErr := hex.DecodeString(key.PublicKey)
		if decodeErr != nil {
			return VerifyResult{}, ErrRejected
		}
		keys[key.KeyID] = ed25519.PublicKey(decoded)
	}
	accepted := make([]string, 0, len(envelope.Signatures))
	seen := make(map[string]bool, len(envelope.Signatures))
	for _, line := range envelope.Signatures {
		public, known := keys[line.KeyID]
		if !known || seen[line.KeyID] || !validHex(line.Sig, 2*ed25519.SignatureSize) {
			return VerifyResult{}, ErrRejected
		}
		raw, decodeErr := hex.DecodeString(line.Sig)
		if decodeErr != nil || !ed25519.Verify(public, options.Statement, raw) {
			return VerifyResult{}, ErrRejected
		}
		seen[line.KeyID] = true
		accepted = append(accepted, line.KeyID)
	}
	if len(accepted) < root.Threshold {
		return VerifyResult{}, ErrRejected
	}
	sort.Strings(accepted)
	return VerifyResult{
		Version: statement.Version, SourceRevision: statement.SourceRevision,
		TrustRootDigest: statement.TrustRootDigest, SignerKeyIDs: accepted,
		Artifacts: len(statement.Artifacts), CompatibilityAuthority: "none",
	}, nil
}

// VerifyDirectory verifies the signature and then confirms that every covered
// artifact is present in the directory with exactly the signed digest and
// size, and that the directory holds no unexpected file. A signature over a
// statement nobody checked against real bytes proves nothing.
func VerifyDirectory(directory string, options VerifyOptions) (VerifyResult, error) {
	result, err := Verify(options)
	if err != nil {
		return VerifyResult{}, ErrRejected
	}
	statement, err := parseStatement(options.Statement, verifyClock(options.Now))
	if err != nil {
		return VerifyResult{}, ErrRejected
	}
	expected := make(map[string]bool, len(statement.Artifacts)+2)
	expected[StatementName] = true
	expected[EnvelopeName] = true
	for _, artifact := range statement.Artifacts {
		expected[artifact.Name] = true
		actualDigest, size, hashErr := hashAsset(directory, artifact.Name)
		if hashErr != nil || actualDigest != artifact.SHA256 || size != artifact.Size {
			return VerifyResult{}, ErrRejected
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return VerifyResult{}, ErrRejected
	}
	if len(entries) != len(expected) {
		return VerifyResult{}, ErrRejected
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return VerifyResult{}, ErrRejected
		}
	}
	return result, nil
}

func verifyClock(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

// hashAsset reads one named release asset without following a symlink and
// returns its lowercase hex SHA-256 and size.
func hashAsset(directory, name string) (string, int64, error) {
	if !validAssetName(name) {
		return "", 0, ErrRejected
	}
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, ErrRejected
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, ErrRejected
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return "", 0, ErrRejected
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, ErrRejected
	}
	after, err := file.Stat()
	if err != nil || written != before.Size() || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return "", 0, ErrRejected
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

// DirectoryArtifacts collects the covered artifacts for the named files.
func DirectoryArtifacts(directory string, names []string) ([]Artifact, error) {
	if len(names) == 0 || len(names) > MaxArtifacts {
		return nil, ErrRejected
	}
	artifacts := make([]Artifact, 0, len(names))
	for _, name := range names {
		assetDigest, size, err := hashAsset(directory, name)
		if err != nil {
			return nil, ErrRejected
		}
		artifacts = append(artifacts, Artifact{Name: name, SHA256: assetDigest, Size: size})
	}
	return normalizeArtifacts(artifacts)
}

// writePrivateDirectory creates a new 0700 directory whose parent is already a
// user-owned 0700 directory outside a Git checkout, and writes each file
// exclusively at 0600. It never overwrites and never follows a symlink.
func writePrivateDirectory(target string, files map[string][]byte) error {
	parent := filepath.Dir(target)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrRejected
	}
	if !outsideGitCheckout(parent) {
		return ErrRejected
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return ErrRejected
	}
	defer parentRoot.Close()
	name := filepath.Base(target)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return ErrRejected
	}
	if err := parentRoot.Mkdir(name, 0o700); err != nil {
		return ErrRejected
	}
	keyRoot, err := parentRoot.OpenRoot(name)
	if err != nil {
		return ErrRejected
	}
	defer keyRoot.Close()
	names := make([]string, 0, len(files))
	for fileName := range files {
		names = append(names, fileName)
	}
	sort.Strings(names)
	for _, fileName := range names {
		file, openErr := keyRoot.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return ErrRejected
		}
		writeErr := file.Chmod(0o600)
		if writeErr == nil {
			_, writeErr = file.Write(files[fileName])
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return ErrRejected
		}
	}
	return nil
}

// outsideGitCheckout refuses to place private key material anywhere under a
// Git checkout, where it could be committed or published by accident.
func outsideGitCheckout(path string) bool {
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if _, gitErr := os.Lstat(filepath.Join(current, ".git")); gitErr == nil {
			return false
		} else if !os.IsNotExist(gitErr) {
			return false
		}
		next := filepath.Dir(current)
		if next == current {
			return true
		}
		current = next
	}
}

// TrustRootDigest returns the pinned digest of exact trust-root bytes. It is
// the value that replaces the UNPINNED placeholder in release metadata.
func TrustRootDigest(raw []byte) (string, error) {
	if _, err := parseTrustRoot(raw, time.Now().UTC()); err != nil {
		return "", ErrRejected
	}
	return digest(raw), nil
}

// Describe renders a short human summary of a verification result.
func Describe(result VerifyResult) string {
	return fmt.Sprintf("release %s at %s verified by %s against %s (integrity only; compatibility authority: %s)",
		result.Version, result.SourceRevision, strings.Join(result.SignerKeyIDs, ","),
		result.TrustRootDigest, result.CompatibilityAuthority)
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
