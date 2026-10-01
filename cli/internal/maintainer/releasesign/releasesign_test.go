// SPDX-License-Identifier: AGPL-3.0-only

package releasesign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

const testPassphrase = "correct horse battery staple"

type fixture struct {
	trustRoot  []byte
	rootDigest string
	key        []byte
	keyID      string
	private    ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyID, err := keyIdentity(public)
	if err != nil {
		t.Fatalf("key identity: %v", err)
	}
	root, err := canonicalBytes(TrustRoot{
		SchemaVersion: TrustRootSchema, Purpose: Purpose,
		Expires: time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		Keys:    []TrustKey{{KeyID: keyID, KeyType: "ed25519", Scheme: "ed25519", PublicKey: hex.EncodeToString(public)}},
	})
	if err != nil {
		t.Fatalf("canonical trust root: %v", err)
	}
	// Threshold must be explicit; canonicalBytes drops nothing, so set it here.
	var decoded TrustRoot
	if err := json.Unmarshal(root, &decoded); err != nil {
		t.Fatalf("decode trust root: %v", err)
	}
	decoded.Threshold = 1
	root, err = canonicalBytes(decoded)
	if err != nil {
		t.Fatalf("re-encode trust root: %v", err)
	}
	encrypted, err := knowledgesign.EncryptedKeyPEM(private, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	return fixture{trustRoot: root, rootDigest: digest(root), key: encrypted, keyID: keyID, private: private}
}

func (f fixture) passphrase() []byte { return []byte(testPassphrase) }

// privateParent returns a user-owned 0700 directory with no symlinked
// ancestor. Init deliberately refuses a symlinked path component, and on macOS
// the temporary root reaches the test through /var, which is a symlink.
func privateParent(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary parent: %v", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	return parent
}

func sampleArtifacts() []Artifact {
	return []Artifact{
		{Name: "SHA256SUMS", SHA256: strings.Repeat("a", 64), Size: 512},
		{Name: "prufyx-cli_1.2.3_linux_amd64.tar.gz", SHA256: strings.Repeat("b", 64), Size: 4096},
	}
}

func (f fixture) statement(t *testing.T) []byte {
	t.Helper()
	raw, err := BuildStatement(StatementOptions{
		Version: "v1.2.3", SourceRevision: strings.Repeat("0", 40),
		SourceTreeDigest: "sha256:" + strings.Repeat("1", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("2", 64),
		GoVersion: "go1.26.8", BuildEpoch: 1757000000,
		Expires:   time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		TrustRoot: f.trustRoot, Artifacts: sampleArtifacts(),
	})
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	return raw
}

func TestBuildStatementIsCanonicalAndSorted(t *testing.T) {
	f := newFixture(t)
	raw := f.statement(t)
	if !bytes.HasPrefix(raw, []byte(`{"artifacts":[`)) {
		t.Fatalf("statement is not canonical JSON with sorted keys: %s", raw)
	}
	statement, err := parseStatement(raw, time.Now().UTC())
	if err != nil {
		t.Fatalf("parse own statement: %v", err)
	}
	if statement.TrustRootDigest != f.rootDigest {
		t.Fatalf("statement did not bind the trust root digest")
	}
	if !statement.CandidateOnly || statement.Purpose != Purpose || statement.Audience != Audience {
		t.Fatalf("statement lost its purpose, audience, or candidate-only binding")
	}
	if statement.Artifacts[0].Name != "SHA256SUMS" {
		t.Fatalf("artifacts were not sorted by name: %+v", statement.Artifacts)
	}
	// Building twice must be byte-identical for the same inputs.
	again, err := BuildStatement(StatementOptions{
		Version: "v1.2.3", SourceRevision: strings.Repeat("0", 40),
		SourceTreeDigest: "sha256:" + strings.Repeat("1", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("2", 64),
		GoVersion: "go1.26.8", BuildEpoch: 1757000000, Expires: statement.Expires,
		TrustRoot: f.trustRoot, Artifacts: sampleArtifacts(),
	})
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("statement derivation is not deterministic")
	}
}

func TestBuildStatementRejectsInvalidIdentity(t *testing.T) {
	f := newFixture(t)
	base := StatementOptions{
		Version: "v1.2.3", SourceRevision: strings.Repeat("0", 40),
		SourceTreeDigest: "sha256:" + strings.Repeat("1", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("2", 64),
		GoVersion: "go1.26.8", BuildEpoch: 1757000000,
		Expires:   time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		TrustRoot: f.trustRoot, Artifacts: sampleArtifacts(),
	}
	cases := map[string]func(*StatementOptions){
		"unprefixed version":     func(o *StatementOptions) { o.Version = "1.2.3" },
		"short revision":         func(o *StatementOptions) { o.SourceRevision = "abc" },
		"unprefixed tree digest": func(o *StatementOptions) { o.SourceTreeDigest = strings.Repeat("1", 64) },
		"bad manifest digest":    func(o *StatementOptions) { o.ReleaseManifestDigest = "sha256:zz" },
		"non-Go toolchain":       func(o *StatementOptions) { o.GoVersion = "rustc1.80" },
		"zero build epoch":       func(o *StatementOptions) { o.BuildEpoch = 0 },
		"past expiry": func(o *StatementOptions) {
			o.Expires = time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
		},
		"expiry beyond max validity": func(o *StatementOptions) {
			o.Expires = time.Now().UTC().Add(400 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
		},
		"non-UTC expiry":   func(o *StatementOptions) { o.Expires = "2027-01-01T00:00:00+02:00" },
		"empty artifacts":  func(o *StatementOptions) { o.Artifacts = nil },
		"path in artifact": func(o *StatementOptions) { o.Artifacts[0].Name = "../escape" },
		"statement covers itself": func(o *StatementOptions) {
			o.Artifacts[0].Name = StatementName
		},
		"envelope covers itself": func(o *StatementOptions) { o.Artifacts[0].Name = EnvelopeName },
		"bad artifact digest":    func(o *StatementOptions) { o.Artifacts[0].SHA256 = "nothex" },
		"negative artifact size": func(o *StatementOptions) { o.Artifacts[0].Size = -1 },
		"duplicate artifact": func(o *StatementOptions) {
			o.Artifacts = []Artifact{o.Artifacts[0], o.Artifacts[0]}
		},
		"empty trust root": func(o *StatementOptions) { o.TrustRoot = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			options := base
			options.Artifacts = sampleArtifacts()
			mutate(&options)
			if _, err := BuildStatement(options); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	envelope, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: f.key, Passphrase: f.passphrase()})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	result, err := Verify(VerifyOptions{Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Version != "v1.2.3" || len(result.SignerKeyIDs) != 1 || result.SignerKeyIDs[0] != f.keyID {
		t.Fatalf("unexpected verify result: %+v", result)
	}
	if result.CompatibilityAuthority != "none" {
		t.Fatalf("integrity verification must not claim compatibility authority")
	}
	if result.Artifacts != len(sampleArtifacts()) {
		t.Fatalf("covered artifact count is wrong: %d", result.Artifacts)
	}
	if !strings.Contains(Describe(result), "integrity only") {
		t.Fatalf("summary omits the integrity-only qualifier")
	}
}

func TestSignRejectsKeyOutsideTrustRoot(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	statement := f.statement(t)
	if _, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: other.key, Passphrase: other.passphrase()}); err == nil {
		t.Fatal("expected rejection for a signer outside the trust root")
	}
}

func TestSignRejectsWrongPassphrase(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	if _, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: f.key, Passphrase: []byte("wrong passphrase here")}); err == nil {
		t.Fatal("expected rejection for a wrong passphrase")
	}
}

func TestSignWipesPassphrase(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	passphrase := f.passphrase()
	if _, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: f.key, Passphrase: passphrase}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, b := range passphrase {
		if b != 0 {
			t.Fatal("signing did not wipe the caller's passphrase buffer")
		}
	}
}

func TestSignRejectsStatementBoundToAnotherRoot(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	statement := f.statement(t)
	if _, err := Sign(SignOptions{Statement: statement, TrustRoot: other.trustRoot, EncryptedKey: other.key, Passphrase: other.passphrase()}); err == nil {
		t.Fatal("expected rejection when the statement binds a different trust root")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	envelope, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: f.key, Passphrase: f.passphrase()})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	other := newFixture(t)
	tampered := bytes.Replace(statement, []byte(`"v1.2.3"`), []byte(`"v1.2.4"`), 1)

	cases := map[string]VerifyOptions{
		"tampered statement": {Statement: tampered, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest},
		"wrong root digest":  {Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: other.rootDigest},
		"substituted root":   {Statement: statement, Envelope: envelope, TrustRoot: other.trustRoot, TrustRootDigest: other.rootDigest},
		"missing envelope":   {Statement: statement, Envelope: nil, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest},
		"missing statement":  {Statement: nil, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest},
		"expired statement": {
			Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest,
			Now: time.Now().UTC().Add(365 * 24 * time.Hour),
		},
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(options); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

func TestVerifyRejectsForgedSignature(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	forged, err := canonicalBytes(Envelope{
		SchemaVersion: EnvelopeSchema, StatementDigest: digest(statement),
		Signatures: []SignatureLine{{KeyID: f.keyID, Sig: strings.Repeat("0", 128)}},
	})
	if err != nil {
		t.Fatalf("encode forged envelope: %v", err)
	}
	if _, err := Verify(VerifyOptions{Statement: statement, Envelope: forged, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}); err == nil {
		t.Fatal("expected rejection for a forged signature")
	}
}

func TestVerifyRejectsDuplicateSignerBelowThreshold(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	signed := ed25519.Sign(f.private, statement)
	duplicate, err := canonicalBytes(Envelope{
		SchemaVersion: EnvelopeSchema, StatementDigest: digest(statement),
		Signatures: []SignatureLine{
			{KeyID: f.keyID, Sig: hex.EncodeToString(signed)},
			{KeyID: f.keyID, Sig: hex.EncodeToString(signed)},
		},
	})
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	if _, err := Verify(VerifyOptions{Statement: statement, Envelope: duplicate, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}); err == nil {
		t.Fatal("expected rejection: a repeated signer must not satisfy a threshold")
	}
}

func TestVerifyRejectsNonCanonicalInput(t *testing.T) {
	f := newFixture(t)
	statement := f.statement(t)
	envelope, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: f.key, Passphrase: f.passphrase()})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pretty := append(append([]byte(nil), statement...), '\n')
	if _, err := Verify(VerifyOptions{Statement: pretty, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}); err == nil {
		t.Fatal("expected rejection for a statement with trailing bytes")
	}
	withUnknown := bytes.Replace(f.trustRoot, []byte(`"threshold"`), []byte(`"thresh0ld"`), 1)
	if _, err := ParseTrustRoot(withUnknown, digest(withUnknown), time.Now().UTC()); err == nil {
		t.Fatal("expected rejection for a trust root with an unknown field")
	}
}

func TestParseTrustRootRejectsMismatchedKeyID(t *testing.T) {
	f := newFixture(t)
	var root TrustRoot
	if err := json.Unmarshal(f.trustRoot, &root); err != nil {
		t.Fatalf("decode: %v", err)
	}
	root.Keys[0].KeyID = strings.Repeat("f", 64)
	raw, err := canonicalBytes(root)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := ParseTrustRoot(raw, digest(raw), time.Now().UTC()); err == nil {
		t.Fatal("expected rejection: a key identifier must derive from its public key")
	}
}

func TestParseTrustRootRejectsExpiredRoot(t *testing.T) {
	f := newFixture(t)
	var root TrustRoot
	if err := json.Unmarshal(f.trustRoot, &root); err != nil {
		t.Fatalf("decode: %v", err)
	}
	root.Expires = time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	raw, err := canonicalBytes(root)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := ParseTrustRoot(raw, digest(raw), time.Now().UTC()); err == nil {
		t.Fatal("expected rejection for an expired trust root")
	}
}

func TestTrustRootDigestRoundTrip(t *testing.T) {
	f := newFixture(t)
	got, err := TrustRootDigest(f.trustRoot)
	if err != nil || got != f.rootDigest {
		t.Fatalf("trust root digest mismatch: %q %v", got, err)
	}
	if _, err := TrustRootDigest([]byte("{}")); err == nil {
		t.Fatal("expected rejection for a non-trust-root document")
	}
}

func writeAsset(t *testing.T, dir, name string, body []byte) Artifact {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	sum := sha256.Sum256(body)
	return Artifact{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}
}

func signedDirectory(t *testing.T, f fixture) (string, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	writeAsset(t, dir, "SHA256SUMS", []byte("sums\n"))
	writeAsset(t, dir, "prufyx-cli_1.2.3_source.tar.gz", []byte("archive bytes\n"))
	artifacts, err := DirectoryArtifacts(dir, []string{"SHA256SUMS", "prufyx-cli_1.2.3_source.tar.gz"})
	if err != nil {
		t.Fatalf("directory artifacts: %v", err)
	}
	statement, err := BuildStatement(StatementOptions{
		Version: "v1.2.3", SourceRevision: strings.Repeat("0", 40),
		SourceTreeDigest: "sha256:" + strings.Repeat("1", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("2", 64),
		GoVersion: "go1.26.8", BuildEpoch: 1757000000,
		Expires:   time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		TrustRoot: f.trustRoot, Artifacts: artifacts,
	})
	if err != nil {
		t.Fatalf("build statement: %v", err)
	}
	envelope, err := Sign(SignOptions{Statement: statement, TrustRoot: f.trustRoot, EncryptedKey: f.key, Passphrase: f.passphrase()})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, StatementName), statement, 0o644); err != nil {
		t.Fatalf("write statement: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, EnvelopeName), envelope, 0o644); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	return dir, statement, envelope
}

func TestVerifyDirectoryBindsRealBytes(t *testing.T) {
	f := newFixture(t)
	dir, statement, envelope := signedDirectory(t, f)
	options := VerifyOptions{Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}
	if _, err := VerifyDirectory(dir, options); err != nil {
		t.Fatalf("verify directory: %v", err)
	}

	t.Run("tampered artifact", func(t *testing.T) {
		dir, statement, envelope := signedDirectory(t, f)
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("tampered\n"), 0o644); err != nil {
			t.Fatalf("tamper: %v", err)
		}
		options := VerifyOptions{Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}
		if _, err := VerifyDirectory(dir, options); err == nil {
			t.Fatal("expected rejection: a signed statement must not pass over changed bytes")
		}
	})

	t.Run("missing artifact", func(t *testing.T) {
		dir, statement, envelope := signedDirectory(t, f)
		if err := os.Remove(filepath.Join(dir, "SHA256SUMS")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		options := VerifyOptions{Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}
		if _, err := VerifyDirectory(dir, options); err == nil {
			t.Fatal("expected rejection for a missing covered artifact")
		}
	})

	t.Run("unexpected extra file", func(t *testing.T) {
		dir, statement, envelope := signedDirectory(t, f)
		if err := os.WriteFile(filepath.Join(dir, "SURPRISE.bin"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write extra: %v", err)
		}
		options := VerifyOptions{Statement: statement, Envelope: envelope, TrustRoot: f.trustRoot, TrustRootDigest: f.rootDigest}
		if _, err := VerifyDirectory(dir, options); err == nil {
			t.Fatal("expected rejection: an unsigned file must not ride along in a signed release")
		}
	})
}

func TestDirectoryArtifactsRejectsUnsafeNames(t *testing.T) {
	dir := t.TempDir()
	writeAsset(t, dir, "SHA256SUMS", []byte("sums\n"))
	for _, name := range []string{"../escape", "sub/dir", "", ".", ".hidden"} {
		if _, err := DirectoryArtifacts(dir, []string{name}); err == nil {
			t.Fatalf("expected rejection for artifact name %q", name)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "LINKED")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := DirectoryArtifacts(dir, []string{"LINKED"}); err == nil {
		t.Fatal("expected rejection: a covered artifact must not be a symlink")
	}
}

func TestValidateInitRequest(t *testing.T) {
	future := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if err := ValidateInitRequest("relative/dir", future); err == nil {
		t.Fatal("expected rejection for a relative key directory")
	}
	if err := ValidateInitRequest("/tmp/prufyx-release-keys", "not-a-time"); err == nil {
		t.Fatal("expected rejection for a malformed expiry")
	}
	if err := ValidateInitRequest("/tmp/prufyx-release-keys", future); err != nil {
		t.Fatalf("expected acceptance for a well-formed request: %v", err)
	}
}

func TestInitCreatesUsableKeyAndRoot(t *testing.T) {
	parent := privateParent(t)
	target := filepath.Join(parent, "release-keys")
	expires := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	result, err := Init(InitOptions{KeyDir: target, Expires: expires, Passphrase: []byte(testPassphrase)})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if !validHex(result.KeyID, 64) || !validDigest(result.TrustRootDigest) {
		t.Fatalf("init produced an invalid identity: %+v", result)
	}
	key, err := os.ReadFile(filepath.Join(target, "release.key.pem"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	info, err := os.Stat(filepath.Join(target, "release.key.pem"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("release signing key must be mode 0600, got %v (%v)", info.Mode().Perm(), err)
	}
	root, err := os.ReadFile(filepath.Join(target, "release-trust-root.json"))
	if err != nil {
		t.Fatalf("read trust root: %v", err)
	}
	if digest(root) != result.TrustRootDigest {
		t.Fatal("reported trust root digest does not match the written bytes")
	}
	statement, err := BuildStatement(StatementOptions{
		Version: "v1.2.3", SourceRevision: strings.Repeat("0", 40),
		SourceTreeDigest: "sha256:" + strings.Repeat("1", 64), ReleaseManifestDigest: "sha256:" + strings.Repeat("2", 64),
		GoVersion: "go1.26.8", BuildEpoch: 1757000000,
		Expires:   time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		TrustRoot: root, Artifacts: sampleArtifacts(),
	})
	if err != nil {
		t.Fatalf("build statement against generated root: %v", err)
	}
	envelope, err := Sign(SignOptions{Statement: statement, TrustRoot: root, EncryptedKey: key, Passphrase: []byte(testPassphrase)})
	if err != nil {
		t.Fatalf("sign with generated key: %v", err)
	}
	if _, err := Verify(VerifyOptions{Statement: statement, Envelope: envelope, TrustRoot: root, TrustRootDigest: result.TrustRootDigest}); err != nil {
		t.Fatalf("verify against generated root: %v", err)
	}
}

func TestInitRefusesExistingDirectory(t *testing.T) {
	parent := privateParent(t)
	target := filepath.Join(parent, "release-keys")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	expires := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if _, err := Init(InitOptions{KeyDir: target, Expires: expires, Passphrase: []byte(testPassphrase)}); err == nil {
		t.Fatal("expected rejection: init must never reuse an existing key directory")
	}
}

func TestInitRefusesGitCheckout(t *testing.T) {
	parent := privateParent(t)
	if err := os.Mkdir(filepath.Join(parent, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	expires := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	target := filepath.Join(parent, "release-keys")
	if _, err := Init(InitOptions{KeyDir: target, Expires: expires, Passphrase: []byte(testPassphrase)}); err == nil {
		t.Fatal("expected rejection: private key material must never land inside a Git checkout")
	}
}

func TestInitWipesPassphrase(t *testing.T) {
	parent := privateParent(t)
	passphrase := []byte(testPassphrase)
	expires := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if _, err := Init(InitOptions{KeyDir: filepath.Join(parent, "release-keys"), Expires: expires, Passphrase: passphrase}); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, b := range passphrase {
		if b != 0 {
			t.Fatal("init did not wipe the caller's passphrase buffer")
		}
	}
}
