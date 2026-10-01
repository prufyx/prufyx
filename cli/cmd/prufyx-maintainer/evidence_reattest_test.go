// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const reattestWorklistPackPath = "/repo/cli/internal/cncfcheck/data/rules.json"

// reattestFixture is one prepared, signed single-rule batch on disk, with a
// throwaway key and trust root that exist only below t.TempDir().
type reattestFixture struct {
	dir, worklist, rules, out, chain, reviews string
	trustRoot, trustRootDigest, envelope      string
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var command *commandError
	if errors.As(err, &command) {
		return command.code
	}
	return -1
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newReattestFixture(t *testing.T) reattestFixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := reattestFixture{
		dir: dir, worklist: filepath.Join(dir, "worklist.json"), rules: filepath.Join(dir, "rules.json"),
		out: filepath.Join(dir, "out"), chain: filepath.Join(dir, "chain"), reviews: filepath.Join(dir, "reviews"),
		trustRoot: filepath.Join(dir, "trust-root.json"), envelope: filepath.Join(dir, "out", "statement.sig.json"),
	}
	for _, d := range []string{f.chain, f.reviews} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	commit := strings.Repeat("a", 40)
	rule := map[string]any{
		"id": "rule-a", "operator": "require", "reasonCode": "TEST_REASON", "nextAction": "TEST_ACTION",
		"subject": map[string]any{"component": "pkg:github/owner/repo", "from": "1.0.0", "to": "2.0.0"},
		"evidence": map[string]any{
			"state": "active", "reviewedAt": at.Add(-30 * 24 * time.Hour).Format(time.RFC3339), "validUntil": at.Add(60 * 24 * time.Hour).Format(time.RFC3339),
			"sources": []any{map[string]any{"id": "rule-a-src", "url": "https://github.com/owner/repo/blob/" + commit + "/VERSION", "revision": commit, "contentDigest": "sha256:" + strings.Repeat("cd", 32), "startLine": 1, "endLine": 1}},
		},
	}
	pack, err := json.Marshal(map[string]any{
		"schema": "test-pack/v1", "revision": "rev-1", "policyId": "policy-1", "policyDigest": "sha256:" + strings.Repeat("ab", 32),
		"entries": []any{map[string]any{"description": "d", "project": "proj-a", "requiredFacts": []any{}, "rule": rule}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.rules, pack)
	worklist, err := json.Marshal(evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: at.Add(-time.Hour).Format(time.RFC3339),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{reattestWorklistPackPath}},
		Repos: []evidencerepin.RepoResolution{{Owner: "owner", Repo: "repo", Status: "RESOLVED", CurrentTag: "v1.2.3", CurrentCommit: commit, ResolvedAt: at.Add(-time.Hour).Format(time.RFC3339)}},
		Citations: []evidencerepin.ClassResult{{
			RulePack: reattestWorklistPackPath, RuleID: "rule-a", Project: "proj-a", SourceID: "rule-a-src",
			Owner: "owner", Repo: "repo", Path: "VERSION", OldCommit: commit, NewCommit: commit, Class: evidencerepin.ClassFileIdentical,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.worklist, worklist)
	writeFile(t, filepath.Join(f.reviews, "rule-a.json"), []byte("{\"reviewed\":\"rule-a\"}\n"))

	var stdout, stderr bytes.Buffer
	if err := run([]string{"evidence", "reattest", "prepare", "--worklist", f.worklist, "--pack", "cncf", "--rules", f.rules,
		"--rules-worklist-path", reattestWorklistPackPath, "--next-revision", "rev-2", "--wave", "1", "--output-dir", f.out,
		"--statement-chain-dir", f.chain, "--review-record-dir", f.reviews, "--attested-at", at.Format(time.RFC3339)}, &stdout, &stderr); err != nil {
		t.Fatalf("prepare: %v %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "eligible=1 sampled=1") {
		t.Fatalf("prepare: unexpected output %q", stdout.String())
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := knowledgesign.EncryptedKeyPEM(private, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	tufKey, err := metadata.KeyFromPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := tufKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json writes map keys sorted and compact, which is the
	// canonical form for this ASCII-only document.
	root, err := json.Marshal(map[string]any{
		"schemaVersion": evidencereattest.TrustRootSchema, "purpose": evidencereattest.Purpose,
		"expires": time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339), "threshold": 1,
		"keys": []any{map[string]any{"keyId": keyID, "keyType": "ed25519", "scheme": "ed25519", "publicKey": hex.EncodeToString(public)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.trustRoot, append(append([]byte(nil), root...), '\n'))
	// The pinned digest is over the file's bytes without its one trailing
	// newline, exactly as the CLI reads it.
	f.trustRootDigest = sourcecorpus.SHA(root)

	statement, err := os.ReadFile(filepath.Join(f.out, "statement.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := evidencereattest.Sign(evidencereattest.SignOptions{
		Statement: bytes.TrimSuffix(statement, []byte("\n")), TrustRoot: root, EncryptedKey: key,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: f.trustRootDigest,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	writeFile(t, f.envelope, append(envelope, '\n'))
	return f
}

func (f reattestFixture) verifyArgs(extra ...string) []string {
	return f.verifyArgsWithReviews(f.reviews, extra...)
}

func (f reattestFixture) verifyArgsWithReviews(reviews string, extra ...string) []string {
	args := []string{"evidence", "reattest", "verify",
		"--statement", filepath.Join(f.out, "statement.json"), "--prior-pack", f.rules, "--next-pack", filepath.Join(f.out, "rules.next.json"),
		"--worklist", f.worklist, "--pack", "cncf", "--rules-worklist-path", reattestWorklistPackPath,
		"--statement-chain-dir", f.chain, "--review-record-dir", reviews}
	return append(args, extra...)
}

func TestEvidenceReattestVerifyExitCodes(t *testing.T) {
	f := newReattestFixture(t)
	badEnvelope := filepath.Join(f.dir, "bad.sig.json")
	raw, err := os.ReadFile(f.envelope)
	if err != nil {
		t.Fatal(err)
	}
	var parsed evidencereattest.Envelope
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	sig := []byte(parsed.Signatures[0].Sig)
	if sig[0] == '0' {
		sig[0] = '1'
	} else {
		sig[0] = '0'
	}
	writeFile(t, badEnvelope, bytes.Replace(raw, []byte(parsed.Signatures[0].Sig), sig, 1))

	sigFlags := []string{"--envelope", f.envelope, "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest}
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"no signature", f.verifyArgs(), 1},
		{"structural only", f.verifyArgs("--structural-only"), 1},
		{"structural only with the chain's trust root", f.verifyArgs("--structural-only", "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest), 1},
		{"structural only with an envelope", f.verifyArgs(append([]string{"--structural-only"}, sigFlags...)...), 2},
		{"envelope without trust root", f.verifyArgs("--envelope", f.envelope), 2},
		{"trust root without digest", f.verifyArgs("--envelope", f.envelope, "--trust-root", f.trustRoot), 2},
		{"digest without trust root", f.verifyArgs("--envelope", f.envelope, "--trust-root-digest", f.trustRootDigest), 2},
		{"bad signature", f.verifyArgs("--envelope", badEnvelope, "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest), 1},
		{"wrong trust root digest", f.verifyArgs("--envelope", f.envelope, "--trust-root", f.trustRoot, "--trust-root-digest", "sha256:"+strings.Repeat("0", 64)), 1},
		{"removed previous-statement flag", f.verifyArgs(append([]string{"--previous-statement", filepath.Join(f.out, "statement.json")}, sigFlags...)...), 2},
		{"valid", f.verifyArgs(sigFlags...), 0},
	} {
		var stdout, stderr bytes.Buffer
		err := run(tc.args, &stdout, &stderr)
		if got := exitCode(err); got != tc.want {
			t.Fatalf("%s: exit code %d, want %d (err=%v stderr=%q)", tc.name, got, tc.want, err, stderr.String())
		}
		if tc.name == "valid" && !strings.Contains(stdout.String(), "evidence reattest verify: OK rules=1") {
			t.Fatalf("valid: unexpected output %q", stdout.String())
		}
		if tc.name == "no signature" && !strings.Contains(stderr.String(), "--envelope, --trust-root, and --trust-root-digest are required") {
			t.Fatalf("no signature: unexpected stderr %q", stderr.String())
		}
		if (tc.name == "bad signature" || tc.name == "wrong trust root digest") && !strings.Contains(stderr.String(), "FAIL: signature") {
			t.Fatalf("%s: expected a signature failure, got stderr %q", tc.name, stderr.String())
		}
		if tc.name == "structural only" && !strings.Contains(stderr.String(), "structural checks passed") {
			t.Fatalf("structural only: the structural checks should have passed: %q", stderr.String())
		}
	}
}

func TestEvidenceReattestVerifyUsesSignedStatementChain(t *testing.T) {
	f := newReattestFixture(t)
	copyFile := func(from, to string) {
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, to, raw)
	}
	copyFile(filepath.Join(f.out, "statement.json"), filepath.Join(f.chain, "0001.statement.json"))
	copyFile(f.envelope, filepath.Join(f.chain, "0001.statement.sig.json"))
	sigFlags := []string{"--envelope", f.envelope, "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest}

	var stdout, stderr bytes.Buffer
	if err := run(f.verifyArgs(sigFlags...), &stdout, &stderr); err != nil {
		t.Fatalf("a statement already appended as the chain head must verify: %v %s", err, stderr.String())
	}
	// A non-empty chain cannot be verified without the pinned trust root.
	if got := exitCode(run(f.verifyArgs("--structural-only"), &stdout, &stderr)); got != 1 {
		t.Fatalf("structural only on a non-empty chain without a trust root: exit %d, want 1", got)
	}

	// Anything in the chain directory other than statement/signature pairs
	// rejects the command outright.
	stray := filepath.Join(f.chain, "notes.txt")
	writeFile(t, stray, []byte("x"))
	if got := exitCode(run(f.verifyArgs(sigFlags...), &stdout, &stderr)); got != 2 {
		t.Fatalf("stray file in chain directory: exit %d, want 2", got)
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(f.chain, "0002.statement.json")
	copyFile(filepath.Join(f.out, "statement.json"), unsigned)
	if got := exitCode(run(f.verifyArgs(sigFlags...), &stdout, &stderr)); got != 2 {
		t.Fatalf("statement without a signature in chain directory: exit %d, want 2", got)
	}
	if err := os.Remove(unsigned); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.chain, "0001.statement.json"), filepath.Join(f.chain, "0003.statement.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.chain, "0001.statement.sig.json"), filepath.Join(f.chain, "0003.statement.sig.json")); err != nil {
		t.Fatal(err)
	}
	if got := exitCode(run(f.verifyArgs(sigFlags...), &stdout, &stderr)); got != 2 {
		t.Fatalf("symlinked chain entry: exit %d, want 2", got)
	}
}

func TestEvidenceReattestRejectsBadReviewRecordDirectory(t *testing.T) {
	f := newReattestFixture(t)
	prepareArgs := func(reviews string) []string {
		return []string{"evidence", "reattest", "prepare", "--worklist", f.worklist, "--pack", "cncf", "--rules", f.rules,
			"--rules-worklist-path", reattestWorklistPackPath, "--next-revision", "rev-2", "--wave", "1",
			"--output-dir", filepath.Join(f.dir, "out-"+filepath.Base(reviews)), "--statement-chain-dir", f.chain, "--review-record-dir", reviews}
	}
	empty := filepath.Join(f.dir, "empty-record")
	duplicate := filepath.Join(f.dir, "duplicate-record")
	for _, d := range []string{empty, duplicate} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(empty, "rule-a.json"), nil)
	writeFile(t, filepath.Join(duplicate, "rule-a.json"), []byte("one"))
	writeFile(t, filepath.Join(duplicate, "rule-a.txt"), []byte("two"))
	var stdout, stderr bytes.Buffer
	for _, dir := range []string{empty, duplicate, "relative/reviews"} {
		if got := exitCode(run(prepareArgs(dir), &stdout, &stderr)); got != 2 {
			t.Fatalf("review record directory %s: exit %d, want 2", dir, got)
		}
		if got := exitCode(run(f.verifyArgsWithReviews(dir, "--structural-only"), &stdout, &stderr)); got != 2 {
			t.Fatalf("verify with review record directory %s: exit %d, want 2", dir, got)
		}
	}
}
