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
	"github.com/prufyx/prufyx/cli/internal/maintainer/reviewrecord"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const reattestWorklistPackPath = "/repo/cli/internal/cncfcheck/data/rules.json"

// reattestFixture is one prepared, signed single-rule batch on disk, with a
// throwaway key and trust root that exist only below t.TempDir().
type reattestFixture struct {
	dir, worklist, rules, out, chain, base, reviews string
	trustRoot, trustRootDigest, envelope            string
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
		out: filepath.Join(dir, "out"), chain: filepath.Join(dir, "chain"), base: filepath.Join(dir, "base-chain"), reviews: filepath.Join(dir, "reviews"),
		trustRoot: filepath.Join(dir, "trust-root.json"), envelope: filepath.Join(dir, "out", "statement.sig.json"),
	}
	for _, d := range []string{f.chain, f.base, f.reviews} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	commit := strings.Repeat("a", 40)
	// The current lease ends before the wave-1 slot and within the
	// renewal window, so the rule is due and its validUntil moves later.
	slot, err := evidencereattest.SlotDate(1, at)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := at.Add(7 * 24 * time.Hour)
	if !validUntil.Before(slot) {
		validUntil = slot.Add(-time.Hour)
	}
	rule := map[string]any{
		"id": "rule-a", "operator": "require", "reasonCode": "TEST_REASON", "nextAction": "TEST_ACTION",
		"subject": map[string]any{"component": "pkg:github/owner/repo", "from": "1.0.0", "to": "2.0.0"},
		"evidence": map[string]any{
			"state": "active", "reviewedAt": at.Add(-30 * 24 * time.Hour).Format(time.RFC3339), "validUntil": validUntil.Format(time.RFC3339),
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
	writeFile(t, filepath.Join(f.reviews, "rule-a.json"), reattestReviewRecord(t, rule, "proj-a", at.Add(-30*time.Minute)))

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
		"schemaVersion": evidencereattest.TrustRootSchemaV1, "purpose": evidencereattest.Purpose,
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
	envelope, err := evidencereattest.Sign(evidencereattest.SignOptions{Role: evidencereattest.RoleHuman,
		Statement: bytes.TrimSuffix(statement, []byte("\n")), TrustRoot: root, EncryptedKey: key,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: f.trustRootDigest, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	writeFile(t, f.envelope, append(envelope, '\n'))
	return f
}

// reattestReviewRecord renders a structurally valid individual review
// record for rule, bound to the rule's exact content, decided at decidedAt.
func reattestReviewRecord(t *testing.T, rule map[string]any, project string, decidedAt time.Time) []byte {
	t.Helper()
	ruleRaw, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	value, err := sourcecorpus.DecodeBounded(ruleRaw, int64(len(ruleRaw)))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := sourcecorpus.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	other := "sha256:" + strings.Repeat("d", 64)
	raw, err := json.Marshal(map[string]any{
		"schema": reviewrecord.RecordSchema,
		"decision": map[string]any{
			"authority": "DECLARED_MAINTAINER_DECISION_NOT_AUTHENTICATED", "state": "ACCEPTED_FOR_SIGNING_REVIEW",
			"maintainer": "Test Reviewer", "decidedAt": decidedAt.UTC().Format(time.RFC3339), "scope": "ONE_RULE_CONSISTENCY_ONLY",
		},
		"subject": map[string]any{"project": project, "ruleId": rule["id"], "knowledgeRevision": "1", "evaluationAt": decidedAt.UTC().Format(time.RFC3339)},
		"bindings": map[string]any{
			"packetDigest": other, "packetReceiptDigest": other, "sourceReceiptDigest": other, "sourceCorpusManifestDigest": other,
			"sourceCorpusReceiptDigest": other, "vectorFileDigest": other, "selectedVectorGroupDigest": other, "targetDigest": other,
			"engineCapabilityDigest": other, "ruleDigest": sourcecorpus.SHA(canonical), "ruleEvidenceDigest": other,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func (f reattestFixture) verifyArgs(extra ...string) []string {
	return f.verifyArgsWithReviews(f.reviews, extra...)
}

func (f reattestFixture) verifyArgsWithReviews(reviews string, extra ...string) []string {
	args := []string{"evidence", "reattest", "verify",
		"--statement", filepath.Join(f.out, "statement.json"), "--prior-pack", f.rules, "--next-pack", filepath.Join(f.out, "rules.next.json"),
		"--worklist", f.worklist, "--pack", "cncf", "--rules-worklist-path", reattestWorklistPackPath,
		"--statement-chain-dir", f.chain, "--base-statement-chain-dir", f.base, "--review-record-dir", reviews}
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
	// chained cases run with the statement and its envelope appended to the
	// statement chain, as the publish gate sees a merged change.
	setChain := func(on bool) {
		for _, name := range []string{"0001.statement.json", "0001.statement.sig.json"} {
			path := filepath.Join(f.chain, name)
			if !on {
				_ = os.Remove(path)
				continue
			}
			from := filepath.Join(f.out, "statement.json")
			if strings.HasSuffix(name, ".sig.json") {
				from = f.envelope
			}
			raw, err := os.ReadFile(from)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, raw)
		}
	}
	for _, tc := range []struct {
		name    string
		args    []string
		want    int
		chained bool
	}{
		{"no signature, statement not in the chain", f.verifyArgs(), 1, false},
		{"no signature, statement in the chain", f.verifyArgs("--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest), 1, true},
		{"structural only", f.verifyArgs("--structural-only"), 1, false},
		{"structural only with the chain's trust root", f.verifyArgs("--structural-only", "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest), 1, false},
		{"structural only with an envelope", f.verifyArgs(append([]string{"--structural-only"}, sigFlags...)...), 2, false},
		{"envelope without trust root", f.verifyArgs("--envelope", f.envelope), 2, false},
		{"trust root without digest", f.verifyArgs("--envelope", f.envelope, "--trust-root", f.trustRoot), 2, false},
		{"digest without trust root", f.verifyArgs("--envelope", f.envelope, "--trust-root-digest", f.trustRootDigest), 2, false},
		{"valid envelope, statement not appended to the chain", f.verifyArgs(sigFlags...), 1, false},
		{"bad signature", f.verifyArgs("--envelope", badEnvelope, "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest), 1, true},
		{"wrong trust root digest", f.verifyArgs("--envelope", f.envelope, "--trust-root", f.trustRoot, "--trust-root-digest", "sha256:"+strings.Repeat("0", 64)), 1, true},
		{"removed previous-statement flag", f.verifyArgs(append([]string{"--previous-statement", filepath.Join(f.out, "statement.json")}, sigFlags...)...), 2, false},
		{"valid", f.verifyArgs(sigFlags...), 0, true},
	} {
		setChain(tc.chained)
		var stdout, stderr bytes.Buffer
		err := run(tc.args, &stdout, &stderr)
		if got := exitCode(err); got != tc.want {
			t.Fatalf("%s: exit code %d, want %d (err=%v stderr=%q)", tc.name, got, tc.want, err, stderr.String())
		}
		if tc.name == "valid" && !strings.Contains(stdout.String(), "evidence reattest verify: OK role=human rules=1") {
			t.Fatalf("valid: unexpected output %q", stdout.String())
		}
		if tc.name == "no signature, statement not in the chain" && !strings.Contains(stderr.String(), "not appended to the statement chain") {
			t.Fatalf("%s: unexpected stderr %q", tc.name, stderr.String())
		}
		if tc.name == "valid envelope, statement not appended to the chain" && !strings.Contains(stderr.String(), "not appended to the statement chain") {
			t.Fatalf("%s: unexpected stderr %q", tc.name, stderr.String())
		}
		if tc.name == "no signature, statement in the chain" && !strings.Contains(stderr.String(), "--envelope, --trust-root, and --trust-root-digest are required") {
			t.Fatalf("%s: unexpected stderr %q", tc.name, stderr.String())
		}
		if tc.name == "bad signature" && !strings.Contains(stderr.String(), "FAIL: signature") {
			t.Fatalf("%s: expected a signature failure, got stderr %q", tc.name, stderr.String())
		}
		if tc.name == "wrong trust root digest" && !strings.Contains(stderr.String(), "signature") {
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
	otherExtension := filepath.Join(f.dir, "other-extension")
	noExtension := filepath.Join(f.dir, "no-extension")
	onlyExtension := filepath.Join(f.dir, "only-extension")
	for _, d := range []string{empty, otherExtension, noExtension, onlyExtension} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	record, err := os.ReadFile(filepath.Join(f.reviews, "rule-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(empty, "rule-a.json"), nil)
	writeFile(t, filepath.Join(otherExtension, "rule-a.json"), record)
	writeFile(t, filepath.Join(otherExtension, "rule-a.txt"), record)
	writeFile(t, filepath.Join(noExtension, "rule-a"), record)
	writeFile(t, filepath.Join(onlyExtension, ".json"), record)
	var stdout, stderr bytes.Buffer
	for _, dir := range []string{empty, otherExtension, noExtension, onlyExtension, "relative/reviews"} {
		if got := exitCode(run(prepareArgs(dir), &stdout, &stderr)); got != 2 {
			t.Fatalf("review record directory %s: exit %d, want 2", dir, got)
		}
		if got := exitCode(run(f.verifyArgsWithReviews(dir, "--structural-only"), &stdout, &stderr)); got != 2 {
			t.Fatalf("verify with review record directory %s: exit %d, want 2", dir, got)
		}
	}
}

func TestLoadReviewRecordsKeysByFileNameWithoutJSONExtension(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "kubernetes.v1.30-rule.json"), []byte("{}"))
	writeFile(t, filepath.Join(dir, "rule-a.json"), []byte("{}"))
	records, err := loadReviewRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records["kubernetes.v1.30-rule"] == nil || records["rule-a"] == nil {
		t.Fatalf("unexpected rule IDs: %v", records)
	}
	writeFile(t, filepath.Join(dir, "kubernetes.v1.30-rule"), []byte("{}"))
	if _, err := loadReviewRecords(dir); err == nil {
		t.Fatal("a review record file without the .json extension was accepted")
	}
}

func TestEvidenceReattestVerifyRequiresChainToExtendBaseChain(t *testing.T) {
	f := newReattestFixture(t)
	copyFile := func(from, to string) {
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, to, raw)
	}
	sigFlags := []string{"--envelope", f.envelope, "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest}
	var stdout, stderr bytes.Buffer

	withoutBase := f.verifyArgs(sigFlags...)
	for i := range withoutBase {
		if withoutBase[i] == "--base-statement-chain-dir" {
			withoutBase = append(withoutBase[:i], withoutBase[i+2:]...)
			break
		}
	}
	if got := exitCode(run(withoutBase, &stdout, &stderr)); got != 2 {
		t.Fatalf("verify without --base-statement-chain-dir: exit %d, want 2", got)
	}

	// The statement is already part of the base branch's chain, and the
	// change's chain directory was emptied.
	copyFile(filepath.Join(f.out, "statement.json"), filepath.Join(f.base, "0001.statement.json"))
	copyFile(f.envelope, filepath.Join(f.base, "0001.statement.sig.json"))
	stderr.Reset()
	if got := exitCode(run(f.verifyArgs(sigFlags...), &stdout, &stderr)); got != 1 || !strings.Contains(stderr.String(), "V5:") || !strings.Contains(stderr.String(), "base chain entry 0001 is missing or changed") {
		t.Fatalf("emptied chain over a non-empty base: exit %d, stderr %q", got, stderr.String())
	}
	copyFile(filepath.Join(f.out, "statement.json"), filepath.Join(f.chain, "0001.statement.json"))
	copyFile(f.envelope, filepath.Join(f.chain, "0001.statement.sig.json"))
	stderr.Reset()
	if got := exitCode(run(f.verifyArgs(sigFlags...), &stdout, &stderr)); got != 1 || !strings.Contains(stderr.String(), "already recorded in the base branch's statement chain") {
		t.Fatalf("statement already in the base chain: exit %d, stderr %q", got, stderr.String())
	}
}

func TestEvidenceReattestRejectsMalformedReviewRecordContent(t *testing.T) {
	f := newReattestFixture(t)
	reviews := filepath.Join(f.dir, "bad-content")
	if err := os.Mkdir(reviews, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(reviews, "rule-a.json"), []byte("{\"reviewed\":\"rule-a\"}\n"))
	var stdout, stderr bytes.Buffer
	args := []string{"evidence", "reattest", "prepare", "--worklist", f.worklist, "--pack", "cncf", "--rules", f.rules,
		"--rules-worklist-path", reattestWorklistPackPath, "--next-revision", "rev-2", "--wave", "1",
		"--output-dir", filepath.Join(f.dir, "out-bad"), "--statement-chain-dir", f.chain, "--review-record-dir", reviews}
	if got := exitCode(run(args, &stdout, &stderr)); got != 2 || !strings.Contains(stderr.String(), "is not a well-formed review record") {
		t.Fatalf("prepare with a malformed review record: exit %d, stderr %q", got, stderr.String())
	}
	stderr.Reset()
	if got := exitCode(run(f.verifyArgsWithReviews(reviews, "--structural-only"), &stdout, &stderr)); got != 1 || !strings.Contains(stderr.String(), "is not a well-formed review record") {
		t.Fatalf("verify with a malformed review record: exit %d, stderr %q", got, stderr.String())
	}
}

func TestEvidenceReattestPrepareRejectsFutureAttestedAt(t *testing.T) {
	f := newReattestFixture(t)
	var stdout, stderr bytes.Buffer
	args := []string{"evidence", "reattest", "prepare", "--worklist", f.worklist, "--pack", "cncf", "--rules", f.rules,
		"--rules-worklist-path", reattestWorklistPackPath, "--next-revision", "rev-2", "--wave", "1",
		"--output-dir", filepath.Join(f.dir, "out-future"), "--statement-chain-dir", f.chain, "--review-record-dir", f.reviews,
		"--attested-at", time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second).Format(time.RFC3339)}
	if got := exitCode(run(args, &stdout, &stderr)); got != 2 || !strings.Contains(stderr.String(), "attestedAt is in the future") {
		t.Fatalf("prepare with a future --attested-at: exit %d, stderr %q", got, stderr.String())
	}
}
