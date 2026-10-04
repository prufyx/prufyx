// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// sampleCLIFixture is a human batch of two due rules (one sampled) in a
// pack padded with expired rules, prepared once through the CLI.
type sampleCLIFixture struct {
	dir, worklist, rules, chain, base, reviews, trustRoot, trustRootDigest string
	at                                                                     time.Time
	sampled, unsampled                                                     string
	key, root                                                              []byte
}

func newSampleCLIFixture(t *testing.T) sampleCLIFixture {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := sampleCLIFixture{
		dir: dir, worklist: filepath.Join(dir, "worklist.json"), rules: filepath.Join(dir, "rules.json"),
		chain: filepath.Join(dir, "chain"), base: filepath.Join(dir, "base-chain"), reviews: filepath.Join(dir, "reviews"),
		trustRoot: filepath.Join(dir, "trust-root.json"),
	}
	for _, d := range []string{f.chain, f.base, f.reviews} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.at = time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	slot, err := evidencereattest.SlotDate(1, f.at)
	if err != nil {
		t.Fatal(err)
	}
	validUntil := f.at.Add(7 * 24 * time.Hour)
	if !validUntil.Before(slot) {
		validUntil = slot.Add(-time.Hour)
	}
	source := func(id, repo, commit string) map[string]any {
		return map[string]any{"id": id, "url": "https://github.com/owner/" + repo + "/blob/" + commit + "/VERSION", "revision": commit, "contentDigest": "sha256:" + strings.Repeat("cd", 32), "startLine": 1, "endLine": 1}
	}
	rule := func(id, reviewedAt, until string, src map[string]any) map[string]any {
		return map[string]any{
			"id": id, "operator": "require", "reasonCode": "TEST_REASON", "nextAction": "TEST_ACTION",
			"subject":  map[string]any{"component": "pkg:github/owner/repo", "from": "1.0.0", "to": "2.0.0"},
			"evidence": map[string]any{"state": "active", "reviewedAt": reviewedAt, "validUntil": until, "sources": []any{src}},
		}
	}
	var entries []any
	var citations []evidencerepin.ClassResult
	var repos []evidencerepin.RepoResolution
	for _, id := range []string{"rule-a", "rule-b"} {
		commit := strings.Repeat(id[len(id)-1:], 40)
		entries = append(entries, map[string]any{"description": "d", "project": "proj-" + id, "requiredFacts": []any{},
			"rule": rule(id, f.at.Add(-30*24*time.Hour).Format(time.RFC3339), validUntil.Format(time.RFC3339), source(id+"-src", "repo-"+id, commit))})
		citations = append(citations, evidencerepin.ClassResult{
			RulePack: reattestWorklistPackPath, RuleID: id, Project: "proj-" + id, SourceID: id + "-src",
			Owner: "owner", Repo: "repo-" + id, Path: "VERSION", OldCommit: commit, NewCommit: commit, Class: evidencerepin.ClassFileIdentical,
		})
		repos = append(repos, evidencerepin.RepoResolution{Owner: "owner", Repo: "repo-" + id, Status: "RESOLVED", CurrentTag: "v1.2.3", CurrentCommit: commit, ResolvedAt: f.at.Add(-time.Hour).Format(time.RFC3339)})
	}
	// Expired, uncited rules in distinct weeks, so the stagger cap holds
	// both renewals in one week.
	past := time.Date(2023, 1, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		until := past.AddDate(0, 0, 7*i)
		entries = append(entries, map[string]any{"description": "d", "project": "proj-past", "requiredFacts": []any{},
			"rule": rule(fmt.Sprintf("past-%02d", i), until.Add(-60*24*time.Hour).Format(time.RFC3339), until.Format(time.RFC3339), source(fmt.Sprintf("past-src-%d", i), "pastrepo", strings.Repeat("f", 40)))})
	}
	pack, err := json.Marshal(map[string]any{
		"schema": "test-pack/v1", "revision": "rev-1", "policyId": "policy-1", "policyDigest": "sha256:" + strings.Repeat("ab", 32), "entries": entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.rules, pack)
	worklist, err := json.Marshal(evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: f.at.Add(-time.Hour).Format(time.RFC3339),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{reattestWorklistPackPath}}, Repos: repos, Citations: citations,
		Summary: evidencerepin.Summary{TotalCitations: 2, Classified: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.worklist, worklist)

	statement := f.prepare(t, "out1", f.at)
	if len(statement.Rules) != 2 || len(statement.SampledForFullReview) != 1 {
		t.Fatalf("setup: expected 2 renewed and 1 sampled, got %+v", statement)
	}
	f.sampled = statement.SampledForFullReview[0].RuleID
	f.unsampled = "rule-a"
	if f.sampled == "rule-a" {
		f.unsampled = "rule-b"
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key, err = knowledgesign.EncryptedKeyPEM(private, []byte("correct horse battery staple"))
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
	f.root, err = json.Marshal(map[string]any{
		"schemaVersion": evidencereattest.TrustRootSchemaV1, "purpose": evidencereattest.Purpose,
		"expires": time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339), "threshold": 1,
		"keys": []any{map[string]any{"keyId": keyID, "keyType": "ed25519", "scheme": "ed25519", "publicKey": hex.EncodeToString(public)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.trustRoot, append(append([]byte(nil), f.root...), '\n'))
	f.trustRootDigest = sourcecorpus.SHA(f.root)
	return f
}

func (f sampleCLIFixture) prepare(t *testing.T, out string, at time.Time) evidencereattest.Statement {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"evidence", "reattest", "prepare", "--worklist", f.worklist, "--pack", "cncf", "--rules", f.rules,
		"--rules-worklist-path", reattestWorklistPackPath, "--next-revision", "rev-2", "--wave", "1", "--output-dir", filepath.Join(f.dir, out),
		"--statement-chain-dir", f.chain, "--review-record-dir", f.reviews, "--attested-at", at.Format(time.RFC3339)}, &stdout, &stderr); err != nil {
		t.Fatalf("prepare: %v %s", err, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, out, "statement.json"))
	if err != nil {
		t.Fatal(err)
	}
	statement, err := evidencereattest.ParseStatement(bytes.TrimSuffix(raw, []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	return statement
}

func (f sampleCLIFixture) newArgs(rule, output string, extra ...string) []string {
	args := []string{"review-record", "new", "--statement", filepath.Join(f.dir, "out1", "statement.json"), "--pack", "cncf",
		"--rules", f.rules, "--rules-worklist-path", reattestWorklistPackPath, "--worklist", f.worklist,
		"--rule", rule, "--reviewer", "airstand", "--decided-at", f.at.Add(5 * time.Minute).Format(time.RFC3339), "--output", output}
	return append(args, extra...)
}

// Acceptance through the CLI: prepare → review-record new → prepare → sign
// → verify passes; a tampered record fails verify; a record for an
// unsampled rule is refused.
func TestReviewRecordNewPrepareSignVerify(t *testing.T) {
	f := newSampleCLIFixture(t)
	recordPath := filepath.Join(f.reviews, f.sampled+".json")
	var stdout, stderr bytes.Buffer
	if err := run(f.newArgs(f.sampled, recordPath), &stdout, &stderr); err != nil {
		t.Fatalf("review-record new: %v %s", err, stderr.String())
	}
	record, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("review-record new: rule=%s recordDigest=%s\n", f.sampled, sourcecorpus.SHA(record)); stdout.String() != want {
		t.Fatalf("stdout %q, want %q", stdout.String(), want)
	}

	// Deterministic: the same inputs give the same bytes.
	again := filepath.Join(f.dir, "again")
	if err := os.Mkdir(again, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run(f.newArgs(f.sampled, filepath.Join(again, f.sampled+".json")), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.ReadFile(filepath.Join(again, f.sampled+".json")); !bytes.Equal(record, second) {
		t.Fatal("review-record new is not deterministic")
	}

	// Refused: an unsampled rule, an existing output, a misnamed output,
	// and a missing flag. Nothing is written.
	stderr.Reset()
	unsampledPath := filepath.Join(f.reviews, f.unsampled+".json")
	if err := run(f.newArgs(f.unsampled, unsampledPath), &stdout, &stderr); exitCode(err) != 2 || !strings.Contains(stderr.String(), "is not sampled for full review") {
		t.Fatalf("unsampled rule: %v %q", err, stderr.String())
	}
	if _, err := os.Stat(unsampledPath); !os.IsNotExist(err) {
		t.Fatal("a record was written for an unsampled rule")
	}
	if err := run(f.newArgs(f.sampled, recordPath), &stdout, &stderr); exitCode(err) != 2 {
		t.Fatalf("existing output: %v", err)
	}
	if err := run(f.newArgs(f.sampled, filepath.Join(f.dir, "other.json")), &stdout, &stderr); exitCode(err) != 2 {
		t.Fatalf("misnamed output: %v", err)
	}
	for _, drop := range []string{"--statement", "--pack", "--rules", "--worklist", "--rule", "--reviewer", "--decided-at", "--output"} {
		args := f.newArgs(f.sampled, filepath.Join(f.dir, f.sampled+".json"))
		for i, a := range args {
			if a == drop {
				args = append(args[:i:i], args[i+2:]...)
				break
			}
		}
		if err := run(args, &stdout, &stderr); exitCode(err) != 2 {
			t.Fatalf("without %s: %v", drop, err)
		}
	}
	if err := run(f.newArgs(f.sampled, filepath.Join(f.dir, f.sampled+".json"), "--rule", f.sampled), &stdout, &stderr); exitCode(err) != 2 {
		t.Fatalf("duplicate flag (refused by the command dispatcher): %v", err)
	}
	for _, bad := range []string{f.at.Add(5 * time.Minute).In(time.FixedZone("x", 3600)).Format(time.RFC3339), "2026-11-24", "relative/path"} {
		args := f.newArgs(f.sampled, filepath.Join(f.dir, f.sampled+".json"))
		for i, a := range args {
			if a == "--decided-at" && !strings.Contains(bad, "/") {
				args[i+1] = bad
			}
			if a == "--rules" && strings.Contains(bad, "/") {
				args[i+1] = bad
			}
		}
		if err := run(args, &stdout, &stderr); exitCode(err) != 2 {
			t.Fatalf("bad value %q: %v", bad, err)
		}
	}
	stdout.Reset()
	if err := run([]string{"review-record", "new", "--help"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "usage: prufyx-maintainer review-record new") {
		t.Fatalf("help: %v %q", err, stdout.String())
	}

	// Prepare again with the record, sign, append, verify.
	attestedAt := f.at.Add(10 * time.Minute)
	statement := f.prepare(t, "out2", attestedAt)
	if statement.SampledForFullReview[0].ReviewRecordDigest != sourcecorpus.SHA(record) {
		t.Fatalf("the statement does not record the review: %+v", statement.SampledForFullReview)
	}
	statementRaw, err := os.ReadFile(filepath.Join(f.dir, "out2", "statement.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := evidencereattest.Sign(evidencereattest.SignOptions{Role: evidencereattest.RoleHuman,
		Statement: bytes.TrimSuffix(statementRaw, []byte("\n")), TrustRoot: f.root, EncryptedKey: f.key,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: f.trustRootDigest, Now: time.Now(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	writeFile(t, filepath.Join(f.chain, "0001.statement.json"), statementRaw)
	writeFile(t, filepath.Join(f.chain, "0001.statement.sig.json"), append(envelope, '\n'))
	verify := func(reviews string) error {
		stderr.Reset()
		return run([]string{"evidence", "reattest", "verify",
			"--statement", filepath.Join(f.chain, "0001.statement.json"), "--prior-pack", f.rules, "--next-pack", filepath.Join(f.dir, "out2", "rules.next.json"),
			"--worklist", f.worklist, "--pack", "cncf", "--rules-worklist-path", reattestWorklistPackPath,
			"--statement-chain-dir", f.chain, "--base-statement-chain-dir", f.base, "--review-record-dir", reviews,
			"--envelope", filepath.Join(f.chain, "0001.statement.sig.json"), "--trust-root", f.trustRoot, "--trust-root-digest", f.trustRootDigest,
			"--rerun-worklist", f.worklist}, &stdout, &stderr)
	}
	if err := verify(f.reviews); err != nil {
		t.Fatalf("verify: %v %s", err, stderr.String())
	}

	// A tampered record (a different compared-citations binding, still a
	// well-formed record) fails verify.
	tampered := filepath.Join(f.dir, "tampered")
	if err := os.Mkdir(tampered, 0o700); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(record, &doc); err != nil {
		t.Fatal(err)
	}
	doc["bindings"].(map[string]any)["citationsDigest"] = "sha256:" + strings.Repeat("e", 64)
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tampered, f.sampled+".json"), append(edited, '\n'))
	if err := verify(tampered); exitCode(err) == 0 {
		t.Fatal("verify accepted a tampered record")
	}
}

// --individual writes an individual review of a renewed rule that the
// statement did not sample.
func TestReviewRecordNewIndividual(t *testing.T) {
	f := newSampleCLIFixture(t)
	path := filepath.Join(f.reviews, f.unsampled+".json")
	var stdout, stderr bytes.Buffer
	if err := run(f.newArgs(f.unsampled, path, "--individual"), &stdout, &stderr); err != nil {
		t.Fatalf("review-record new --individual: %v %s", err, stderr.String())
	}
	record, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(record, []byte(`"scope":"ONE_INDIVIDUALLY_REVIEWED_RULE_OF_ONE_PREPARED_STATEMENT"`)) {
		t.Fatalf("not an individual review: %s", record)
	}
	statement := f.prepare(t, "out2", f.at.Add(10*time.Minute))
	recorded := false
	for _, r := range statement.IndividualReviews {
		recorded = recorded || (r.RuleID == f.unsampled && r.ReviewRecordDigest == sourcecorpus.SHA(record))
	}
	if !recorded {
		t.Fatalf("the individual review is not recorded: %+v", statement.IndividualReviews)
	}
}

// The dispatcher refuses a repeated option in either spelling.
func TestDuplicateOptionInEitherSpellingIsRefused(t *testing.T) {
	f := newSampleCLIFixture(t)
	out := filepath.Join(f.dir, f.sampled+".json")
	for _, extra := range [][]string{{"-rule", f.unsampled}, {"-rule=" + f.unsampled}, {"--rule=" + f.unsampled}} {
		var stdout, stderr bytes.Buffer
		err := run(f.newArgs(f.sampled, out, extra...), &stdout, &stderr)
		var command *commandError
		if !errors.As(err, &command) || command.code != 2 || command.message != "prufyx-maintainer: duplicate option rejected" {
			t.Fatalf("%v: %v", extra, err)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a record was written")
	}
	if !duplicateLongFlag([]string{"--a", "1", "-a", "2"}, nil) || duplicateLongFlag([]string{"--n", "-1", "--m", "-1"}, nil) || duplicateLongFlag([]string{"--a", "x", "--", "--a"}, nil) {
		t.Fatal("duplicateLongFlag spelling rules")
	}
}

// writeNewFile never replaces an existing file or symlink, and leaves
// nothing behind when it refuses.
func TestWriteNewFileLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "a.json")
	writeFile(t, existing, []byte("old"))
	if err := writeNewFile(existing, []byte("new")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing file: %v", err)
	}
	dangling := filepath.Join(dir, "b.json")
	if err := os.Symlink(filepath.Join(dir, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(dangling, []byte("new")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("dangling symlink: %v", err)
	}
	if err := writeNewFile(filepath.Join(dir, "missing-dir", "c.json"), []byte("new")); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	if err := writeNewFile(filepath.Join(dir, "d.json"), []byte("data")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "a.json,b.json,d.json" {
		t.Fatalf("directory holds %v", names)
	}
	if got, _ := os.ReadFile(existing); string(got) != "old" {
		t.Fatal("an existing file was replaced")
	}
	info, err := os.Stat(filepath.Join(dir, "d.json"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode: %v %v", info, err)
	}
}
