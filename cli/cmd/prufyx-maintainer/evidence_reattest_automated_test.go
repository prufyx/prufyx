// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const automationTestPassphrase = "automation passphrase for tests only"

type cliKey struct {
	public ed25519.PublicKey
	id     string
	path   string
}

// newCLIKey writes a throwaway encrypted key, mode 0600, below dir.
func newCLIKey(t *testing.T, dir, name string) cliKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tufKey, err := metadata.KeyFromPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	id, err := tufKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := knowledgesign.EncryptedKeyPEM(private, []byte(automationTestPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	writeFile(t, path, encrypted)
	return cliKey{public: public, id: id, path: path}
}

// writeRoot writes a trust root with the given keys (role "" for a v1 root)
// and returns its pinned digest.
func writeRoot(t *testing.T, path, schema string, keys map[string]cliKey) string {
	t.Helper()
	var list []any
	for role, key := range keys {
		entry := map[string]any{"keyId": key.id, "keyType": "ed25519", "scheme": "ed25519", "publicKey": hex.EncodeToString(key.public)}
		if schema == evidencereattest.TrustRootSchema {
			entry["role"] = role
		}
		list = append(list, entry)
	}
	if len(list) == 2 && list[0].(map[string]any)["keyId"].(string) > list[1].(map[string]any)["keyId"].(string) {
		list[0], list[1] = list[1], list[0]
	}
	raw, err := cjson.EncodeCanonical(map[string]any{
		"schemaVersion": schema, "purpose": evidencereattest.Purpose, "threshold": 1, "keys": list,
		"expires": time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(append([]byte(nil), raw...), '\n'))
	return sourcecorpus.SHA(raw)
}

type automatedFixture struct {
	reattestFixture
	autoOut, root, rootDigest, passphraseFile string
	human, automation                         cliKey
}

// newAutomatedFixture prepares an automated statement for the same single
// due rule the human fixture renews, under a v2 root with a human and an
// automation key.
func newAutomatedFixture(t *testing.T) automatedFixture {
	t.Helper()
	f := automatedFixture{reattestFixture: newReattestFixture(t)}
	f.autoOut = filepath.Join(f.dir, "auto-out")
	f.human, f.automation = newCLIKey(t, f.dir, "human.pem"), newCLIKey(t, f.dir, "automation.pem")
	f.root = filepath.Join(f.dir, "trust-root-v2.json")
	f.rootDigest = writeRoot(t, f.root, evidencereattest.TrustRootSchema, map[string]cliKey{evidencereattest.RoleHuman: f.human, evidencereattest.RoleAutomation: f.automation})
	f.passphraseFile = filepath.Join(f.dir, "passphrase.txt")
	writeFile(t, f.passphraseFile, []byte(automationTestPassphrase+"\n"))

	// Automated mode renews only citations compared on their release line.
	f.worklist = filepath.Join(f.dir, "worklist-line.json")
	var wl evidencerepin.Worklist
	raw, err := os.ReadFile(filepath.Join(f.dir, "worklist.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &wl); err != nil {
		t.Fatal(err)
	}
	c := &wl.Citations[0]
	c.Baseline, c.BaselineMode, c.BaselineLine, c.PinnedTag, c.BaselineTag = evidencerepin.BaselineReleaseLine, evidencerepin.BaselineModeReleaseLine, "0.9", "v0.9.0", "v0.9.4"
	wl.Lines = []evidencerepin.LineResolution{{
		Owner: c.Owner, Repo: c.Repo, Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: c.NewCommit, ResolvedAt: wl.Repos[0].ResolvedAt,
	}}
	if raw, err = json.Marshal(wl); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.worklist, raw)

	attestedAt := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	var stdout, stderr bytes.Buffer
	if err := run(f.prepareArgs("--attested-at", attestedAt.Format(time.RFC3339)), &stdout, &stderr); err != nil {
		t.Fatalf("automated prepare: %v %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "mode=automated signerRole=automation eligible=1 sampled=0") {
		t.Fatalf("automated prepare: unexpected output %q", stdout.String())
	}
	return f
}

func (f automatedFixture) prepareArgs(extra ...string) []string {
	args := []string{"evidence", "reattest", "prepare", "--mode", "automated", "--worklist", f.worklist, "--pack", "cncf", "--rules", f.rules,
		"--rules-worklist-path", reattestWorklistPackPath, "--next-revision", "rev-2", "--output-dir", f.autoOut, "--statement-chain-dir", f.chain}
	return append(args, extra...)
}

func (f automatedFixture) signArgs(statement, output string, extra ...string) []string {
	args := []string{"evidence", "reattest", "sign", "--statement", statement, "--trust-root", f.root, "--trust-root-digest", f.rootDigest, "--output", output}
	return append(args, extra...)
}

func TestEvidenceReattestPrepareAutomatedMode(t *testing.T) {
	f := newAutomatedFixture(t)
	statement, err := os.ReadFile(filepath.Join(f.autoOut, "statement.json"))
	if err != nil {
		t.Fatal(err)
	}
	if role, err := evidencereattest.StatementSignerRole(bytes.TrimSuffix(statement, []byte("\n"))); err != nil || role != evidencereattest.RoleAutomation {
		t.Fatalf("automated statement role %q, %v", role, err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"automated mode with a wave", f.prepareArgs("--wave", "1")},
		{"unknown mode", append(f.prepareArgs()[:4], append([]string{"robot"}, f.prepareArgs()[5:]...)...)},
	} {
		var stdout, stderr bytes.Buffer
		if got := exitCode(run(tc.args, &stdout, &stderr)); got != 2 {
			t.Fatalf("%s: exit code %d, want 2", tc.name, got)
		}
	}
}

func TestEvidenceReattestSignAutomationRoleUnattended(t *testing.T) {
	f := newAutomatedFixture(t)
	statement := filepath.Join(f.autoOut, "statement.json")
	verifyWith := func(envelope string, extra ...string) (int, string) {
		// The gate verifies a statement that is already the chain's one
		// new entry, against a worklist this job produced itself.
		statementRaw, err := os.ReadFile(statement)
		if err != nil {
			t.Fatal(err)
		}
		envelopeRaw, err := os.ReadFile(envelope)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.chain, "0001.statement.json"), statementRaw)
		writeFile(t, filepath.Join(f.chain, "0001.statement.sig.json"), envelopeRaw)
		var stdout, stderr bytes.Buffer
		args := []string{"evidence", "reattest", "verify",
			"--statement", statement, "--prior-pack", f.rules, "--next-pack", filepath.Join(f.autoOut, "rules.next.json"),
			"--worklist", f.worklist, "--pack", "cncf", "--rules-worklist-path", reattestWorklistPackPath,
			"--statement-chain-dir", f.chain, "--base-statement-chain-dir", f.base,
			"--envelope", envelope, "--trust-root", f.root, "--trust-root-digest", f.rootDigest}
		return exitCode(run(append(args, extra...), &stdout, &stderr)), stdout.String() + stderr.String()
	}
	verify := func(envelope string) (int, string) {
		return verifyWith(envelope, "--rerun-worklist", f.worklist)
	}

	fromFiles := filepath.Join(f.dir, "files.sig.json")
	var stdout, stderr bytes.Buffer
	if err := run(f.signArgs(statement, fromFiles, "--role", "automation", "--key", f.automation.path, "--passphrase-file", f.passphraseFile), &stdout, &stderr); err != nil {
		t.Fatalf("sign from files: %v %s", err, stderr.String())
	}
	if code, out := verify(fromFiles); code != 0 || !strings.Contains(out, "OK role=automation rules=1 sampled=0") || !strings.Contains(out, f.automation.id) {
		t.Fatalf("verify: exit %d, %q", code, out)
	}

	// The gate does not take the signing job's worklist on trust: without
	// a worklist the verifying job produced itself it refuses, and a
	// citation the independent worklist classifies differently is a V9
	// failure.
	if code, out := verifyWith(fromFiles); code != 1 || !strings.Contains(out, "--rerun-worklist") {
		t.Fatalf("verify without --rerun-worklist: exit %d, %q", code, out)
	}
	var independent evidencerepin.Worklist
	rawWorklist, err := os.ReadFile(f.worklist)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawWorklist, &independent); err != nil {
		t.Fatal(err)
	}
	independent.Citations[0].Class = evidencerepin.ClassSpanIdentical
	rawIndependent, err := json.Marshal(independent)
	if err != nil {
		t.Fatal(err)
	}
	differing := filepath.Join(f.dir, "independent-worklist.json")
	writeFile(t, differing, rawIndependent)
	if code, out := verifyWith(fromFiles, "--rerun-worklist", differing); code != 1 || !strings.Contains(out, "V9:") {
		t.Fatalf("verify against a differing independent worklist: exit %d, %q", code, out)
	}

	keyPEM, err := os.ReadFile(f.automation.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_REATTEST_KEY", string(keyPEM))
	t.Setenv("TEST_REATTEST_PASSPHRASE", automationTestPassphrase)
	t.Setenv("TEST_REATTEST_EMPTY", "")
	fromEnv := filepath.Join(f.dir, "env.sig.json")
	stdout.Reset()
	stderr.Reset()
	if err := run(f.signArgs(statement, fromEnv, "--role", "automation", "--key-env", "TEST_REATTEST_KEY", "--passphrase-env", "TEST_REATTEST_PASSPHRASE"), &stdout, &stderr); err != nil {
		t.Fatalf("sign from environment: %v %s", err, stderr.String())
	}
	if code, out := verify(fromEnv); code != 0 {
		t.Fatalf("verify: exit %d, %q", code, out)
	}
	// Both variables are removed from the process as soon as they are read.
	for _, name := range []string{"TEST_REATTEST_KEY", "TEST_REATTEST_PASSPHRASE"} {
		if _, still := os.LookupEnv(name); still {
			t.Fatalf("%s is still set after signing", name)
		}
	}
	t.Setenv("TEST_REATTEST_KEY", string(keyPEM))
	t.Setenv("TEST_REATTEST_PASSPHRASE", automationTestPassphrase)

	looseFile := filepath.Join(f.dir, "loose-passphrase.txt")
	if err := os.WriteFile(looseFile, []byte(automationTestPassphrase), 0o644); err != nil {
		t.Fatal(err)
	}
	wrongFile := filepath.Join(f.dir, "wrong-passphrase.txt")
	writeFile(t, wrongFile, []byte("not the passphrase"))
	out := func(name string) string { return filepath.Join(f.dir, name+".sig.json") }
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"both key sources", f.signArgs(statement, out("a"), "--role", "automation", "--key", f.automation.path, "--key-env", "TEST_REATTEST_KEY", "--passphrase-file", f.passphraseFile)},
		{"no key source", f.signArgs(statement, out("b"), "--role", "automation", "--passphrase-file", f.passphraseFile)},
		{"both passphrase sources", f.signArgs(statement, out("c"), "--role", "automation", "--key", f.automation.path, "--passphrase-file", f.passphraseFile, "--passphrase-env", "TEST_REATTEST_PASSPHRASE")},
		{"no passphrase source", f.signArgs(statement, out("d"), "--role", "automation", "--key", f.automation.path)},
		{"unset environment variable", f.signArgs(statement, out("e"), "--role", "automation", "--key-env", "TEST_REATTEST_UNSET", "--passphrase-file", f.passphraseFile)},
		{"empty passphrase variable", f.signArgs(statement, out("f"), "--role", "automation", "--key", f.automation.path, "--passphrase-env", "TEST_REATTEST_EMPTY")},
		{"passphrase file readable by others", f.signArgs(statement, out("g"), "--role", "automation", "--key", f.automation.path, "--passphrase-file", looseFile)},
		{"relative passphrase file", f.signArgs(statement, out("h"), "--role", "automation", "--key", f.automation.path, "--passphrase-file", "passphrase.txt")},
		{"wrong passphrase", f.signArgs(statement, out("i"), "--role", "automation", "--key", f.automation.path, "--passphrase-file", wrongFile)},
		{"human key as the automation role", f.signArgs(statement, out("j"), "--role", "automation", "--key", f.human.path, "--passphrase-file", f.passphraseFile)},
		{"unknown role", f.signArgs(statement, out("k"), "--role", "robot", "--key", f.automation.path, "--passphrase-file", f.passphraseFile)},
	} {
		stdout.Reset()
		stderr.Reset()
		if got := exitCode(run(tc.args, &stdout, &stderr)); got != 2 {
			t.Fatalf("%s: exit code %d, want 2 (stderr %q)", tc.name, got, stderr.String())
		}
		if strings.Contains(tc.name, "empty passphrase") && !strings.Contains(stderr.String(), "unavailable or empty") {
			t.Fatalf("%s: stderr %q", tc.name, stderr.String())
		}
	}
}

// Each role signs only its own statements, and the human role never reads
// a key or passphrase from a file or the environment: it refuses those
// flags, and an automated statement, before any terminal prompt.
func TestEvidenceReattestSignRefusesRoleMismatch(t *testing.T) {
	f := newAutomatedFixture(t)
	automated := filepath.Join(f.autoOut, "statement.json")
	human := filepath.Join(f.out, "statement.json")
	out := func(name string) string { return filepath.Join(f.dir, name+".sig.json") }
	for _, tc := range []struct {
		name, wantStderr string
		args             []string
	}{
		{"automation role on a human statement", `must be signed with role "human", not "automation"`,
			f.signArgs(human, out("a"), "--role", "automation", "--key", f.automation.path, "--passphrase-file", f.passphraseFile)},
		{"human role on an automated statement", `must be signed with role "automation", not "human"`,
			f.signArgs(automated, out("b"), "--role", "human", "--key", f.human.path)},
		{"default role on an automated statement", `must be signed with role "automation", not "human"`,
			f.signArgs(automated, out("c"), "--key", f.human.path)},
		{"human role with a passphrase file", "only at a terminal", f.signArgs(human, out("d"), "--role", "human", "--key", f.human.path, "--passphrase-file", f.passphraseFile)},
		{"human role with a passphrase variable", "only at a terminal", f.signArgs(human, out("e"), "--role", "human", "--key", f.human.path, "--passphrase-env", "HOME")},
		{"human role with a key variable", "only at a terminal", f.signArgs(human, out("f"), "--role", "human", "--key-env", "HOME")},
	} {
		var stdout, stderr bytes.Buffer
		if got := exitCode(run(tc.args, &stdout, &stderr)); got != 2 {
			t.Fatalf("%s: exit code %d, want 2", tc.name, got)
		}
		if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
			t.Fatalf("%s: stderr %q does not contain %q", tc.name, stderr.String(), tc.wantStderr)
		}
		if strings.Contains(stderr.String(), "Passphrase:") {
			t.Fatalf("%s: prompted for a passphrase", tc.name)
		}
	}
}

func TestEvidenceReattestTrustRootMigrate(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	human, automation := newCLIKey(t, dir, "human.pem"), newCLIKey(t, dir, "automation.pem")
	v1 := filepath.Join(dir, "v1.json")
	v1Digest := writeRoot(t, v1, evidencereattest.TrustRootSchemaV1, map[string]cliKey{"": human})
	v2 := filepath.Join(dir, "v2.json")
	args := func(output, digest string, extra ...string) []string {
		return append([]string{"evidence", "reattest", "trust-root", "migrate", "--from", v1, "--from-digest", digest, "--output", output}, extra...)
	}
	var stdout, stderr bytes.Buffer
	if err := run(args(v2, v1Digest, "--add-automation-key", hex.EncodeToString(automation.public)), &stdout, &stderr); err != nil {
		t.Fatalf("migrate: %v %s", err, stderr.String())
	}
	raw, err := os.ReadFile(v2)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	digest := sourcecorpus.SHA(raw)
	if !strings.Contains(stdout.String(), "trustRootDigest="+digest) ||
		!strings.Contains(stdout.String(), "key "+human.id+" role human") || !strings.Contains(stdout.String(), "key "+automation.id+" role automation") {
		t.Fatalf("unexpected output %q", stdout.String())
	}
	root, err := evidencereattest.ParseTrustRoot(raw, digest, time.Now().UTC())
	if err != nil || root.SchemaVersion != evidencereattest.TrustRootSchema || len(root.Keys) != 2 {
		t.Fatalf("migrated root: %+v %v", root, err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"output exists", args(v2, v1Digest)},
		{"wrong pinned digest", args(filepath.Join(dir, "x.json"), digest)},
		{"relative output", args("x.json", v1Digest)},
		{"bad automation key", args(filepath.Join(dir, "y.json"), v1Digest, "--add-automation-key", "00")},
		{"remove unknown key", args(filepath.Join(dir, "z.json"), v1Digest, "--remove-key", automation.id)},
	} {
		stdout.Reset()
		stderr.Reset()
		if got := exitCode(run(tc.args, &stdout, &stderr)); got != 2 {
			t.Fatalf("%s: exit code %d, want 2", tc.name, got)
		}
	}
}
