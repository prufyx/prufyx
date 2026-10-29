// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const keygenTestPassphrase = "keygen passphrase for tests only"

func parseKeygenOutput(out string) (keyID, publicKey string) {
	for _, field := range strings.Fields(out) {
		if v, ok := strings.CutPrefix(field, "keyId="); ok {
			keyID = v
		}
		if v, ok := strings.CutPrefix(field, "publicKey="); ok {
			publicKey = v
		}
	}
	return keyID, publicKey
}

func keygenArgs(outDir string, extra ...string) []string {
	return append([]string{"evidence", "reattest", "keygen", "--out-dir", outDir}, extra...)
}

func TestEvidenceReattestKeygenRoundTrip(t *testing.T) {
	f := newAutomatedFixture(t)
	outDir := filepath.Join(f.dir, "keys", "new")
	t.Setenv("KEYGEN_TEST_PASSPHRASE", keygenTestPassphrase)
	var stdout, stderr bytes.Buffer
	if err := run(keygenArgs(outDir, "--passphrase-env", "KEYGEN_TEST_PASSPHRASE"), &stdout, &stderr); err != nil {
		t.Fatalf("keygen: %v %s", err, stderr.String())
	}
	keyID, pubHex := parseKeygenOutput(stdout.String())
	if len(keyID) != 64 || len(pubHex) != 64 {
		t.Fatalf("unexpected stdout %q", stdout.String())
	}
	if lines := strings.Count(stdout.String(), "\n"); lines != 1 {
		t.Fatalf("stdout has %d lines: %q", lines, stdout.String())
	}

	keyPath, pubPath := filepath.Join(outDir, keyID+".key.pem"), filepath.Join(outDir, keyID+".pub")
	for path, want := range map[string]os.FileMode{outDir: 0o700, keyPath: 0o600, pubPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: %v %v, want mode %v", path, info, err, want)
		}
	}
	pubFile, err := os.ReadFile(pubPath)
	if err != nil || strings.TrimSpace(string(pubFile)) != pubHex {
		t.Fatalf("pub file %q %v", pubFile, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	private, err := knowledgesign.DecryptPrivateKey(keyPEM, []byte(keygenTestPassphrase))
	if err != nil {
		t.Fatalf("generated key does not decrypt: %v", err)
	}
	// Stdout and stderr carry the public key only, never private key bytes
	// (raw, seed or hex) or the passphrase.
	for _, secret := range []string{hex.EncodeToString(private), hex.EncodeToString(private.Seed()), keygenTestPassphrase, string(keyPEM)} {
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatal("output leaks key material")
		}
	}

	// migrate --add-automation-key -> sign --role automation -> verify.
	newRoot := filepath.Join(f.dir, "trust-root-new.json")
	stdout.Reset()
	if err := run([]string{"evidence", "reattest", "trust-root", "migrate", "--from", f.root, "--from-digest", f.rootDigest,
		"--output", newRoot, "--add-automation-key", pubHex}, &stdout, &stderr); err != nil {
		t.Fatalf("migrate: %v %s", err, stderr.String())
	}
	rootRaw, err := os.ReadFile(newRoot)
	if err != nil {
		t.Fatal(err)
	}
	rootRaw = bytes.TrimSuffix(rootRaw, []byte("\n"))
	if _, err := evidencereattest.ParseTrustRoot(rootRaw, sourcecorpus.SHA(rootRaw), time.Now().UTC()); err != nil {
		t.Fatalf("migrated root: %v", err)
	}
	passphraseFile := filepath.Join(f.dir, "keygen-passphrase.txt")
	writeFile(t, passphraseFile, []byte(keygenTestPassphrase+"\n"))
	statement := filepath.Join(f.autoOut, "statement.json")
	envelope := filepath.Join(f.dir, "keygen.sig.json")
	signArgs := []string{"evidence", "reattest", "sign", "--statement", statement, "--trust-root", newRoot, "--trust-root-digest", sourcecorpus.SHA(rootRaw),
		"--output", envelope, "--role", "automation", "--key", keyPath, "--passphrase-file", passphraseFile}
	stdout.Reset()
	if err := run(signArgs, &stdout, &stderr); err != nil {
		t.Fatalf("sign: %v %s", err, stderr.String())
	}
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
	stdout.Reset()
	stderr.Reset()
	if err := run([]string{"evidence", "reattest", "verify",
		"--statement", statement, "--prior-pack", f.rules, "--next-pack", filepath.Join(f.autoOut, "rules.next.json"),
		"--worklist", f.worklist, "--pack", "cncf", "--rules-worklist-path", reattestWorklistPackPath,
		"--statement-chain-dir", f.chain, "--base-statement-chain-dir", f.base, "--rerun-worklist", f.worklist,
		"--envelope", envelope, "--trust-root", newRoot, "--trust-root-digest", sourcecorpus.SHA(rootRaw)}, &stdout, &stderr); err != nil {
		t.Fatalf("verify: %v %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK role=automation") || !strings.Contains(stdout.String(), keyID) {
		t.Fatalf("verify output %q", stdout.String())
	}
}

func TestEvidenceReattestKeygenRefusals(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	passphraseFile := filepath.Join(dir, "good.txt")
	writeFile(t, passphraseFile, []byte(keygenTestPassphrase+"\n"))
	shortFile := filepath.Join(dir, "short.txt")
	writeFile(t, shortFile, []byte("short\n"))
	emptyFile := filepath.Join(dir, "empty.txt")
	writeFile(t, emptyFile, nil)
	looseFile := filepath.Join(dir, "loose.txt")
	writeFile(t, looseFile, []byte(keygenTestPassphrase))
	if err := os.Chmod(looseFile, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYGEN_TEST_GOOD", keygenTestPassphrase)
	t.Setenv("KEYGEN_TEST_SHORT", "fifteen chars!!")
	t.Setenv("KEYGEN_TEST_EMPTY", "")
	fileAsDir := filepath.Join(dir, "afile")
	writeFile(t, fileAsDir, []byte("x"))

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no passphrase source", keygenArgs(filepath.Join(dir, "a"))},
		{"both passphrase sources", keygenArgs(filepath.Join(dir, "b"), "--passphrase-file", passphraseFile, "--passphrase-env", "KEYGEN_TEST_GOOD")},
		{"unset env", keygenArgs(filepath.Join(dir, "c"), "--passphrase-env", "KEYGEN_TEST_UNSET")},
		{"empty env", keygenArgs(filepath.Join(dir, "d"), "--passphrase-env", "KEYGEN_TEST_EMPTY")},
		{"short env", keygenArgs(filepath.Join(dir, "e"), "--passphrase-env", "KEYGEN_TEST_SHORT")},
		{"short file", keygenArgs(filepath.Join(dir, "f"), "--passphrase-file", shortFile)},
		{"empty file", keygenArgs(filepath.Join(dir, "g"), "--passphrase-file", emptyFile)},
		{"group-readable passphrase file", keygenArgs(filepath.Join(dir, "h"), "--passphrase-file", looseFile)},
		{"relative out-dir", keygenArgs("rel", "--passphrase-file", passphraseFile)},
		{"missing out-dir", []string{"evidence", "reattest", "keygen", "--passphrase-file", passphraseFile}},
		{"out-dir is a file", keygenArgs(fileAsDir, "--passphrase-file", passphraseFile)},
	} {
		var stdout, stderr bytes.Buffer
		if got := exitCode(run(tc.args, &stdout, &stderr)); got != 2 {
			t.Fatalf("%s: exit code %d, want 2", tc.name, got)
		}
		if stdout.Len() != 0 {
			t.Fatalf("%s: wrote to stdout: %q", tc.name, stdout.String())
		}
	}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		if entries, err := os.ReadDir(filepath.Join(dir, name)); err == nil && len(entries) != 0 {
			t.Fatalf("%s: refused run left files", name)
		}
	}
}

func TestEvidenceReattestKeygenNeverOverwrites(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	// Two runs into one directory both succeed with distinct key IDs and
	// leave the first run's files byte-identical.
	var first []byte
	var firstPath string
	for i := 0; i < 2; i++ {
		// keygen unsets the variable once it has read it.
		t.Setenv("KEYGEN_TEST_GOOD", keygenTestPassphrase)
		var stdout, stderr bytes.Buffer
		if err := run(keygenArgs(outDir, "--passphrase-env", "KEYGEN_TEST_GOOD"), &stdout, &stderr); err != nil {
			t.Fatalf("keygen %d: %v %s", i, err, stderr.String())
		}
		keyID, _ := parseKeygenOutput(stdout.String())
		path := filepath.Join(outDir, keyID+".key.pem")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first, firstPath = raw, path
			continue
		}
		if path == firstPath {
			t.Fatal("two runs produced the same key ID")
		}
		again, err := os.ReadFile(firstPath)
		if err != nil || !bytes.Equal(again, first) {
			t.Fatal("first key was modified")
		}
	}
	// A pre-existing file with an output name is never overwritten.
	if err := writeNewPrivate(firstPath, []byte("x")); err == nil {
		t.Fatal("writeNewPrivate overwrote an existing file")
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(firstPath, link); err != nil {
		t.Fatal(err)
	}
	if err := writeNewPrivate(link, []byte("x")); err == nil {
		t.Fatal("writeNewPrivate followed a symbolic link")
	}
}
