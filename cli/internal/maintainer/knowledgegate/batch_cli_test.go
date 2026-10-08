// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runBatchCommand runs an approval command with a key on standard input, a
// fixed review nonce and answer as what the owner types on the terminal.
func runBatchCommand(t *testing.T, key []byte, answer string, now time.Time, args ...string) approvalRun {
	t.Helper()
	var out, errOut bytes.Buffer
	env := approvalEnv{
		stdin: bytes.NewReader(key), now: func() time.Time { return now }, checkStdin: func(io.Reader) error { return nil },
		random: bytes.NewReader(bytes.Repeat([]byte{7}, batchNonceHexBytes)),
		confirm: func(string) (string, error) {
			if answer == "" {
				return "", errors.New("no terminal")
			}
			return answer, nil
		},
	}
	code := approvalMain(args, env, DefaultLayout(), &out, &errOut)
	return approvalRun{code, out.String(), errOut.String()}
}

func (f batchFixture) keysArgs(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return []string{"--keys", path, "--keys-digest", pinnedDigest(raw)}
}

func (f batchFixture) signBatchArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	args := []string{"sign", "--batch", "--base", f.base.Root, "--head", f.head.Root, "--batch-id", testBatchID, "--candidate-id", "pr-7", "--identity", "airstand", "--key-stdin"}
	return append(append(args, f.keysArgs(t)...), extra...)
}

func (f batchFixture) verifyBatchArgs(t *testing.T) []string {
	t.Helper()
	args := []string{"verify", "--batch", batchFilePath(f.head, testBatchID+".json"), "--base", f.base.Root, "--head", f.head.Root, "--now", gateNow.Format(time.RFC3339)}
	return append(args, f.keysArgs(t)...)
}

func requireRun(t *testing.T, r approvalRun, code int, want string) {
	t.Helper()
	if r.code != code || !strings.Contains(r.stdout+r.stderr, want) {
		t.Fatalf("code %d, want %d with %q\nstdout:\n%s\nstderr:\n%s", r.code, code, want, r.stdout, r.stderr)
	}
}

func TestBatchSignRoundTrip(t *testing.T) {
	f := newBatchFixture(t, 4)
	pemKey := f.key.pemKey(t)
	r := runBatchCommand(t, pemKey, testBatchID, signNow, f.signBatchArgs(t)...)
	requireRun(t, r, 0, "batch approval written")
	for _, want := range []string{"# Batch approval " + testBatchID, "## Entries to read in full (3)", "| sample"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("summary lacks %q:\n%s", want, r.stdout)
		}
	}
	for _, secret := range f.key.secretMarkers(t) {
		if strings.Contains(r.stdout+r.stderr, secret) {
			t.Fatal("the key was printed")
		}
	}
	// The gate admits the file the signer wrote.
	gate := runGate(t, Options{Base: f.base, Head: f.head})
	requirePass(t, gate)
	requireBatchProof(t, gate, f.ids)
	requireRun(t, runBatchCommand(t, nil, "", gateNow, f.verifyBatchArgs(t)...), 0, "batch OK")
	// Signing again never replaces the file.
	requireRun(t, runBatchCommand(t, pemKey, testBatchID, signNow, f.signBatchArgs(t)...), 2, "never replaced")
	// Once merged, the batch is spent: verify says so before the gate does.
	raw, err := os.ReadFile(batchFilePath(f.head, testBatchID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, f.base, "b-20261002-1.json", raw)
	f.write(t, f.head, "b-20261002-1.json", raw)
	requireRun(t, runBatchCommand(t, nil, "", gateNow, f.verifyBatchArgs(t)...), 1, "already in the base")
}

func TestBatchSignRefusals(t *testing.T) {
	t.Run("not confirmed", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), "b-20261003-2", signNow, f.signBatchArgs(t)...), 2, "not confirmed")
		if _, err := os.Stat(batchFilePath(f.head, testBatchID+".json")); err == nil {
			t.Fatal("a batch file was written without confirmation")
		}
	})
	t.Run("no terminal", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), "", signNow, f.signBatchArgs(t)...), 2, "no terminal")
	})
	t.Run("51 entries", func(t *testing.T) {
		f := newBatchFixture(t, MaxBatchEntries+1)
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t)...), 2, "at most 50")
	})
	t.Run("nothing to approve", func(t *testing.T) {
		f := newBatchFixture(t, 1)
		f.head = copyTree(t, f.base)
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t)...), 2, "no reviewed loosening change")
	})
	t.Run("a removal", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		gone := readPack(t, f.base, cncfRulesPath).activeReviewed()[10]
		editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
			for i, e := range p.entries {
				if ruleID(e) == gone {
					p.entries = append(p.entries[:i], p.entries[i+1:]...)
					break
				}
			}
		})
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t)...), 2, "is removed")
	})
	t.Run("empty base directory", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		args := f.signBatchArgs(t)
		args[3] = t.TempDir()
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, args...), 2, "holds no readable")
	})
	t.Run("validity over 72 hours", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t, "--valid-for", "73h")...), 2, "--valid-for")
	})
	t.Run("output elsewhere", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		out := filepath.Join(t.TempDir(), "approvals", testBatchID+".json")
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t, "--output", out)...), 2, "--output must end in batches/")
	})
	t.Run("bad batch id", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		args := f.signBatchArgs(t)
		args[7] = "batch-1"
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), "batch-1", signNow, args...), 2, "--batch-id must be")
	})
	t.Run("not an owner", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		args := f.signBatchArgs(t)
		args[11] = "someone"
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, args...), 2, "not an owner")
	})
}

func TestBatchVerifyRefusals(t *testing.T) {
	sign := func(t *testing.T) batchFixture {
		f := newBatchFixture(t, 3)
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t)...), 0, "batch approval written")
		return f
	}
	t.Run("entry added after signing", func(t *testing.T) {
		f := sign(t)
		renewRules(t, f.head, append(append([]string{}, f.ids...), readPack(t, f.base, cncfRulesPath).activeReviewed()[10]))
		requireRun(t, runBatchCommand(t, nil, "", gateNow, f.verifyBatchArgs(t)...), 1, "is not in the batch")
	})
	t.Run("another file changed", func(t *testing.T) {
		f := sign(t)
		writeFile(t, filepath.Join(f.head.Root, "cli", "docs", "note.md"), []byte("x\n"))
		requireRun(t, runBatchCommand(t, nil, "", gateNow, f.verifyBatchArgs(t)...), 1, "cli/docs/note.md")
	})
	t.Run("expired", func(t *testing.T) {
		f := sign(t)
		args := f.verifyBatchArgs(t)
		args[8] = signNow.Add(MaxBatchValidity).Format(time.RFC3339)
		requireRun(t, runBatchCommand(t, nil, "", gateNow, args...), 1, "expired at")
	})
	t.Run("empty base directory", func(t *testing.T) {
		f := sign(t)
		args := f.verifyBatchArgs(t)
		args[4] = t.TempDir()
		requireRun(t, runBatchCommand(t, nil, "", gateNow, args...), 2, "holds no readable")
	})
}
