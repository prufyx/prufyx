// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"errors"
	"fmt"
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
	r, _ := runBatchCommandPrompt(t, key, answer, now, args...)
	return r
}

// runBatchCommandPrompt also returns the prompt the owner was shown on the
// terminal ("" when none was).
func runBatchCommandPrompt(t *testing.T, key []byte, answer string, now time.Time, args ...string) (approvalRun, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	var prompt string
	env := approvalEnv{
		stdin: bytes.NewReader(key), now: func() time.Time { return now }, checkStdin: func(io.Reader) error { return nil },
		random: bytes.NewReader(bytes.Repeat([]byte{7}, batchNonceHexBytes)),
		confirm: func(p string) (string, error) {
			prompt = p
			if answer == "" {
				return "", errors.New("no terminal")
			}
			return answer, nil
		},
	}
	code := approvalMain(args, env, DefaultLayout(), &out, &errOut)
	return approvalRun{code, out.String(), errOut.String()}, prompt
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

// Everything the owner signs is shown before the batch id is asked for: who
// signs, with which key, for how long, how many entries, and which ones to
// read. The prompt goes to the terminal, so it holds whatever happens to
// standard output.
func TestBatchSignShowsWhatIsSignedBeforeAsking(t *testing.T) {
	f := newBatchFixture(t, 4)
	r, prompt := runBatchCommandPrompt(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t, "--valid-for", "48h")...)
	requireRun(t, r, 0, "batch approval written")
	for _, want := range []string{
		"Signer airstand", "key " + ApprovalKeyID(f.key.public),
		"Valid " + signNow.Format("2006-01-02T15:04:05Z") + " to " + signNow.Add(48*time.Hour).Format("2006-01-02T15:04:05Z") + " (48h0m0s)",
		"4 entries", "sample #", "flagged none", "0 other changes", "Type the batch id " + testBatchID,
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the prompt lacks %q:\n%s", want, prompt)
		}
	}
	// What was shown is what was signed.
	raw, err := os.ReadFile(batchFilePath(f.head, testBatchID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	env := mustDecodeBatch(raw)
	if env.KeyID != ApprovalKeyID(f.key.public) || env.Record.DecidedAt != signNow.Format("2006-01-02T15:04:05Z") || env.Record.NotAfter != signNow.Add(48*time.Hour).Format("2006-01-02T15:04:05Z") {
		t.Fatalf("signed %+v key %s", env.Record, env.KeyID)
	}
	if !strings.Contains(prompt, fmt.Sprintf("sample %s", indexList(env.Record.Sample))) {
		t.Fatalf("the prompt does not name the sample %v:\n%s", env.Record.Sample, prompt)
	}
}

// A signer that cannot sign is refused before the owner is asked anything.
func TestBatchSignRefusesBeforeAsking(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(args []string) []string
		want string
	}{
		"not an owner": {func(a []string) []string { a[11] = "someone"; return a }, "not an owner"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 2)
			r, prompt := runBatchCommandPrompt(t, f.key.pemKey(t), testBatchID, signNow, tc.edit(f.signBatchArgs(t))...)
			requireRun(t, r, 2, tc.want)
			if prompt != "" {
				t.Fatalf("asked: %s", prompt)
			}
		})
	}
	t.Run("expired key", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		f.key.pinUntil(t, f.base, signNow.Add(-time.Hour).Format(time.RFC3339), "airstand")
		f.key.pinUntil(t, f.head, signNow.Add(-time.Hour).Format(time.RFC3339), "airstand")
		r, prompt := runBatchCommandPrompt(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t)...)
		requireRun(t, r, 2, "expired at")
		if prompt != "" {
			t.Fatalf("asked: %s", prompt)
		}
	})
}

// The signer applies the changed-path allowlist the gate applies, before it
// draws a nonce or asks anything.
func TestBatchSignRefusesChangedPaths(t *testing.T) {
	for name, edit := range map[string]func(t *testing.T, f batchFixture){
		"documentation": func(t *testing.T, f batchFixture) {
			writeFile(t, filepath.Join(f.head.Root, "cli", "docs", "note.md"), []byte("x\n"))
		},
		"trust material": func(t *testing.T, f batchFixture) { newApprovalKey(t).pin(t, f.head, "airstand") },
		"a second batch file": func(t *testing.T, f batchFixture) {
			f.write(t, f.head, "b-20261003-2.json", []byte("{}\n"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 2)
			edit(t, f)
			random := &countingReader{}
			var out, errOut bytes.Buffer
			asked := false
			env := approvalEnv{
				stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return signNow }, checkStdin: func(io.Reader) error { return nil },
				random:  random,
				confirm: func(string) (string, error) { asked = true; return testBatchID, nil },
			}
			code := approvalMain(f.signBatchArgs(t), env, DefaultLayout(), &out, &errOut)
			if code != 2 || !strings.Contains(errOut.String()+out.String(), "may not touch") {
				t.Fatalf("code %d\n%s\n%s", code, out.String(), errOut.String())
			}
			if asked || random.n != 0 {
				t.Fatalf("asked %v, nonce bytes drawn %d", asked, random.n)
			}
			if _, err := os.Stat(batchFilePath(f.head, testBatchID+".json")); err == nil {
				t.Fatal("a batch file was written")
			}
		})
	}
}

type countingReader struct{ n int }

func (r *countingReader) Read(p []byte) (int, error) {
	r.n += len(p)
	for i := range p {
		p[i] = 7
	}
	return len(p), nil
}

// The batch directory is read with a bound; the signer does not add to one
// that is nearly full.
func TestBatchSignRefusesFullDirectory(t *testing.T) {
	f := newBatchFixture(t, 2)
	for _, tr := range []Tree{f.base, f.head} {
		dir := filepath.Dir(batchFilePath(tr, "x"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < maxBatchFiles-batchDirHeadroom; i++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("old-%d", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t)...), 2, "remove the batches that expired more than 14 days ago")
}

// --summary-out holds the summary the owner was shown, is created
// exclusively and is never written through a link.
func TestBatchSummaryOut(t *testing.T) {
	t.Run("written", func(t *testing.T) {
		f := newBatchFixture(t, 4)
		out := filepath.Join(t.TempDir(), "review", "summary.md")
		r := runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t, "--summary-out", out)...)
		requireRun(t, r, 0, "review summary written")
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(raw), "# Batch approval "+testBatchID) || !strings.Contains(r.stdout, string(raw)) {
			t.Fatalf("the file is not the summary printed:\n%s", raw)
		}
		env := mustDecodeBatch(mustRead(t, batchFilePath(f.head, testBatchID+".json")))
		if CandidateDigest(raw) != env.Record.SummaryDigest {
			t.Fatal("the file is not the summary whose digest was signed")
		}
	})
	t.Run("exists", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		out := filepath.Join(t.TempDir(), "summary.md")
		if err := os.WriteFile(out, []byte("mine"), 0o644); err != nil {
			t.Fatal(err)
		}
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t, "--summary-out", out)...), 2, "already exists")
		if string(mustRead(t, out)) != "mine" {
			t.Fatal("the file was overwritten")
		}
	})
	t.Run("symbolic link", func(t *testing.T) {
		f := newBatchFixture(t, 2)
		dir := t.TempDir()
		target := filepath.Join(dir, "target.md")
		if err := os.WriteFile(target, []byte("mine"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "summary.md")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("no symbolic links")
		}
		requireRun(t, runBatchCommand(t, f.key.pemKey(t), testBatchID, signNow, f.signBatchArgs(t, "--summary-out", link)...), 2, "already exists")
		if string(mustRead(t, target)) != "mine" {
			t.Fatal("written through the link")
		}
	})
	t.Run("link created after the check", func(t *testing.T) {
		// The writer itself refuses a link at the path (O_EXCL), whatever the
		// earlier check saw.
		dir := t.TempDir()
		target := filepath.Join(dir, "target.md")
		link := filepath.Join(dir, "summary.md")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("no symbolic links")
		}
		if err := writeApprovalFile(link, []byte("x")); err == nil {
			t.Fatal("wrote through a dangling link")
		}
		if _, err := os.Stat(target); err == nil {
			t.Fatal("the link target was created")
		}
	})
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
