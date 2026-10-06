// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every key in these tests is generated here, for the test only.

// signNow is the signer's clock in these tests: an hour before the gate's.
var signNow = gateNow.Add(-time.Hour)

// pemKey returns the key in PKCS #8 PEM form, as openssl writes it.
func (k testApprovalKey) pemKey(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k.private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// keyFile writes the key to a new file with mode perm and returns its path.
func (k testApprovalKey) keyFile(t *testing.T, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approval-key.pem")
	if err := os.WriteFile(path, k.pemKey(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// secretMarkers are strings of the key that must never be printed.
func (k testApprovalKey) secretMarkers(t *testing.T) []string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k.private)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	return []string{hex.EncodeToString(k.private.Seed()), b64[16:48], base64.StdEncoding.EncodeToString(k.private.Seed())[:24]}
}

type approvalRun struct {
	code           int
	stdout, stderr string
}

func runApproval(t *testing.T, stdin []byte, now time.Time, args ...string) approvalRun {
	t.Helper()
	var out, errOut bytes.Buffer
	env := approvalEnv{stdin: bytes.NewReader(stdin), now: func() time.Time { return now }, checkStdin: func(io.Reader) error { return nil }}
	code := approvalMain(args, env, DefaultLayout(), &out, &errOut)
	return approvalRun{code, out.String(), errOut.String()}
}

// signFixture is one proposed change with a pinned key, ready to sign.
type signFixture struct {
	base, head Tree
	id         string
	key        testApprovalKey
	keysDigest string
}

func (f signFixture) keysPath() string {
	return filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
}

func (f signFixture) out() string { return approvalPath(f.head, f.id) }

// subjectArgs are the flags naming the fixture's subject.
func (f signFixture) subjectArgs(rule string) []string {
	return []string{
		"--pack", "cncf", "--rule", rule,
		"--base-pack", filepath.Join(f.base.Root, filepath.FromSlash(cncfRulesPath)),
		"--head-pack", filepath.Join(f.head.Root, filepath.FromSlash(cncfRulesPath)),
		"--keys", f.keysPath(), "--keys-digest", f.keysDigest,
	}
}

func (f signFixture) signArgs(keyArgs ...string) []string {
	args := append([]string{"sign"}, f.subjectArgs(f.id)...)
	args = append(args, "--identity", "airstand", "--candidate-id", "pr-42", "--output", f.out())
	return append(args, keyArgs...)
}

func (f signFixture) verifyArgs(now string) []string {
	args := append([]string{"verify", "--approval", f.out()}, f.subjectArgs(f.id)...)
	if now != "" {
		args = append(args, "--now", now)
	}
	return args
}

func pinFixture(t *testing.T, base, head Tree, id string) signFixture {
	t.Helper()
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, "airstand")
	raw, err := os.ReadFile(filepath.Join(base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)))
	if err != nil {
		t.Fatal(err)
	}
	return signFixture{base: base, head: head, id: id, key: key, keysDigest: pinnedDigest(raw)}
}

// newRuleFixture proposes a new reviewed rule (base digest "absent").
func newRuleFixture(t *testing.T) signFixture {
	t.Helper()
	base, head, id, _ := approvalTrees(t)
	return pinFixture(t, base, head, id)
}

// changedRuleFixture extends the lease of an existing reviewed rule (base
// digest of the base entry).
func changedRuleFixture(t *testing.T) signFixture {
	t.Helper()
	base, head := trees(t)
	id := readPack(t, base, cncfRulesPath).activeReviewed()[0]
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		e := p.find(t, id)
		evidenceOf(e)["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
		evidenceOf(e)["validUntil"] = gateNow.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	})
	return pinFixture(t, base, head, id)
}

func requireCode(t *testing.T, r approvalRun, code int, want string) {
	t.Helper()
	if r.code != code || !strings.Contains(r.stdout+r.stderr, want) {
		t.Fatalf("exit %d, want %d with %q\nstdout: %s\nstderr: %s", r.code, code, want, r.stdout, r.stderr)
	}
}

// The round trip: an approval written by "approval sign" is accepted by
// the whole gate for a new rule and for a changed rule, read from a key
// file and from standard input, and "approval verify" accepts it too.
func TestApprovalSignRoundTripThroughGate(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) signFixture{"new rule": newRuleFixture, "changed rule": changedRuleFixture} {
		for _, src := range []string{"file", "stdin"} {
			t.Run(name+" key "+src, func(t *testing.T) {
				f := mk(t)
				var r approvalRun
				if src == "file" {
					r = runApproval(t, nil, signNow, f.signArgs("--key", f.key.keyFile(t, 0o600))...)
				} else {
					r = runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...)
				}
				requireCode(t, r, 0, "approval written")
				for _, m := range f.key.secretMarkers(t) {
					if strings.Contains(r.stdout+r.stderr, m) {
						t.Fatal("key material printed")
					}
				}
				report := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest})
				requirePass(t, report)
				if c := change(t, report, f.id); c.Proof != ProofApproval {
					t.Fatalf("proof %q, want %q", c.Proof, ProofApproval)
				}
				requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs("")...), 0, "approval OK")
			})
		}
	}
}

// The file the signer writes is byte for byte the one the gate's own test
// signer builds from the same record: the format is the gate's.
func TestApprovalSignBytesMatchGateFormat(t *testing.T) {
	f := changedRuleFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
	got, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	cls, err := Classify(DefaultLayout(), f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	want := f.key.sign(t, ApprovalRecord{
		BaseDigest:      CandidateDigest(cls.base["cncf"].Entries[f.id].Canonical),
		CandidateDigest: CandidateDigest(cls.head["cncf"].Entries[f.id].Canonical),
		CandidateID:     "pr-42", DecidedAt: signNow.Format(time.RFC3339), Decision: "approve",
		Identity: "airstand", Pack: "cncf", RuleID: f.id,
	})
	if !bytes.Equal(got, want) {
		t.Fatalf("signer output differs from the gate's format:\n%s\nwant:\n%s", got, want)
	}
}

// Changing any signed field, the key id, the signature or the schema of a
// signed approval makes both "approval verify" and the gate refuse it.
func TestApprovalSignTamperRefused(t *testing.T) {
	f := changedRuleFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
	signed, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	var env ApprovalEnvelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	other := "sha256:" + strings.Repeat("ab", 32)
	otherSig := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize))
	cases := map[string]func(e *ApprovalEnvelope){
		"baseDigest":      func(e *ApprovalEnvelope) { e.Record.BaseDigest = ApprovalBaseAbsent },
		"candidateDigest": func(e *ApprovalEnvelope) { e.Record.CandidateDigest = other },
		"candidateId":     func(e *ApprovalEnvelope) { e.Record.CandidateID = "pr-43" },
		"decidedAt":       func(e *ApprovalEnvelope) { e.Record.DecidedAt = signNow.Add(time.Second).Format(time.RFC3339) },
		"decision":        func(e *ApprovalEnvelope) { e.Record.Decision = "reject" },
		"identity":        func(e *ApprovalEnvelope) { e.Record.Identity = "airstand2" },
		"pack":            func(e *ApprovalEnvelope) { e.Record.Pack = "community" },
		"ruleId":          func(e *ApprovalEnvelope) { e.Record.RuleID = f.id + "x" },
		"keyId":           func(e *ApprovalEnvelope) { e.KeyID = other },
		"signature":       func(e *ApprovalEnvelope) { e.Signature = otherSig },
		"schema":          func(e *ApprovalEnvelope) { e.Schema = "prufyx.io/knowledge-approval/v1" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			e := env
			mut(&e)
			raw, err := json.MarshalIndent(e, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.out(), append(raw, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs("")...), 1, "approval REFUSED")
			report := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest})
			if c := change(t, report, f.id); c.OK {
				t.Fatalf("the gate admitted a tampered %s", name)
			}
		})
	}
	// The untampered file is still accepted (the loop changed only copies).
	if err := os.WriteFile(f.out(), signed, 0o644); err != nil {
		t.Fatal(err)
	}
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs("")...), 0, "approval OK")
}

// A change to the proposed or the base entry after signing invalidates the
// approval.
func TestApprovalSignEntryChangedAfterSigning(t *testing.T) {
	f := changedRuleFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
	editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, f.id))["validUntil"] = gateNow.Add(61 * 24 * time.Hour).Format(time.RFC3339)
	})
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs("")...), 1, "candidate digest does not match")

	g := changedRuleFixture(t)
	requireCode(t, runApproval(t, g.key.pemKey(t), signNow, g.signArgs("--key-stdin")...), 0, "approval written")
	editPack(t, g.base, cncfRulesPath, func(p *packDoc) {
		ruleOf(p.find(t, g.id))["nextAction"] = "Changed in the base."
	})
	requireCode(t, runApproval(t, nil, gateNow, g.verifyArgs("")...), 1, "base digest does not match")
}

func TestApprovalSignWrongKey(t *testing.T) {
	f := newRuleFixture(t)
	stranger := newApprovalKey(t)
	// Signing with a key that is not pinned is refused before anything is
	// written.
	r := runApproval(t, stranger.pemKey(t), signNow, f.signArgs("--key-stdin")...)
	requireCode(t, r, 2, "is not pinned")
	if _, err := os.Lstat(f.out()); !os.IsNotExist(err) {
		t.Fatal("an approval was written")
	}
	// An approval by the pinned key is refused when the base pins another
	// key instead.
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
	stranger.pin(t, f.base, "airstand")
	raw, err := os.ReadFile(f.keysPath())
	if err != nil {
		t.Fatal(err)
	}
	f.keysDigest = pinnedDigest(raw)
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs("")...), 1, "signed by a key that is not pinned")
	report := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest})
	requireFail(t, report, "signed by a key that is not pinned")
}

func TestApprovalSignKeyAndOwnerChecks(t *testing.T) {
	t.Run("expired key", func(t *testing.T) {
		f := newRuleFixture(t)
		f.key.pinUntil(t, f.base, signNow.Add(-time.Second).Format(time.RFC3339), "airstand")
		raw, _ := os.ReadFile(f.keysPath())
		f.keysDigest = pinnedDigest(raw)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "expired")
	})
	t.Run("not an owner", func(t *testing.T) {
		f := newRuleFixture(t)
		args := f.signArgs("--key-stdin")
		for i := range args {
			if args[i] == "airstand" && args[i-1] == "--identity" {
				args[i] = "someone-else"
			}
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "is not an owner")
	})
	t.Run("key file digest mismatch", func(t *testing.T) {
		f := newRuleFixture(t)
		f.keysDigest = "sha256:" + strings.Repeat("0", 64)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "does not match the pinned digest")
	})
	t.Run("output exists", func(t *testing.T) {
		f := newRuleFixture(t)
		writeFile(t, f.out(), []byte("keep me\n"))
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "already exists")
		if raw, _ := os.ReadFile(f.out()); string(raw) != "keep me\n" {
			t.Fatal("existing file replaced")
		}
	})
	t.Run("output is a link", func(t *testing.T) {
		f := newRuleFixture(t)
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.MkdirAll(filepath.Dir(f.out()), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, f.out()); err != nil {
			t.Fatal(err)
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "already exists")
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatal("written through a link")
		}
	})
}

// An approval is accepted from its decision time (with the gate's five
// minutes of skew) until 14 days later, and refused outside that window.
func TestApprovalSignDecidedAtWindow(t *testing.T) {
	f := newRuleFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
	at := func(d time.Duration) string { return signNow.Add(d).Format(time.RFC3339) }
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(at(MaxApprovalAge))...), 0, "approval OK")
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(at(MaxApprovalAge+time.Second))...), 1, "older than 14 days")
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(at(-approvalClockSkew))...), 0, "approval OK")
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(at(-approvalClockSkew-time.Second))...), 1, "decided in the future")
	// The gate agrees at the same clocks.
	requireFail(t, runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest, Now: signNow.Add(MaxApprovalAge + time.Second)}), "older than 14 days")
	requireFail(t, runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest, Now: signNow.Add(-approvalClockSkew - time.Second)}), "decided in the future")
}

func TestApprovalSignSubjectRefusals(t *testing.T) {
	t.Run("unsupported subject kind", func(t *testing.T) {
		f := newRuleFixture(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, append(f.signArgs("--key-stdin"), "--subject", "pathPolicy")...), 2, "not supported")
		if _, _, err := SignApproval(SignApprovalOptions{Subject: ApprovalSubject{Kind: "pathPolicy"}}); err == nil {
			t.Fatal("unsupported subject kind signed")
		}
	})
	t.Run("mechanical rule", func(t *testing.T) {
		base, head, entries := mechanicalTrees(t, func(entries []map[string]any) { ruleOf(entries[0])["nextAction"] = "Changed." })
		f := pinFixture(t, base, head, ruleID(entries[0]))
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "admits only a reviewed rule")
	})
	t.Run("rule not in the proposed pack", func(t *testing.T) {
		f := newRuleFixture(t)
		f.id = "no.such.rule"
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "has no rule no.such.rule")
	})
	t.Run("unchanged rule", func(t *testing.T) {
		f := newRuleFixture(t)
		f.id = readPack(t, f.base, cncfRulesPath).activeReviewed()[1]
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "nothing to approve")
	})
	t.Run("rule id outside the record alphabet", func(t *testing.T) {
		f := newRuleFixture(t)
		f.id = "bad id"
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "not a valid approval rule id")
	})
	t.Run("duplicate subject in the proposed pack", func(t *testing.T) {
		f := newRuleFixture(t)
		p := readPack(t, f.head, cncfRulesPath)
		p.entries = append(p.entries, deepCopy(p.find(t, f.id)).(map[string]any))
		p.write(t, f.head, cncfRulesPath)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "appears twice")
	})
	t.Run("duplicate subject in the base pack", func(t *testing.T) {
		f := changedRuleFixture(t)
		p := readPack(t, f.base, cncfRulesPath)
		p.entries = append(p.entries, deepCopy(p.find(t, f.id)).(map[string]any))
		p.write(t, f.base, cncfRulesPath)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "appears twice")
	})
	t.Run("subject named twice", func(t *testing.T) {
		f := newRuleFixture(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, append(f.signArgs("--key-stdin"), "--rule", f.id)...), 2, "given twice")
	})
	t.Run("approval for another rule", func(t *testing.T) {
		f := changedRuleFixture(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
		other := readPack(t, f.base, cncfRulesPath).activeReviewed()[1]
		editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
			ruleOf(p.find(t, other))["nextAction"] = "Changed."
		})
		args := append([]string{"verify", "--approval", f.out()}, f.subjectArgs(other)...)
		requireCode(t, runApproval(t, nil, gateNow, args...), 1, "approves a different rule")
	})
}

// The key file must be the file itself (no link anywhere in its path, one
// hard link), owned by the user, with no group or other permission.
func TestApprovalSignKeyFileRefusals(t *testing.T) {
	f := newRuleFixture(t)
	for _, perm := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o602, 0o620, 0o610, 0o601, 0o666, os.ModeSetuid | 0o600, os.ModeSetgid | 0o600, os.ModeSticky | 0o600} {
		path := f.key.keyFile(t, perm)
		r := runApproval(t, nil, signNow, f.signArgs("--key", path)...)
		if r.code != 2 || !strings.Contains(r.stderr, "group or others") {
			t.Fatalf("mode %#o: exit %d %s", perm, r.code, r.stderr)
		}
	}
	for _, perm := range []os.FileMode{0o600, 0o400} {
		g := newRuleFixture(t)
		requireCode(t, runApproval(t, nil, signNow, g.signArgs("--key", g.key.keyFile(t, perm))...), 0, "approval written")
	}

	good := f.key.keyFile(t, 0o600)
	link := filepath.Join(t.TempDir(), "link.pem")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", link)...), 2, "the key file is a symbolic link")

	linkedDir := filepath.Join(t.TempDir(), "keys")
	if err := os.Symlink(filepath.Dir(good), linkedDir); err != nil {
		t.Fatal(err)
	}
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", filepath.Join(linkedDir, filepath.Base(good)))...), 2, "cannot be read")

	hard := filepath.Join(filepath.Dir(good), "hard.pem")
	if err := os.Link(good, hard); err != nil {
		t.Fatal(err)
	}
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", hard)...), 2, "one link")

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", dir)...), 2, "cannot be read")
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", filepath.Join(dir, "missing.pem"))...), 2, "cannot be read")

	if _, err := os.Lstat(f.out()); !os.IsNotExist(err) {
		t.Fatal("an approval was written from a refused key")
	}
}

// A key on standard input may end with line breaks (as echo, a password
// manager or a file usually leave it) and nothing else, and is never read
// from a terminal.
func TestApprovalSignKeyStdin(t *testing.T) {
	key := newApprovalKey(t)
	block := bytes.TrimRight(key.pemKey(t), "\n")
	for name, suffix := range map[string]string{"no newline": "", "newline": "\n", "CRLF": "\r\n", "two newlines": "\n\n"} {
		t.Run(name, func(t *testing.T) {
			f := newRuleFixture(t)
			key.pinBoth(t, f.base, f.head, "airstand")
			raw, _ := os.ReadFile(f.keysPath())
			f.keysDigest = pinnedDigest(raw)
			requireCode(t, runApproval(t, append(append([]byte(nil), block...), suffix...), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
			var env ApprovalEnvelope
			got, _ := os.ReadFile(f.out())
			if err := json.Unmarshal(got, &env); err != nil || env.KeyID != ApprovalKeyID(key.public) {
				t.Fatalf("key id %q", env.KeyID)
			}
		})
	}
	crlf := bytes.ReplaceAll(key.pemKey(t), []byte("\n"), []byte("\r\n"))
	refused := map[string][]byte{
		"trailing text":   append(append([]byte(nil), key.pemKey(t)...), "x"...),
		"trailing space":  append(append([]byte(nil), block...), " \n"...),
		"leading newline": append([]byte("\n"), key.pemKey(t)...),
		"leading text":    append([]byte("key:\n"), key.pemKey(t)...),
		"two keys":        append(key.pemKey(t), newApprovalKey(t).pemKey(t)...),
		"empty":           nil,
		"raw seed":        []byte(hex.EncodeToString(key.private.Seed()) + "\n"),
		"wrong type":      bytes.ReplaceAll(key.pemKey(t), []byte("PRIVATE KEY"), []byte("PUBLIC KEY")),
		"oversized":       append(key.pemKey(t), bytes.Repeat([]byte("\n"), MaxApprovalKeyBytes)...),
		"pem header":      bytes.Replace(key.pemKey(t), []byte("-----\n"), []byte("-----\nProc-Type: 4,ENCRYPTED\n\n"), 1),
		"corrupt body":    bytes.Replace(key.pemKey(t), block[40:44], []byte("!!!!"), 1),
	}
	for name, in := range refused {
		t.Run("refused "+name, func(t *testing.T) {
			f := newRuleFixture(t)
			key.pinBoth(t, f.base, f.head, "airstand")
			raw, _ := os.ReadFile(f.keysPath())
			f.keysDigest = pinnedDigest(raw)
			r := runApproval(t, in, signNow, f.signArgs("--key-stdin")...)
			requireCode(t, r, 2, "PKCS #8 PEM")
			for _, m := range key.secretMarkers(t) {
				if strings.Contains(r.stdout+r.stderr, m) {
					t.Fatal("key material printed")
				}
			}
		})
	}
	t.Run("CRLF throughout", func(t *testing.T) {
		if _, err := ParseApprovalPrivateKey(crlf); err != nil {
			t.Fatalf("CRLF key refused: %v", err)
		}
	})
	t.Run("standard input refused", func(t *testing.T) {
		f := newRuleFixture(t)
		var out, errOut bytes.Buffer
		env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return signNow }, checkStdin: func(io.Reader) error { return errors.New("not a pipe") }}
		if code := approvalMain(f.signArgs("--key-stdin"), env, DefaultLayout(), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "not a pipe") {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
	})
	t.Run("both or neither key source", func(t *testing.T) {
		f := newRuleFixture(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin", "--key", f.key.keyFile(t, 0o600))...), 2, "exactly one of")
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs()...), 2, "exactly one of")
	})
}

func TestApprovalPublicKeyAndKeysDigest(t *testing.T) {
	f := newRuleFixture(t)
	r := runApproval(t, nil, signNow, "public-key", "--key", f.key.keyFile(t, 0o600))
	requireCode(t, r, 0, ApprovalKeyID(f.key.public))
	if !strings.Contains(r.stdout, hex.EncodeToString(f.key.public)) {
		t.Fatalf("public key missing: %s", r.stdout)
	}
	for _, m := range f.key.secretMarkers(t) {
		if strings.Contains(r.stdout+r.stderr, m) {
			t.Fatal("key material printed")
		}
	}
	requireCode(t, runApproval(t, nil, signNow, "public-key", "--key", f.key.keyFile(t, 0o640)), 2, "group or others")
	requireCode(t, runApproval(t, nil, signNow, "keys-digest", "--keys", f.keysPath()), 0, f.keysDigest)
	bad := filepath.Join(t.TempDir(), "keys.json")
	writeFile(t, bad, []byte(`{"schema":"prufyx.io/web-approval-keys/v1","role":"human","owners":["a"],"keys":[]}`))
	requireCode(t, runApproval(t, nil, signNow, "keys-digest", "--keys", bad), 2, "wrong schema")
}

// The digest "approval keys-digest" prints for a key file is the one the
// gate pins: sha256 of the file without one final newline (not what
// sha256sum prints for a file that ends in a newline). Checked against an
// independent computation, for the endings editors and tools write, through
// the whole gate.
func TestApprovalKeysDigestOfNewlineTerminatedFile(t *testing.T) {
	for name, ending := range map[string]string{"LF": "\n", "two LF": "\n\n", "CRLF": "\r\n"} {
		t.Run(name, func(t *testing.T) {
			f := newRuleFixture(t)
			raw, err := os.ReadFile(f.keysPath())
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, ending...)
			for _, tr := range []Tree{f.base, f.head} {
				writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)), raw)
			}
			pinned := sha256.Sum256(bytes.TrimSuffix(raw, []byte("\n")))
			want := "sha256:" + hex.EncodeToString(pinned[:])
			whole := sha256.Sum256(raw)
			if want == "sha256:"+hex.EncodeToString(whole[:]) {
				t.Fatal("test file does not end in a newline")
			}
			r := runApproval(t, nil, signNow, "keys-digest", "--keys", f.keysPath())
			if r.code != 0 || r.stdout != want+"\n" {
				t.Fatalf("keys-digest printed %q (exit %d), want %s", r.stdout, r.code, want)
			}
			f.keysDigest = strings.TrimSpace(r.stdout)
			requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 0, "approval written")
			report := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest})
			requirePass(t, report)
			if c := change(t, report, f.id); c.Proof != ProofApproval {
				t.Fatalf("proof %q", c.Proof)
			}
			// What sha256sum prints is not the pinned digest.
			requireFail(t, runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: "sha256:" + hex.EncodeToString(whole[:])}), "does not match the pinned digest")
		})
	}
}

// A change the gate classifies as tightening needs no approval; the signer
// refuses it instead of writing a file the gate's records check would fail.
func TestApprovalSignRefusesTightening(t *testing.T) {
	for name, edit := range map[string]func(e map[string]any){
		"withdrawn": func(e map[string]any) { evidenceOf(e)["state"] = "withdrawn" },
		"earlier lease end": func(e map[string]any) {
			evidenceOf(e)["validUntil"] = shiftTime(t, evidenceOf(e)["validUntil"], -24*time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			id := readPack(t, base, cncfRulesPath).activeReviewed()[0]
			editPack(t, head, cncfRulesPath, func(p *packDoc) { edit(p.find(t, id)) })
			f := pinFixture(t, base, head, id)
			requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "not loosening")
			if _, err := os.Lstat(f.out()); !os.IsNotExist(err) {
				t.Fatal("an approval was written")
			}
		})
	}
	t.Run("new rule added withdrawn", func(t *testing.T) {
		f := newRuleFixture(t)
		editPack(t, f.head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, f.id))["state"] = "withdrawn" })
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs("--key-stdin")...), 2, "not loosening")
	})
}

func TestApprovalSignOutputName(t *testing.T) {
	f := newRuleFixture(t)
	for _, out := range []string{
		filepath.Join(t.TempDir(), "approval.json"),
		filepath.Join(t.TempDir(), "community", f.id+".json"),
		filepath.Join(t.TempDir(), "cncf", "other.json"),
	} {
		args := f.signArgs("--key-stdin")
		args[len(args)-2] = out
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "--output must end in cncf/"+f.id+".json")
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Fatalf("%s written", out)
		}
	}
}

// Help prints the usage on standard output and exits 0; a refused command
// line prints the reason and then the usage, line by line.
func TestApprovalHelpAndUsage(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"sign", "--help"}, {"sign", "-h"}, {"verify", "--help"}, {"public-key", "-help"}, {"keys-digest", "--help"}} {
		r := runApproval(t, nil, signNow, args...)
		if r.code != 0 || !strings.HasPrefix(r.stdout, "usage: prufyx-maintainer approval") || !strings.Contains(r.stdout, "\n  verify ") || r.stderr != "" {
			t.Fatalf("%v: exit %d stdout %q stderr %q", args, r.code, r.stdout, r.stderr)
		}
	}
	for args, want := range map[string]string{
		"sign":                            "approval: --identity, --candidate-id and --output are required\nusage: prufyx-maintainer approval",
		"keys-digest":                     "approval: --keys is required\nusage:",
		"keys-digest --keys k.json extra": "approval: unexpected argument extra\nusage:",
		"verify --approval a.json more":   "approval: unexpected argument more\nusage:",
		"sign --nope":                     "approval: flag provided but not defined: -nope\nusage:",
	} {
		r := runApproval(t, nil, signNow, strings.Fields(args)...)
		if r.code != 2 || !strings.HasPrefix(r.stderr, want) || strings.Contains(r.stderr, "%0A") || !strings.Contains(r.stderr, "\n  keys-digest --keys FILE") {
			t.Fatalf("%s: exit %d stderr %q", args, r.code, r.stderr)
		}
	}
}
