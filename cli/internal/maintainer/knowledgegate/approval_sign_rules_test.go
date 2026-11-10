// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every key is generated here; no key file outside the test is read.

// rulesFixture proposes n new reviewed rules and pins a key.
type rulesFixture struct {
	signFixture
	ids       []string
	rulesFile string
	outDir    string
	// identity and candidate are the signer's flags; keyID the key id the
	// owner expects (the fixture key's).
	identity, candidate, keyID string
}

func newRulesFixture(t *testing.T, n int) rulesFixture {
	t.Helper()
	base, head := trees(t)
	src := readPack(t, base, cncfRulesPath).activeReviewed()[0]
	var ids []string
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		for i := 0; i < n; i++ {
			added := deepCopy(p.find(t, src)).(map[string]any)
			id := src + "-batch-" + string(rune('a'+i))
			ruleOf(added)["id"] = id
			evidenceOf(added)["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
			evidenceOf(added)["validUntil"] = gateNow.Add(time.Duration(60+i) * 24 * time.Hour).Format(time.RFC3339)
			p.entries = append(p.entries, added)
			ids = append(ids, id)
		}
		p.sortByID()
	})
	f := pinFixture(t, base, head, ids[0])
	// The approvals directory is in the repository; the pack's may be new.
	if err := os.MkdirAll(filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().ApprovalDir)), 0o755); err != nil {
		t.Fatal(err)
	}
	rf := filepath.Join(t.TempDir(), "rules.txt")
	writeFile(t, rf, []byte(strings.Join(ids, "\n")+"\n"))
	return rulesFixture{signFixture: f, ids: ids, rulesFile: rf, outDir: filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), "cncf"),
		identity: "airstand", candidate: "pr-42", keyID: ApprovalKeyID(f.key.public)}
}

func (f rulesFixture) packArgs() []string {
	return []string{"--pack", "cncf", "--rules-file", f.rulesFile,
		"--base-pack", filepath.Join(f.base.Root, filepath.FromSlash(cncfRulesPath)),
		"--head-pack", filepath.Join(f.head.Root, filepath.FromSlash(cncfRulesPath)),
		"--identity", f.identity, "--candidate-id", f.candidate, "--key-id", f.keyID}
}

func (f rulesFixture) signArgs2(extra ...string) []string {
	args := append([]string{"sign"}, f.packArgs()...)
	args = append(args, "--keys", f.keysPath(), "--keys-digest", f.keysDigest, "--output-dir", f.outDir)
	return append(args, extra...)
}

// listDigest runs the dry run and returns the digest it prints.
func (f rulesFixture) listDigest(t *testing.T) string {
	t.Helper()
	r := runApproval(t, nil, signNow, append([]string{"sign", "--dry-run"}, f.packArgs()...)...)
	requireCode(t, r, 0, "dry run")
	for _, l := range strings.Split(r.stdout, "\n") {
		if d, ok := strings.CutPrefix(l, "list digest: "); ok {
			return d
		}
	}
	t.Fatal("no list digest printed")
	return ""
}

func noFiles(t *testing.T, f rulesFixture) {
	t.Helper()
	for _, id := range f.ids {
		if _, err := os.Lstat(filepath.Join(f.outDir, id+".json")); !os.IsNotExist(err) {
			t.Fatalf("an approval was written for %s", id)
		}
	}
	ents, _ := os.ReadDir(filepath.Dir(f.outDir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".approval-stage-") {
			t.Fatal("staging directory left behind")
		}
	}
}

func expectArgs(f rulesFixture, t *testing.T) []string {
	return []string{"--expect-count", "3", "--expect-list-digest", f.listDigest(t)}
}

func TestApprovalSignRulesRoundTripAndSameBytesAsSingle(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 3)
	r := runApproval(t, f.key.pemKey(t), signNow, f.signArgs2(append(expectArgs(f, t), "--key-stdin")...)...)
	requireCode(t, r, 0, "approvals written: 3")
	for _, m := range f.key.secretMarkers(t) {
		if strings.Contains(r.stdout+r.stderr, m) {
			t.Fatal("key material printed")
		}
	}
	requirePass(t, runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest}))
	// The same rule signed alone, at the same time, gives the same bytes.
	for _, id := range f.ids {
		batch, err := os.ReadFile(filepath.Join(f.outDir, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		single := filepath.Join(t.TempDir(), "cncf", id+".json")
		args := append([]string{"sign"}, f.subjectArgs(id)...)
		args = append(args, "--identity", "airstand", "--candidate-id", "pr-42", "--output", single, "--key-stdin")
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 0, "approval written")
		want, _ := os.ReadFile(single)
		if !bytes.Equal(batch, want) {
			t.Fatalf("batch record for %s differs from the single-rule record", id)
		}
		info, _ := os.Stat(filepath.Join(f.outDir, id+".json"))
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("mode %v", info.Mode())
		}
	}
	// Same expiry: 14 days from decidedAt, as printed for a single record.
	if !strings.Contains(r.stdout, "accepted until "+signNow.Add(MaxApprovalAge).UTC().Format(time.RFC3339)) {
		t.Fatalf("expiry not the single-rule one:\n%s", r.stdout)
	}
}

func TestApprovalSignRulesExistingDirectory(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 3)
	other := filepath.Join(f.outDir, "keep.json")
	writeFile(t, other, []byte("x"))
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2(append(expectArgs(f, t), "--key-stdin")...)...), 0, "approvals written: 3")
	if _, err := os.Stat(other); err != nil {
		t.Fatal(err)
	}
	requirePassFiles(t, f)
}

func requirePassFiles(t *testing.T, f rulesFixture) {
	t.Helper()
	for _, id := range f.ids {
		if _, err := os.Stat(filepath.Join(f.outDir, id+".json")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApprovalSignRulesDryRunReadsNoKey(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 3)
	missing := filepath.Join(t.TempDir(), "no-such-key.pem")
	// The key path is not even accepted with --dry-run.
	args := append(append([]string{"sign", "--dry-run"}, f.packArgs()...), "--key", missing)
	requireCode(t, runApproval(t, nil, signNow, args...), 2, "reads no key")
	r := runApproval(t, nil, signNow, append([]string{"sign", "--dry-run"}, f.packArgs()...)...)
	requireCode(t, r, 0, "rules to approve: 3")
	if !strings.Contains(r.stdout, "base absent") || !strings.Contains(r.stdout, "list digest: sha256:") {
		t.Fatal(r.stdout)
	}
	noFiles(t, f)
	// Stable, and independent of the order in the rules file.
	d1 := f.listDigest(t)
	rev := []string{f.ids[2], f.ids[0], f.ids[1]}
	writeFile(t, f.rulesFile, []byte(strings.Join(rev, "\n")))
	if d2 := f.listDigest(t); d1 != d2 {
		t.Fatal("digest depends on file order")
	}
}

func TestApprovalSignRulesRefusals(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 3)
	key := f.key.pemKey(t)
	good := f.listDigest(t)
	flip := good[:len(good)-1] + map[bool]string{true: "1", false: "0"}[good[len(good)-1] == '0']
	cases := map[string]struct {
		extra []string
		want  string
	}{
		"count mismatch":    {[]string{"--expect-count", "2", "--expect-list-digest", good}, "--expect-count is 2"},
		"digest mismatch":   {[]string{"--expect-count", "3", "--expect-list-digest", flip}, "does not match"},
		"count only":        {[]string{"--expect-count", "3"}, "both --expect-count"},
		"digest only":       {[]string{"--expect-list-digest", good}, "both --expect-count"},
		"no confirm source": {nil, "confirmation"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runApproval(t, key, signNow, f.signArgs2(append(c.extra, "--key-stdin")...)...)
			requireCode(t, r, 2, c.want)
			noFiles(t, f)
		})
	}
	t.Run("key not read before confirmation", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.pem")
		r := runApproval(t, nil, signNow, f.signArgs2("--expect-count", "2", "--expect-list-digest", good, "--key", missing)...)
		requireCode(t, r, 2, "--expect-count is 2")
		if strings.Contains(r.stderr, "absent.pem") {
			t.Fatal("the key file was touched")
		}
	})
	t.Run("changed set", func(t *testing.T) {
		// A digest from a list of two rules does not sign a list of three.
		writeFile(t, f.rulesFile, []byte(strings.Join(f.ids[:2], "\n")))
		two := f.listDigest(t)
		writeFile(t, f.rulesFile, []byte(strings.Join(f.ids, "\n")))
		requireCode(t, runApproval(t, key, signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", two, "--key-stdin")...), 2, "does not match")
		noFiles(t, f)
	})
}

func TestApprovalSignRulesTerminalConfirmation(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 3)
	run := func(answer string) approvalRun {
		var out, errOut bytes.Buffer
		env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return signNow }, checkStdin: func(io.Reader) error { return nil },
			confirm: func(string) (string, error) { return answer, nil }}
		code := approvalMain(f.signArgs2("--key-stdin"), env, DefaultLayout(), &out, &errOut)
		return approvalRun{code, out.String(), errOut.String()}
	}
	d := strings.TrimPrefix(f.listDigest(t), "sha256:")
	for _, bad := range []string{"", "yes", "sign 3", "sign 2 " + d, "sign 3 " + d[:12], "sign 3 " + d[:32], "sign 3 " + d[:63], "sign 3 " + strings.Repeat("0", 64), "sign 3 sha256:" + d} {
		requireCode(t, run(bad), 2, "does not match")
		noFiles(t, f)
	}
	requireCode(t, run("sign 3 "+d), 0, "approvals written: 3")
}

func TestApprovalSignRulesAllOrNothing(t *testing.T) {
	t.Parallel()
	t.Run("a rule that is not loosening", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		editPack(t, f.head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, f.ids[1]))["state"] = "withdrawn" })
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", "sha256:"+strings.Repeat("0", 64), "--key-stdin")...), 2, "not loosening")
		noFiles(t, f)
	})
	t.Run("a rule the head lacks", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		writeFile(t, f.rulesFile, []byte(strings.Join(append(f.ids, "no-such-rule"), "\n")))
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "4", "--expect-list-digest", "sha256:"+strings.Repeat("0", 64), "--key-stdin")...), 2, "has no rule")
		noFiles(t, f)
	})
	t.Run("an existing approval file", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		writeFile(t, filepath.Join(f.outDir, f.ids[2]+".json"), []byte("old"))
		d := f.listDigest(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...), 2, "already exists")
		for _, id := range f.ids[:2] {
			if _, err := os.Lstat(filepath.Join(f.outDir, id+".json")); !os.IsNotExist(err) {
				t.Fatal("partial write")
			}
		}
	})
	t.Run("signer refused for every rule", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		d := f.listDigest(t)
		other := newApprovalKey(t)
		r := runApproval(t, other.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...)
		requireCode(t, r, 2, "does not match --key-id")
		noFiles(t, f)
		r = runApproval(t, f.key.pemKey(t), signNow, append(f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin"), []string{}...)...)
		requireCode(t, r, 0, "approvals written")
	})
	t.Run("wrong identity", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		f.identity = "someone-else"
		d := f.listDigest(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...), 2, "not an owner")
		noFiles(t, f)
	})
	t.Run("key id not the one expected", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		other := newApprovalKey(t)
		f.keyID = ApprovalKeyID(other.public) // not pinned
		d := f.listDigest(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...), 2, "not pinned")
		noFiles(t, f)
		// Pinned id, but the key supplied is another one: abort before signing.
		f = newRulesFixture(t, 3)
		d = f.listDigest(t)
		r := runApproval(t, other.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...)
		requireCode(t, r, 2, "does not match --key-id")
		noFiles(t, f)
	})
	t.Run("write failure rolls back", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		raws := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		// A directory where the third file must go: the link fails.
		if err := os.MkdirAll(filepath.Join(f.outDir, f.ids[2]+".json"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeApprovalFiles(f.outDir, f.ids, raws); err == nil {
			t.Fatal("expected an error")
		}
		for _, id := range f.ids[:2] {
			if _, err := os.Lstat(filepath.Join(f.outDir, id+".json")); !os.IsNotExist(err) {
				t.Fatal("not rolled back")
			}
		}
		ents, _ := os.ReadDir(filepath.Dir(f.outDir))
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".approval-stage-") {
				t.Fatal("staging left")
			}
		}
	})
}

func TestApprovalSignRulesInputRefusals(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 2)
	for name, c := range map[string]struct{ content, want string }{
		"empty": {"\n\n", "names no rule"}, "duplicate": {f.ids[0] + "\n" + f.ids[0], "twice"}, "bad id": {"../x", "not a valid rule id"}, "comment": {"# " + f.ids[0], "not a valid rule id"},
		"too many": {manyIDs(MaxRulesPerSigning + 1), "more than the 64"},
	} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, f.rulesFile, []byte(c.content))
			requireCode(t, runApproval(t, nil, signNow, append([]string{"sign", "--dry-run"}, f.packArgs()...)...), 2, c.want)
		})
	}
	t.Run("output dir name", func(t *testing.T) {
		writeFile(t, f.rulesFile, []byte(strings.Join(f.ids, "\n")))
		args := f.signArgs2("--expect-count", "2", "--expect-list-digest", f.listDigest(t), "--key-stdin")
		for i, a := range args {
			if a == f.outDir {
				args[i] = filepath.Join(f.head.Root, "elsewhere")
			}
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "--output-dir must end in cncf")
	})
	t.Run("single-rule flags mixed in", func(t *testing.T) {
		requireCode(t, runApproval(t, nil, signNow, append(append([]string{"sign", "--dry-run"}, f.packArgs()...), "--rule", "x")...), 2, "")
	})
}

func manyIDs(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("rule-")
		b.WriteString(strings.Repeat("a", 1+i%5))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + i/26)))
		b.WriteString("\n")
	}
	return b.String()
}

func TestApprovalSignRulesDigestBindsSigner(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 3)
	d := f.listDigest(t)
	for name, mod := range map[string]func(*rulesFixture){
		"identity":  func(g *rulesFixture) { g.identity = "other-owner" },
		"candidate": func(g *rulesFixture) { g.candidate = "pr-43" },
		"key id":    func(g *rulesFixture) { g.keyID = ApprovalKeyID(newApprovalKey(t).public) },
	} {
		g := f
		mod(&g)
		if g.listDigest(t) == d {
			t.Fatalf("changing the %s does not change the list digest", name)
		}
	}
	// A digest made for another identity does not sign.
	g := f
	g.identity = "other-owner"
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", g.listDigest(t), "--key-stdin")...), 2, "does not match")
	noFiles(t, f)
	// The prompt names identity, candidate and key id.
	var prompt string
	var out, errOut bytes.Buffer
	env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return signNow }, checkStdin: func(io.Reader) error { return nil },
		confirm: func(p string) (string, error) { prompt = p; return "", nil }}
	approvalMain(f.signArgs2("--key-stdin"), env, DefaultLayout(), &out, &errOut)
	for _, want := range []string{f.identity, f.candidate, f.keyID} {
		if !strings.Contains(out.String()+prompt, want) {
			t.Fatalf("%s not shown to the owner", want)
		}
	}
}

func TestApprovalSignRulesStagingAndDirectories(t *testing.T) {
	t.Parallel()
	t.Run("stale staging directories are cleaned, links are not followed", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		parent := filepath.Dir(f.outDir)
		stale := filepath.Join(parent, ".approval-stage-0011223344556677")
		writeFile(t, filepath.Join(stale, "old.json"), []byte("x"))
		old := time.Now().Add(-2 * time.Hour)
		if err := os.Chtimes(stale, old, old); err != nil {
			t.Fatal(err)
		}
		victim := t.TempDir()
		writeFile(t, filepath.Join(victim, "keep.json"), []byte("keep"))
		if err := os.Symlink(victim, filepath.Join(parent, ".approval-stage-evil")); err != nil {
			t.Fatal(err)
		}
		fresh := filepath.Join(parent, ".approval-stage-8899aabbccddeeff") // a run in progress
		writeFile(t, filepath.Join(fresh, "new.json"), []byte("x"))
		other := filepath.Join(parent, ".approval-other")
		writeFile(t, filepath.Join(other, "keep.json"), []byte("keep"))
		d := f.listDigest(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...), 0, "approvals written")
		if _, err := os.Lstat(stale); !os.IsNotExist(err) {
			t.Fatal("stale staging directory left")
		}
		for _, p := range []string{filepath.Join(victim, "keep.json"), filepath.Join(other, "keep.json"), filepath.Join(fresh, "new.json")} {
			if _, err := os.Stat(p); err != nil {
				t.Fatalf("%s was removed", p)
			}
		}
	})
	t.Run("a symbolic link in the parent path is refused", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		real := filepath.Dir(f.outDir)
		link := filepath.Join(t.TempDir(), "approvals-link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		d := f.listDigest(t)
		args := f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")
		for i, a := range args {
			if a == f.outDir {
				args[i] = filepath.Join(link, "cncf")
			}
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "symbolic link")
		noFiles(t, f)
	})
	t.Run("a symbolic link as the output directory is refused", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		target := t.TempDir()
		if err := os.Symlink(target, f.outDir); err != nil {
			t.Fatal(err)
		}
		d := f.listDigest(t)
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")...), 2, "")
		if ents, _ := os.ReadDir(target); len(ents) != 0 {
			t.Fatal("wrote through the link")
		}
	})
}

func TestApprovalSignRulesRollbackKeepsSwappedFile(t *testing.T) {
	f := newRulesFixture(t, 3) // not parallel: sets a test hook
	if err := os.MkdirAll(filepath.Join(f.outDir, f.ids[2]+".json"), 0o755); err != nil {
		t.Fatal(err)
	}
	swapped := filepath.Join(f.outDir, f.ids[0]+".json")
	afterApprovalLink = func(name string) {
		if name == f.ids[0]+".json" {
			if err := os.Remove(swapped); err != nil {
				t.Error(err)
			}
			writeFile(t, swapped, []byte("someone else's file"))
		}
	}
	defer func() { afterApprovalLink = func(string) {} }()
	if err := writeApprovalFiles(f.outDir, f.ids, [][]byte{[]byte("a"), []byte("b"), []byte("c")}); err == nil {
		t.Fatal("expected an error")
	}
	if got, err := os.ReadFile(swapped); err != nil || string(got) != "someone else's file" {
		t.Fatal("a file that was swapped in was removed by the rollback")
	}
	if _, err := os.Lstat(filepath.Join(f.outDir, f.ids[1]+".json")); !os.IsNotExist(err) {
		t.Fatal("untouched link not rolled back")
	}
}

func TestApprovalSignRulesDryRunPrintsPackDigests(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 2)
	r := runApproval(t, nil, signNow, append([]string{"sign", "--dry-run"}, f.packArgs()...)...)
	requireCode(t, r, 0, "rules to approve: 2")
	for label, root := range map[string]string{"base pack sha256: ": f.base.Root, "head pack sha256: ": f.head.Root} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(cncfRulesPath)))
		if err != nil {
			t.Fatal(err)
		}
		if want := label + sha256Hex(raw) + "\n"; !strings.Contains(r.stdout, want) {
			t.Fatalf("missing %q in:\n%s", want, r.stdout)
		}
	}
}

func TestApprovalSignRulesHeadEditedAfterDryRun(t *testing.T) {
	t.Parallel()
	f := newRulesFixture(t, 2)
	old := f.listDigest(t)
	editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, f.ids[0]))["validUntil"] = gateNow.Add(50 * 24 * time.Hour).Format(time.RFC3339)
	})
	if f.listDigest(t) == old {
		t.Fatal("head edit did not change the digest")
	}
	r := runApproval(t, f.key.pemKey(t), signNow, f.signArgs2("--expect-count", "2", "--expect-list-digest", old, "--key-stdin")...)
	requireCode(t, r, 2, "does not match")
	noFiles(t, f)
}

func TestApprovalSignRulesUnsupportedPlatformRefusesBeforeKey(t *testing.T) {
	f := newRulesFixture(t, 2) // not parallel: sets a package variable
	approvalSigningSupported = false
	defer func() { approvalSigningSupported = true }()
	var prompted bool
	var out, errOut bytes.Buffer
	env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return signNow }, checkStdin: func(io.Reader) error { return nil },
		confirm: func(string) (string, error) { prompted = true; return "", nil }}
	code := approvalMain(f.signArgs2("--key-stdin"), env, DefaultLayout(), &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "Linux and macOS only") || prompted {
		t.Fatalf("code %d prompted %v: %s", code, prompted, errOut.String())
	}
	noFiles(t, f)
}
