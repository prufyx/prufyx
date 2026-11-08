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
	rf := filepath.Join(t.TempDir(), "rules.txt")
	writeFile(t, rf, []byte(strings.Join(ids, "\n")+"\n"))
	return rulesFixture{signFixture: f, ids: ids, rulesFile: rf, outDir: filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), "cncf")}
}

func (f rulesFixture) packArgs() []string {
	return []string{"--pack", "cncf", "--rules-file", f.rulesFile,
		"--base-pack", filepath.Join(f.base.Root, filepath.FromSlash(cncfRulesPath)),
		"--head-pack", filepath.Join(f.head.Root, filepath.FromSlash(cncfRulesPath))}
}

func (f rulesFixture) signArgs2(extra ...string) []string {
	args := append([]string{"sign"}, f.packArgs()...)
	args = append(args, "--keys", f.keysPath(), "--keys-digest", f.keysDigest, "--identity", "airstand", "--candidate-id", "pr-42", "--output-dir", f.outDir)
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
	d := strings.TrimPrefix(f.listDigest(t), "sha256:")[:12]
	for _, bad := range []string{"", "yes", "sign 3", "sign 2 " + d, "sign 3 " + strings.Repeat("0", 12)} {
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
		requireCode(t, r, 2, "not pinned")
		noFiles(t, f)
		r = runApproval(t, f.key.pemKey(t), signNow, append(f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin"), []string{}...)...)
		requireCode(t, r, 0, "approvals written")
	})
	t.Run("wrong identity", func(t *testing.T) {
		f := newRulesFixture(t, 3)
		d := f.listDigest(t)
		args := f.signArgs2("--expect-count", "3", "--expect-list-digest", d, "--key-stdin")
		for i, a := range args {
			if a == "airstand" {
				args[i] = "someone-else"
			}
		}
		requireCode(t, runApproval(t, f.key.pemKey(t), signNow, args...), 2, "not an owner")
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
	for name, content := range map[string]string{
		"empty": "\n\n", "duplicate": f.ids[0] + "\n" + f.ids[0], "bad id": "../x", "comment": "# " + f.ids[0],
		"too many": strings.Repeat("r\n", 0) + manyIDs(MaxRulesPerSigning+1),
	} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, f.rulesFile, []byte(content))
			requireCode(t, runApproval(t, nil, signNow, append([]string{"sign", "--dry-run"}, f.packArgs()...)...), 2, "")
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
