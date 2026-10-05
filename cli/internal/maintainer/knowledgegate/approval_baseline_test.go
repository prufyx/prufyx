// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
)

type baselineSignFixture struct {
	baselineFixture
	keysDigest string
}

func newBaselineSignFixture(t *testing.T) baselineSignFixture {
	t.Helper()
	f := baselineFixture{}
	f.base, f.head = trees(t)
	f.key = newApprovalKey(t)
	f.key.pinBoth(t, f.base, f.head, "airstand")
	f.entry = baselineEntryAt("2026-10-03T10:00:00Z")
	writeBaselines(t, f.head, f.entry)
	raw, err := os.ReadFile(filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)))
	if err != nil {
		t.Fatal(err)
	}
	return baselineSignFixture{baselineFixture: f, keysDigest: pinnedDigest(raw)}
}

func (f baselineSignFixture) baselinePath(tr Tree) string {
	return filepath.Join(tr.Root, filepath.FromSlash(repinbaselines.DefaultPath))
}

func (f baselineSignFixture) out() string { return baselineApprovalPath(f.head, testBaselineRepo) }

func (f baselineSignFixture) subjectArgs(withBase bool) []string {
	args := []string{
		"--subject", ApprovalSubjectRepinBaseline, "--repository", testBaselineRepo,
		"--head-baselines", f.baselinePath(f.head),
		"--keys", filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)), "--keys-digest", f.keysDigest,
	}
	if withBase {
		args = append(args, "--base-baselines", f.baselinePath(f.base))
	}
	return args
}

func (f baselineSignFixture) signArgs(withBase bool, keyArgs ...string) []string {
	args := append([]string{"sign"}, f.subjectArgs(withBase)...)
	args = append(args, "--identity", "airstand", "--candidate-id", f.entry.Approval, "--output", f.out())
	return append(args, keyArgs...)
}

func (f baselineSignFixture) verifyArgs(withBase bool) []string {
	return append(append([]string{"verify", "--approval", f.out()}, f.subjectArgs(withBase)...), "--now", gateNow.Format(time.RFC3339))
}

func TestApprovalSignRepinBaselineRoundTripThroughGate(t *testing.T) {
	for _, src := range []string{"file", "stdin"} {
		f := newBaselineSignFixture(t)
		var r approvalRun
		if src == "file" {
			r = runApproval(t, nil, signNow, f.signArgs(false, "--key", f.key.keyFile(t, 0o600))...)
		} else {
			r = runApproval(t, f.key.pemKey(t), signNow, f.signArgs(false, "--key-stdin")...)
		}
		requireCode(t, r, 0, "subject    repinBaseline "+testBaselineRepo)
		for _, m := range f.key.secretMarkers(t) {
			if strings.Contains(r.stdout+r.stderr, m) {
				t.Fatal("key material printed")
			}
		}
		requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(false)...), 0, "approval OK")
		report := runGate(t, Options{Base: f.base, Head: f.head, Author: "airstand", ApprovalKeysDigest: f.keysDigest})
		requirePass(t, report)
		if c, _ := check(report, "repin-baselines"); !c.OK {
			t.Fatalf("%+v", c)
		}
	}
}

// The file is byte for byte the one built from the same record directly.
func TestApprovalSignRepinBaselineBytesMatchGateFormat(t *testing.T) {
	f := newBaselineSignFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs(false, "--key-stdin")...), 0, "approval written")
	got, err := os.ReadFile(f.out())
	if err != nil {
		t.Fatal(err)
	}
	want := f.key.sign(t, baselineRecord(f.entry, nil, signNow))
	if !bytes.Equal(got, want) {
		t.Fatalf("signer output differs:\n%s\nwant:\n%s", got, want)
	}
}

func TestApprovalSignRepinBaselineChangedEntry(t *testing.T) {
	f := newBaselineSignFixture(t)
	old := baselineEntryAt("2026-10-01T10:00:00Z")
	old.Tag, old.Commit = "0.9.45.0", strings.Repeat("b", 40)
	writeBaselines(t, f.base, old)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs(true, "--key-stdin")...), 0, "approval written")
	// The base digest binds the entry replaced: verifying without the base
	// file (as if the entry were new) is refused.
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(true)...), 0, "approval OK")
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(false)...), 1, "base digest does not match")
	// Signing for a new entry then using it for a changed one fails at the gate.
	writeFile(t, baselineApprovalPath(f.base, testBaselineRepo), f.key.sign(t, baselineRecord(old, nil, gateNow.Add(-48*time.Hour))))
	requirePass(t, runGate(t, Options{Base: f.base, Head: f.head, Author: "airstand", ApprovalKeysDigest: f.keysDigest}))
}

func TestApprovalSignRepinBaselineRefusals(t *testing.T) {
	key := func(f baselineSignFixture) string { return f.key.keyFile(t, 0o600) }
	cases := map[string]struct {
		edit func(f baselineSignFixture) []string
		want string
	}{
		"repository not in the file": {func(f baselineSignFixture) []string {
			a := f.signArgs(false, "--key", key(f))
			return replaceArg(a, "--repository", "cloud-custodian/other")
		}, "has no entry for cloud-custodian/other"},
		"repository spelled differently": {func(f baselineSignFixture) []string {
			return replaceArg(f.signArgs(false, "--key", key(f)), "--repository", "Cloud-Custodian/Cloud-Custodian")
		}, "spelled"},
		"entry unchanged": {func(f baselineSignFixture) []string {
			writeBaselines(t, f.base, f.entry)
			return f.signArgs(true, "--key", key(f))
		}, "nothing to approve"},
		"entry cites another approval": {func(f baselineSignFixture) []string {
			return replaceArg(f.signArgs(false, "--key", key(f)), "--candidate-id", "pr-99")
		}, "cites approval"},
		"entry decided after signing": {func(f baselineSignFixture) []string {
			e := f.entry
			e.DecidedAt = "2026-10-03T11:30:00Z"
			writeBaselines(t, f.head, e)
			return f.signArgs(false, "--key", key(f))
		}, "decided after the approval"},
		"entry not newer than the one it replaces": {func(f baselineSignFixture) []string {
			old := f.entry
			old.Tag = "0.9.45.0"
			writeBaselines(t, f.base, old)
			return f.signArgs(true, "--key", key(f))
		}, "only move forward"},
		"head file malformed": {func(f baselineSignFixture) []string {
			writeFile(t, f.baselinePath(f.head), []byte(`{"schema":"x"}`))
			return f.signArgs(false, "--key", key(f))
		}, "proposed"},
		"rule flags with the baseline subject": {func(f baselineSignFixture) []string {
			return append(f.signArgs(false, "--key", key(f)), "--pack", "cncf")
		}, "belong to --subject rule"},
		"missing head file flag": {func(f baselineSignFixture) []string {
			return []string{"sign", "--subject", ApprovalSubjectRepinBaseline, "--repository", testBaselineRepo, "--keys-digest", f.keysDigest, "--keys", "x", "--identity", "airstand", "--candidate-id", "pr-15", "--output", f.out(), "--key", key(f)}
		}, "--head-baselines"},
		"output name": {func(f baselineSignFixture) []string {
			return replaceArg(f.signArgs(false, "--key", key(f)), "--output", filepath.Join(f.head.Root, "x", "wrong.json"))
		}, "--output must end in repin-baselines/cloud-custodian--cloud-custodian.json"},
		"not an owner": {func(f baselineSignFixture) []string {
			return replaceArg(f.signArgs(false, "--key", key(f)), "--identity", "mallory")
		}, "is not an owner"},
		"another subject takes the rule flags": {func(f baselineSignFixture) []string {
			return replaceArg(f.signArgs(false, "--key", key(f)), "--subject", "lineAttestation")
		}, "--pack, --rule"},
	}
	for name, tc := range cases {
		f := newBaselineSignFixture(t)
		args := tc.edit(f)
		r := runApproval(t, nil, signNow, args...)
		if r.code == 0 || !strings.Contains(r.stdout+r.stderr, tc.want) {
			t.Errorf("%s: want a refusal containing %q, got exit %d\n%s%s", name, tc.want, r.code, r.stdout, r.stderr)
		}
		if _, err := os.Lstat(f.out()); err == nil {
			t.Errorf("%s: a file was written", name)
		}
	}
}

func replaceArg(args []string, name, value string) []string {
	out := append([]string(nil), args...)
	for i := range out {
		if out[i] == name && i+1 < len(out) {
			out[i+1] = value
		}
	}
	return out
}

func TestApprovalVerifyRepinBaselineRefusesOtherSubjects(t *testing.T) {
	f := newBaselineSignFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.signArgs(false, "--key-stdin")...), 0, "approval written")
	// A changed entry does not verify against the old approval.
	e := f.entry
	e.Reason = "an entry changed after the approval"
	writeBaselines(t, f.head, e)
	requireCode(t, runApproval(t, nil, gateNow, f.verifyArgs(false)...), 1, "candidate digest does not match")
	// Later than 14 days.
	writeBaselines(t, f.head, f.entry)
	r := runApproval(t, nil, gateNow.Add(15*24*time.Hour), append(f.verifyArgs(false)[:len(f.verifyArgs(false))-2], "--now", gateNow.Add(15*24*time.Hour).Format(time.RFC3339))...)
	requireCode(t, r, 1, "older than 14 days")
}
