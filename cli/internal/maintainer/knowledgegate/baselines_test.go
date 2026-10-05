// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/repinbaselines"
)

const testBaselineRepo = "cloud-custodian/cloud-custodian"

func baselineEntryAt(decidedAt string) repinbaselines.Entry {
	return repinbaselines.Entry{
		Approval: "pr-15", Commit: strings.Repeat("a", 40), DecidedAt: decidedAt,
		Reason: "the project publishes this tag as its stable line", Repository: testBaselineRepo, Tag: "0.9.46.0",
	}
}

func writeBaselines(t *testing.T, tr Tree, entries ...repinbaselines.Entry) {
	t.Helper()
	raw, err := repinbaselines.File{Schema: repinbaselines.Schema, Entries: entries}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(repinbaselines.DefaultPath)), raw)
}

func baselineApprovalPath(tr Tree, repo string) string {
	id, _ := repinbaselines.ApprovalID(repo)
	return filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), repinbaselines.ApprovalPack, id+".json")
}

func baselineRecord(e repinbaselines.Entry, base *repinbaselines.Entry, decided time.Time) ApprovalRecord {
	id, _ := repinbaselines.ApprovalID(e.Repository)
	baseDigest := ApprovalBaseAbsent
	if base != nil {
		baseDigest = CandidateDigest(base.Canonical())
	}
	return ApprovalRecord{
		BaseDigest: baseDigest, CandidateDigest: CandidateDigest(e.Canonical()), CandidateID: e.Approval,
		DecidedAt: decided.UTC().Format("2006-01-02T15:04:05Z"), Decision: ApprovalDecisionApprove, Identity: "airstand",
		Pack: repinbaselines.ApprovalPack, RuleID: id, Scope: e.Repository, Subject: ApprovalSubjectRepinBaseline,
	}
}

type baselineFixture struct {
	base, head Tree
	key        testApprovalKey
	entry      repinbaselines.Entry
}

// newBaselineFixture proposes one new entry with a valid approval.
func newBaselineFixture(t *testing.T) baselineFixture {
	t.Helper()
	base, head := trees(t)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, "airstand")
	f := baselineFixture{base: base, head: head, key: key, entry: baselineEntryAt("2026-10-03T10:00:00Z")}
	writeBaselines(t, head, f.entry)
	writeFile(t, baselineApprovalPath(head, testBaselineRepo), key.sign(t, baselineRecord(f.entry, nil, gateNow.Add(-time.Hour))))
	return f
}

func (f baselineFixture) run(t *testing.T) *Report {
	t.Helper()
	return runGate(t, Options{Base: f.base, Head: f.head, Author: "airstand"})
}

func TestGateAdmitsAnOwnerBaselineEntryWithAnApproval(t *testing.T) {
	f := newBaselineFixture(t)
	r := f.run(t)
	requirePass(t, r)
	if c, ok := check(r, "repin-baselines"); !ok || !c.OK || !strings.Contains(c.Detail, "1 entries added, 0 changed, 0 removed") {
		t.Fatalf("check %+v", c)
	}
	if c, _ := check(r, "knowledge-records"); !c.OK {
		t.Fatalf("records: %+v", c)
	}
	if r.AutoMerge.Eligible {
		t.Fatal("a baseline change is never auto-mergeable")
	}
}

func TestGateAdmitsAChangedEntryWithANewerApproval(t *testing.T) {
	f := newBaselineFixture(t)
	old := baselineEntryAt("2026-10-01T10:00:00Z")
	old.Tag, old.Commit, old.Approval = "0.9.45.0", strings.Repeat("b", 40), "pr-9"
	writeBaselines(t, f.base, old)
	writeFile(t, baselineApprovalPath(f.base, testBaselineRepo), f.key.sign(t, baselineRecord(old, nil, gateNow.Add(-48*time.Hour))))
	writeFile(t, baselineApprovalPath(f.head, testBaselineRepo), f.key.sign(t, baselineRecord(f.entry, &old, gateNow.Add(-time.Hour))))
	r := f.run(t)
	requirePass(t, r)
	if c, _ := check(r, "repin-baselines"); !strings.Contains(c.Detail, "0 entries added, 1 changed") {
		t.Fatalf("%+v", c)
	}
}

func TestGateAdmitsRemovingABaselineEntryWithoutAnApproval(t *testing.T) {
	f := newBaselineFixture(t)
	old := baselineEntryAt("2026-10-01T10:00:00Z")
	writeBaselines(t, f.base, old)
	writeFile(t, baselineApprovalPath(f.base, testBaselineRepo), f.key.sign(t, baselineRecord(old, nil, gateNow.Add(-48*time.Hour))))
	writeBaselines(t, f.head)
	writeFile(t, baselineApprovalPath(f.head, testBaselineRepo), f.key.sign(t, baselineRecord(old, nil, gateNow.Add(-48*time.Hour))))
	r := f.run(t)
	requirePass(t, r)
	if c, _ := check(r, "repin-baselines"); !strings.Contains(c.Detail, "0 entries added, 0 changed, 1 removed") {
		t.Fatalf("%+v", c)
	}
	// A live approval of the base may not be deleted with it.
	if err := os.Remove(baselineApprovalPath(f.head, testBaselineRepo)); err != nil {
		t.Fatal(err)
	}
	requireFail(t, f.run(t), "may not be removed while it could still verify")
}

func TestGateRefusesAnOwnerBaselineEntryWithoutAValidApproval(t *testing.T) {
	sign := func(f baselineFixture, mutate func(r *ApprovalRecord)) {
		rec := baselineRecord(f.entry, nil, gateNow.Add(-time.Hour))
		mutate(&rec)
		writeFile(t, baselineApprovalPath(f.head, testBaselineRepo), f.key.sign(t, rec))
	}
	cases := map[string]struct {
		edit func(f baselineFixture)
		want string
	}{
		"no approval": {func(f baselineFixture) {
			_ = os.Remove(baselineApprovalPath(f.head, testBaselineRepo))
		}, "no owner approval"},
		"rule approval": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.Subject, r.Scope = "", "" })
		}, "approves a different kind of subject"},
		"line attestation approval": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.Subject, r.Scope = ApprovalSubjectLineAttestation, "pkg:generic/x fam 1.2" })
		}, "approves a different kind of subject"},
		"other repository scope": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.Scope = "cloud-custodian/other" })
		}, "approves a different rule"},
		"other pack": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.Pack = "cncf" })
		}, "approves a different rule"},
		"other approval id": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.RuleID = "other--repo" })
		}, "approves a different rule"},
		"entry changed after approval": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.CandidateDigest = CandidateDigest([]byte("x")) })
		}, "candidate digest does not match"},
		"base digest for a new entry": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.BaseDigest = r.CandidateDigest })
		}, "base digest does not match"},
		"approval cited by another reference": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.CandidateID = "pr-99" })
		}, "cites approval"},
		"entry decided after the approval": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.DecidedAt = "2026-10-03T09:00:00Z" })
		}, "decided after the approval"},
		"approval older than 14 days": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.DecidedAt = "2026-09-10T10:00:00Z" })
		}, "older than 14 days"},
		"approval from the future": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.DecidedAt = "2026-10-03T13:00:00Z" })
		}, "decided in the future"},
		"not an owner": {func(f baselineFixture) {
			sign(f, func(r *ApprovalRecord) { r.Identity = "mallory" })
		}, "is not an owner"},
		"another key": {func(f baselineFixture) {
			rec := baselineRecord(f.entry, nil, gateNow.Add(-time.Hour))
			writeFile(t, baselineApprovalPath(f.head, testBaselineRepo), newApprovalKey(t).sign(t, rec))
		}, "not pinned"},
	}
	for name, tc := range cases {
		f := newBaselineFixture(t)
		tc.edit(f)
		r := f.run(t)
		if c, ok := check(r, "repin-baselines"); !ok || c.OK || !strings.Contains(c.Detail, tc.want) {
			t.Errorf("%s: want a failure containing %q, got %+v", name, tc.want, c)
		}
		if r.Passed() {
			t.Errorf("%s: the gate passed", name)
		}
	}
}

func TestGateBaselineApprovalKeyPinning(t *testing.T) {
	f := newBaselineFixture(t)
	r := runGate(t, Options{Base: f.base, Head: f.head, Author: "airstand", ApprovalKeysDigest: "none"})
	requireFail(t, r, "no owner approval key digest")
	r = runGate(t, Options{Base: f.base, Head: f.head, Author: "airstand", ApprovalKeysDigest: "sha256:" + strings.Repeat("0", 64)})
	requireFail(t, r, "does not match the pinned digest")
}

// An approval admits the change it arrives with. One that is already in the
// base (the entry was removed, then proposed again) is spent; and a base
// decision made later than the offered approval cannot be put back.
func TestGateBaselineApprovalsAreSingleUseAndForwardOnly(t *testing.T) {
	f := newBaselineFixture(t)
	spent := baselineRecord(f.entry, nil, gateNow.Add(-time.Hour))
	writeFile(t, baselineApprovalPath(f.base, testBaselineRepo), f.key.sign(t, spent))
	writeBaselines(t, f.base) // the entry was removed after the approval was used
	r := f.run(t)
	if c, _ := check(r, "repin-baselines"); c.OK || !strings.Contains(c.Detail, "already in the base") {
		t.Fatalf("replay: %+v", c)
	}

	f = newBaselineFixture(t)
	later := baselineRecord(f.entry, nil, gateNow.Add(-30*time.Minute))
	later.CandidateDigest = CandidateDigest([]byte("another entry"))
	writeFile(t, baselineApprovalPath(f.base, testBaselineRepo), f.key.sign(t, later))
	writeBaselines(t, f.base)
	r = f.run(t)
	if c, _ := check(r, "repin-baselines"); c.OK || !strings.Contains(c.Detail, "decided at the same time or later") {
		t.Fatalf("superseded: %+v", c)
	}
}

func TestGateRefusesBaselineEntriesThatMoveBackward(t *testing.T) {
	f := newBaselineFixture(t)
	old := baselineEntryAt("2026-10-03T10:00:00Z")
	old.Tag = "0.9.45.0"
	writeBaselines(t, f.base, old)
	writeFile(t, baselineApprovalPath(f.base, testBaselineRepo), f.key.sign(t, baselineRecord(old, nil, gateNow.Add(-90*time.Minute))))
	// Same decidedAt as the entry it replaces.
	writeFile(t, baselineApprovalPath(f.head, testBaselineRepo), f.key.sign(t, baselineRecord(f.entry, &old, gateNow.Add(-time.Hour))))
	if c, _ := check(f.run(t), "repin-baselines"); c.OK || !strings.Contains(c.Detail, "only move forward") {
		t.Fatalf("%+v", c)
	}
}

func TestGateRefusesBaselineFileFromTheAutomationAccount(t *testing.T) {
	f := newBaselineFixture(t)
	r := runGate(t, Options{Base: f.base, Head: f.head, Author: DefaultBotLogin})
	if c, _ := check(r, "repin-baselines"); c.OK || !strings.Contains(c.Detail, "automation account") {
		t.Fatalf("%+v", c)
	}
	if r.AutoMerge.Eligible {
		t.Fatal("never auto-mergeable")
	}
}

func TestGateRefusesMalformedBaselineFiles(t *testing.T) {
	for name, edit := range map[string]func(f baselineFixture){
		"head malformed": func(f baselineFixture) {
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(repinbaselines.DefaultPath)), []byte(`{"schema":"x"}`))
		},
		"head extra field": func(f baselineFixture) {
			writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(repinbaselines.DefaultPath)), []byte(`{"entries":[],"schema":"`+repinbaselines.Schema+`","note":1}`))
		},
		"base malformed": func(f baselineFixture) {
			writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(repinbaselines.DefaultPath)), []byte(`{"schema":"x"}`))
		},
	} {
		f := newBaselineFixture(t)
		edit(f)
		r := f.run(t)
		if c, ok := check(r, "repin-baselines"); !ok || c.OK || r.Passed() {
			t.Errorf("%s: %+v", name, c)
		}
	}
}

// An approval file under the baseline directory needs the baseline change
// it admitted in the same change.
func TestGateRefusesBaselineApprovalFilesWithoutTheirChange(t *testing.T) {
	f := newBaselineFixture(t)
	writeBaselines(t, f.head) // entry not proposed after all
	r := f.run(t)
	if c, _ := check(r, "knowledge-records"); c.OK || !strings.Contains(c.Detail, "no admitted baseline entry uses this approval") {
		t.Fatalf("%+v", c)
	}
	f = newBaselineFixture(t)
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().ApprovalDir), repinbaselines.ApprovalPack, "stray.json"), []byte("{}"))
	if c, _ := check(f.run(t), "knowledge-records"); c.OK || !strings.Contains(c.Detail, "not <owner>--<repo>.json") {
		t.Fatalf("%+v", c)
	}
}

func TestGateWithoutABaselineFileHasNoBaselineCheck(t *testing.T) {
	base, head := trees(t)
	r := runGate(t, Options{Base: base, Head: head, Author: "airstand"})
	if _, ok := check(r, "repin-baselines"); ok {
		t.Fatal("no file in either tree: no check")
	}
	l := DefaultLayout()
	l.BaselinesPath = ""
	f := newBaselineFixture(t)
	r = runGate(t, Options{Layout: l, Base: f.base, Head: f.head, Author: "airstand"})
	if _, ok := check(r, "repin-baselines"); ok {
		t.Fatal("a layout without a baseline file path adds no check")
	}
}

func TestBaselineApprovalRecordScopeIsARepository(t *testing.T) {
	rec := baselineRecord(baselineEntryAt("2026-10-03T10:00:00Z"), nil, gateNow)
	if _, err := SignedApprovalBytes(rec); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "cloud-custodian", "cloud-custodian/", "/repo", "a b/c", "pkg:generic/x fam 1.2", "own--er/repo", "a/b/c"} {
		rec.Scope = scope
		if _, err := SignedApprovalBytes(rec); err == nil {
			t.Errorf("scope %q accepted", scope)
		}
	}
}
