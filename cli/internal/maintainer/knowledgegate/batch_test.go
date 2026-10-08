// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

// Batch approvals: one owner signature for up to 50 reviewed entries. Every
// key here is generated for the test only.

const testBatchID = "b-20261003-1"

// testNonce is a fixed review nonce (the signing tool draws one).
const testNonce = "00112233445566778899aabbccddeeff"

type batchFixture struct {
	base, head Tree
	key        testApprovalKey
	ids        []string
}

// renewWeeks are later lease ends within the 90-day review window of the
// shipped pack whose ISO weeks hold few leases (the shipped pack's leases
// end in 2026-W50 and W52), so the stagger cap holds for 51 renewals.
var renewWeeks = []time.Time{
	time.Date(2026, 12, 16, 0, 0, 0, 0, time.UTC),
	time.Date(2026, 12, 29, 0, 0, 0, 0, time.UTC),
}

// renewRules renews rules of the head's CNCF pack, spreading the new
// leases over renewWeeks.
func renewRules(t *testing.T, head Tree, ids []string) {
	t.Helper()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		for i, id := range ids {
			ev := evidenceOf(p.find(t, id))
			ev["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
			week := renewWeeks[i%len(renewWeeks)]
			ev["validUntil"] = week.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		}
	})
}

// newBatchFixture renews n reviewed rules in the head and pins a key.
func newBatchFixture(t *testing.T, n int) batchFixture {
	t.Helper()
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()[:n]
	renewRules(t, head, ids)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, "airstand")
	return batchFixture{base: base, head: head, key: key, ids: ids}
}

func (f batchFixture) state(t *testing.T) *batchState {
	t.Helper()
	cls, err := Classify(DefaultLayout(), f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newBatchState(DefaultLayout(), cls)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// record drafts the batch for the fixture's change, as the owner would
// sign it an hour before the gate's clock.
func (f batchFixture) record(t *testing.T) BatchRecord {
	t.Helper()
	rec, _, err := f.state(t).draftRecord(testBatchID, "pr-7", testNonce)
	if err != nil {
		t.Fatal(err)
	}
	rec.Identity, rec.Decision = "airstand", ApprovalDecisionApprove
	rec.DecidedAt = signNow.Format(time.RFC3339)
	rec.NotAfter = signNow.Add(MaxBatchValidity).Format(time.RFC3339)
	return rec
}

// reseal draws the sample and the summary again for a changed record, so a
// test changes exactly one bound value.
func (f batchFixture) reseal(t *testing.T, rec *BatchRecord) {
	t.Helper()
	sample, err := batchSample(rec.core())
	if err != nil {
		t.Fatal(err)
	}
	rec.Sample = sample
	rec.SummaryDigest = CandidateDigest([]byte(f.state(t).summary(*rec)))
}

// signBatchRecord signs any record as it is.
func (k testApprovalKey) signBatch(t *testing.T, r BatchRecord) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	msg := append([]byte(BatchDomain), raw...)
	out, err := json.MarshalIndent(BatchEnvelope{Schema: BatchSchema, Record: r, KeyID: ApprovalKeyID(k.public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(k.private, msg))}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func batchFilePath(tr Tree, name string) string {
	return filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().BatchDir), name)
}

func (f batchFixture) write(t *testing.T, tr Tree, name string, raw []byte) {
	t.Helper()
	writeFile(t, batchFilePath(tr, name), raw)
}

func (f batchFixture) signAndWrite(t *testing.T, rec BatchRecord) {
	t.Helper()
	f.write(t, f.head, rec.BatchID+".json", f.key.signBatch(t, rec))
}

func requireBatchProof(t *testing.T, r *Report, ids []string) {
	t.Helper()
	for _, id := range ids {
		if c := change(t, r, id); !c.OK || c.Proof != ProofBatchApproval {
			t.Fatalf("change %s: %+v", id, c)
		}
	}
}

func TestBatchGateAdmits(t *testing.T) {
	for _, n := range []int{1, 5, MaxBatchEntries} {
		f := newBatchFixture(t, n)
		f.signAndWrite(t, f.record(t))
		r := runGate(t, Options{Base: f.base, Head: f.head})
		requirePass(t, r)
		requireBatchProof(t, r, f.ids)
		if c, ok := check(r, CheckBatch); !ok || !c.OK {
			t.Fatalf("batch check %+v", c)
		}
		alarmed := false
		for _, k := range r.alarmKinds {
			alarmed = alarmed || k == AlarmBatch
		}
		if !alarmed {
			t.Fatal("a batch raised no alarm")
		}
		if r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, ";"), "batch approval") {
			t.Fatalf("auto-merge %+v", r.AutoMerge)
		}
		if c, _ := check(r, "knowledge-records"); !c.OK {
			t.Fatalf("records %+v", c)
		}
	}
}

func TestBatchLimit(t *testing.T) {
	f := newBatchFixture(t, MaxBatchEntries+1)
	if err := f.state(t).readyForBatch(); err == nil || !strings.Contains(err.Error(), "at most 50") {
		t.Fatalf("51 entries: %v", err)
	}
	// A record listing 51 entries is out of range before anything else.
	st := f.state(t)
	rec := BatchRecord{BatchID: testBatchID, CandidateID: "pr-7", Entries: st.entries(), Nonce: testNonce, Packs: st.packs}
	if err := rec.validate(); err == nil {
		t.Fatal("51 entries validated")
	}
	// The gate refuses a batch of the first 50 for the change of 51: the
	// 51st is not in the batch.
	rec50 := f.record(t)
	rec50.Entries = rec50.Entries[:0]
	for _, e := range st.entries()[:MaxBatchEntries] {
		rec50.Entries = append(rec50.Entries, e)
	}
	f.reseal(t, &rec50)
	f.signAndWrite(t, rec50)
	requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), "at most 50")
}

func TestBatchGateRefusals(t *testing.T) {
	other := newApprovalKey(t)
	cases := map[string]struct {
		edit func(t *testing.T, f batchFixture, rec *BatchRecord) Options
		want string
	}{
		"entry missing": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.Entries = rec.Entries[1:]
			f.reseal(t, rec)
			return Options{}
		}, "is not in the batch"},
		"entry not changed by the change": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			extra := readPack(t, f.base, cncfRulesPath).activeReviewed()[10]
			rec.Entries = append(rec.Entries, BatchEntry{BaseDigest: ApprovalBaseAbsent, CandidateDigest: rec.Entries[0].CandidateDigest, ID: extra, Pack: "cncf", Subject: BatchSubjectRule})
			sortEntries(rec.Entries)
			f.reseal(t, rec)
			return Options{}
		}, "the change does not change it"},
		"tightening masquerade": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			withdrawn := readPack(t, f.base, cncfRulesPath).activeReviewed()[10]
			editPack(t, f.head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, withdrawn))["state"] = "withdrawn" })
			st := f.state(t)
			c := st.changes[batchKey("cncf", BatchSubjectRule, withdrawn)]
			b, h := c.canonicalSides()
			*rec = f.record(t)
			rec.Entries = append(rec.Entries, BatchEntry{BaseDigest: CandidateDigest(b), CandidateDigest: CandidateDigest(h), ID: withdrawn, Pack: "cncf", Subject: BatchSubjectRule})
			sortEntries(rec.Entries)
			f.reseal(t, rec)
			return Options{}
		}, "is a tightening change"},
		"candidate digest": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.Entries[0].CandidateDigest = "sha256:" + strings.Repeat("ab", 32)
			f.reseal(t, rec)
			return Options{}
		}, "candidate digest does not match"},
		"base digest": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.Entries[0].BaseDigest = ApprovalBaseAbsent
			f.reseal(t, rec)
			return Options{}
		}, "base digest does not match"},
		"entry added after signing": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			renewRules(t, f.head, append(append([]string{}, f.ids...), readPack(t, f.base, cncfRulesPath).activeReviewed()[10]))
			return Options{}
		}, "is not in the batch"},
		"pack bytes changed after signing": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			path := filepath.Join(f.head.Root, filepath.FromSlash(cncfRulesPath))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, raw); err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, compact.Bytes())
			return Options{}
		}, "a pack file differs"},
		"change set": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.ChangeSetDigest = "sha256:" + strings.Repeat("cd", 32)
			f.reseal(t, rec)
			return Options{}
		}, "the change set differs"},
		"citations": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.CitationsDigest = "sha256:" + strings.Repeat("ef", 32)
			f.reseal(t, rec)
			return Options{}
		}, "cited sources differ"},
		"sample chosen by hand": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			for i := range rec.Sample {
				rec.Sample[i] = i
			}
			if equalInts(rec.Sample, mustSample(t, rec.core())) {
				rec.Sample[len(rec.Sample)-1]++
			}
			return Options{}
		}, "the sample is not the one drawn"},
		"summary": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.SummaryDigest = "sha256:" + strings.Repeat("01", 32)
			return Options{}
		}, "summary digest does not match"},
		"expired": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			return Options{Now: signNow.Add(MaxBatchValidity)}
		}, "expired at"},
		"valid longer than 72 hours": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.NotAfter = signNow.Add(MaxBatchValidity + time.Second).Format(time.RFC3339)
			return Options{}
		}, "at most 72 hours"},
		"decided in the future": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.DecidedAt = gateNow.Add(6 * time.Minute).Format(time.RFC3339)
			rec.NotAfter = gateNow.Add(time.Hour).Format(time.RFC3339)
			return Options{}
		}, "decided in the future"},
		"not an owner": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.Identity = "someone"
			return Options{}
		}, "not an owner"},
		"decision": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			rec.Decision = "reject"
			return Options{}
		}, "decision is"},
		"no key digest": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			return Options{ApprovalKeysDigest: "none"}
		}, "no owner approval key digest"},
		"offline citations": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			return Options{Citations: OfflineCitations{}}
		}, "offline mode"},
		"citation finding": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			return Options{Citations: findingCitations{}}
		}, "do not verify upstream"},
		"citation verifier error": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			return Options{Citations: brokenCitations{}}
		}, "could not be verified"},
		"documentation changed too": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			writeFile(t, filepath.Join(f.head.Root, "cli", "docs", "note.md"), []byte("x\n"))
			return Options{}
		}, "1 other files"},
		"registry changed too": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			path := filepath.Join(f.head.Root, filepath.FromSlash("cli/internal/projectcheck/data/projects.json"))
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, append(raw, '\n'))
			return Options{}
		}, "projectcheck/data/projects.json"},
		"trust material changed too": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			other.pin(t, f.head, "airstand")
			return Options{}
		}, "web-approval-keys.json"},
		"per-entry approval file too": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			writeFile(t, approvalPath(f.head, f.ids[0]), []byte("{}\n"))
			return Options{}
		}, "other files"},
		"a rule removed too": {func(t *testing.T, f batchFixture, rec *BatchRecord) Options {
			gone := readPack(t, f.base, cncfRulesPath).activeReviewed()[10]
			editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
				for i, e := range p.entries {
					if ruleID(e) == gone {
						p.entries = append(p.entries[:i], p.entries[i+1:]...)
						break
					}
				}
			})
			*rec = f.record(t)
			return Options{}
		}, "is removed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 4)
			rec := f.record(t)
			opts := tc.edit(t, f, &rec)
			f.signAndWrite(t, rec)
			opts.Base, opts.Head = f.base, f.head
			r := runGate(t, opts)
			requireFail(t, r, tc.want)
			for _, id := range f.ids {
				if c := change(t, r, id); c.OK {
					t.Fatalf("change %s admitted by a refused batch", id)
				}
			}
		})
	}
}

func sortEntries(e []BatchEntry) {
	for i := 1; i < len(e); i++ {
		for j := i; j > 0 && e[j].key() < e[j-1].key(); j-- {
			e[j], e[j-1] = e[j-1], e[j]
		}
	}
}

func mustSample(t *testing.T, core batchCore) []int {
	t.Helper()
	s, err := batchSample(core)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type findingCitations struct{}

func (findingCitations) VerifyItems(_ context.Context, items []rulecheck.CitationItem) (rulecheck.CitationReport, error) {
	return rulecheck.CitationReport{Pass: false, SourcesChecked: len(items), Findings: []rulecheck.CitationFinding{{RuleID: items[0].ID, SourceID: "s", Check: rulecheck.CheckCitationDigest}}}, nil
}

type brokenCitations struct{}

func (brokenCitations) VerifyItems(context.Context, []rulecheck.CitationItem) (rulecheck.CitationReport, error) {
	return rulecheck.CitationReport{}, errors.New("rate limited")
}

func TestBatchSignatureAndFile(t *testing.T) {
	cases := map[string]struct {
		write func(t *testing.T, f batchFixture, rec BatchRecord)
		want  string
	}{
		"unpinned key": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			f.write(t, f.head, testBatchID+".json", newApprovalKey(t).signBatch(t, rec))
		}, "not pinned"},
		"signature altered": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			raw := f.key.signBatch(t, rec)
			var env BatchEnvelope
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			env.Record.CandidateID = "pr-8"
			out, _ := json.Marshal(env)
			f.write(t, f.head, testBatchID+".json", out)
		}, "signature does not verify"},
		"per-entry approval domain": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			raw, _ := json.Marshal(rec)
			sig := ed25519.Sign(f.key.private, append([]byte(ApprovalDomain), raw...))
			out, _ := json.Marshal(BatchEnvelope{Schema: BatchSchema, Record: rec, KeyID: ApprovalKeyID(f.key.public), Signature: base64.StdEncoding.EncodeToString(sig)})
			f.write(t, f.head, testBatchID+".json", out)
		}, "signature does not verify"},
		"file named otherwise": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			f.write(t, f.head, "b-20261003-2.json", f.key.signBatch(t, rec))
		}, "not named after its batch id"},
		"two batch files": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			f.write(t, f.head, testBatchID+".json", f.key.signBatch(t, rec))
			rec.BatchID = "b-20261003-2"
			f.write(t, f.head, rec.BatchID+".json", f.key.signBatch(t, rec))
		}, "may add one batch approval"},
		"unknown member": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			raw := f.key.signBatch(t, rec)
			raw = bytes.Replace(raw, []byte(`"schema"`), []byte(`"extra": 1, "schema"`), 1)
			f.write(t, f.head, testBatchID+".json", raw)
		}, "unknown field"},
		"approval v2 schema": {func(t *testing.T, f batchFixture, rec BatchRecord) {
			raw := bytes.Replace(f.key.signBatch(t, rec), []byte(BatchSchema), []byte(ApprovalSchema), 1)
			f.write(t, f.head, testBatchID+".json", raw)
		}, "wrong schema"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 3)
			tc.write(t, f, f.record(t))
			requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), tc.want)
		})
	}
}

// A batch admits only the change that adds it, and decisions only move
// forward, for rules as for records.
func TestBatchSingleUseAndForwardOnly(t *testing.T) {
	t.Run("same batch in the base", func(t *testing.T) {
		f := newBatchFixture(t, 3)
		rec := f.record(t)
		raw := f.key.signBatch(t, rec)
		f.write(t, f.head, testBatchID+".json", raw)
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			t.Fatal(err)
		}
		// Re-encoded and renamed in the base: the decision, not the bytes
		// or the name, is compared.
		f.write(t, f.base, "b-20261001-9.json", compact.Bytes())
		f.write(t, f.head, "b-20261001-9.json", compact.Bytes())
		requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), "already in the base")
	})
	t.Run("later batch decision in the base", func(t *testing.T) {
		f := newBatchFixture(t, 3)
		rec := f.record(t)
		f.signAndWrite(t, rec)
		later := rec
		later.BatchID, later.CandidateID = "b-20261003-9", "pr-6"
		later.DecidedAt = signNow.Add(time.Minute).Format(time.RFC3339)
		laterRaw := f.key.signBatch(t, later)
		f.write(t, f.base, later.BatchID+".json", laterRaw)
		f.write(t, f.head, later.BatchID+".json", laterRaw)
		requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), "made at the same time or later")
	})
	t.Run("later per-entry approval in the base", func(t *testing.T) {
		f := newBatchFixture(t, 3)
		f.signAndWrite(t, f.record(t))
		v2 := ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:" + strings.Repeat("0", 64), CandidateID: "pr-5", DecidedAt: signNow.Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: f.ids[1]}
		writeFile(t, approvalPath(f.base, f.ids[1]), f.key.sign(t, v2))
		writeFile(t, approvalPath(f.head, f.ids[1]), f.key.sign(t, v2))
		requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), "decided at the same time or later")
	})
	t.Run("earlier per-entry approval in the base is no obstacle", func(t *testing.T) {
		f := newBatchFixture(t, 3)
		f.signAndWrite(t, f.record(t))
		v2 := ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:" + strings.Repeat("0", 64), CandidateID: "pr-5", DecidedAt: signNow.Add(-time.Hour).Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: f.ids[1]}
		writeFile(t, approvalPath(f.base, f.ids[1]), f.key.sign(t, v2))
		writeFile(t, approvalPath(f.head, f.ids[1]), f.key.sign(t, v2))
		requirePass(t, runGate(t, Options{Base: f.base, Head: f.head}))
	})
}

// The batch directory is append-only while a batch could still verify.
func TestBatchFilesAreKept(t *testing.T) {
	f := newBatchFixture(t, 2)
	rec := f.record(t)
	raw := f.key.signBatch(t, rec)
	// The batch merged: base and head both hold it, and the next change
	// touches it.
	f.write(t, f.base, testBatchID+".json", raw)
	head := copyTree(t, f.base)
	recordsCheck := func(t *testing.T, opts Options) Check {
		t.Helper()
		opts.Base, opts.Head = f.base, head
		c, ok := check(runGate(t, opts), "knowledge-records")
		if !ok {
			t.Fatal("no knowledge-records check")
		}
		return c
	}
	t.Run("changed", func(t *testing.T) {
		f.write(t, head, testBatchID+".json", append(raw, '\n'))
		if c := recordsCheck(t, Options{}); c.OK || !strings.Contains(c.Detail, "never changed") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("removed while live", func(t *testing.T) {
		if err := os.Remove(batchFilePath(head, testBatchID+".json")); err != nil {
			t.Fatal(err)
		}
		if c := recordsCheck(t, Options{}); c.OK || !strings.Contains(c.Detail, "could still verify") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("removed once expired", func(t *testing.T) {
		if c := recordsCheck(t, Options{Now: signNow.Add(MaxBatchValidity)}); !c.OK {
			t.Fatalf("%+v", c)
		}
	})
}

// A record approval older than a merged batch decision for the record
// cannot replace it.
func TestRecordApprovalBehindBatch(t *testing.T) {
	base, _ := trees(t)
	key := newApprovalKey(t)
	id := attestationID("1.25")
	scope := recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64)).Scope
	rec := BatchRecord{
		BatchID: testBatchID, CandidateID: "pr-7", ChangeSetDigest: "sha256:" + strings.Repeat("1", 64), CitationsDigest: "sha256:" + strings.Repeat("2", 64),
		DecidedAt: gateNow.Format(time.RFC3339), Decision: "approve", Identity: "airstand", Nonce: testNonce, NotAfter: gateNow.Add(time.Hour).Format(time.RFC3339),
		Entries: []BatchEntry{{BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:" + strings.Repeat("3", 64), ID: id, Pack: "cncf", Scope: scope, Subject: BatchSubjectLineAttestation}},
		Packs:   []BatchPack{{Base: ApprovalBaseAbsent, Head: ApprovalBaseAbsent, Pack: "cncf"}}, Sample: []int{0}, SummaryDigest: "sha256:" + strings.Repeat("4", 64),
	}
	writeFile(t, batchFilePath(base, testBatchID+".json"), key.signBatch(t, rec))
	approvals := &baseApprovals{opts: Options{Base: base, Layout: DefaultLayout(), Now: gateNow}}
	older := key.sign(t, recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64)))
	if why, err := approvals.refuse(older); err != nil || !strings.Contains(why, "batch decision") {
		t.Fatalf("older record approval: %q %v", why, err)
	}
	newer := recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64))
	newer.DecidedAt = gateNow.Add(time.Minute).Format(time.RFC3339)
	if why, err := approvals.refuse(key.sign(t, newer)); err != nil || why != "" {
		t.Fatalf("newer record approval: %q %v", why, err)
	}
}

func TestBatchLineAttestation(t *testing.T) {
	for line, want := range map[string]string{"1.25": "", "1.33": "cross-check with the extractor"} {
		t.Run(line, func(t *testing.T) {
			base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22", line}, nil)
			key := newApprovalKey(t)
			key.pinBoth(t, base, head, "airstand")
			f := batchFixture{base: base, head: head, key: key}
			rec := f.record(t)
			if len(rec.Entries) != 1 || rec.Entries[0].Subject != BatchSubjectLineAttestation || rec.Entries[0].ID != attestationID(line) {
				t.Fatalf("entries %+v", rec.Entries)
			}
			f.signAndWrite(t, rec)
			r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource})
			c := change(t, r, attestationID(line))
			if want == "" {
				requireAdmittedButUnsplit(t, r)
				if c.Proof != ProofBatchApproval {
					t.Fatalf("change %+v", c)
				}
				return
			}
			if c.OK || !strings.Contains(c.Detail, want) {
				t.Fatalf("change %+v", c)
			}
		})
	}
}

func TestBatchSample(t *testing.T) {
	for n, want := range map[int]int{1: 1, 2: 2, 3: 3, 4: 3, 30: 3, 31: 4, 49: 5, 50: 5} {
		if got := batchSampleSize(n); got != want {
			t.Fatalf("sample size of %d: %d, want %d", n, got, want)
		}
	}
	entries := make([]BatchEntry, 50)
	for i := range entries {
		entries[i] = BatchEntry{ID: "r" + string(rune('a'+i/26)) + string(rune('a'+i%26)), Pack: "cncf", Subject: BatchSubjectRule}
	}
	core := batchCore{BatchID: testBatchID, Entries: entries, Nonce: testNonce}
	a, b := mustSample(t, core), mustSample(t, core)
	if !equalInts(a, b) || len(a) != 5 {
		t.Fatalf("not deterministic: %v %v", a, b)
	}
	counts := make([]int, 50)
	const trials = 4000
	for i := 0; i < trials; i++ {
		core.Nonce = fmt.Sprintf("%032x", i)
		s := mustSample(t, core)
		for j, x := range s {
			if x < 0 || x >= 50 || (j > 0 && s[j-1] >= x) {
				t.Fatalf("sample %v", s)
			}
			counts[x]++
		}
	}
	// Each entry is drawn with probability 5/50: 400 expected per entry.
	for i, c := range counts {
		if c < 280 || c > 520 {
			t.Fatalf("entry %d drawn %d times of %d", i, c, trials)
		}
	}
}

func TestTermSafe(t *testing.T) {
	if got := termSafe("a‮b\x1bc\n|"); got != `a\u{202E}b\u{001B}c`+"\n|" {
		t.Fatalf("%q", got)
	}
	if got := cell("x|y\nz"); got != `x\|y z` {
		t.Fatalf("%q", got)
	}
}
