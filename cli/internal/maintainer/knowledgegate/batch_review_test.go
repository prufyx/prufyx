// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Tests added by the review of the batch approval: forward-only in both
// directions between batches and per-entry approvals, the time boundaries,
// the refusals inside the batch path, the owner-facing summary and the
// golden vectors of the format shared by signer and gate.

// batchWith is a hand-built batch of the base: entries with decidedAt.
func batchWith(id, decidedAt string, entries ...BatchEntry) BatchEnvelope {
	return BatchEnvelope{Schema: BatchSchema, Record: BatchRecord{BatchID: id, DecidedAt: decidedAt, Entries: entries}, Signature: "sig-" + id}
}

func ruleEntry(pack, id string) BatchEntry {
	return BatchEntry{Pack: pack, ID: id, Subject: BatchSubjectRule}
}

func recordEntry(pack, id string) BatchEntry {
	return BatchEntry{Pack: pack, ID: id, Subject: BatchSubjectLineAttestation}
}

func otherPack(t *testing.T) string {
	t.Helper()
	for _, spec := range DefaultLayout().Packs {
		if spec.Name != "cncf" {
			return spec.Name
		}
	}
	t.Fatal("the layout has one pack only")
	return ""
}

// A per-entry approval of a rule is refused behind a base batch entry for the
// same rule decided at the same time or later: forward-only for rules runs in
// both directions, like it does for records.
func TestRuleApprovalBehindBatch(t *testing.T) {
	key := newApprovalKey(t)
	decided := gateNow.Add(-time.Hour)
	setup := func(t *testing.T, batchAt time.Time, pack string) (Tree, Tree, string) {
		base, head, id, digest := approvalTrees(t)
		key.pinBoth(t, base, head, "airstand")
		writeFile(t, approvalPath(head, id), key.sign(t, ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: digest, CandidateID: "cand-1", DecidedAt: decided.Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id}))
		env := batchWith("b-20261001-1", batchAt.Format(time.RFC3339), ruleEntry(pack, id))
		raw := key.signBatch(t, env.Record)
		f := batchFixture{}
		f.write(t, base, "b-20261001-1.json", raw)
		f.write(t, head, "b-20261001-1.json", raw)
		return base, head, id
	}
	for name, tc := range map[string]struct {
		batchAt time.Duration // relative to the approval's decidedAt
		pack    string
		refused bool
	}{
		"batch later":              {time.Second, "cncf", true},
		"batch at the same time":   {0, "cncf", true},
		"batch earlier":            {-time.Second, "cncf", false},
		"batch of another pack":    {time.Second, otherPack(t), false},
		"batch of another pack eq": {0, otherPack(t), false},
	} {
		t.Run(name, func(t *testing.T) {
			base, head, id := setup(t, decided.Add(tc.batchAt), tc.pack)
			r := runGate(t, Options{Base: base, Head: head})
			c := change(t, r, id)
			if tc.refused {
				if c.OK || !strings.Contains(c.Detail, "batch decision about this rule") {
					t.Fatalf("change %+v", c)
				}
				return
			}
			if !c.OK || c.Proof != ProofApproval {
				t.Fatalf("change %+v", c)
			}
		})
	}
}

// Record ids do not name a pack, so forward-only between per-entry approvals
// and batches ignores the pack of a record, whichever side holds the later
// decision; rule ids belong to their pack.
func TestForwardOnlyPackScoping(t *testing.T) {
	other := otherPack(t)
	at := gateNow.Add(-time.Hour)
	id := attestationID("1.25")
	scope := recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64)).Scope
	rec := func(pack string) BatchEntry {
		e := recordEntry(pack, id)
		e.Scope = scope
		return e
	}
	approvalInPack := func(t *testing.T, key testApprovalKey, base Tree, dirPack, subject, ruleID string, when time.Time) {
		t.Helper()
		a := ApprovalRecord{BaseDigest: ApprovalBaseAbsent, CandidateDigest: "sha256:" + strings.Repeat("0", 64), CandidateID: "cand-1", DecidedAt: when.Format(time.RFC3339), Decision: "approve", Identity: "airstand", Pack: dirPack, RuleID: ruleID}
		if subject != "" {
			a.Subject, a.Scope = subject, scope
		}
		writeFile(t, fmt.Sprintf("%s/%s/%s/%s.json", base.Root, DefaultLayout().ApprovalDir, dirPack, ruleID), key.sign(t, a))
	}
	refuse := func(base Tree, head BatchEnvelope) string {
		why, err := (&baseApprovals{opts: Options{Base: base, Layout: DefaultLayout()}}).refuseBatch(head)
		if err != nil {
			t.Fatal(err)
		}
		return why
	}
	key := newApprovalKey(t)
	t.Run("record: batch in one pack, approval in another", func(t *testing.T) {
		for name, tc := range map[string]struct {
			approvalAt time.Duration
			refused    bool
		}{"approval later": {time.Second, true}, "approval at the same time": {0, true}, "approval earlier": {-time.Second, false}} {
			t.Run(name, func(t *testing.T) {
				base, _ := trees(t)
				approvalInPack(t, key, base, other, ApprovalSubjectLineAttestation, id, at.Add(tc.approvalAt))
				why := refuse(base, batchWith("b-20261003-1", at.Format(time.RFC3339), rec("cncf")))
				if tc.refused != strings.Contains(why, "approval for lineAttestation") || (!tc.refused && why != "") {
					t.Fatalf("refused %q", why)
				}
			})
		}
	})
	t.Run("record: batch against a base batch of another pack", func(t *testing.T) {
		base, _ := trees(t)
		f := batchFixture{}
		older := batchWith("b-20261002-1", at.Add(time.Second).Format(time.RFC3339), rec(other))
		f.write(t, base, "b-20261002-1.json", key.signBatch(t, older.Record))
		if why := refuse(base, batchWith("b-20261003-1", at.Format(time.RFC3339), rec("cncf"))); !strings.Contains(why, "made at the same time or later") {
			t.Fatalf("refused %q", why)
		}
	})
	t.Run("rule: another pack is no obstacle", func(t *testing.T) {
		base, _ := trees(t)
		approvalInPack(t, key, base, other, "", "some.rule", at.Add(time.Minute))
		f := batchFixture{}
		f.write(t, base, "b-20261002-1.json", key.signBatch(t, batchWith("b-20261002-1", at.Add(time.Minute).Format(time.RFC3339), ruleEntry(other, "some.rule")).Record))
		if why := refuse(base, batchWith("b-20261003-1", at.Format(time.RFC3339), ruleEntry("cncf", "some.rule"))); why != "" {
			t.Fatalf("refused %q", why)
		}
		approvalInPack(t, key, base, "cncf", "", "some.rule", at.Add(time.Minute))
		if why := refuse(base, batchWith("b-20261003-1", at.Format(time.RFC3339), ruleEntry("cncf", "some.rule"))); !strings.Contains(why, "approval for rule") {
			t.Fatalf("refused %q", why)
		}
	})
	t.Run("record approval against a base batch of another pack", func(t *testing.T) {
		base, _ := trees(t)
		f := batchFixture{}
		f.write(t, base, "b-20261002-1.json", key.signBatch(t, batchWith("b-20261002-1", at.Format(time.RFC3339), rec(other)).Record))
		approvals := &baseApprovals{opts: Options{Base: base, Layout: DefaultLayout()}}
		older := recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64))
		older.DecidedAt = at.Format(time.RFC3339)
		if why, err := approvals.refuse(key.sign(t, older)); err != nil || !strings.Contains(why, "batch decision") {
			t.Fatalf("refused %q %v", why, err)
		}
		older.DecidedAt = at.Add(time.Second).Format(time.RFC3339)
		if why, err := approvals.refuse(key.sign(t, older)); err != nil || why != "" {
			t.Fatalf("refused %q %v", why, err)
		}
	})
}

// The refusals inside the batch path: a change a batch may not approve is
// refused whatever else the batch holds.
func TestBatchRefusesForbiddenChanges(t *testing.T) {
	good := func() *Change {
		return &Change{Pack: "cncf", RuleID: "rule.ok", Class: ClassLoosening, Kinds: []string{KindRenew}, Basis: constraintengine.BasisReviewed, head: &entry{RuleID: "rule.ok", Canonical: []byte("{}\n")}}
	}
	for name, tc := range map[string]struct {
		chains []string
		extra  *Change
		want   string
	}{
		"supersede half": {nil, &Change{Pack: "cncf", RuleID: "rule.sup", Class: ClassLoosening, Kinds: []string{KindNew}, Basis: constraintengine.BasisReviewed, head: &entry{RuleID: "rule.sup", Canonical: []byte("{}\n")}, supersedes: &Change{}}, "half of a supersede pair"},
		"removed rule":   {nil, &Change{Pack: "cncf", RuleID: "rule.gone", Class: ClassLoosening, Kinds: []string{KindRemove}, Basis: constraintengine.BasisReviewed}, "is removed"},
		"path policy":    {nil, &Change{Pack: "cncf", Section: sectionPolicies, RuleID: "pol", Class: ClassLoosening, Kinds: []string{KindModify}, rhead: &record{ID: "pol", Basis: constraintengine.BasisReviewed}}, "path policy"},
		"chain":          {[]string{"cncf"}, nil, "statement chain of cncf changed"},
		"pack member":    {nil, &Change{Pack: "cncf", Member: "other", Class: ClassLoosening, Kinds: []string{KindPackMember}}, "pack member"},
		"mechanical to reviewed attestation": {nil, &Change{Pack: "cncf", Section: sectionAttestations, RuleID: "att", Class: ClassLoosening, Kinds: []string{KindBasis},
			rbase: &record{ID: "att", Basis: constraintengine.BasisMechanical}, rhead: &record{ID: "att", Basis: constraintengine.BasisReviewed, Scope: "x"}}, "turns a mechanical record into a reviewed one"},
	} {
		t.Run(name, func(t *testing.T) {
			cls := &Classification{Changes: []*Change{good()}, ChainsChanged: tc.chains}
			if tc.extra != nil {
				cls.Changes = append(cls.Changes, tc.extra)
			}
			st, err := newBatchState(DefaultLayout(), cls)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.readyForBatch(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ready: %v, want %q", err, tc.want)
			}
		})
	}
	// Without the forbidden change the same state is ready.
	st, err := newBatchState(DefaultLayout(), &Classification{Changes: []*Change{good()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.readyForBatch(); err != nil {
		t.Fatal(err)
	}
}

// A real change from a mechanical attestation to a reviewed one is a
// problem the signer refuses (PR #60: only the gate's re-derivation makes a
// record mechanical, and an owner approval never turns one reviewed).
func TestBatchRefusesMechanicalToReviewedAttestation(t *testing.T) {
	base, head := trees(t)
	editPack(t, base, cncfRulesPath, func(p *packDoc) { setAttestations(t, p, []map[string]any{derivedAttestation(t, "1.31")}) })
	editPack(t, head, cncfRulesPath, func(p *packDoc) { setAttestations(t, p, []map[string]any{reviewedAttestation(t, p, "1.31")}) })
	cls, err := Classify(DefaultLayout(), base, head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newBatchState(DefaultLayout(), cls)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.readyForBatch(); err == nil || !strings.Contains(err.Error(), "turns a mechanical record into a reviewed one") {
		t.Fatalf("ready: %v", err)
	}
}

// The entry's scope is signed and bound by the comparison with the scope
// the gate derives from the record.
func TestBatchEntryScopeIsCompared(t *testing.T) {
	base, head := attestedTrees(t, []string{"1.22"}, []string{"1.22", "1.25"}, nil)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, "airstand")
	f := batchFixture{base: base, head: head, key: key}
	rec := f.record(t)
	if len(rec.Entries) != 1 || rec.Entries[0].Subject != BatchSubjectLineAttestation {
		t.Fatalf("entries %+v", rec.Entries)
	}
	rec.Entries[0].Scope = strings.TrimSuffix(rec.Entries[0].Scope, "1.25") + "1.26"
	f.reseal(t, &rec)
	f.signAndWrite(t, rec)
	requireFail(t, runGate(t, Options{Base: base, Head: head, Source: fixtureSource}), "scope differs")
}

// The nonce the signing tool draws is part of what the sample is drawn from:
// the same change signed with other nonces gets other samples.
func TestBatchSampleDependsOnNonce(t *testing.T) {
	f := newBatchFixture(t, 30)
	st := f.state(t)
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		rec, _, err := st.draftRecord(testBatchID, "pr-7", fmt.Sprintf("%032x", i+1))
		if err != nil {
			t.Fatal(err)
		}
		if want := mustSample(t, rec.core()); !equalInts(want, rec.Sample) {
			t.Fatalf("draft sample %v is not the sample of its core %v", rec.Sample, want)
		}
		seen[fmt.Sprint(rec.Sample)] = true
	}
	if len(seen) < 6 {
		t.Fatalf("12 nonces gave only %d distinct samples: the nonce does not steer the draw", len(seen))
	}
	// A record signed with one nonce does not verify with another, sample
	// and all.
	rec := f.record(t)
	rec.Nonce = "ffeeddccbbaa99887766554433221100"
	f.signAndWrite(t, rec)
	requireFail(t, runGate(t, Options{Base: f.base, Head: f.head}), "the sample is not the one drawn")
}

// The gate refuses a batch signed with a key that is no longer valid, at the
// boundary.
func TestBatchSigningKeyExpiry(t *testing.T) {
	for name, tc := range map[string]struct {
		keyEnd time.Time
		want   string
	}{
		"expires now":    {gateNow, "signing key has expired"},
		"expired":        {gateNow.Add(-time.Hour), "signing key has expired"},
		"expires in 1s":  {gateNow.Add(time.Second), ""},
		"expires in 1 h": {gateNow.Add(time.Hour), ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 3)
			f.key.pinUntil(t, f.base, tc.keyEnd.Format(time.RFC3339), "airstand")
			f.key.pinUntil(t, f.head, tc.keyEnd.Format(time.RFC3339), "airstand")
			f.signAndWrite(t, f.record(t))
			r := runGate(t, Options{Base: f.base, Head: f.head})
			if tc.want != "" {
				requireFail(t, r, tc.want)
				return
			}
			requirePass(t, r)
			requireBatchProof(t, r, f.ids)
		})
	}
}

// The time window of a batch at its boundaries.
func TestBatchTimeBoundaries(t *testing.T) {
	for name, tc := range map[string]struct {
		decided  time.Time
		notAfter time.Time
		now      time.Time
		want     string
	}{
		"last second of validity": {signNow, signNow.Add(MaxBatchValidity), signNow.Add(MaxBatchValidity - time.Second), ""},
		"decided at the skew":     {gateNow.Add(approvalClockSkew), gateNow.Add(time.Hour), gateNow, ""},
		"decided past the skew":   {gateNow.Add(approvalClockSkew + time.Second), gateNow.Add(time.Hour), gateNow, "decided in the future"},
		"72 hours exactly":        {signNow, signNow.Add(MaxBatchValidity), gateNow, ""},
		"not after is decided at": {signNow, signNow, gateNow, "at most 72 hours"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 3)
			rec := f.record(t)
			rec.DecidedAt, rec.NotAfter = tc.decided.Format(time.RFC3339), tc.notAfter.Format(time.RFC3339)
			f.signAndWrite(t, rec)
			r := runGate(t, Options{Base: f.base, Head: f.head, Now: tc.now})
			if tc.want != "" {
				requireFail(t, r, tc.want)
				return
			}
			if c, ok := check(r, CheckBatch); !ok || !c.OK {
				t.Fatalf("batch check %+v", c)
			}
		})
	}
}

// The same-time boundary of forward-only: a decision made at the same
// second is as good as a later one, an earlier one is not.
func TestRecordApprovalBehindBatchBoundary(t *testing.T) {
	base, _ := trees(t)
	key := newApprovalKey(t)
	id := attestationID("1.25")
	scope := recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64)).Scope
	batchAt := gateNow.Add(-time.Hour)
	e := recordEntry("cncf", id)
	e.Scope = scope
	rec := batchWith(testBatchID, batchAt.Format(time.RFC3339), e).Record
	batchFixture{}.write(t, base, testBatchID+".json", key.signBatch(t, rec))
	approvals := &baseApprovals{opts: Options{Base: base, Layout: DefaultLayout()}}
	for name, tc := range map[string]struct {
		d       time.Duration
		refused bool
	}{"a second before": {-time.Second, true}, "same second": {0, true}, "a second after": {time.Second, false}} {
		t.Run(name, func(t *testing.T) {
			a := recordApproval(id, "1.25", ApprovalBaseAbsent, "sha256:"+strings.Repeat("0", 64))
			a.DecidedAt = batchAt.Add(tc.d).Format(time.RFC3339)
			why, err := approvals.refuse(key.sign(t, a))
			if err != nil || tc.refused != (why != "") {
				t.Fatalf("refused %q %v", why, err)
			}
		})
	}
	// The same boundary when a batch is offered behind a base batch.
	for name, tc := range map[string]struct {
		d       time.Duration
		refused bool
	}{"batch a second before": {-time.Second, true}, "batch same second": {0, true}, "batch a second after": {time.Second, false}} {
		t.Run(name, func(t *testing.T) {
			head := batchWith("b-20261003-9", batchAt.Add(tc.d).Format(time.RFC3339), e)
			why, err := approvals.refuseBatch(head)
			if err != nil || tc.refused != (why != "") {
				t.Fatalf("refused %q %v", why, err)
			}
		})
	}
}

// decodeBatch reads at most maxBatchBytes.
func TestDecodeBatchBound(t *testing.T) {
	if _, err := decodeBatch(make([]byte, maxBatchBytes+1)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("%v", err)
	}
	if _, err := decodeBatch(make([]byte, maxBatchBytes)); err == nil || strings.Contains(err.Error(), "too large") {
		t.Fatalf("%v", err)
	}
}

// The owner sees every sampled entry and every flagged entry in full, with
// the base and the proposed text; modify is flagged.
func TestBatchSummaryShowsSampledAndFlaggedInFull(t *testing.T) {
	f := newBatchFixture(t, 30)
	edited := f.ids[7]
	editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
		e := p.find(t, edited)
		e["description"] = e["description"].(string) + " marker-text-for-the-owner"
	})
	st := f.state(t)
	idx := -1
	for i, e := range st.entries() {
		if e.ID == edited {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("the edited rule is no entry")
	}
	if c := st.items[idx].change; !containsKind(c.Kinds, KindModify) || !flaggedChange(c) {
		t.Fatalf("kinds %v are not flagged", c.Kinds)
	}
	// Find a nonce whose sample does not draw the edited rule: it is then
	// shown in full only because it is flagged.
	var rec BatchRecord
	var summary string
	for n := 1; ; n++ {
		var err error
		rec, summary, err = st.draftRecord(testBatchID, "pr-7", fmt.Sprintf("%032x", n))
		if err != nil {
			t.Fatal(err)
		}
		drawn := false
		for _, s := range rec.Sample {
			drawn = drawn || s == idx
		}
		if !drawn {
			break
		}
	}
	full := map[int]bool{idx: true}
	for _, s := range rec.Sample {
		full[s] = true
	}
	if got := strings.Count(summary, "\n### #"); got != len(full) {
		t.Fatalf("%d entries in full, want %d (sample %v + flagged #%d)", got, len(full), rec.Sample, idx)
	}
	for i := range rec.Entries {
		section := fmt.Sprintf("\n### #%d ", i)
		if strings.Contains(summary, section) != full[i] {
			t.Fatalf("entry %d in full: %v, want %v", i, strings.Contains(summary, section), full[i])
		}
	}
	for i := range full {
		rest := summary[strings.Index(summary, fmt.Sprintf("\n### #%d ", i)):]
		if end := strings.Index(rest[5:], "\n### #"); end > 0 {
			rest = rest[:end+5]
		}
		for _, want := range []string{"Base:", "Proposed:", "```json", `"id": "` + rec.Entries[i].ID + `"`} {
			if !strings.Contains(rest, want) {
				t.Fatalf("entry %d in full lacks %q:\n%s", i, want, rest)
			}
		}
		if (i == idx) != strings.Contains(rest, "marker-text-for-the-owner") {
			t.Fatalf("the edit shows in entry %d: %v", i, strings.Contains(rest, "marker-text-for-the-owner"))
		}
	}
	if !strings.Contains(summary, "flagged") || !strings.Contains(summary, "| sample") {
		t.Fatal("the table does not say why an entry is read in full")
	}
	if got := st.flaggedIndexes(rec); len(got) != 1 || got[0] != idx {
		t.Fatalf("flagged %v, want [%d]", got, idx)
	}
}

// Every kind a reviewed edit can have is either flagged or a plain
// renewal-like edit; reactivation, widening, narrowing, range changes, basis
// changes and modification are always read.
func TestBatchFlaggedKinds(t *testing.T) {
	for _, k := range []string{KindReactivate, KindBasis, KindWiden, KindNarrow, KindRangeChange, KindModify} {
		if !batchFlaggedKinds[k] {
			t.Fatalf("%s is not flagged", k)
		}
	}
	for _, k := range []string{KindNew, KindRenew, KindRepin} {
		if batchFlaggedKinds[k] {
			t.Fatalf("%s is flagged", k)
		}
	}
}

// The "Other changes" table is bounded, led by counts, and cannot push the
// entries out of view.
func TestBatchSummaryBoundsOtherChanges(t *testing.T) {
	cls := &Classification{}
	good := &Change{Pack: "cncf", RuleID: "rule.ok", Class: ClassLoosening, Kinds: []string{KindRenew}, Basis: constraintengine.BasisReviewed, head: &entry{RuleID: "rule.ok", Canonical: []byte("{}\n")}}
	cls.Changes = append(cls.Changes, good)
	const others = 250
	for i := 0; i < others; i++ {
		cls.Changes = append(cls.Changes, &Change{Pack: "cncf", RuleID: fmt.Sprintf("rule.t%03d", i), Class: ClassTightening, Kinds: []string{KindWithdraw}, Basis: constraintengine.BasisReviewed})
	}
	cls.Changes = append(cls.Changes, &Change{Pack: "cncf", Member: "extra", Class: ClassLoosening, Kinds: []string{KindPackMember}})
	st, err := newBatchState(DefaultLayout(), cls)
	if err != nil {
		t.Fatal(err)
	}
	rec, summary, err := st.draftRecord(testBatchID, "pr-7", testNonce)
	if err != nil {
		t.Fatal(err)
	}
	head := summary[:strings.Index(summary, "\n## Entries")]
	if !strings.Contains(head, "Other changes not approved by this batch: 251.") {
		t.Fatalf("the header lacks the count:\n%s", head)
	}
	for _, want := range []string{"## Other changes in this change (251)", "By class: pack member 1, tightening 250.", "151 more changes are not listed (the first 100 are)"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary lacks %q:\n%s", want, summary)
		}
	}
	table := summary[strings.Index(summary, "| Pack | Section | ID | Class"):strings.Index(summary, "151 more")]
	if rows := strings.Count(table, "\n| cncf |"); rows != batchOtherRows {
		t.Fatalf("%d rows in the other-changes table, want %d", rows, batchOtherRows)
	}
	if strings.Index(summary, "## Entries (1)") > strings.Index(summary, "## Other changes") {
		t.Fatal("the entries come after the other changes")
	}
	if len(rec.Entries) != 1 || rec.Entries[0].ID != "rule.ok" {
		t.Fatalf("entries %+v", rec.Entries)
	}
	// Up to the bound the table is complete.
	cls.Changes = cls.Changes[:1+batchOtherRows]
	st, err = newBatchState(DefaultLayout(), cls)
	if err != nil {
		t.Fatal(err)
	}
	_, summary, err = st.draftRecord(testBatchID, "pr-7", testNonce)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary, "are not listed") || strings.Count(summary, "\n| cncf | entries |") != batchOtherRows {
		t.Fatalf("summary of exactly %d other changes is cut:\n%s", batchOtherRows, summary)
	}
}

// Golden vectors of the format signer and gate share. Each value was
// computed by an independent implementation of the documented format
// (compact JSON, the domain prefix, SHA-256), not by this code, so a silent
// change to a field, its order, a domain string or the sample draw shows up
// here and not as a signature that suddenly fails to verify in production.
func TestBatchGoldenVectors(t *testing.T) {
	a, b, c := "sha256:"+strings.Repeat("aa", 32), "sha256:"+strings.Repeat("bb", 32), "sha256:"+strings.Repeat("cc", 32)
	t.Run("change set", func(t *testing.T) {
		got, err := changeSetDigestOf([]changeSetItem{
			{Pack: "cncf", ID: "rule.a", Class: "loosening", Kinds: []string{"renew", "repin"}, Basis: "reviewed", Project: "p", Base: a, Head: b},
			{Pack: "cncf", Section: "lineAttestations", ID: "rec1", Class: "tightening", Base: b, Head: ApprovalBaseAbsent},
		}, []string{"cncf"}, false)
		if err != nil || got != "sha256:d899d6baee948ae4186de735a3bcfe1291953adae311fd0ca56fd0846987e97e" {
			t.Fatalf("%s %v", got, err)
		}
	})
	t.Run("citations", func(t *testing.T) {
		got, err := citationsDigestOf([]batchCitation{
			{Pack: "cncf", Subject: "rule", ID: "rule.a", Sources: []byte(`[{"url":"https://example.org/a"}]`)},
			{Pack: "cncf", Subject: "lineAttestation", ID: "rec1", Sources: []byte("null")},
		})
		if err != nil || got != "sha256:2d1aa563459690b58879ef5e059460f72ddcb9da4c290a6d86b5011e7e753076" {
			t.Fatalf("%s %v", got, err)
		}
	})
	t.Run("signed bytes", func(t *testing.T) {
		raw, err := SignedBatchBytes(BatchRecord{
			BatchID: testBatchID, CandidateID: "pr-7", ChangeSetDigest: a, CitationsDigest: b, DecidedAt: "2026-10-03T11:00:00Z", Decision: "approve",
			Entries: []BatchEntry{
				{BaseDigest: b, CandidateDigest: c, ID: "rec1", Pack: "cncf", Scope: "pkg:generic/k8s removed-served-gvk 1.25", Subject: BatchSubjectLineAttestation},
				{BaseDigest: ApprovalBaseAbsent, CandidateDigest: a, ID: "rule.a", Pack: "cncf", Subject: BatchSubjectRule},
			},
			Identity: "airstand", Nonce: testNonce, NotAfter: "2026-10-06T11:00:00Z",
			Packs: []BatchPack{{Base: a, Head: b, Pack: "cncf"}}, Sample: []int{0, 1}, SummaryDigest: c,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(raw), "prufyx.io/knowledge-approval-batch/v1\x00{\"batchId\":\"b-20261003-1\",\"candidateId\":\"pr-7\",\"changeSetDigest\"") {
			t.Fatalf("prefix %q", raw[:120])
		}
		if got := CandidateDigest(raw); got != "sha256:5e58bc99b1b85f45bfd1c871903858c6557dee43704f93fef80ee5fa828e2dc0" || len(raw) != 1175 {
			t.Fatalf("%s %d", got, len(raw))
		}
	})
	t.Run("sample", func(t *testing.T) {
		entries := make([]BatchEntry, 50)
		for i := range entries {
			entries[i] = BatchEntry{BaseDigest: ApprovalBaseAbsent, CandidateDigest: a, ID: fmt.Sprintf("rule.%02d", i), Pack: "cncf", Subject: BatchSubjectRule}
		}
		got := mustSample(t, batchCore{BatchID: testBatchID, CandidateID: "pr-7", ChangeSetDigest: a, CitationsDigest: b, Entries: entries, Nonce: testNonce, Packs: []BatchPack{{Base: a, Head: b, Pack: "cncf"}}})
		if !equalInts(got, []int{15, 22, 34, 38, 45}) {
			t.Fatalf("%v", got)
		}
	})
}
