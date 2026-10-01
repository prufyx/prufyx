// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// ---------------------------------------------------------------------
// Append-only against the base branch's chain
// ---------------------------------------------------------------------

func chainOf(f *chainFixture, entries ...ChainEntry) *Chain {
	return &Chain{Entries: entries, TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
}

func signedEntry(t *testing.T, f *chainFixture, name string, statement Statement) ChainEntry {
	t.Helper()
	raw, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	return ChainEntry{Name: name, Statement: raw, Envelope: f.sign(raw)}
}

func pendingSpecs(n int, at time.Time) []ruleSpec {
	specs := cycleSpecs(n, at)
	for i := range specs {
		specs[i].class = evidencerepin.ClassPending
	}
	return specs
}

func TestVerifyRejectsChainNotExtendingBase(t *testing.T) {
	f, _, c2, _, t3 := twoCycleChain(t)
	e := f.entries
	honest := prepareCycle(t, f, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	honestEntry := ChainEntry{Name: "0003", Statement: honest.res.StatementCanonical, Envelope: f.sign(honest.res.StatementCanonical)}
	base := chainOf(f, e[0], e[1])

	if err := verifyCycleAgainstBase(honest, base, chainOf(f, e[0], e[1])); err != nil {
		t.Fatalf("a chain equal to its base must verify: %v", err)
	}
	if err := verifyCycleAgainstBase(honest, base, chainOf(f, e[0], e[1], honestEntry)); err != nil {
		t.Fatalf("a chain adding only the statement under verification must verify: %v", err)
	}
	if err := verifyCycleAgainstBase(honest, base, chainOf(f, honestEntry, e[1], e[0])); err != nil {
		t.Fatalf("entry order in the supplied chain is not significant: %v", err)
	}

	// The whole chain deleted, and a statement prepared as if the pack had
	// no history: every count would restart.
	reset := prepareCycle(t, newChainFixture(t), c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	resetEntry := ChainEntry{Name: "0001", Statement: reset.res.StatementCanonical, Envelope: f.sign(reset.res.StatementCanonical)}

	otherAttestedAt := c2.res.Statement
	otherAttestedAt.Pack.Next.Revision = "rev-3-resigned"
	resigned := signedEntry(t, f, "0002", otherAttestedAt)
	reEnveloped := ChainEntry{Name: e[1].Name, Statement: e[1].Statement, Envelope: newChainFixture(t).sign(e[1].Statement)}

	for name, tc := range map[string]struct {
		c     cycle
		base  *Chain
		chain *Chain
		want  string
	}{
		"whole chain deleted":                   {honest, base, chainOf(f), "base chain entry 0001 is missing or changed"},
		"whole chain deleted, reset statement":  {reset, base, chainOf(f, resetEntry), "is missing or changed"},
		"latest entry dropped":                  {honest, base, chainOf(f, e[0]), "base chain entry 0002 is missing or changed"},
		"entry replaced by a re-signed variant": {honest, base, chainOf(f, e[0], resigned), "base chain entry 0002 is missing or changed"},
		"entry envelope replaced":               {honest, base, chainOf(f, e[0], reEnveloped), "base chain entry 0002 is missing or changed"},
		"two entries added":                     {honest, base, chainOf(f, e[0], e[1], honestEntry, resigned), "adds 2 entries"},
		"other entry added":                     {honest, base, chainOf(f, e[0], e[1], resigned), "is added to the base chain but is not the statement under verification"},
		"statement already in base":             {c2, base, chainOf(f, e[0], e[1]), "already recorded in the base branch's statement chain"},
		"no base chain":                         {honest, nil, chainOf(f, e[0], e[1]), "the base branch's statement chain is required"},
	} {
		err := verifyCycleAgainstBase(tc.c, tc.base, tc.chain)
		if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: expected a V5 error containing %q, got %v", name, tc.want, err)
		}
	}
}

// A signer can sign a statement that renews nothing, links to an older
// chain entry, and is dated after the real head; with the later entries
// dropped from the supplied chain, the chain alone is self-consistent.
// Only the base branch's chain shows that entries were removed.
func TestVerifyRejectsRenewNothingStatementDroppingLaterEntries(t *testing.T) {
	f, c1, _, _, t3 := twoCycleChain(t)
	e := f.entries
	dropped := chainOf(f, e[0])
	renewNothing := prepareCycle(t, &chainFixture{t: t, key: f.key, root: f.root, digest: f.digest, entries: []ChainEntry{e[0]}},
		c1.res.NextPack, t3, pendingSpecs(12, t3), "rev-x", nil)
	if len(renewNothing.res.Statement.Rules) != 0 {
		t.Fatalf("setup: expected a statement that renews nothing, got %d rules", len(renewNothing.res.Statement.Rules))
	}
	renewNothingEntry := ChainEntry{Name: "0002", Statement: renewNothing.res.StatementCanonical, Envelope: f.sign(renewNothing.res.StatementCanonical)}
	if err := verifyCycleAgainstBase(renewNothing, dropped, chainOf(f, e[0], renewNothingEntry)); err != nil {
		t.Fatalf("setup: the statement must be self-consistent against the shortened chain: %v", err)
	}
	err := verifyCycleAgainstBase(renewNothing, chainOf(f, e[0], e[1]), chainOf(f, e[0], renewNothingEntry))
	if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "base chain entry 0002 is missing or changed") {
		t.Fatalf("expected a V5 append-only error, got %v", err)
	}
}

// A prior-pack rule whose reviewedAt equals a chain entry's attestedAt
// must be one that entry renewed (with the validUntil it set) or recorded
// an individual review for.
func TestPriorPackDatesMustMatchTheChainEntryTheyClaim(t *testing.T) {
	f, _, c2, target, t3 := twoCycleChain(t)
	edit := func(ruleID string, mutate func(evidence map[string]any)) []byte {
		var doc packDocument
		if err := json.Unmarshal(c2.res.NextPack, &doc); err != nil {
			t.Fatal(err)
		}
		for i := range doc.Entries {
			fields, _ := parseRuleFields(doc.Entries[i].Rule)
			if fields.ID != ruleID {
				continue
			}
			var rule map[string]any
			_ = json.Unmarshal(doc.Entries[i].Rule, &rule)
			mutate(rule["evidence"].(map[string]any))
			doc.Entries[i].Rule, _ = json.Marshal(rule)
		}
		raw, err := buildNextPack(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	prepare := func(prior []byte, records map[string][]byte) error {
		wl, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
		_, err := Prepare(PrepareOptions{
			WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: f.chain(),
			Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: records,
		})
		return err
	}
	claimed := edit("past-007", func(evidence map[string]any) { evidence["reviewedAt"] = c2.res.Statement.AttestedAt })
	if err := prepare(claimed, nil); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "rule past-007 carries a chain entry's attestedAt as its reviewedAt but that entry neither renewed it") {
		t.Fatalf("expected a V5 error for a rule claiming a renewal the chain does not record, got %v", err)
	}
	if err := prepare(claimed, map[string][]byte{"past-007": testReviewRecord(t, claimed, "past-007", t3.Add(-time.Hour), "Individual Reviewer")}); err != nil {
		t.Fatalf("a new individual review must account for the edited dates: %v", err)
	}
	moved := edit(target, func(evidence map[string]any) { evidence["validUntil"] = rfc3339(t3.Add(80 * 24 * time.Hour)) })
	if err := prepare(moved, nil); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "not the validUntil that entry set") {
		t.Fatalf("expected a V5 error for a renewed rule whose validUntil drifted, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Individual review records: content, not only digest
// ---------------------------------------------------------------------

func TestReviewRecordsMustBindToRuleVersionAndChain(t *testing.T) {
	f, c1, c2, target, t3 := twoCycleChain(t)
	prior := c2.res.NextPack
	sampledInC2 := c2.res.Statement.SampledForFullReview[0].RuleID
	other := ""
	for _, ra := range c2.res.Statement.Rules {
		if ra.RuleID != target {
			other = ra.RuleID
			break
		}
	}
	reRendered := func(raw []byte, mutate func(record map[string]any)) []byte {
		var record map[string]any
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		mutate(record)
		out, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	prepare := func(records map[string][]byte) error {
		wl, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
		_, err := Prepare(PrepareOptions{
			WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: f.chain(),
			Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: records,
		})
		return err
	}
	good := testReviewRecord(t, prior, target, t3.Add(-time.Hour), "Individual Reviewer")
	if err := prepare(map[string][]byte{target: good}); err != nil {
		t.Fatalf("a valid new review record rejected: %v", err)
	}
	c2Record := c2.reviews[sampledInC2]
	for name, tc := range map[string]struct {
		records map[string][]byte
		want    string
	}{
		"another rule's record copied": {map[string][]byte{target: testReviewRecord(t, prior, other, t3.Add(-time.Hour), "Individual Reviewer")}, "names a different rule or project"},
		"wrong project": {map[string][]byte{target: reRendered(good, func(r map[string]any) {
			r["subject"].(map[string]any)["project"] = "another-project"
		})}, "names a different rule or project"},
		"older rule version":             {map[string][]byte{target: testReviewRecord(t, c1.res.NextPack, target, t3.Add(-time.Hour), "Individual Reviewer")}, "not bound to the rule's current version"},
		"already counted, byte appended": {map[string][]byte{sampledInC2: append(append([]byte(nil), c2Record...), ' ')}, "not bound to the rule's current version"},
		"not later than last review":     {map[string][]byte{sampledInC2: testReviewRecord(t, prior, sampledInC2, c2.at.Add(-2*time.Hour), "Another Reviewer")}, "is not later than the rule's last individual review recorded in the chain"},
		"decided after attestedAt":       {map[string][]byte{target: testReviewRecord(t, prior, target, t3.Add(time.Hour), "Individual Reviewer")}, "was decided after attestedAt"},
		"rule not in pack":               {map[string][]byte{"ghost-rule": good}, "review record ghost-rule names no rule in the pack"},
		"not a review record":            {map[string][]byte{target: []byte(`{"reviewed":true}`)}, "is not a well-formed review record"},
		"empty":                          {map[string][]byte{target: {}}, "is empty or too large"},
	} {
		err := prepare(tc.records)
		if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: expected a V5 error containing %q, got %v", name, tc.want, err)
		}
	}
}

// A review record the chain has already recorded stays in the review
// record directory for the next cycle: it is skipped, never counted again,
// and the rule it covered stays at its derived count. Exercised end to end
// through Prepare and Verify over a signed chain.
func TestReusedReviewRecordDoesNotResetConsecutiveCycles(t *testing.T) {
	f, c1, c2, _, t3 := twoCycleChain(t)
	reused := ""
	for _, sample := range c1.res.Statement.SampledForFullReview {
		if cyclesOf(c2, sample.RuleID) == 2 {
			reused = sample.RuleID
		}
	}
	if reused == "" {
		t.Fatal("setup: no rule reviewed in cycle 1 and batch-renewed in cycle 2")
	}
	c3 := prepareCycleWithRecords(t, f, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil, map[string][]byte{reused: c1.reviews[reused]})
	if cyclesOf(c3, reused) != -1 || worstClassOf(c3, reused) != reasonConsecutiveCycleCap {
		t.Fatalf("a reused review record reset %s: cycles=%d reason=%q", reused, cyclesOf(c3, reused), worstClassOf(c3, reused))
	}
	for _, review := range c3.res.Statement.IndividualReviews {
		if review.RuleID == reused {
			t.Fatalf("a reused review record was listed again as a new individual review: %+v", review)
		}
	}
	if err := verifyCycle(c3, f.chain()); err != nil {
		t.Fatalf("cycle 3 verify: %v", err)
	}

	// The same record listed again inside a signed statement is rejected.
	forged := c3.res.Statement
	forged.IndividualReviews = append([]IndividualReview{{RuleID: reused, ReviewRecordDigest: sourcecorpus.SHA(c1.reviews[reused])}}, forged.IndividualReviews...)
	sortReviews(forged.IndividualReviews)
	state, err := deriveChainState(f.chain(), PackCNCF, t3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV5(forged, state); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "already recorded earlier in the chain") {
		t.Fatalf("expected a V5 error for a review record listed twice in the chain, got %v", err)
	}
}

// signUnchecked signs statementRaw with f's key directly, without Sign's
// own refusal of an unreviewed sample, for simulations that model a
// maintainer who never supplies an individual review.
func signUnchecked(t *testing.T, f *chainFixture, statementRaw []byte) []byte {
	t.Helper()
	private, err := knowledgesign.DecryptPrivateKey(f.key, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	public := private.Public().(ed25519.PublicKey)
	keyID, err := keyIdentity(public)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := canonicalBytes(Envelope{
		SchemaVersion: EnvelopeSchema, StatementDigest: sourcecorpus.SHA(statementRaw),
		Signatures: []SignatureLine{{KeyID: keyID, Sig: hex.EncodeToString(ed25519.Sign(private, statementRaw))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func sortReviews(reviews []IndividualReview) {
	for i := 1; i < len(reviews); i++ {
		for j := i; j > 0 && reviews[j].RuleID < reviews[j-1].RuleID; j-- {
			reviews[j], reviews[j-1] = reviews[j-1], reviews[j]
		}
	}
}

// A rule not renewed in some cycle keeps its count; only a recorded
// individual review resets it.
func TestRuleNotRenewedInACycleKeepsItsCount(t *testing.T) {
	f := newChainFixture(t)
	t1 := baseNow
	_, pack := buildWorklistAndPack(t, chainPackPath, t1, cycleSpecs(12, t1))
	pack = padPackWithPastRules(t, pack, 80)
	c1 := prepareCycle(t, f, pack, t1, cycleSpecs(12, t1), "rev-2", nil)
	sampled := map[string]bool{}
	for _, sample := range c1.res.Statement.SampledForFullReview {
		sampled[sample.RuleID] = true
	}
	target := ""
	for _, ra := range c1.res.Statement.Rules {
		if !sampled[ra.RuleID] {
			target = ra.RuleID
			break
		}
	}
	f.append("0001", c1.res.StatementCanonical)

	t2 := t1.Add(cycleSpacing)
	specs2 := cycleSpecs(12, t2)
	for i := range specs2 {
		if specs2[i].id == target {
			specs2[i].repoResolvedAt = rfc3339(t2.Add(-100 * time.Hour)) // stale: not renewed this cycle
		}
	}
	c2 := prepareCycle(t, f, c1.res.NextPack, t2, specs2, "rev-3", nil)
	if cyclesOf(c2, target) != -1 || worstClassOf(c2, target) != reasonStaleBaseline {
		t.Fatalf("setup: expected %s not renewed in cycle 2, got cycles=%d reason=%q", target, cyclesOf(c2, target), worstClassOf(c2, target))
	}
	if err := verifyCycle(c2, f.chain()); err != nil {
		t.Fatalf("cycle 2 verify: %v", err)
	}
	f.append("0002", c2.res.StatementCanonical)

	t3 := t2.Add(cycleSpacing)
	wl, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
	c3, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: c2.res.NextPack, Chain: f.chain(),
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed := (cycle{res: c3}); cyclesOf(renewed, target) != 2 {
		t.Fatalf("expected %s renewed at count 2 in cycle 3, got %d", target, cyclesOf(renewed, target))
	}
}

// ---------------------------------------------------------------------
// Chain entries: each check on its own
// ---------------------------------------------------------------------

func TestChainRejectsGenesisEntryWithoutValidSignature(t *testing.T) {
	f, c1, _, _, t3 := twoCycleChain(t)
	untrusted := newChainFixture(t)
	for name, envelope := range map[string][]byte{
		"unsigned":      nil,
		"garbage":       []byte("{}"),
		"untrusted key": untrusted.sign(c1.res.StatementCanonical),
	} {
		chain := chainOf(f, ChainEntry{Name: "0001", Statement: c1.res.StatementCanonical, Envelope: envelope})
		if _, err := deriveChainState(chain, PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "chain entry 0001 has no valid signature") {
			t.Fatalf("%s genesis: expected a V5 signature error, got %v", name, err)
		}
	}
}

func TestChainRejectsLaterEntryWithoutValidSignature(t *testing.T) {
	f, _, _, _, t3 := twoCycleChain(t)
	e := f.entries
	reSigned := ChainEntry{Name: e[1].Name, Statement: e[1].Statement, Envelope: newChainFixture(t).sign(e[1].Statement)}
	if _, err := deriveChainState(chainOf(f, e[0], reSigned), PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "chain entry 0002 has no valid signature") {
		t.Fatalf("expected a V5 signature error for an otherwise valid entry signed by an untrusted key, got %v", err)
	}
}

func TestChainRejectsNonIncreasingAttestedAt(t *testing.T) {
	f, c1, c2, _, t3 := twoCycleChain(t)
	for name, at := range map[string]string{"equal": c1.res.Statement.AttestedAt, "earlier": rfc3339(c1.at.Add(-time.Hour))} {
		backdated := c2.res.Statement
		backdated.AttestedAt = at
		chain := chainOf(f, f.entries[0], signedEntry(t, f, "0002", backdated))
		if _, err := deriveChainState(chain, PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "attestedAt is not after the chain head's attestedAt") {
			t.Fatalf("%s: expected a V5 ordering error, got %v", name, err)
		}
	}
}

func TestChainRejectsSampledReviewNotRecordedAsIndividualReview(t *testing.T) {
	f, c1, _, _, t3 := twoCycleChain(t)
	forged := c1.res.Statement
	forged.SampledForFullReview = append([]SampledEntry(nil), forged.SampledForFullReview...)
	forged.SampledForFullReview[0].ReviewRecordDigest = "sha256:" + strings.Repeat("ab", 32)
	if _, err := deriveChainState(chainOf(f, signedEntry(t, f, "0001", forged)), PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "is not a new individual review recorded by this statement") {
		t.Fatalf("expected a V5 sample-link error, got %v", err)
	}
}

func TestChainRejectsIndividualReviewForRuleOutsideTheStatement(t *testing.T) {
	f, c1, _, _, t3 := twoCycleChain(t)
	forged := c1.res.Statement
	forged.IndividualReviews = append(append([]IndividualReview(nil), forged.IndividualReviews...), IndividualReview{RuleID: "zz-not-in-any-pack", ReviewRecordDigest: "sha256:" + strings.Repeat("ab", 32)})
	if _, err := deriveChainState(chainOf(f, signedEntry(t, f, "0001", forged)), PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "rule zz-not-in-any-pack has an individual review but is in neither") {
		t.Fatalf("expected a V5 error for an individual review of a rule outside the statement, got %v", err)
	}
}

// ---------------------------------------------------------------------
// The clock: nothing future-dated is prepared, signed, or built upon
// ---------------------------------------------------------------------

func TestFutureAttestedAtIsRejectedByPrepareSignAndChain(t *testing.T) {
	spec := freshSpec("rule-a", "proj-a", baseNow)
	wl, pack := buildWorklistAndPack(t, chainPackPath, baseNow, []ruleSpec{spec})
	opts := PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{},
		Wave: 1, AttestedAt: baseNow, Now: baseNow.Add(-time.Minute), NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	}
	if _, err := Prepare(opts); err == nil || !strings.Contains(err.Error(), "attestedAt is in the future") {
		t.Fatalf("expected Prepare to reject a future attestedAt, got %v", err)
	}
	opts.Now = time.Time{}
	if _, err := Prepare(opts); err == nil || !strings.Contains(err.Error(), "current time is required") {
		t.Fatalf("expected Prepare to require a clock, got %v", err)
	}
	opts.Now = baseNow
	opts.ReviewRecords = singleRecords(t, pack)
	res, err := Prepare(opts)
	if err != nil {
		t.Fatal(err)
	}
	f := newChainFixture(t)
	if _, err := Sign(SignOptions{Role: RoleHuman,
		Statement: res.StatementCanonical, TrustRoot: f.root, EncryptedKey: f.key, Passphrase: []byte(testPassphrase),
		ExpectedTrustRootDigest: f.digest, Now: baseNow.Add(-time.Second),
	}); err == nil || !strings.Contains(err.Error(), "attestedAt is in the future") {
		t.Fatalf("expected Sign to reject a future attestedAt, got %v", err)
	}
	f.append("0001", res.StatementCanonical)
	if _, err := deriveChainState(f.chain(), PackCNCF, baseNow.Add(-time.Second), ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "chain entry 0001 is attested after the current time") {
		t.Fatalf("expected a V5 error for a future-dated chain entry, got %v", err)
	}
	next := opts
	next.PackRaw = res.NextPack
	next.Chain = f.chain()
	next.AttestedAt = baseNow.Add(-time.Hour)
	next.Now = baseNow.Add(-time.Minute)
	next.ReviewRecords = nil
	if _, err := Prepare(next); err == nil || !strings.Contains(err.Error(), "is attested after the current time") {
		t.Fatalf("expected Prepare to refuse to build on a future-dated chain entry, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Renewal never moves validUntil earlier
// ---------------------------------------------------------------------

func TestPrepareRenewsOnlyRulesWhoseValidUntilMovesLater(t *testing.T) {
	// The waves whose slot dates come soonest and latest after baseNow.
	soonest, latest := 0, 0
	slots := map[int]time.Time{}
	for w := minWave; w <= maxWave; w++ {
		s, err := SlotDate(w, baseNow)
		if err != nil {
			t.Fatal(err)
		}
		slots[w] = s
		if soonest == 0 || s.Before(slots[soonest]) {
			soonest = w
		}
		if latest == 0 || s.After(slots[latest]) {
			latest = w
		}
	}
	slot := slots[soonest]
	if slot.Sub(baseNow) > renewalWindow-48*time.Hour || slots[latest].Sub(baseNow) < renewalWindow+48*time.Hour {
		t.Fatalf("setup: slots %s and %s do not straddle the renewal window", slot, slots[latest])
	}
	specs := cycleSpecs(4, baseNow)
	specs[0].validUntil = rfc3339(slot.Add(-24 * time.Hour))              // renewed: moves later
	specs[1].validUntil = rfc3339(slot)                                   // equal: not renewed
	specs[2].validUntil = rfc3339(slot.Add(24 * time.Hour))               // later already: not renewed
	specs[3].validUntil = rfc3339(baseNow.Add(renewalWindow + time.Hour)) // most of the lease left: not yet due
	wl, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 20)
	worklistRaw := marshalWorklist(t, wl)
	// Whichever renewed rule the seeded sample picks has a review record.
	records := map[string][]byte{}
	for _, id := range []string{"rule-00", "rule-01", "rule-02"} {
		records[id] = testReviewRecord(t, pack, id, baseNow.Add(-time.Hour), "Sample Reviewer")
	}
	for wave, want := range map[int]map[string]string{
		soonest: {"rule-01": reasonNotLaterThanCurrent, "rule-02": reasonNotLaterThanCurrent},
		latest:  {"rule-03": reasonNotYetDue},
	} {
		res, err := Prepare(PrepareOptions{
			WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{},
			Wave: wave, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: records,
		})
		if err != nil {
			t.Fatal(err)
		}
		c := cycle{res: res, worklistRaw: worklistRaw, prior: pack, at: baseNow, reviews: records}
		if cyclesOf(c, "rule-00") != 1 {
			t.Fatalf("wave %d: expected rule-00 renewed, got %q", wave, renewedIDs(res))
		}
		for id, reason := range want {
			if worstClassOf(c, id) != reason {
				t.Fatalf("wave %d: expected %s not extended with %s, got %q", wave, id, reason, worstClassOf(c, id))
			}
		}
		if err := verifyCycle(c, &Chain{}); err != nil {
			t.Fatalf("wave %d: Verify must recompute the same selection: %v", wave, err)
		}
	}
}

// Weekly batches over the real embedded packs, rotating through all seven
// waves, with every citation mechanically unchanged and no individual
// review ever supplied: no renewal may move a rule's validUntil earlier,
// and the consecutive-cycle cap must not be reached by most of the pack
// within a few weeks.
func TestWeeklyBatchSimulationOnRealPacks(t *testing.T) {
	const weeks = 16
	for _, tc := range []struct {
		pack, path string
		maxCapped  int
	}{
		{PackCNCF, filepath.Join("..", "..", "cncfcheck", "data", "rules.json"), 130},
		{PackCommunity, filepath.Join("..", "..", "projectcheck", "data", "rules.json"), 25},
	} {
		raw, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		f := newChainFixture(t)
		start := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
		renewals, notLater, notDue, lapsed := 0, 0, 0, 0
		capped := map[string]bool{}
		// lastRenewed and minGap track, per rule, the shortest time
		// between two consecutive batch renewals.
		lastRenewed := map[string]time.Time{}
		minGap := time.Duration(0)
		total := 0
		for week := 0; week < weeks; week++ {
			at := start.AddDate(0, 0, 7*week)
			wave := week%maxWave + 1
			doc, err := loadPack(raw)
			if err != nil {
				t.Fatal(err)
			}
			total = len(doc.Entries)
			current := map[string]time.Time{}
			wl := evidencerepin.Worklist{
				Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: rfc3339(at),
				Scope: evidencerepin.WorklistScope{RulePacks: []string{tc.path}},
				Repos: []evidencerepin.RepoResolution{{Owner: "o", Repo: "r", Status: "RESOLVED", CurrentTag: "v1", ResolvedAt: rfc3339(at.Add(-time.Hour))}},
			}
			for _, entry := range doc.Entries {
				fields, _ := parseRuleFields(entry.Rule)
				current[fields.ID], _ = parseUTC(fields.Evidence.ValidUntil)
				if current[fields.ID].Before(at) {
					lapsed++
				}
				for _, source := range fields.Evidence.Sources {
					wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
						RulePack: tc.path, RuleID: fields.ID, Project: entry.Project, SourceID: source.ID,
						Owner: "o", Repo: "r", OldCommit: source.Revision, NewCommit: source.Revision, Class: evidencerepin.ClassFileIdentical,
					})
				}
			}
			worklistRaw := marshalWorklist(t, wl)
			res, err := Prepare(PrepareOptions{
				WorklistRaw: worklistRaw, PackName: tc.pack, PackPath: tc.path, PackRaw: raw, Chain: f.chain(),
				Wave: wave, AttestedAt: at, Now: at, NextRevision: fmt.Sprintf("sim-%02d", week+1), EngineCapabilityDigest: testEngineCapabilityDigest,
			})
			if err != nil {
				t.Fatalf("%s week %d: Prepare: %v", tc.pack, week+1, err)
			}
			validUntil, _ := parseUTC(res.Statement.ValidUntil)
			for _, ra := range res.Statement.Rules {
				renewals++
				if !validUntil.After(current[ra.RuleID]) {
					t.Fatalf("%s week %d: renewing %s moves validUntil from %s to %s", tc.pack, week+1, ra.RuleID, current[ra.RuleID].Format(time.RFC3339), res.Statement.ValidUntil)
				}
				if ra.ConsecutiveBatchCycles == maxConsecutiveBatchCycles {
					capped[ra.RuleID] = true
				}
				if last, ok := lastRenewed[ra.RuleID]; ok && (minGap == 0 || at.Sub(last) < minGap) {
					minGap = at.Sub(last)
				}
				lastRenewed[ra.RuleID] = at
			}
			for _, ne := range res.Statement.NotExtended {
				switch ne.WorstClass {
				case reasonNotLaterThanCurrent:
					notLater++
				case reasonNotYetDue:
					notDue++
				}
			}
			// Verify recomputes the identical statement; with no review
			// supplied, the only thing it may still object to is the
			// unreviewed sample.
			_, verr := Verify(VerifyOptions{
				StatementRaw: res.StatementCanonical, PriorPackRaw: raw, NextPackRaw: res.NextPack, WorklistRaw: worklistRaw,
				Chain: f.chain(), BaseChain: f.chain(), PackName: tc.pack, PackPath: tc.path, EngineCapabilityDigest: testEngineCapabilityDigest,
				AttestedAtNow: at.Add(time.Hour), PreSign: true,
			})
			if len(res.Statement.Rules) == 0 && verr != nil {
				t.Fatalf("%s week %d: Verify: %v", tc.pack, week+1, verr)
			}
			if len(res.Statement.Rules) > 0 && (verr == nil || !strings.Contains(verr.Error(), "has no recorded individual review")) {
				t.Fatalf("%s week %d: Verify must fail only on the unreviewed sample, got %v", tc.pack, week+1, verr)
			}
			f.entries = append(f.entries, ChainEntry{Name: fmt.Sprintf("%04d", week+1), Statement: res.StatementCanonical, Envelope: signUnchecked(t, f, res.StatementCanonical)})
			raw = res.NextPack
			t.Logf("%s week %2d wave %d: renewed %d", tc.pack, week+1, wave, len(res.Statement.Rules))
		}
		t.Logf("%s after %d weeks: %d renewals, none moved validUntil earlier; rule-weeks not renewed as NOT_LATER_THAN_CURRENT %d, as NOT_YET_DUE %d; %d of %d rules reached %d consecutive batch cycles; shortest time between two renewals of one rule %d days; rule-weeks whose lease had already ended when the batch ran %d",
			tc.pack, weeks, renewals, notLater, notDue, len(capped), total, maxConsecutiveBatchCycles, int(minGap.Hours()/24), lapsed)
		if minGap != 0 && minGap < renewalWindow {
			t.Fatalf("%s: a rule was renewed again only %s after its previous renewal", tc.pack, minGap)
		}
		if len(capped) > tc.maxCapped {
			t.Fatalf("%s: %d rules reached the consecutive-cycle cap within %d weeks, more than %d", tc.pack, len(capped), weeks, tc.maxCapped)
		}
	}
}
