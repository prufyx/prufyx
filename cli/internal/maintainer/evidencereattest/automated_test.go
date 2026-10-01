// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// ---------------------------------------------------------------------
// Fixtures: a v2 trust root with one human and one automation key
// ---------------------------------------------------------------------

type testKeyPair struct {
	encrypted []byte
	public    ed25519.PublicKey
	id        string
}

func newKeyPair(t *testing.T) testKeyPair {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := keyIdentity(public)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := knowledgesign.EncryptedKeyPEM(private, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	return testKeyPair{encrypted: encrypted, public: public, id: id}
}

func (k testKeyPair) trustKey(role string) TrustKey {
	return TrustKey{KeyID: k.id, KeyType: "ed25519", Scheme: "ed25519", PublicKey: hex.EncodeToString(k.public), Role: role}
}

func renderRoot(t *testing.T, schema string, threshold int, keys ...TrustKey) []byte {
	t.Helper()
	sortKeys(keys)
	raw, err := canonicalBytes(TrustRoot{
		SchemaVersion: schema, Purpose: Purpose, Expires: rfc3339(time.Now().UTC().Add(365 * 24 * time.Hour)),
		Threshold: threshold, Keys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sortKeys(keys []TrustKey) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j].KeyID < keys[j-1].KeyID; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
}

// roleFixture is a chainFixture whose trust root is a v2 root holding the
// chainFixture's human key and an automation key.
type roleFixture struct {
	*chainFixture
	human, automation testKeyPair
}

func newRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	human, automation := newKeyPair(t), newKeyPair(t)
	root := renderRoot(t, TrustRootSchema, 1, human.trustKey(RoleHuman), automation.trustKey(RoleAutomation))
	return &roleFixture{
		chainFixture: &chainFixture{t: t, key: human.encrypted, root: root, digest: sourcecorpus.SHA(root)},
		human:        human, automation: automation,
	}
}

// signAs signs statementRaw through Sign as role with key, with the
// signer's clock an hour after the statement's attestedAt.
func (f *roleFixture) signAs(role string, key testKeyPair, statementRaw []byte) ([]byte, error) {
	return Sign(SignOptions{
		Role: role, Statement: statementRaw, TrustRoot: f.root, EncryptedKey: key.encrypted,
		Passphrase: []byte(testPassphrase), ExpectedTrustRootDigest: f.digest, Now: signerClock(f.t, statementRaw),
	})
}

func signerClock(t *testing.T, statementRaw []byte) time.Time {
	t.Helper()
	var statement Statement
	if err := json.Unmarshal(statementRaw, &statement); err != nil {
		t.Fatal(err)
	}
	return mustParse(statement.AttestedAt).Add(time.Hour)
}

func (f *roleFixture) appendAutomated(name string, statementRaw []byte) {
	f.t.Helper()
	envelope, err := f.signAs(RoleAutomation, f.automation, statementRaw)
	if err != nil {
		f.t.Fatalf("automation Sign: %v", err)
	}
	f.entries = append(f.entries, ChainEntry{Name: name, Statement: statementRaw, Envelope: envelope})
}

// rawEnvelope signs statementRaw with key directly, bypassing every check
// Sign makes, so tests can present VerifySignature and the chain with
// signatures Sign would never produce.
func rawEnvelope(t *testing.T, key testKeyPair, statementRaw []byte) []byte {
	t.Helper()
	private, err := knowledgesign.DecryptPrivateKey(key.encrypted, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := canonicalBytes(Envelope{
		SchemaVersion: EnvelopeSchema, StatementDigest: sourcecorpus.SHA(statementRaw),
		Signatures: []SignatureLine{{KeyID: key.id, Sig: hex.EncodeToString(ed25519.Sign(private, statementRaw))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// automatedSpacing separates automated test cycles: an automated renewal
// gives at most a 90-day lease, so 70 days later every renewed rule is due
// again.
const automatedSpacing = 70 * 24 * time.Hour

// prepareAutomated prepares one automated batch against f's chain, over a
// worklist built from specs at at.
func prepareAutomated(t *testing.T, f *chainFixture, prior []byte, at time.Time, specs []ruleSpec, revision string, records map[string][]byte) cycle {
	t.Helper()
	wl, _ := buildWorklistAndPack(t, chainPackPath, at, specs)
	lineBaselined(&wl)
	return prepareAutomatedWith(t, f, prior, at, marshalWorklist(t, wl), revision, records)
}

// lineBaselined rewrites every citation of wl as a comparison with the
// newest release on its pinned tag's release line, backed by a resolved
// line record, the only baseline automated mode renews. It leaves each
// citation's class and commits alone.
func lineBaselined(wl *evidencerepin.Worklist) {
	wl.Lines = nil
	for i := range wl.Citations {
		c := &wl.Citations[i]
		c.Baseline, c.BaselineMode = evidencerepin.BaselineReleaseLine, evidencerepin.BaselineModeReleaseLine
		c.BaselineLine, c.PinnedTag, c.BaselineTag = "0.9", "v0.9.0", "v0.9.4"
		resolvedAt := ""
		for _, repo := range wl.Repos {
			if repo.Owner == c.Owner && repo.Repo == c.Repo {
				resolvedAt = repo.ResolvedAt
			}
		}
		wl.Lines = append(wl.Lines, evidencerepin.LineResolution{
			Owner: c.Owner, Repo: c.Repo, Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: c.NewCommit, ResolvedAt: resolvedAt,
		})
	}
}

func prepareAutomatedWith(t *testing.T, f *chainFixture, prior []byte, at time.Time, worklistRaw []byte, revision string, records map[string][]byte) cycle {
	t.Helper()
	if records == nil {
		records = map[string][]byte{}
	}
	res, err := Prepare(PrepareOptions{
		Mode: ModeAutomated, WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: f.chain(),
		AttestedAt: at, Now: at, NextRevision: revision, EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: records,
	})
	if err != nil {
		t.Fatalf("automated Prepare %s: %v", revision, err)
	}
	return cycle{res: res, worklistRaw: worklistRaw, prior: prior, at: at, reviews: records}
}

// automatedPack is twelve due rules in a pack padded to 92 rules, so the
// stagger cap (13 a week) never defers any of them.
func automatedPack(t *testing.T, at time.Time) []byte {
	t.Helper()
	_, pack := buildWorklistAndPack(t, chainPackPath, at, cycleSpecs(12, at))
	return padPackWithPastRules(t, pack, 80)
}

func nextRuleDates(t *testing.T, packRaw []byte, ruleID string) (reviewedAt, validUntil string) {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc.Entries {
		fields, _ := parseRuleFields(entry.Rule)
		if fields.ID == ruleID {
			return fields.Evidence.ReviewedAt, fields.Evidence.ValidUntil
		}
	}
	t.Fatalf("rule %s not in pack", ruleID)
	return "", ""
}

// setRuleDates rewrites one rule's evidence dates, as an individual review
// merged outside the statement chain would.
func setRuleDates(t *testing.T, packRaw []byte, ruleID, reviewedAt, validUntil string) []byte {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range doc.Entries {
		fields, _ := parseRuleFields(entry.Rule)
		if fields.ID == ruleID {
			doc.Entries[i].Rule, err = mutateRuleEvidenceDates(entry.Rule, reviewedAt, validUntil)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	raw, err := buildNextPack(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---------------------------------------------------------------------
// Automated mode: no sample, per-rule schedule, recomputed by Verify
// ---------------------------------------------------------------------

func TestAutomatedPrepareRenewsWithoutSampleOnAPerRuleSchedule(t *testing.T) {
	f := newRoleFixture(t)
	c := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	statement := c.res.Statement
	if len(statement.Rules) != 12 {
		t.Fatalf("expected all 12 due rules renewed, got %d (%+v)", len(statement.Rules), statement.NotExtended)
	}
	if statement.SignerRole != RoleAutomation || statement.Schema != StatementSchema || statement.Authority != AuthorityAutomated || statement.Wave != 0 {
		t.Fatalf("unexpected automated statement header: role=%q schema=%q authority=%q wave=%d", statement.SignerRole, statement.Schema, statement.Authority, statement.Wave)
	}
	if len(statement.SampledForFullReview) != 0 || c.res.SampledRuleCount != 0 {
		t.Fatalf("an automated statement carries no sample, got %+v", statement.SampledForFullReview)
	}
	slots := AutomatedSlots(baseNow)
	if statement.ValidUntil != rfc3339(slots[len(slots)-1]) {
		t.Fatalf("statement validUntil %s is not the automated horizon %s", statement.ValidUntil, rfc3339(slots[len(slots)-1]))
	}
	for _, ra := range statement.Rules {
		// No contention: each rule gets exactly its preferred slot.
		if want := rfc3339(slots[slotPreference(ra.RuleID, len(slots))]); ra.ValidUntil != want {
			t.Fatalf("rule %s scheduled to %s, want its preferred slot %s", ra.RuleID, ra.ValidUntil, want)
		}
		reviewedAt, validUntil := nextRuleDates(t, c.res.NextPack, ra.RuleID)
		if reviewedAt != statement.AttestedAt || validUntil != ra.ValidUntil {
			t.Fatalf("rule %s next-pack dates %s/%s, want %s/%s", ra.RuleID, reviewedAt, validUntil, statement.AttestedAt, ra.ValidUntil)
		}
	}
	// The preference hash spreads the rules: twelve rules land in at least
	// three different weeks.
	weeks := map[string]bool{}
	for _, ra := range statement.Rules {
		weeks[isoWeek(mustParse(ra.ValidUntil))] = true
	}
	if len(weeks) < 3 {
		t.Fatalf("twelve rules were scheduled into only %d weeks", len(weeks))
	}
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("Verify rejected Prepare's own automated statement: %v", err)
	}
	envelope, err := f.signAs(RoleAutomation, f.automation, c.res.StatementCanonical)
	if err != nil {
		t.Fatalf("automation Sign: %v", err)
	}
	result, err := VerifySignature(VerifySignatureOptions{Statement: c.res.StatementCanonical, Envelope: envelope, TrustRoot: f.root, ExpectedTrustRootDigest: f.digest})
	if err != nil || result.SignerRole != RoleAutomation || len(result.SignerKeyIDs) != 1 || result.SignerKeyIDs[0] != f.automation.id {
		t.Fatalf("VerifySignature: %+v, %v", result, err)
	}
}

func TestAutomatedPrepareIsDeterministicAndIndependentOfPackOrder(t *testing.T) {
	f := newRoleFixture(t)
	pack := automatedPack(t, baseNow)
	first := prepareAutomated(t, f.chainFixture, pack, baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	second := prepareAutomated(t, f.chainFixture, pack, baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	if string(first.res.StatementCanonical) != string(second.res.StatementCanonical) || string(first.res.NextPack) != string(second.res.NextPack) {
		t.Fatal("two automated Prepare runs over the same inputs differ")
	}
	doc, err := loadPack(pack)
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(doc.Entries)-1; i < j; i, j = i+1, j-1 {
		doc.Entries[i], doc.Entries[j] = doc.Entries[j], doc.Entries[i]
	}
	reversed, err := buildNextPack(doc)
	if err != nil {
		t.Fatal(err)
	}
	third := prepareAutomated(t, f.chainFixture, reversed, baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	schedule := func(c cycle) string {
		var parts []string
		for _, ra := range c.res.Statement.Rules {
			parts = append(parts, ra.RuleID+"="+ra.ValidUntil)
		}
		return strings.Join(parts, ",")
	}
	if schedule(first) != schedule(third) {
		t.Fatalf("the schedule depends on pack order:\n%s\n%s", schedule(first), schedule(third))
	}
}

func TestAutomatedSlotsStayWithinTheLeaseWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for at := start; at.Before(start.AddDate(1, 0, 0)); at = at.Add(7 * time.Hour) {
		slots := AutomatedSlots(at)
		if len(slots) < 6 {
			t.Fatalf("%s: only %d slots", rfc3339(at), len(slots))
		}
		weeks := map[string]bool{}
		for i, slot := range slots {
			if slot.Weekday() != time.Monday || slot.Hour() != 12 || slot.Minute() != 0 || slot.Second() != 0 {
				t.Fatalf("%s: slot %s is not Monday 12:00 UTC", rfc3339(at), rfc3339(slot))
			}
			// Literal bounds, independent of the constants: more than six
			// weeks (twice the 21-day renewal window) and at most 90 days.
			if slot.Sub(at) <= 42*24*time.Hour || slot.Sub(at) > 90*24*time.Hour {
				t.Fatalf("%s: slot %s is outside (%s, %s]", rfc3339(at), rfc3339(slot), automatedMinLease, maxLease)
			}
			if i > 0 && !slot.After(slots[i-1]) {
				t.Fatalf("%s: slots are not increasing", rfc3339(at))
			}
			if weeks[isoWeek(slot)] {
				t.Fatalf("%s: two slots in ISO week %s", rfc3339(at), isoWeek(slot))
			}
			weeks[isoWeek(slot)] = true
		}
		if slots[0].Sub(at) > automatedMinLease+7*24*time.Hour || maxLease-slots[len(slots)-1].Sub(at) >= 7*24*time.Hour {
			t.Fatalf("%s: slots do not cover the whole window", rfc3339(at))
		}
	}
}

// Fifty due rules in a pack of fifty: the cap is 7 a week, so the schedule
// must spread them over the slots, never exceed the cap in any week, and
// defer only what no slot can take.
func TestAutomatedScheduleSpreadsUnderTheStaggerCap(t *testing.T) {
	f := newRoleFixture(t)
	specs := cycleSpecs(50, baseNow)
	_, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	c := prepareAutomated(t, f.chainFixture, pack, baseNow, specs, "rev-2", nil)
	weekCap := staggerCap(50)
	slots := AutomatedSlots(baseNow)
	counts := map[string]int{}
	for _, ra := range c.res.Statement.Rules {
		counts[isoWeek(mustParse(ra.ValidUntil))]++
	}
	for week, count := range counts {
		if count > weekCap {
			t.Fatalf("week %s holds %d renewed rules, over the cap of %d", week, count, weekCap)
		}
	}
	deferred := 0
	for _, ne := range c.res.Statement.NotExtended {
		if ne.WorstClass != reasonStaggerDeferred {
			t.Fatalf("unexpected exclusion %+v", ne)
		}
		deferred++
	}
	wantRenewed := weekCap * len(slots)
	if wantRenewed > 50 {
		wantRenewed = 50
	}
	if len(c.res.Statement.Rules) != wantRenewed || deferred != 50-wantRenewed {
		t.Fatalf("renewed %d and deferred %d, want %d and %d (cap %d over %d slots)", len(c.res.Statement.Rules), deferred, wantRenewed, 50-wantRenewed, weekCap, len(slots))
	}
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("Verify rejected a spread schedule: %v", err)
	}
}

func TestAutomatedPrepareKeepsNotYetDueAndNotLaterThanCurrent(t *testing.T) {
	f := newRoleFixture(t)
	specs := cycleSpecs(3, baseNow)
	specs[1].validUntil = rfc3339(baseNow.Add(30 * 24 * time.Hour))
	specs[2].validUntil = rfc3339(baseNow.Add(95 * 24 * time.Hour))
	_, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 40)
	c := prepareAutomated(t, f.chainFixture, pack, baseNow, specs, "rev-2", nil)
	if cyclesOf(c, "rule-00") != 1 || worstClassOf(c, "rule-01") != reasonNotYetDue || worstClassOf(c, "rule-02") != reasonNotLaterThanCurrent {
		t.Fatalf("unexpected outcome: renewed=%s notExtended=%+v", renewedIDs(c.res), c.res.Statement.NotExtended)
	}
}

func TestAutomatedPrepareRefusesMechanicalRules(t *testing.T) {
	f := newRoleFixture(t)
	specs := cycleSpecs(2, baseNow)
	specs[1].mechanical = true
	_, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 40)
	c := prepareAutomated(t, f.chainFixture, pack, baseNow, specs, "rev-2", nil)
	if cyclesOf(c, "rule-00") != 1 || worstClassOf(c, "rule-01") != reasonMechanicalRule {
		t.Fatalf("expected the mechanical rule excluded, got renewed=%s notExtended=%+v", renewedIDs(c.res), c.res.Statement.NotExtended)
	}
}

// The owner's approval of automated renewal covers byte-identical citations
// on their own release line. A citation compared with the repository's
// latest release is excluded in automated mode, however well the worklist
// backs it; human mode is unchanged and renews the same rule.
func TestAutomatedPrepareExcludesLatestReleaseBaselines(t *testing.T) {
	f := newRoleFixture(t)
	specs := cycleSpecs(2, baseNow)
	wl, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 40)
	lineBaselined(&wl)
	// rule-01 alone is compared with its repository's latest release, with
	// a repository record that fully backs that comparison.
	for i := range wl.Citations {
		if wl.Citations[i].RuleID == "rule-01" {
			c := &wl.Citations[i]
			c.Baseline, c.BaselineMode, c.BaselineLine, c.PinnedTag, c.BaselineTag = evidencerepin.BaselineLatest, "", "", "", ""
		}
	}
	worklistRaw := marshalWorklist(t, wl)
	c := prepareAutomatedWith(t, f.chainFixture, pack, baseNow, worklistRaw, "rev-2", nil)
	if renewedIDs(c.res) != "rule-00" || worstClassOf(c, "rule-01") != reasonLatestBaselineNotAutomatable {
		t.Fatalf("expected rule-01 excluded as %s, got renewed=%s notExtended=%+v", reasonLatestBaselineNotAutomatable, renewedIDs(c.res), c.res.Statement.NotExtended)
	}
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	human, err := Prepare(PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{},
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewedIDs(human) != "rule-00,rule-01" {
		t.Fatalf("human mode must be unchanged and renew both, got %s (%+v)", renewedIDs(human), human.Statement.NotExtended)
	}
}

// A statement that renews a rule on a latest-release baseline is not a
// valid automated statement: V8 refuses it however it was produced.
func TestVerifyRejectsAutomatedStatementWithLatestBaselineCitation(t *testing.T) {
	f := newRoleFixture(t)
	c := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	statement := c.res.Statement
	statement.Rules = append([]RuleAttestation(nil), statement.Rules...)
	statement.Rules[0].Citations = append([]CitationAttestation(nil), statement.Rules[0].Citations...)
	statement.Rules[0].Citations[0].Baseline, statement.Rules[0].Citations[0].BaselineLine, statement.Rules[0].Citations[0].PinnedTag = "", "", ""
	priorDoc, err := loadPack(c.prior)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(priorDoc)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRolePolicy(statement, candidatesByID(candidates)); err == nil || !strings.Contains(err.Error(), "release line") {
		t.Fatalf("V8 must refuse a latest-baseline citation in an automated statement, got %v", err)
	}
	if err := checkRolePolicy(c.res.Statement, candidatesByID(candidates)); err != nil {
		t.Fatalf("the untampered statement must pass V8: %v", err)
	}
}

func TestAutomatedPrepareRequiresCurrentWorklistSchemaAndNoWave(t *testing.T) {
	wl, pack := buildWorklistAndPack(t, chainPackPath, baseNow, cycleSpecs(1, baseNow))
	lineBaselined(&wl)
	opts := PrepareOptions{
		Mode: ModeAutomated, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{},
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
		WorklistRaw: marshalWorklist(t, wl),
	}
	if _, err := Prepare(opts); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	withWave := opts
	withWave.Wave = 1
	if _, err := Prepare(withWave); err == nil {
		t.Fatal("automated mode accepted a wave")
	}
	wl.Schema = evidencerepin.SchemaV1
	v1 := opts
	v1.WorklistRaw = marshalWorklist(t, wl)
	if _, err := Prepare(v1); err == nil || !strings.Contains(err.Error(), "current-schema worklist") {
		t.Fatalf("automated mode accepted a v1 worklist: %v", err)
	}
	unknown := opts
	unknown.Mode = "robot"
	if _, err := Prepare(unknown); err == nil {
		t.Fatal("Prepare accepted an unknown mode")
	}
}

// ---------------------------------------------------------------------
// Consecutive-cycle cap in automated mode
// ---------------------------------------------------------------------

func TestAutomatedRenewalsStopAtTheConsecutiveCycleCap(t *testing.T) {
	f := newRoleFixture(t)
	t1 := baseNow
	prior := automatedPack(t, t1)
	for round, want := range []int{1, 2} {
		at := t1.Add(time.Duration(round) * automatedSpacing)
		c := prepareAutomated(t, f.chainFixture, prior, at, cycleSpecs(12, at), fmt.Sprintf("rev-%d", round+2), nil)
		if len(c.res.Statement.Rules) != 12 {
			t.Fatalf("round %d: expected 12 renewals, got %d (%+v)", round+1, len(c.res.Statement.Rules), c.res.Statement.NotExtended)
		}
		for _, ra := range c.res.Statement.Rules {
			if ra.ConsecutiveBatchCycles != want {
				t.Fatalf("round %d: rule %s has %d consecutive cycles, want %d", round+1, ra.RuleID, ra.ConsecutiveBatchCycles, want)
			}
		}
		if err := verifyCycle(c, f.chain()); err != nil {
			t.Fatalf("round %d verify: %v", round+1, err)
		}
		f.appendAutomated(fmt.Sprintf("%04d", round+1), c.res.StatementCanonical)
		prior = c.res.NextPack
	}
	t3 := t1.Add(2 * automatedSpacing)
	c3 := prepareAutomated(t, f.chainFixture, prior, t3, cycleSpecs(12, t3), "rev-4", nil)
	if len(c3.res.Statement.Rules) != 0 {
		t.Fatalf("a third consecutive automated renewal happened: %s", renewedIDs(c3.res))
	}
	for i := 0; i < 12; i++ {
		if got := worstClassOf(c3, fmt.Sprintf("rule-%02d", i)); got != reasonConsecutiveCycleCap {
			t.Fatalf("rule-%02d: want %s, got %q", i, reasonConsecutiveCycleCap, got)
		}
	}
	if err := verifyCycle(c3, f.chain()); err != nil {
		t.Fatalf("round 3 verify: %v", err)
	}
}

// The cap counts every batch renewal since the last individual review,
// human or automated alike: a human batch followed by an automated one
// leaves no room for a third.
func TestConsecutiveCycleCapIsSharedBetweenHumanAndAutomatedRenewals(t *testing.T) {
	f := newRoleFixture(t)
	c1 := prepareCycle(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	if err := verifyCycle(c1, f.chain()); err != nil {
		t.Fatal(err)
	}
	f.append("0001", c1.res.StatementCanonical)
	t2 := mustParse(c1.res.Statement.ValidUntil)
	c2 := prepareAutomated(t, f.chainFixture, c1.res.NextPack, t2, cycleSpecs(12, t2), "rev-3", nil)
	if len(c2.res.Statement.Rules) != 12 {
		t.Fatalf("expected 12 automated renewals, got %d (%+v)", len(c2.res.Statement.Rules), c2.res.Statement.NotExtended)
	}
	for _, ra := range c2.res.Statement.Rules {
		if ra.ConsecutiveBatchCycles != 2 {
			t.Fatalf("rule %s: %d consecutive cycles after a human and an automated renewal, want 2", ra.RuleID, ra.ConsecutiveBatchCycles)
		}
	}
	if err := verifyCycle(c2, f.chain()); err != nil {
		t.Fatal(err)
	}
	f.appendAutomated("0002", c2.res.StatementCanonical)
	t3 := t2.Add(automatedSpacing)
	c3 := prepareAutomated(t, f.chainFixture, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	if len(c3.res.Statement.Rules) != 0 || worstClassOf(c3, "rule-00") != reasonConsecutiveCycleCap {
		t.Fatalf("expected every rule capped, got renewed=%s notExtended=%+v", renewedIDs(c3.res), c3.res.Statement.NotExtended)
	}
}

// twoAutomatedRounds runs two signed automated rounds over twelve rules and
// returns the second round, after which every rule is at the cap.
func twoAutomatedRounds(t *testing.T) (*roleFixture, cycle) {
	t.Helper()
	f := newRoleFixture(t)
	prior := automatedPack(t, baseNow)
	var c cycle
	for round := 0; round < 2; round++ {
		at := baseNow.Add(time.Duration(round) * automatedSpacing)
		c = prepareAutomated(t, f.chainFixture, prior, at, cycleSpecs(12, at), fmt.Sprintf("rev-%d", round+2), nil)
		f.appendAutomated(fmt.Sprintf("%04d", round+1), c.res.StatementCanonical)
		prior = c.res.NextPack
	}
	return f, c
}

// A review record is not authenticated by itself. An automated statement,
// which no person signs, must not count one that the pack does not already
// require (a rule reviewed after the chain head), so supplying records can
// never reset the cap; a human statement with the same record does.
func TestAutomatedModeIgnoresReviewRecordsThePackDoesNotRequire(t *testing.T) {
	f, c2 := twoAutomatedRounds(t)
	t3 := c2.at.Add(automatedSpacing)
	records := map[string][]byte{"rule-00": testReviewRecord(t, c2.res.NextPack, "rule-00", t3.Add(-time.Hour), "Some Maintainer")}
	c3 := prepareAutomated(t, f.chainFixture, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", records)
	if cyclesOf(c3, "rule-00") != -1 || worstClassOf(c3, "rule-00") != reasonConsecutiveCycleCap || len(c3.res.Statement.IndividualReviews) != 0 {
		t.Fatalf("an automated statement counted an unanchored review record: renewed=%s reviews=%+v", renewedIDs(c3.res), c3.res.Statement.IndividualReviews)
	}
	if err := verifyCycle(c3, f.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	wl, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
	human, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: c2.res.NextPack, Chain: f.chain(),
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: records,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ra := range human.Statement.Rules {
		found = found || (ra.RuleID == "rule-00" && ra.ConsecutiveBatchCycles == 1)
	}
	if !found {
		t.Fatalf("the same record in a human statement must reset rule-00, got %s", renewedIDs(human))
	}
}

// With no chain head there is nothing a review record could be anchored
// to: an automated statement opening a chain records none.
func TestAutomatedModeRecordsNoReviewOnAnEmptyChain(t *testing.T) {
	f := newRoleFixture(t)
	pack := automatedPack(t, baseNow)
	records := map[string][]byte{"rule-00": testReviewRecord(t, pack, "rule-00", baseNow.Add(-time.Hour), "Some Maintainer")}
	c := prepareAutomated(t, f.chainFixture, pack, baseNow, cycleSpecs(12, baseNow), "rev-2", records)
	if len(c.res.Statement.IndividualReviews) != 0 {
		t.Fatalf("an automated statement on an empty chain recorded %+v", c.res.Statement.IndividualReviews)
	}
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatal(err)
	}
}

// A rule whose evidence dates the base branch already moved after the chain
// head (an individual review merged outside the chain) is never renewed by
// an automated statement, which counts no review record: it is excluded
// with an explicit reason and left to a human statement, which records the
// review and resets its count. Nothing else is held back.
func TestAutomatedModeLeavesARuleReviewedOutsideTheChainToAHuman(t *testing.T) {
	f, c2 := twoAutomatedRounds(t)
	t3 := c2.at.Add(automatedSpacing)
	reviewedAt := c2.at.Add(24 * time.Hour)
	prior := setRuleDates(t, c2.res.NextPack, "rule-01", rfc3339(reviewedAt), rfc3339(t3.Add(7*24*time.Hour)))
	records := map[string][]byte{"rule-01": testReviewRecord(t, prior, "rule-01", reviewedAt, "Individual Reviewer")}
	for name, supplied := range map[string]map[string][]byte{"without a record": nil, "with a record": records} {
		c3 := prepareAutomated(t, f.chainFixture, prior, t3, cycleSpecs(12, t3), "rev-4", supplied)
		if worstClassOf(c3, "rule-01") != reasonReviewedOutsideChain || len(c3.res.Statement.IndividualReviews) != 0 {
			t.Fatalf("%s: expected rule-01 excluded as %s with no review recorded, got renewed=%s notExtended=%+v reviews=%+v",
				name, reasonReviewedOutsideChain, renewedIDs(c3.res), c3.res.Statement.NotExtended, c3.res.Statement.IndividualReviews)
		}
		if renewedIDs(c3.res) != "" {
			t.Fatalf("%s: every other rule is at the cap, got renewals %s", name, renewedIDs(c3.res))
		}
		if err := verifyCycle(c3, f.chain()); err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
	}
	wl, _ := buildWorklistAndPack(t, chainPackPath, t3, cycleSpecs(12, t3))
	human, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: f.chain(),
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: records,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(human.Statement.IndividualReviews) != 1 || human.Statement.IndividualReviews[0].RuleID != "rule-01" {
		t.Fatalf("a human statement must record the review, got %+v", human.Statement.IndividualReviews)
	}
}

// Verify applies the same anchoring as automated Prepare when it ties the
// prior pack to the chain: a rule claiming the chain head's attestedAt as
// its reviewedAt, which the head did not renew, is a V5 failure even when
// a review record for it is supplied, because an automated statement may
// not count that record.
func TestVerifyAnchorsReviewRecordsForAutomatedStatements(t *testing.T) {
	f, c2 := twoAutomatedRounds(t)
	t3 := c2.at.Add(automatedSpacing)
	c3 := prepareAutomated(t, f.chainFixture, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	prior := setRuleDates(t, c2.res.NextPack, "past-000", c2.res.Statement.AttestedAt, rfc3339(t3.Add(7*24*time.Hour)))
	tampered := c3
	tampered.prior = prior
	tampered.reviews = map[string][]byte{"past-000": testReviewRecord(t, prior, "past-000", t3.Add(-time.Hour), "Some Maintainer")}
	err := verifyCycle(tampered, f.chain())
	// Reported by Verify's own chain check, not only by the recomputation.
	if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "neither renewed it nor recorded") || strings.Contains(err.Error(), "V3:") {
		t.Fatalf("expected the unanchored record to be ignored and V5 to fire, got %v", err)
	}
}

func TestCoveringReviewsAreNoneForAutomatedStatements(t *testing.T) {
	fresh := map[string]string{"rule-a": "sha256:" + strings.Repeat("ee", 32)}
	if got := coveringReviews(RoleHuman, fresh); len(got) != 1 {
		t.Fatalf("a human statement keeps its new reviews as V6 coverage, got %v", got)
	}
	if got := coveringReviews(RoleAutomation, fresh); len(got) != 0 {
		t.Fatalf("an automated statement may not use review records as V6 coverage, got %v", got)
	}
	prior := map[string]json.RawMessage{"rule-a": ruleJSON(t, "rule-a", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")}
	next := map[string]json.RawMessage{"rule-a": ruleJSON(t, "rule-a", "2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z")}
	if err := checkV6(prior, next, Statement{}, coveringReviews(RoleAutomation, fresh), true); err == nil || !strings.Contains(err.Error(), "V6:") {
		t.Fatalf("expected V6 to reject a date change covered only by a review record in an automated statement, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Role binding: statement role, signing role, key role
// ---------------------------------------------------------------------

func humanStatementFor(t *testing.T, f *roleFixture) cycle {
	t.Helper()
	return prepareCycle(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
}

func TestSignBindsSigningRoleStatementRoleAndKeyRole(t *testing.T) {
	f := newRoleFixture(t)
	human := humanStatementFor(t, f).res.StatementCanonical
	automated := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil).res.StatementCanonical
	// Each refusal is asserted by its own reason, so every one of the three
	// checks (a role is given, it is the statement's role, the key holds
	// it) is shown to fire on its own rather than being masked by Sign's
	// final self-verification.
	for _, tc := range []struct {
		name      string
		role      string
		key       testKeyPair
		statement []byte
		wantErr   string
	}{
		{"human key signs human statement", RoleHuman, f.human, human, ""},
		{"automation key signs automated statement", RoleAutomation, f.automation, automated, ""},
		{"automation role refuses a human statement", RoleAutomation, f.automation, human, "must be signed with the human role, not the automation role"},
		{"human role refuses an automated statement", RoleHuman, f.human, automated, "must be signed with the automation role, not the human role"},
		{"automation role refuses a human key", RoleAutomation, f.human, automated, "does not hold the automation role in the trust root"},
		{"human role refuses an automation key", RoleHuman, f.automation, human, "does not hold the human role in the trust root"},
		{"no role", "", f.human, human, "a signing role is required"},
	} {
		_, err := f.signAs(tc.role, tc.key, tc.statement)
		if tc.wantErr == "" {
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: want an error containing %q, got %v", tc.name, tc.wantErr, err)
		}
	}
}

func TestVerifySignatureBindsKeyRoleToStatementRole(t *testing.T) {
	f := newRoleFixture(t)
	human := humanStatementFor(t, f).res.StatementCanonical
	automated := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil).res.StatementCanonical
	verify := func(statement, envelope []byte) error {
		_, err := VerifySignature(VerifySignatureOptions{Statement: statement, Envelope: envelope, TrustRoot: f.root, ExpectedTrustRootDigest: f.digest})
		return err
	}
	if err := verify(human, rawEnvelope(t, f.human, human)); err != nil {
		t.Fatalf("human key over a human statement: %v", err)
	}
	if err := verify(automated, rawEnvelope(t, f.automation, automated)); err != nil {
		t.Fatalf("automation key over an automated statement: %v", err)
	}
	if err := verify(human, rawEnvelope(t, f.automation, human)); err == nil {
		t.Fatal("an automation key's signature verified a human statement")
	}
	if err := verify(automated, rawEnvelope(t, f.human, automated)); err == nil {
		t.Fatal("a human key's signature verified an automated statement")
	}
	// The binding holds in the chain too: an automated statement signed by
	// a human key is not a valid chain entry.
	bad := &Chain{Entries: []ChainEntry{{Name: "0001", Statement: automated, Envelope: rawEnvelope(t, f.human, automated)}}, TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
	if _, err := deriveChainState(bad, PackCNCF, baseNow.Add(time.Hour), ""); err == nil {
		t.Fatal("the chain accepted an automated statement signed by a human key")
	}
}

// ---------------------------------------------------------------------
// Statement shape per role (ParseStatement) and the role policy (V8)
// ---------------------------------------------------------------------

func reencode(t *testing.T, statement Statement) []byte {
	t.Helper()
	raw, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseStatementEnforcesEachRolesShape(t *testing.T) {
	f := newRoleFixture(t)
	human := humanStatementFor(t, f).res.Statement
	automated := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil).res.Statement
	for _, tc := range []struct {
		name string
		base Statement
		mut  func(*Statement)
	}{
		{"v2 without a signer role", human, func(s *Statement) { s.SignerRole = "" }},
		{"unknown signer role", human, func(s *Statement) { s.SignerRole = "robot" }},
		{"v1 with a signer role", human, func(s *Statement) { s.Schema = StatementSchemaV1 }},
		{"human statement with the automated authority", human, func(s *Statement) { s.Authority = AuthorityAutomated }},
		{"human statement with the automated text", human, func(s *Statement) {
			s.Statement = AutomatedStatementText(s.Worklist.GeneratedAt, s.ValidUntil)
		}},
		{"human statement without a wave", human, func(s *Statement) { s.Wave = 0 }},
		{"human statement with a per-rule validUntil", human, func(s *Statement) { s.Rules[0].ValidUntil = s.ValidUntil }},
		{"human statement relabelled automated", human, func(s *Statement) { s.SignerRole = RoleAutomation }},
		{"automated statement relabelled human", automated, func(s *Statement) { s.SignerRole = RoleHuman }},
		{"automated statement with the human authority", automated, func(s *Statement) { s.Authority = Authority }},
		{"automated statement with a wave", automated, func(s *Statement) { s.Wave = 1 }},
		{"automated statement with a sample", automated, func(s *Statement) {
			s.SampledForFullReview = []SampledEntry{{RuleID: s.Rules[0].RuleID, ReviewRecordDigest: "sha256:" + strings.Repeat("ee", 32)}}
		}},
		{"automated rule without its validUntil", automated, func(s *Statement) { s.Rules[0].ValidUntil = "" }},
		{"automated rule validUntil after the statement's", automated, func(s *Statement) {
			s.Rules[0].ValidUntil = rfc3339(mustParse(s.ValidUntil).Add(time.Hour))
		}},
		{"automated rule validUntil not after attestedAt", automated, func(s *Statement) { s.Rules[0].ValidUntil = s.AttestedAt }},
	} {
		statement := deepCopyStatement(t, tc.base)
		if _, err := ParseStatement(reencode(t, statement)); err != nil {
			t.Fatalf("%s: unmodified base does not parse: %v", tc.name, err)
		}
		tc.mut(&statement)
		if _, err := ParseStatement(reencode(t, statement)); err == nil {
			t.Fatalf("%s: ParseStatement accepted it", tc.name)
		}
	}
}

func deepCopyStatement(t *testing.T, statement Statement) Statement {
	t.Helper()
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	var out Statement
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The sample exemption belongs to the automation role only.
func TestSampleExemptionIsOnlyForAutomatedStatements(t *testing.T) {
	f := newRoleFixture(t)
	human := humanStatementFor(t, f).res.Statement
	if err := checkSampleReviewed(human); err != nil {
		t.Fatalf("a reviewed human sample: %v", err)
	}
	noSample := deepCopyStatement(t, human)
	noSample.SampledForFullReview = []SampledEntry{}
	if err := checkSampleReviewed(noSample); err == nil {
		t.Fatal("a human statement that renews rules passed with no sample")
	}
	automated := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil).res.Statement
	if err := checkSampleReviewed(automated); err != nil {
		t.Fatalf("an automated statement needs no sample: %v", err)
	}
	withSample := deepCopyStatement(t, automated)
	withSample.SampledForFullReview = []SampledEntry{{RuleID: automated.Rules[0].RuleID, ReviewRecordDigest: "sha256:" + strings.Repeat("ee", 32)}}
	if err := checkSampleReviewed(withSample); err == nil {
		t.Fatal("an automated statement carrying a sample passed")
	}
}

func TestCheckRolePolicyRejectsWhatTheRoleMayNotRenew(t *testing.T) {
	f := newRoleFixture(t)
	hc := humanStatementFor(t, f)
	ac := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	priorOf := func(c cycle) map[string]ruleCandidate {
		doc, err := loadPack(c.prior)
		if err != nil {
			t.Fatal(err)
		}
		candidates, _, err := packCandidates(doc)
		if err != nil {
			t.Fatal(err)
		}
		return candidatesByID(candidates)
	}
	for _, base := range []cycle{hc, ac} {
		if err := checkRolePolicy(base.res.Statement, priorOf(base)); err != nil {
			t.Fatalf("Prepare's own %s statement fails V8: %v", base.res.Statement.SignerRole, err)
		}
	}
	mutatePrior := func(c cycle, ruleID string, mut func(rule map[string]any)) map[string]ruleCandidate {
		prior := priorOf(c)
		candidate := prior[ruleID]
		var rule map[string]any
		if err := json.Unmarshal(candidate.Raw, &rule); err != nil {
			t.Fatal(err)
		}
		mut(rule)
		raw, err := json.Marshal(rule)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := parseRuleFields(raw)
		if err != nil {
			t.Fatal(err)
		}
		candidate.Raw, candidate.Fields = raw, fields
		prior[ruleID] = candidate
		return prior
	}
	first := ac.res.Statement.Rules[0].RuleID
	for _, tc := range []struct {
		name  string
		base  cycle
		mut   func(*Statement)
		prior func(cycle) map[string]ruleCandidate
	}{
		{"citation classified CONTENT_CHANGED", ac, func(s *Statement) { s.Rules[0].Citations[0].Class = evidencerepin.ClassContentChanged }, nil},
		{"citation classified NO_RELEASE_BASELINE", ac, func(s *Statement) { s.Rules[0].Citations[0].Class = evidencerepin.ClassNoReleaseBaseline }, nil},
		{"citation with an unknown baseline", ac, func(s *Statement) { s.Rules[0].Citations[0].Baseline = "tag" }, nil},
		{"citation pinned to another commit", ac, func(s *Statement) { s.Rules[0].Citations[0].PinnedCommit = strings.Repeat("9", 40) }, nil},
		{"citation for an unknown source", ac, func(s *Statement) { s.Rules[0].Citations[0].SourceID = "other" }, nil},
		{"citation for an unknown source with no pinned commit", ac, func(s *Statement) {
			s.Rules[0].Citations[0].SourceID, s.Rules[0].Citations[0].PinnedCommit = "other", ""
		}, nil},
		{"missing citation", ac, func(s *Statement) { s.Rules[0].Citations = nil }, nil},
		{"duplicate citation", ac, func(s *Statement) {
			s.Rules[0].Citations = append(s.Rules[0].Citations, s.Rules[0].Citations[0])
		}, nil},
		{"third consecutive cycle", ac, func(s *Statement) { s.Rules[0].ConsecutiveBatchCycles = 3 }, nil},
		{"zero consecutive cycles", ac, func(s *Statement) { s.Rules[0].ConsecutiveBatchCycles = 0 }, nil},
		{"rule not in the prior pack", ac, func(s *Statement) { s.Rules[0].RuleID = "no-such-rule" }, nil},
		{"automated statement with a wave", ac, func(s *Statement) { s.Wave = 1 }, nil},
		{"automated statement with a sample", ac, func(s *Statement) { s.SampledForFullReview = []SampledEntry{{RuleID: first}} }, nil},
		{"automated rule without its validUntil", ac, func(s *Statement) { s.Rules[0].ValidUntil = "" }, nil},
		{"human statement without a wave", hc, func(s *Statement) { s.Wave = 0 }, nil},
		{"human statement without a sample", hc, func(s *Statement) { s.SampledForFullReview = nil }, nil},
		{"human rule with a per-rule validUntil", hc, func(s *Statement) { s.Rules[0].ValidUntil = s.ValidUntil }, nil},
		{"mechanical rule", ac, nil, func(c cycle) map[string]ruleCandidate {
			return mutatePrior(c, first, func(rule map[string]any) { markMechanical(rule, "2026-09-01T00:00:00Z") })
		}},
		{"ranged rule", ac, nil, func(c cycle) map[string]ruleCandidate {
			return mutatePrior(c, first, func(rule map[string]any) { rule["range"] = map[string]any{"fromMin": "1.0.0"} })
		}},
		{"duplicate citation for one of two sources", ac, func(s *Statement) {
			s.Rules[0].Citations = append(s.Rules[0].Citations, s.Rules[0].Citations[0])
		}, func(c cycle) map[string]ruleCandidate {
			return mutatePrior(c, first, func(rule map[string]any) {
				evidence := rule["evidence"].(map[string]any)
				sources := evidence["sources"].([]any)
				second := map[string]any{}
				for k, v := range sources[0].(map[string]any) {
					second[k] = v
				}
				second["id"] = "second-src"
				evidence["sources"] = append(sources, second)
			})
		}},
		{"withdrawn rule", ac, nil, func(c cycle) map[string]ruleCandidate {
			return mutatePrior(c, first, func(rule map[string]any) { rule["evidence"].(map[string]any)["state"] = "withdrawn" })
		}},
	} {
		statement := deepCopyStatement(t, tc.base.res.Statement)
		if tc.mut != nil {
			tc.mut(&statement)
		}
		prior := priorOf(tc.base)
		if tc.prior != nil {
			prior = tc.prior(tc.base)
		}
		if err := checkRolePolicy(statement, prior); err == nil || !strings.Contains(err.Error(), "V8:") {
			t.Fatalf("%s: expected a V8 rejection, got %v", tc.name, err)
		}
	}
}

func TestCheckV2ChecksTheAutomatedSchedule(t *testing.T) {
	f := newRoleFixture(t)
	automated := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil).res.Statement
	if err := checkV2(automated); err != nil {
		t.Fatalf("Prepare's own automated statement fails V2: %v", err)
	}
	slots := AutomatedSlots(baseNow)
	for _, tc := range []struct {
		name, want string
		mut        func(*Statement)
	}{
		{"rule validUntil between slots", "not an automated slot", func(s *Statement) { s.Rules[0].ValidUntil = rfc3339(slots[1].Add(-24 * time.Hour)) }},
		{"rule validUntil before the shortest automated lease", "not an automated slot", func(s *Statement) {
			s.Rules[0].ValidUntil = rfc3339(slots[0].Add(-7 * 24 * time.Hour))
		}},
		{"rule validUntil past the lease cap", "exceeds the policy-v1 90-day cap", func(s *Statement) {
			s.Rules[0].ValidUntil = rfc3339(slots[len(slots)-1].Add(7 * 24 * time.Hour))
		}},
		{"statement validUntil not the horizon", "horizon", func(s *Statement) { s.ValidUntil = rfc3339(slots[len(slots)-2]) }},
	} {
		statement := deepCopyStatement(t, automated)
		tc.mut(&statement)
		if err := checkV2(statement); err == nil || !strings.Contains(err.Error(), "V2:") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: expected a V2 rejection containing %q, got %v", tc.name, tc.want, err)
		}
	}
}

// Verify recomputes an automated statement in automated mode: an automated
// statement that also renews a rule the automated policy does not allow,
// with the next pack edited to match, fails.
func TestVerifyRejectsAutomatedStatementRenewingAnIneligibleRule(t *testing.T) {
	f := newRoleFixture(t)
	specs := cycleSpecs(3, baseNow)
	specs[2].class = evidencerepin.ClassContentChanged
	_, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 40)
	c := prepareAutomated(t, f.chainFixture, pack, baseNow, specs, "rev-2", nil)
	if worstClassOf(c, "rule-02") != evidencerepin.ClassContentChanged {
		t.Fatalf("setup: rule-02 must be excluded, got %+v", c.res.Statement.NotExtended)
	}
	statement := deepCopyStatement(t, c.res.Statement)
	extra := statement.Rules[0]
	extra.RuleID = "rule-02"
	statement.Rules = append(statement.Rules, extra)
	statement.NotExtended = []NotExtendedEntry{}
	next := setRuleDates(t, c.res.NextPack, "rule-02", statement.AttestedAt, extra.ValidUntil)
	tampered := c
	tampered.res.StatementCanonical = reencode(t, statement)
	tampered.res.NextPack = next
	if err := verifyCycle(tampered, f.chain()); err == nil {
		t.Fatal("Verify accepted an automated statement renewing an ineligible rule")
	}
}

// ---------------------------------------------------------------------
// Trust roots: v2 roles, v1 compatibility, migration
// ---------------------------------------------------------------------

func TestParseTrustRootRoles(t *testing.T) {
	now := time.Now().UTC()
	h, a, b := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	parse := func(raw []byte) error {
		_, err := ParseTrustRoot(raw, sourcecorpus.SHA(raw), now)
		return err
	}
	if err := parse(renderRoot(t, TrustRootSchema, 1, h.trustKey(RoleHuman), a.trustKey(RoleAutomation))); err != nil {
		t.Fatalf("v2 root with both roles: %v", err)
	}
	if err := parse(renderRoot(t, TrustRootSchemaV1, 1, h.trustKey(""))); err != nil {
		t.Fatalf("v1 root: %v", err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"v2 key without a role", renderRoot(t, TrustRootSchema, 1, h.trustKey(""))},
		{"v2 key with an unknown role", renderRoot(t, TrustRootSchema, 1, h.trustKey("root"))},
		{"v1 key with a role", renderRoot(t, TrustRootSchemaV1, 1, h.trustKey(RoleHuman))},
		{"threshold one role cannot meet", renderRoot(t, TrustRootSchema, 2, h.trustKey(RoleHuman), b.trustKey(RoleHuman), a.trustKey(RoleAutomation))},
	} {
		if err := parse(tc.raw); err == nil {
			t.Fatalf("%s: ParseTrustRoot accepted it", tc.name)
		}
	}
	if err := parse(renderRoot(t, TrustRootSchema, 2, h.trustKey(RoleHuman), b.trustKey(RoleHuman))); err != nil {
		t.Fatalf("a threshold every listed role meets: %v", err)
	}
}

// Every key of a v1 root is a human key: it signs human statements and
// can never sign, or verify, an automated one.
func TestV1TrustRootKeysAreHumanKeys(t *testing.T) {
	f := newRoleFixture(t)
	v1 := renderRoot(t, TrustRootSchemaV1, 1, f.automation.trustKey(""))
	digest := sourcecorpus.SHA(v1)
	human := humanStatementFor(t, f).res.StatementCanonical
	automated := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil).res.StatementCanonical
	sign := func(role string, statement []byte) error {
		_, err := Sign(SignOptions{
			Role: role, Statement: statement, TrustRoot: v1, EncryptedKey: f.automation.encrypted,
			Passphrase: []byte(testPassphrase), ExpectedTrustRootDigest: digest, Now: signerClock(t, statement),
		})
		return err
	}
	if err := sign(RoleHuman, human); err != nil {
		t.Fatalf("a v1 key signs a human statement: %v", err)
	}
	if err := sign(RoleAutomation, automated); err == nil {
		t.Fatal("a v1 key signed an automated statement")
	}
	if _, err := VerifySignature(VerifySignatureOptions{Statement: automated, Envelope: rawEnvelope(t, f.automation, automated), TrustRoot: v1, ExpectedTrustRootDigest: digest}); err == nil {
		t.Fatal("a v1 key's signature verified an automated statement")
	}
}

// asV1 renders statement the way a build that predates roles did: schema
// v1 and no signerRole.
func asV1(t *testing.T, statementRaw []byte) []byte {
	t.Helper()
	statement, err := ParseStatement(statementRaw)
	if err != nil {
		t.Fatal(err)
	}
	statement.Schema, statement.SignerRole = StatementSchemaV1, ""
	raw := reencode(t, statement)
	if role, err := StatementSignerRole(raw); err != nil || role != RoleHuman {
		t.Fatalf("a v1 statement must parse as a human statement: %q %v", role, err)
	}
	return raw
}

// A chain begun under a v1 root, with v1 statements, stays verifiable after
// the root is migrated to v2 (its key becoming the human key, plus a new
// automation key), and automated statements then extend it.
func TestV1ChainSurvivesTrustRootMigration(t *testing.T) {
	human, automation := newKeyPair(t), newKeyPair(t)
	v1Root := renderRoot(t, TrustRootSchemaV1, 1, human.trustKey(""))
	f := &chainFixture{t: t, key: human.encrypted, root: v1Root, digest: sourcecorpus.SHA(v1Root)}

	c1 := prepareCycle(t, f, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	v1Statement := asV1(t, c1.res.StatementCanonical)
	f.entries = append(f.entries, ChainEntry{Name: "0001", Statement: v1Statement, Envelope: f.sign(v1Statement)})
	if _, err := deriveChainState(f.chain(), PackCNCF, baseNow.Add(time.Hour), ""); err != nil {
		t.Fatalf("v1 chain under the v1 root: %v", err)
	}

	migrated, err := MigrateTrustRoot(MigrateTrustRootOptions{
		From: v1Root, ExpectedFromDigest: f.digest, Now: time.Now().UTC(),
		AddAutomationKeys: []string{hex.EncodeToString(automation.public)},
	})
	if err != nil {
		t.Fatalf("MigrateTrustRoot: %v", err)
	}
	for _, key := range migrated.Keys {
		want := RoleAutomation
		if key.KeyID == human.id {
			want = RoleHuman
		}
		if key.Role != want {
			t.Fatalf("key %s migrated with role %q, want %q", key.KeyID, key.Role, want)
		}
	}
	rf := &roleFixture{
		chainFixture: &chainFixture{t: t, key: human.encrypted, root: migrated.TrustRoot, digest: migrated.Digest, entries: f.entries},
		human:        human, automation: automation,
	}
	if _, err := deriveChainState(rf.chain(), PackCNCF, baseNow.Add(time.Hour), ""); err != nil {
		t.Fatalf("the v1 chain no longer verifies under the migrated root: %v", err)
	}

	t2 := mustParse(c1.res.Statement.ValidUntil)
	c2 := prepareAutomated(t, rf.chainFixture, c1.res.NextPack, t2, cycleSpecs(12, t2), "rev-3", nil)
	if *c2.res.Statement.PreviousAttestationDigest != sourcecorpus.SHA(v1Statement) {
		t.Fatal("the automated statement does not link to the v1 head")
	}
	if len(c2.res.Statement.Rules) == 0 {
		t.Fatalf("expected automated renewals on top of the v1 chain, got %+v", c2.res.Statement.NotExtended)
	}
	if err := verifyCycle(c2, rf.chain()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	rf.appendAutomated("0002", c2.res.StatementCanonical)
	if _, err := deriveChainState(rf.chain(), PackCNCF, t2.Add(time.Hour), ""); err != nil {
		t.Fatalf("mixed v1/v2 chain: %v", err)
	}

	// A v1 statement is a human statement even under the v2 root: the
	// automation key's signature on it is not a valid chain entry.
	forged := &Chain{Entries: []ChainEntry{{Name: "0001", Statement: v1Statement, Envelope: rawEnvelope(t, automation, v1Statement)}}, TrustRoot: migrated.TrustRoot, ExpectedTrustRootDigest: migrated.Digest}
	if _, err := deriveChainState(forged, PackCNCF, baseNow.Add(time.Hour), ""); err == nil {
		t.Fatal("an automation key's signature on a v1 statement was accepted")
	}
}

func TestMigrateTrustRoot(t *testing.T) {
	now := time.Now().UTC()
	h, a, a2 := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	v1 := renderRoot(t, TrustRootSchemaV1, 1, h.trustKey(""))
	v1Digest := sourcecorpus.SHA(v1)
	migrate := func(opts MigrateTrustRootOptions) (MigrateTrustRootResult, error) {
		if opts.Now.IsZero() {
			opts.Now = now
		}
		return MigrateTrustRoot(opts)
	}
	plain, err := migrate(MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest})
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseTrustRoot(plain.TrustRoot, plain.Digest, now)
	if err != nil || root.SchemaVersion != TrustRootSchema || len(root.Keys) != 1 || root.Keys[0].Role != RoleHuman || root.Keys[0].KeyID != h.id {
		t.Fatalf("v1 to v2 without changes: %+v %v", root, err)
	}
	var v1Parsed TrustRoot
	if err := json.Unmarshal(v1, &v1Parsed); err != nil {
		t.Fatal(err)
	}
	if root.Expires != v1Parsed.Expires || root.Threshold != v1Parsed.Threshold {
		t.Fatal("expiry and threshold must carry over")
	}
	again, err := migrate(MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest})
	if err != nil || string(again.TrustRoot) != string(plain.TrustRoot) {
		t.Fatal("migration is not deterministic")
	}
	added, err := migrate(MigrateTrustRootOptions{From: plain.TrustRoot, ExpectedFromDigest: plain.Digest, AddAutomationKeys: []string{hex.EncodeToString(a.public)}})
	if err != nil {
		t.Fatal(err)
	}
	// Rotation keeps every remaining key's role.
	rotated, err := migrate(MigrateTrustRootOptions{
		From: added.TrustRoot, ExpectedFromDigest: added.Digest, RemoveKeyIDs: []string{a.id}, AddAutomationKeys: []string{hex.EncodeToString(a2.public)},
		Expires: rfc3339(now.Add(48 * time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, key := range rotated.Keys {
		roles[key.KeyID] = key.Role
	}
	if len(roles) != 2 || roles[h.id] != RoleHuman || roles[a2.id] != RoleAutomation {
		t.Fatalf("rotation: %+v", roles)
	}
	for _, tc := range []struct {
		name string
		opts MigrateTrustRootOptions
	}{
		{"wrong pinned digest", MigrateTrustRootOptions{From: v1, ExpectedFromDigest: plain.Digest}},
		{"remove an unknown key", MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest, RemoveKeyIDs: []string{a.id}}},

		{"malformed public key", MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest, AddAutomationKeys: []string{"zz"}}},
		{"expiry in the past", MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest, Expires: rfc3339(now.Add(-time.Hour))}},
		{"no keys left", MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest, RemoveKeyIDs: []string{h.id}}},
	} {
		if _, err := migrate(tc.opts); err == nil {
			t.Fatalf("%s: MigrateTrustRoot accepted it", tc.name)
		}
	}
	// A key already in the root, in either role, is refused as such; a
	// human key can never be re-added as an automation key.
	for _, tc := range []struct {
		name string
		opts MigrateTrustRootOptions
	}{
		{"add a key already present", MigrateTrustRootOptions{From: added.TrustRoot, ExpectedFromDigest: added.Digest, AddAutomationKeys: []string{hex.EncodeToString(a.public)}}},
		{"add the human key as an automation key", MigrateTrustRootOptions{From: v1, ExpectedFromDigest: v1Digest, AddAutomationKeys: []string{hex.EncodeToString(h.public)}}},
	} {
		if _, err := migrate(tc.opts); err == nil || !strings.Contains(err.Error(), "already in the trust root") {
			t.Fatalf("%s: want an already-present refusal, got %v", tc.name, err)
		}
	}
}
