// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

const pinPackPath = "/p/rules.json"

// pinSpec is a fresh rule of an operator the fixed-version predicate admits.
func pinSpec(id string, now time.Time) ruleSpec {
	spec := freshSpec(id, "proj-"+id, now)
	spec.operator = "forbid_predicate_value"
	return spec
}

// onReleaseLine turns every citation of a worklist into a release-line
// citation backed by a resolved line record, as evidence repin records one.
func onReleaseLine(wl *evidencerepin.Worklist, at time.Time) {
	for i := range wl.Citations {
		c := &wl.Citations[i]
		commit := strings.Repeat("c", 40)
		c.NewCommit, c.Baseline, c.BaselineMode = commit, evidencerepin.BaselineReleaseLine, evidencerepin.BaselineModeReleaseLine
		c.BaselineLine, c.PinnedTag, c.BaselineTag = "0.9", "v0.9.0", "v0.9.4"
		wl.Lines = append(wl.Lines, evidencerepin.LineResolution{
			Owner: c.Owner, Repo: c.Repo, Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: commit,
			ResolvedAt: rfc3339(at.Add(-time.Hour)),
		})
	}
}

// pinFixture prepares a pinning statement for the given specs in a pack padded
// with unrelated rules, with the sample reviewed.
type pinned struct {
	wl      evidencerepin.Worklist
	pack    []byte
	wlRaw   []byte
	opts    PrepareOptions
	result  PrepareResult
	reviews map[string][]byte
}

func pinFixture(t *testing.T, maxRules int, specs ...ruleSpec) pinned {
	t.Helper()
	wl, pack := buildWorklistAndPack(t, pinPackPath, baseNow, specs)
	onReleaseLine(&wl, baseNow)
	pack = padPackWithSpreadRules(t, pack, 12)
	wlRaw := marshalWorklist(t, wl)
	opts := PrepareOptions{
		WorklistRaw: wlRaw, PackName: PackCNCF, PackPath: pinPackPath, PackRaw: pack, Pin: true, MaxRules: maxRules,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	}
	opts = withSampleRecords(t, opts)
	result, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return pinned{wl: wl, pack: pack, wlRaw: wlRaw, opts: opts, result: result, reviews: opts.ReviewRecords}
}

func (p pinned) verifyOptions() VerifyOptions {
	return VerifyOptions{
		StatementRaw: p.result.StatementCanonical, PriorPackRaw: p.pack, NextPackRaw: p.result.NextPack, WorklistRaw: p.wlRaw,
		Chain: &Chain{}, BaseChain: &Chain{}, PackName: PackCNCF, PackPath: pinPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: baseNow.Add(time.Hour), ReviewRecords: p.reviews, PreSign: true,
	}
}

func ruleEvidence(t *testing.T, pack []byte, id string) map[string]any {
	t.Helper()
	var doc struct {
		Entries []struct {
			Rule map[string]any `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(pack, &doc); err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc.Entries {
		if entry.Rule["id"] == id {
			return entry.Rule["evidence"].(map[string]any)
		}
	}
	t.Fatalf("rule %s not in the pack", id)
	return nil
}

// A pinning statement moves exactly the pinned fields and verifies.
func TestPinPrepareAndVerify(t *testing.T) {
	p := pinFixture(t, 0, pinSpec("rule-a", baseNow))
	if len(p.result.Statement.Rules) != 1 {
		t.Fatalf("expected the rule pinned: %+v", p.result.Statement.NotExtended)
	}
	row := p.result.Statement.Rules[0]
	if row.Lease != constraintengine.LeasePinned || row.ValidUntil != "" || row.ConsecutiveBatchCycles != 1 {
		t.Fatalf("pinned row: %+v", row)
	}
	if p.result.Statement.Statement != PinnedStatementText(p.wl.GeneratedAt) || p.result.Statement.Authority != Authority || p.result.Statement.SignerRole != RoleHuman {
		t.Fatalf("a pinning statement is a human statement with its own text: %+v", p.result.Statement)
	}
	evidence := ruleEvidence(t, p.result.NextPack, "rule-a")
	if evidence["lease"] != "pinned" || evidence["reviewedAt"] != rfc3339(baseNow) || evidence["validUntil"] != "2036-10-06T12:00:00Z" {
		t.Fatalf("pinned evidence: %+v", evidence)
	}
	if prior := ruleEvidence(t, p.pack, "rule-a"); prior["lease"] != nil {
		t.Fatalf("the prior pack must not hold a lease: %+v", prior)
	}
	if _, err := Verify(p.verifyOptions()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A pinning batch takes only rules that meet the predicate and is capped by
// --max-rules; the rest are listed with their reason.
func TestPinSelectsOnlyPinnableRulesAndCaps(t *testing.T) {
	notPinnable := pinSpec("rule-d", baseNow)
	notPinnable.operator = "require_component_version"
	p := pinFixture(t, 2, pinSpec("rule-a", baseNow), pinSpec("rule-b", baseNow), pinSpec("rule-c", baseNow), notPinnable)
	if got := renewedIDs(p.result); got != "rule-a,rule-b" {
		t.Fatalf("pinned %q", got)
	}
	reasons := map[string]string{}
	for _, ne := range p.result.Statement.NotExtended {
		reasons[ne.RuleID] = ne.WorstClass
	}
	if reasons["rule-c"] != reasonStaggerDeferred {
		t.Fatalf("a rule beyond the cap is deferred: %v", reasons)
	}
	if want := reasonPinnedNotEligible + ":" + constraintengine.PinnedReasonOperator; reasons["rule-d"] != want {
		t.Fatalf("rule-d: %q, want %q", reasons["rule-d"], want)
	}
	if _, err := Verify(p.verifyOptions()); err != nil {
		t.Fatalf("a capped pinning statement must verify: %v", err)
	}
}

// Automation never pins.
func TestPinRefusedForAutomation(t *testing.T) {
	wl, pack := buildWorklistAndPack(t, pinPackPath, baseNow, []ruleSpec{pinSpec("rule-a", baseNow)})
	onReleaseLine(&wl, baseNow)
	_, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: pinPackPath, PackRaw: pack, Pin: true, Mode: ModeAutomated,
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "refuses pinning") {
		t.Fatalf("automated pinning: %v", err)
	}
	// A hand-made automated statement with a pinned row never parses either.
	p := pinFixture(t, 0, pinSpec("rule-a", baseNow))
	forged := p.result.Statement
	forged.SignerRole = RoleAutomation
	forged.Wave = 0
	forged.SampledForFullReview = nil
	forged.Authority = AuthorityAutomated
	forged.Statement = AutomatedStatementText(forged.Worklist.GeneratedAt, forged.ValidUntil)
	forged.Rules = append([]RuleAttestation(nil), forged.Rules...)
	forged.Rules[0].ValidUntil = forged.ValidUntil
	raw, err := CanonicalStatement(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStatement(raw); err == nil {
		t.Fatal("an automated statement with a pinned row parsed")
	}
	if err := checkRowLeases(forged, RoleAutomation); err == nil {
		t.Fatal("an automated role accepted a pinned row")
	}
}

// The statement's lease column is closed: an unknown token, a mixed batch and
// a v1 statement are refused.
func TestPinRowLeaseColumnIsClosed(t *testing.T) {
	p := pinFixture(t, 0, pinSpec("rule-a", baseNow), pinSpec("rule-b", baseNow))
	st := p.result.Statement
	for name, mutate := range map[string]func(*Statement){
		"unknown token": func(s *Statement) { s.Rules[0].Lease = "forever" },
		"time token":    func(s *Statement) { s.Rules[0].Lease = "time" },
		"mixed rows":    func(s *Statement) { s.Rules[1].Lease = "" },
	} {
		forged := st
		forged.Rules = append([]RuleAttestation(nil), st.Rules...)
		mutate(&forged)
		raw, err := CanonicalStatement(forged)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseStatement(raw); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// Only a release-line comparison can pin: a citation compared with the latest
// release is not on a derivable line.
func TestPinNeedsReleaseLineCitations(t *testing.T) {
	wl, pack := buildWorklistAndPack(t, pinPackPath, baseNow, []ruleSpec{pinSpec("rule-a", baseNow)})
	_, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: pinPackPath, PackRaw: pack, Pin: true, Wave: 1,
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err == nil || !strings.Contains(err.Error(), reasonPinNothing) {
		t.Fatalf("a batch with no derivable line must pin nothing: %v", err)
	}
	// With a second, pinnable rule the first is listed with its reason.
	specs := []ruleSpec{pinSpec("rule-a", baseNow), pinSpec("rule-b", baseNow)}
	wl, pack = buildWorklistAndPack(t, pinPackPath, baseNow, specs)
	only := wl
	only.Citations = []evidencerepin.ClassResult{wl.Citations[1]}
	onReleaseLine(&only, baseNow)
	wl.Citations[1] = only.Citations[0]
	wl.Lines = only.Lines
	opts := withSampleRecords(t, PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: pinPackPath, PackRaw: pack, Pin: true, Wave: 1,
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	result, err := Prepare(opts)
	if err != nil {
		t.Fatal(err)
	}
	if renewedIDs(result) != "rule-b" {
		t.Fatalf("pinned %q", renewedIDs(result))
	}
	want := reasonPinnedNotEligible + ":citation-line-not-derivable"
	for _, ne := range result.Statement.NotExtended {
		if ne.RuleID == "rule-a" && ne.WorstClass == want {
			return
		}
	}
	t.Fatalf("rule-a must be left out as %s: %+v", want, result.Statement.NotExtended)
}

// A rule already on the pinned lease is never renewed by any batch.
func TestPinnedRuleIsNotRenewedAgain(t *testing.T) {
	spec := pinSpec("rule-a", baseNow)
	spec.lease = constraintengine.LeasePinned
	spec.reviewedAt = rfc3339(baseNow.Add(-24 * time.Hour))
	spec.validUntil = "2036-10-05T12:00:00Z"
	for _, pin := range []bool{false, true} {
		wl, pack := buildWorklistAndPack(t, pinPackPath, baseNow, []ruleSpec{spec})
		onReleaseLine(&wl, baseNow)
		_, err := Prepare(PrepareOptions{
			WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: pinPackPath, PackRaw: pack, Pin: pin, Wave: 1,
			AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
		})
		if pin {
			if err == nil || !strings.Contains(err.Error(), reasonPinNothing) {
				t.Fatalf("pinning a pinned rule: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	wl, pack := buildWorklistAndPack(t, pinPackPath, baseNow, []ruleSpec{spec})
	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: pinPackPath, PackRaw: pack, Wave: 1,
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil || len(result.Statement.Rules) != 0 || len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != reasonAlreadyPinned {
		t.Fatalf("a time batch must leave a pinned rule alone: %v %+v", err, result.Statement)
	}
}

// Everything a signed pinning row binds is recomputed byte for byte: the
// row's lease, the pinned window, and the lease in the pack.
func TestPinVerifyRecomputesTheLeaseBytes(t *testing.T) {
	p := pinFixture(t, 0, pinSpec("rule-a", baseNow))
	// Surgical edits of the exact next-pack bytes, so a rejection can only be
	// about the edited lease bytes.
	tamper := func(old, replacement string) []byte {
		text := string(p.result.NextPack)
		if strings.Count(text, old) != 1 {
			t.Fatalf("setup: %q is not in the next pack exactly once", old)
		}
		return []byte(strings.Replace(text, old, replacement, 1))
	}
	for name, next := range map[string][]byte{
		"lease dropped from the pack":      tamper(`"lease": "pinned",`, ``),
		"lease set to time in the pack":    tamper(`"lease": "pinned"`, `"lease": "time"`),
		"window one second long":           tamper(`2036-10-06T12:00:00Z`, `2036-10-06T12:00:01Z`),
		"window shortened to a time lease": tamper(`2036-10-06T12:00:00Z`, `2027-01-04T12:00:00Z`),
	} {
		opts := p.verifyOptions()
		opts.NextPackRaw = next
		if _, err := Verify(opts); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// The row of the statement itself: dropping its lease no longer parses
	// (the signed text names the pin), and a row that pins a rule the pack
	// does not pin fails the recomputation.
	forged := p.result.Statement
	forged.Rules = append([]RuleAttestation(nil), forged.Rules...)
	forged.Rules[0].Lease = ""
	raw, err := CanonicalStatement(forged)
	if err != nil {
		t.Fatal(err)
	}
	opts := p.verifyOptions()
	opts.StatementRaw = raw
	if _, err := Verify(opts); err == nil {
		t.Fatal("a statement whose row lost its lease verified")
	}
	// Unpinned pack against a pinning statement.
	opts = p.verifyOptions()
	opts.NextPackRaw = p.pack
	if _, err := Verify(opts); err == nil {
		t.Fatal("a pinning statement verified against an unchanged pack")
	}
}

// A signature over a pinning statement does not cover a statement whose row
// lease was altered.
func TestPinSignatureBindsTheRowLease(t *testing.T) {
	p := pinFixture(t, 0, pinSpec("rule-a", baseNow))
	f := newChainFixture(t)
	envelope := f.sign(p.result.StatementCanonical)
	forged := p.result.Statement
	forged.Rules = append([]RuleAttestation(nil), forged.Rules...)
	forged.Rules[0].Lease = ""
	raw, err := CanonicalStatement(forged)
	if err != nil {
		t.Fatal(err)
	}
	options := VerifySignatureOptions{Statement: p.result.StatementCanonical, Envelope: envelope, TrustRoot: f.root, ExpectedTrustRootDigest: f.digest, Now: baseNow.Add(time.Hour)}
	if _, err := VerifySignature(options); err != nil {
		t.Fatalf("the signed statement must verify: %v", err)
	}
	options.Statement = raw
	if _, err := VerifySignature(options); err == nil {
		t.Fatal("a signature verified a statement with another lease")
	}
}

// pinCycleSpecs are cycleSpecs of an operator the predicate admits.
func pinCycleSpecs(n int, at time.Time) []ruleSpec {
	specs := cycleSpecs(n, at)
	for i := range specs {
		specs[i].operator = "forbid_predicate_value"
	}
	return specs
}

// Pinning counts as one batch cycle and never resets the count; a rule that
// has used its two cycles cannot be pinned.
func TestPinCountsAsACycleAndRespectsTheCap(t *testing.T) {
	f := newChainFixture(t)
	t1 := baseNow
	_, pack := buildWorklistAndPack(t, chainPackPath, t1, pinCycleSpecs(12, t1))
	pack = padPackWithPastRules(t, pack, 80)
	c1 := prepareCycle(t, f, pack, t1, pinCycleSpecs(12, t1), "rev-2", nil)
	if err := verifyCycle(c1, f.chain()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	f.append("0001", c1.res.StatementCanonical)
	t2 := t1.Add(cycleSpacing)
	c2 := prepareCycle(t, f, c1.res.NextPack, t2, pinCycleSpecs(12, t2), "rev-3", nil)
	if err := verifyCycle(c2, f.chain()); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	f.append("0002", c2.res.StatementCanonical)
	atCap := ""
	for _, ra := range c2.res.Statement.Rules {
		if ra.ConsecutiveBatchCycles == 2 {
			atCap = ra.RuleID
		}
	}
	if atCap == "" {
		t.Fatal("setup: no rule is at the cap")
	}

	// Cycle 3 pins.
	t3 := t2.Add(cycleSpacing)
	wl, _ := buildWorklistAndPack(t, chainPackPath, t3, pinCycleSpecs(12, t3))
	onReleaseLine(&wl, t3)
	wlRaw := marshalWorklist(t, wl)
	opts := PrepareOptions{
		WorklistRaw: wlRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: c2.res.NextPack, Chain: f.chain(), Pin: true,
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest,
	}
	opts = withSampleRecords(t, opts)
	res, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	reason := ""
	for _, ne := range res.Statement.NotExtended {
		if ne.RuleID == atCap {
			reason = ne.WorstClass
		}
	}
	if reason != reasonConsecutiveCycleCap {
		t.Fatalf("a rule at the cap must not be pinned: %q (%s)", reason, renewedIDs(res))
	}
	priorCycles := map[string]int{}
	for _, ra := range c2.res.Statement.Rules {
		priorCycles[ra.RuleID] = ra.ConsecutiveBatchCycles
	}
	reviewed := map[string]bool{}
	for _, review := range res.Statement.IndividualReviews {
		reviewed[review.RuleID] = true
	}
	if len(res.Statement.Rules) == 0 {
		t.Fatal("setup: nothing was pinned")
	}
	for _, ra := range res.Statement.Rules {
		want := priorCycles[ra.RuleID] + 1
		if reviewed[ra.RuleID] {
			want = 1 // only a new individual review resets the count
		}
		if ra.RuleID == atCap || ra.ConsecutiveBatchCycles != want {
			t.Fatalf("pinning must count as one more cycle, not reset it: %+v (want %d)", ra, want)
		}
	}
	verify := VerifyOptions{
		StatementRaw: res.StatementCanonical, PriorPackRaw: c2.res.NextPack, NextPackRaw: res.NextPack, WorklistRaw: wlRaw,
		Chain: f.chain(), BaseChain: f.chain(), PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: t3.Add(time.Hour), ReviewRecords: opts.ReviewRecords, PreSign: true,
	}
	if _, err := Verify(verify); err != nil {
		t.Fatalf("the pinning cycle must verify: %v", err)
	}
	// A statement that also pins the capped rule is refused by the chain.
	capped := res.Statement
	capped.Rules = append(append([]RuleAttestation(nil), capped.Rules...), RuleAttestation{
		RuleID: atCap, ConsecutiveBatchCycles: 3, Lease: constraintengine.LeasePinned,
	})
	state, err := deriveChainState(f.chain(), PackCNCF, t3.Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	cloned := state.clone()
	if err := cloned.apply(capped); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("a third consecutive cycle through a pin: %v", err)
	}
}

// Pinned rules are exempt from the stagger cap and nothing else is.
func TestCheckV7ExemptsPinnedRulesOnly(t *testing.T) {
	slot := time.Date(2036, 10, 6, 12, 0, 0, 0, time.UTC)
	build := func(lease string) (Statement, map[string]json.RawMessage) {
		next := map[string]json.RawMessage{}
		var st Statement
		for i := 0; i < 20; i++ {
			id := fmt.Sprintf("rule-%02d", i)
			leaseField := ""
			if lease != "" {
				leaseField = fmt.Sprintf(`"lease":%q,`, lease)
			}
			raw := fmt.Sprintf(`{"id":%q,"evidence":{"state":"active",%s"reviewedAt":"2026-10-06T12:00:00Z","validUntil":%q,"sources":[]}}`, id, leaseField, rfc3339(slot))
			next[id] = json.RawMessage(raw)
			st.Rules = append(st.Rules, RuleAttestation{RuleID: id, Lease: lease})
		}
		return st, next
	}
	if st, next := build("pinned"); checkV7(st, next) != nil {
		t.Fatalf("twenty pinned rules in one week: %v", checkV7(st, next))
	}
	if st, next := build(""); checkV7(st, next) == nil {
		t.Fatal("twenty time-lease rules in one week passed the stagger cap")
	}
}
