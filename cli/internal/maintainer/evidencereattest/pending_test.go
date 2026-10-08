// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const pendingPackPath = "/p/rules.json"

// pendingSetup builds a pack of rule-a (clean), rule-b and rule-c (both
// citing the pending repository owner/shared) and rule-d (clean), and
// returns the prepared statement with everything Verify needs.
func pendingSetup(t *testing.T) (PrepareResult, VerifyOptions) {
	t.Helper()
	specs := []ruleSpec{freshSpec("rule-a", "proj-a", baseNow), freshSpec("rule-b", "proj-b", baseNow), freshSpec("rule-c", "proj-c", baseNow), freshSpec("rule-d", "proj-d", baseNow)}
	wl, pack := buildWorklistAndPack(t, pendingPackPath, baseNow, specs)
	for i := range wl.Citations {
		if id := wl.Citations[i].RuleID; id == "rule-b" || id == "rule-c" {
			wl.Citations[i].Class = evidencerepin.ClassPending
			wl.Citations[i].Owner, wl.Citations[i].Repo = "owner", "shared"
		}
	}
	// The worklist lists the pending citations in reverse order: the
	// statement must still record them sorted.
	for i, j := 0, len(wl.Citations)-1; i < j; i, j = i+1, j-1 {
		wl.Citations[i], wl.Citations[j] = wl.Citations[j], wl.Citations[i]
	}
	pack = padPackWithSpreadRules(t, pack, 12)
	raw := marshalWorklist(t, wl)
	prepare := PrepareOptions{
		WorklistRaw: raw, PackName: PackCNCF, PackPath: pendingPackPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	}
	result, records := prepareWithSample(t, prepare)
	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw, opts.PriorPackRaw, opts.NextPackRaw = result.StatementCanonical, pack, result.NextPack
	opts.WorklistRaw, opts.PackName, opts.PackPath = raw, PackCNCF, pendingPackPath
	opts.EngineCapabilityDigest, opts.ReviewRecords = testEngineCapabilityDigest, records
	return result, opts
}

func TestPendingCitationExcludesOnlyTheRulesThatCiteIt(t *testing.T) {
	result, _ := pendingSetup(t)
	renewed := map[string]bool{}
	for _, ra := range result.Statement.Rules {
		renewed[ra.RuleID] = true
	}
	if !renewed["rule-a"] || !renewed["rule-d"] || renewed["rule-b"] || renewed["rule-c"] {
		t.Fatalf("only rule-b and rule-c must be excluded: %v", renewed)
	}
	byID := map[string]NotExtendedEntry{}
	for _, ne := range result.Statement.NotExtended {
		byID[ne.RuleID] = ne
	}
	for _, id := range []string{"rule-b", "rule-c"} {
		ne := byID[id]
		if ne.WorstClass != reasonCitationPending || len(ne.PendingRepositories) != 1 || ne.PendingRepositories[0] != "owner/shared" {
			t.Fatalf("%s: want CITATION_PENDING naming owner/shared, got %+v", id, ne)
		}
	}
	for id, ne := range byID {
		if ne.WorstClass == reasonScopeIncomplete {
			t.Fatalf("%s: a pending citation must not make the worklist incomplete", id)
		}
	}
	want := []PendingCitation{
		{Repo: "owner/shared", RuleID: "rule-b", SourceID: "rule-b-src"},
		{Repo: "owner/shared", RuleID: "rule-c", SourceID: "rule-c-src"},
	}
	got := result.Statement.PendingCitations
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("pending citations not recorded sorted: %+v", got)
	}
	summary := PendingRepositorySummary(result.Statement)
	if len(summary) != 1 || summary[0].Rules != 2 || summary[0].Citations != 2 {
		t.Fatalf("pending repository summary: %+v", summary)
	}
	if !strings.Contains(string(result.Summary), "owner/shared: 2 rules, 2 citations") {
		t.Fatalf("summary text does not name the pending repository:\n%s", result.Summary)
	}
}

func TestUnclassifiedCitationKeepsWorklistLevelGate(t *testing.T) {
	wl, pack := buildWorklistAndPack(t, pendingPackPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow), freshSpec("rule-b", "proj-b", baseNow)})
	wl.Citations[1].Class = ""
	result := prepareSingle(t, wl, pack, pendingPackPath)
	if len(result.Statement.Rules) != 0 || len(result.Statement.NotExtended) != 2 {
		t.Fatalf("an unclassified citation must disqualify the whole worklist: %+v", result.Statement.Rules)
	}
	for _, ne := range result.Statement.NotExtended {
		if ne.WorstClass != reasonScopeIncomplete {
			t.Fatalf("want %s, got %+v", reasonScopeIncomplete, ne)
		}
	}
}

func TestVerifyAcceptsStatementWithPendingExclusions(t *testing.T) {
	_, opts := pendingSetup(t)
	if _, err := Verify(opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsStatementDroppingAPendingCitation(t *testing.T) {
	result, opts := pendingSetup(t)
	statement := result.Statement
	statement.PendingCitations = statement.PendingCitations[:1]
	raw, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	opts.StatementRaw = raw
	assertVerifyRejects(t, opts, "V11")

	statement.PendingCitations = nil
	raw, _ = CanonicalStatement(statement)
	opts.StatementRaw = raw
	assertVerifyRejects(t, opts, "V11")
}

func TestVerifyRejectsStatementWithSwappedPendingCitation(t *testing.T) {
	result, opts := pendingSetup(t)
	statement := result.Statement
	statement.PendingCitations = append([]PendingCitation(nil), statement.PendingCitations...)
	statement.PendingCitations[1].SourceID = "other-src"
	raw, _ := CanonicalStatement(statement)
	opts.StatementRaw = raw
	assertVerifyRejects(t, opts, "V11")
}

func TestVerifyRejectsPendingCitationMissingFromIndependentWorklist(t *testing.T) {
	_, opts := pendingSetup(t)
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(opts.WorklistRaw, &wl); err != nil {
		t.Fatal(err)
	}
	wl.Citations = append(wl.Citations, evidencerepin.ClassResult{RulePack: pendingPackPath, RuleID: "rule-a", SourceID: "rule-a-src2", Owner: "owner", Repo: "other", Class: evidencerepin.ClassPending})
	opts.IndependentWorklistRaw = marshalWorklist(t, wl)
	assertVerifyRejects(t, opts, "V11")
}

func TestVerifyRejectsStatementWithInventedPendingCitation(t *testing.T) {
	result, opts := pendingSetup(t)
	statement := result.Statement
	statement.PendingCitations = append(append([]PendingCitation(nil), statement.PendingCitations...), PendingCitation{Repo: "owner/zzz", RuleID: "rule-z", SourceID: "s"})
	raw, _ := CanonicalStatement(statement)
	opts.StatementRaw = raw
	assertVerifyRejects(t, opts, "V11")
}

func TestVerifyRejectsRenewalOfARuleCitingAPendingCitation(t *testing.T) {
	result, opts := pendingSetup(t)
	statement := result.Statement
	statement.Rules = append(append([]RuleAttestation(nil), statement.Rules...), RuleAttestation{RuleID: "rule-b"})
	err := checkV11(statement, opts.PackPath, opts.WorklistRaw, packRulesOf(t, opts.PriorPackRaw))
	if err == nil || !strings.Contains(err.Error(), "must not be renewed") {
		t.Fatalf("want a refusal to renew rule-b, got %v", err)
	}
}

func TestVerifyRejectsExclusionWithoutPendingRepositories(t *testing.T) {
	result, opts := pendingSetup(t)
	statement := result.Statement
	statement.NotExtended = append([]NotExtendedEntry(nil), statement.NotExtended...)
	for i := range statement.NotExtended {
		if statement.NotExtended[i].RuleID == "rule-b" {
			statement.NotExtended[i].PendingRepositories = nil
		}
	}
	err := checkV11(statement, opts.PackPath, opts.WorklistRaw, packRulesOf(t, opts.PriorPackRaw))
	if err == nil || !strings.Contains(err.Error(), "does not name its pending repositories") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestVerifyRederivesPendingFromTheIndependentWorklist(t *testing.T) {
	result, opts := pendingSetup(t)
	// An independent worklist in which a renewed rule has a pending
	// citation is refused, even though the signing job's own worklist
	// agrees with the statement.
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(opts.WorklistRaw, &wl); err != nil {
		t.Fatal(err)
	}
	wl.Citations = append(wl.Citations, evidencerepin.ClassResult{RulePack: pendingPackPath, RuleID: "rule-a", SourceID: "rule-a-src2", Owner: "owner", Repo: "other", Class: evidencerepin.ClassPending})
	if err := checkV11Independent(result.Statement, pendingPackPath, marshalWorklist(t, wl)); err == nil {
		t.Fatal("a renewed rule citing a pending citation of the independent worklist must be refused")
	}
}

func rehearsalStatement(t *testing.T) PrepareResult {
	t.Helper()
	wl, pack := buildWorklistAndPack(t, pendingPackPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	result, _ := prepareWithSample(t, PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: pendingPackPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
		Rehearsal: true,
	})
	return result
}

func TestRehearsalStatementIsMarkedAndNeverSignedOrVerified(t *testing.T) {
	result := rehearsalStatement(t)
	if !result.Statement.Rehearsal || !strings.Contains(string(result.Summary), "REHEARSAL") {
		t.Fatal("a rehearsal statement must be marked in the statement and the summary")
	}
	encryptedKey, trustRoot, _ := generateTestKey(t, []byte("correct horse battery staple"))
	digest := sourcecorpus.SHA(trustRoot)
	_, err := Sign(SignOptions{Role: RoleHuman, Statement: result.StatementCanonical, TrustRoot: trustRoot, EncryptedKey: encryptedKey,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: digest, Now: baseNow.Add(time.Hour)})
	if err == nil || !strings.Contains(err.Error(), "rehearsal") {
		t.Fatalf("Sign must refuse a rehearsal statement, got %v", err)
	}
	// A real statement's signature over other bytes cannot launder it.
	real, _, _ := prepareOnePassResult(t, baseNow, pendingPackPath, freshSpec("rule-a", "proj-a", baseNow))
	envelope, err := Sign(SignOptions{Role: RoleHuman, Statement: real.StatementCanonical, TrustRoot: trustRoot, EncryptedKey: encryptedKey,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: digest, Now: baseNow.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Sign real: %v", err)
	}
	_, err = VerifySignature(VerifySignatureOptions{Statement: result.StatementCanonical, Envelope: envelope, TrustRoot: trustRoot, ExpectedTrustRootDigest: digest})
	if err == nil || !strings.Contains(err.Error(), "rehearsal") {
		t.Fatalf("VerifySignature must refuse a rehearsal statement, got %v", err)
	}
	wl, pack := buildWorklistAndPack(t, pendingPackPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw, opts.PriorPackRaw, opts.NextPackRaw = result.StatementCanonical, pack, result.NextPack
	opts.WorklistRaw, opts.PackName, opts.PackPath = marshalWorklist(t, wl), PackCNCF, pendingPackPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	assertVerifyRejects(t, opts, "rehearsal")
}

func packRulesOf(t *testing.T, packRaw []byte) map[string]json.RawMessage {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := rulesByID(doc)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// A pending citation of the independent worklist on a rule nobody renews
// does not make a correct statement unverifiable (14-M2): pending is
// volatile between two worklists, and only renewed rules carry integrity.
func TestVerifyAcceptsExtraPendingOnAnUnrenewedRuleInTheIndependentWorklist(t *testing.T) {
	result, opts := pendingSetup(t)
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(opts.WorklistRaw, &wl); err != nil {
		t.Fatal(err)
	}
	wl.Citations = append(wl.Citations, evidencerepin.ClassResult{RulePack: pendingPackPath, RuleID: "rule-b", SourceID: "rule-b-src2", Owner: "owner", Repo: "other", Class: evidencerepin.ClassPending})
	independent := marshalWorklist(t, wl)
	if err := checkV11Independent(result.Statement, pendingPackPath, independent); err != nil {
		t.Fatalf("an extra pending citation of an unrenewed rule must be accepted: %v", err)
	}
	// The same worklist is refused when it is the signing worklist: its
	// pending set is the statement's to record exactly.
	if err := checkV11(result.Statement, pendingPackPath, independent, packRulesOf(t, opts.PriorPackRaw)); err == nil {
		t.Fatal("the signing worklist must still match the statement's pending set exactly")
	}
	opts.IndependentWorklistRaw = independent
	if _, err := Verify(opts); err != nil {
		t.Fatalf("Verify with such an independent worklist: %v", err)
	}
}

// Both directions at once: dropping a pending citation from the independent
// worklist is also fine for an unrenewed rule, but a renewed rule that is
// pending there is refused.
func TestVerifyIndependentPendingFailsClosedOnlyForRenewedRules(t *testing.T) {
	result, opts := pendingSetup(t)
	var wl evidencerepin.Worklist
	if err := json.Unmarshal(opts.WorklistRaw, &wl); err != nil {
		t.Fatal(err)
	}
	kept := wl.Citations[:0:0]
	for _, c := range wl.Citations {
		if c.RuleID != "rule-c" {
			kept = append(kept, c)
		}
	}
	wl.Citations = kept
	if err := checkV11Independent(result.Statement, pendingPackPath, marshalWorklist(t, wl)); err != nil {
		t.Fatalf("fewer pending citations for an unrenewed rule must be accepted: %v", err)
	}
	for i := range wl.Citations {
		if wl.Citations[i].RuleID == "rule-d" {
			wl.Citations[i].Class = evidencerepin.ClassPending
		}
	}
	err := checkV11Independent(result.Statement, pendingPackPath, marshalWorklist(t, wl))
	if err == nil || !strings.Contains(err.Error(), "rule-d") || !strings.Contains(err.Error(), "V11") {
		t.Fatalf("a renewed rule pending in the independent worklist must be refused naming it, got %v", err)
	}
}

// 14-m3: a pending rule of the pack that the statement neither renews nor
// lists is named in the V11 refusal.
func TestVerifyNamesAPendingRuleMissingFromTheStatement(t *testing.T) {
	result, opts := pendingSetup(t)
	statement := result.Statement
	statement.NotExtended = nil
	for _, ne := range result.Statement.NotExtended {
		if ne.RuleID != "rule-b" {
			statement.NotExtended = append(statement.NotExtended, ne)
		}
	}
	err := checkV11(statement, opts.PackPath, opts.WorklistRaw, packRulesOf(t, opts.PriorPackRaw))
	if err == nil || !strings.Contains(err.Error(), "rule-b") || !strings.Contains(err.Error(), "missing from the statement") {
		t.Fatalf("want a refusal naming rule-b as missing, got %v", err)
	}
}

// 14-m1: a pending citation does not mask a drifted citation of the same
// rule. The drift reason is reported, with the pending repositories.
func TestPendingCitationDoesNotMaskADriftedCitationOfTheSameRule(t *testing.T) {
	for _, driftFirst := range []bool{false, true} {
		commit := strings.Repeat("a", 40)
		digest := "sha256:" + strings.Repeat("cd", 32)
		src1 := testSource("s1", "owner", "shared", commit, "VERSION", digest, 1, 1)
		src2 := testSource("s2", "owner", "repo-a", commit, "VERSION", digest, 1, 1)
		rule := testRule("rule-a", "active", rfc3339(baseNow.Add(-30*24*time.Hour)), rfc3339(baseNow.Add(7*24*time.Hour)), false, src1, src2)
		pack := padPackWithSpreadRules(t, testPack(t, testEntry("proj-a", rule)), 12)
		pending := evidencerepin.ClassResult{
			RulePack: pendingPackPath, RuleID: "rule-a", Project: "proj-a", SourceID: "s1", Owner: "owner", Repo: "shared",
			Path: "VERSION", OldCommit: commit, NewCommit: commit, Class: evidencerepin.ClassPending,
		}
		changed := pending
		changed.SourceID, changed.Repo, changed.Class = "s2", "repo-a", evidencerepin.ClassContentChanged
		citations := []evidencerepin.ClassResult{pending, changed}
		if driftFirst {
			citations = []evidencerepin.ClassResult{changed, pending}
		}
		wl := evidencerepin.Worklist{
			Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: rfc3339(baseNow),
			Scope: evidencerepin.WorklistScope{RulePacks: []string{pendingPackPath}},
			Repos: []evidencerepin.RepoResolution{
				{Owner: "owner", Repo: "repo-a", Status: "RESOLVED", CurrentTag: "v1.2.3", CurrentCommit: commit, ResolvedAt: rfc3339(baseNow.Add(-time.Hour))},
			},
			Citations: citations,
			Summary:   evidencerepin.Summary{TotalCitations: 2, Classified: 2, Pending: 1},
		}
		result := prepareSingle(t, wl, pack, pendingPackPath)
		var got *NotExtendedEntry
		for i := range result.Statement.NotExtended {
			if result.Statement.NotExtended[i].RuleID == "rule-a" {
				got = &result.Statement.NotExtended[i]
			}
		}
		if got == nil || got.WorstClass != evidencerepin.ClassContentChanged || len(got.PendingRepositories) != 1 || got.PendingRepositories[0] != "owner/shared" {
			t.Fatalf("driftFirst=%v: want CONTENT_CHANGED naming owner/shared, got %+v", driftFirst, got)
		}
	}
}
