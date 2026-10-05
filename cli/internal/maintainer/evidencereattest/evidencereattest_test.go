// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
	"github.com/prufyx/prufyx/cli/internal/maintainer/reviewrecord"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const testEngineCapabilityDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func testSource(id, owner, repo, commit, path, digest string, start, end int) map[string]any {
	return map[string]any{
		"id": id, "url": "https://github.com/" + owner + "/" + repo + "/blob/" + commit + "/" + path,
		"revision": commit, "contentDigest": digest, "startLine": start, "endLine": end,
	}
}

func testRule(id, state, reviewedAt, validUntil string, ranged bool, sources ...map[string]any) map[string]any {
	rule := map[string]any{
		"id": id, "operator": "require",
		"subject":    map[string]any{"component": "pkg:github/owner/repo", "from": "1.0.0", "to": "2.0.0"},
		"evidence":   map[string]any{"state": state, "reviewedAt": reviewedAt, "validUntil": validUntil, "sources": sources},
		"reasonCode": "TEST_REASON", "nextAction": "TEST_ACTION",
	}
	if ranged {
		rule["range"] = map[string]any{"fromMin": "1.0.0", "fromMax": "1.9.9"}
	}
	return rule
}

func testPack(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schema": "test-pack/v1", "revision": "rev-1", "policyId": "policy-1",
		"policyDigest": "sha256:" + strings.Repeat("ab", 32), "entries": entries,
	})
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	return raw
}

func testEntry(project string, rule map[string]any) map[string]any {
	return map[string]any{"description": "d", "project": project, "requiredFacts": []any{}, "rule": rule}
}

// ruleSpec describes one rule, its single fresh, Releases-resolved,
// non-tag-fallback citation, and the matching worklist plumbing for it, so
// tests can assemble a small multi-rule worklist quickly.
type ruleSpec struct {
	id, project, commit, path string
	class                     string
	resolution                string
	stale                     bool
	repoResolvedAt            string
	reviewedAt, validUntil    string
	state                     string
	ranged                    bool
	mechanical                bool
}

func buildWorklistAndPack(t *testing.T, packPath string, generatedAt time.Time, specs []ruleSpec) (worklist evidencerepin.Worklist, pack []byte) {
	t.Helper()
	var entries []map[string]any
	var citations []evidencerepin.ClassResult
	repos := map[string]evidencerepin.RepoResolution{}
	digest := "sha256:" + strings.Repeat("cd", 32)
	for _, spec := range specs {
		source := testSource(spec.id+"-src", "owner", "repo-"+spec.id, spec.commit, spec.path, digest, 1, 1)
		rule := testRule(spec.id, spec.state, spec.reviewedAt, spec.validUntil, spec.ranged, source)
		if spec.mechanical {
			markMechanical(rule, spec.reviewedAt)
		}
		entries = append(entries, testEntry(spec.project, rule))

		citations = append(citations, evidencerepin.ClassResult{
			RulePack: packPath, RuleID: spec.id, Project: spec.project, SourceID: spec.id + "-src",
			Owner: "owner", Repo: "repo-" + spec.id, Path: spec.path, OldCommit: spec.commit, NewCommit: spec.commit,
			Class: spec.class, Resolution: spec.resolution, Stale: spec.stale,
		})
		repos["owner/repo-"+spec.id] = evidencerepin.RepoResolution{
			Owner: "owner", Repo: "repo-" + spec.id, Status: "RESOLVED", CurrentTag: "v1.2.3",
			CurrentCommit: spec.commit, ResolvedAt: spec.repoResolvedAt, Resolution: spec.resolution,
		}
	}
	repoList := make([]evidencerepin.RepoResolution, 0, len(repos))
	for _, repo := range repos {
		repoList = append(repoList, repo)
	}
	// A fixed order keeps the worklist bytes, and so the seeded sample,
	// the same on every run.
	sort.Slice(repoList, func(i, j int) bool { return repoList[i].Repo < repoList[j].Repo })
	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: rfc3339(generatedAt),
		Scope:     evidencerepin.WorklistScope{RulePacks: []string{packPath}},
		Repos:     repoList,
		Citations: citations,
		Summary:   evidencerepin.Summary{TotalCitations: len(citations), Classified: len(citations), Pending: 0},
	}
	return wl, testPack(t, entries...)
}

func marshalWorklist(t *testing.T, wl evidencerepin.Worklist) []byte {
	t.Helper()
	raw, err := json.Marshal(wl)
	if err != nil {
		t.Fatalf("marshal worklist: %v", err)
	}
	return raw
}

func freshSpec(id, project string, now time.Time) ruleSpec {
	return ruleSpec{
		id: id, project: project, commit: strings.Repeat("a", 40), path: "VERSION",
		class: evidencerepin.ClassFileIdentical, resolution: "",
		repoResolvedAt: rfc3339(now.Add(-time.Hour)),
		reviewedAt:     rfc3339(now.Add(-30 * 24 * time.Hour)), validUntil: rfc3339(now.Add(7 * 24 * time.Hour)),
		state: "active",
	}
}

// baseNow is a fixed, arbitrary instant used across tests as "when repin
// ran / when prepare runs". It is not tied to any particular wave's slot;
// SlotDate(wave, baseNow) always returns a usable, within-cap date because
// the slot cycle is shorter than the lease cap (see SlotDate).
var baseNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// padPackWithSpreadRules adds n additional, already-current rules (not
// touched by this batch) to a pack, each with a distinct validUntil ISO
// week, so a small batch's stagger check (V7) has a realistically sized
// pack to check against instead of failing purely on population size.
func padPackWithSpreadRules(t *testing.T, packRaw []byte, n int) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(packRaw, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["entries"].([]any)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		validUntil := base.AddDate(0, 0, 14*i) // 2-week spacing keeps each rule in its own ISO week
		source := testSource(fmt.Sprintf("pad-src-%d", i), "owner", "padrepo", strings.Repeat("f", 40), "VERSION", "sha256:"+strings.Repeat("cd", 32), 1, 1)
		rule := testRule(fmt.Sprintf("pad-rule-%d", i), "active", rfc3339(validUntil.Add(-60*24*time.Hour)), rfc3339(validUntil), false, source)
		entries = append(entries, testEntry("proj-pad", rule))
	}
	doc["entries"] = entries
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---------------------------------------------------------------------
// Prepare: eligibility is recomputed from citations, never declared
// ---------------------------------------------------------------------

func TestPrepareEligibleHappyPath(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 1 || result.Statement.Rules[0].RuleID != "rule-a" {
		t.Fatalf("expected rule-a eligible, got %+v", result.Statement.Rules)
	}
	if len(result.Statement.NotExtended) != 0 {
		t.Fatalf("expected no not-extended rules, got %+v", result.Statement.NotExtended)
	}
	if len(result.Statement.SampledForFullReview) != 1 {
		t.Fatalf("expected the single eligible rule to be sampled (ceil(0.10*1)=1), got %+v", result.Statement.SampledForFullReview)
	}
	if _, err := ParseStatement(result.StatementCanonical); err != nil {
		t.Fatalf("statement failed self-parse: %v", err)
	}
}

func TestPrepareExcludesStaleBaseline(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	spec.repoResolvedAt = rfc3339(baseNow.Add(-100 * time.Hour)) // older than the 72h bound
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 {
		t.Fatalf("expected the stale-baseline rule excluded, got %+v", result.Statement.Rules)
	}
	if len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != reasonStaleBaseline {
		t.Fatalf("expected reasonStaleBaseline, got %+v", result.Statement.NotExtended)
	}
}

func TestPrepareExcludesTagFallback(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	spec.resolution = resolutionTagFallback
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 {
		t.Fatalf("expected the tag-fallback rule excluded, got %+v", result.Statement.Rules)
	}
	if len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != reasonTagFallbackBaseline {
		t.Fatalf("expected reasonTagFallbackBaseline, got %+v", result.Statement.NotExtended)
	}
}

// TestPrepareOneBadCitationExcludesWholeRule covers the case where a rule
// has several citations and only one is not mechanically unchanged: the
// whole rule must be excluded, never partially renewed.
func TestPrepareOneBadCitationExcludesWholeRule(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"

	source1 := testSource("rule-a-src1", "owner", "repo-a", strings.Repeat("a", 40), "VERSION", "sha256:"+strings.Repeat("cd", 32), 1, 1)
	source2 := testSource("rule-a-src2", "owner", "repo-a", strings.Repeat("a", 40), "OTHER", "sha256:"+strings.Repeat("cd", 32), 1, 1)
	rule := testRule("rule-a", "active", rfc3339(baseNow.Add(-30*24*time.Hour)), rfc3339(baseNow.Add(60*24*time.Hour)), false, source1, source2)
	pack := testPack(t, testEntry("proj-a", rule))

	wl := evidencerepin.Worklist{
		Schema: evidencerepin.Schema, GeneratedAt: rfc3339(baseNow),
		Scope: evidencerepin.WorklistScope{RulePacks: []string{packPath}},
		Repos: []evidencerepin.RepoResolution{{Owner: "owner", Repo: "repo-a", Status: "RESOLVED", CurrentTag: "v1.2.3", CurrentCommit: strings.Repeat("a", 40), ResolvedAt: rfc3339(baseNow.Add(-time.Hour))}},
		Citations: []evidencerepin.ClassResult{
			{RulePack: packPath, RuleID: "rule-a", Project: "proj-a", SourceID: "rule-a-src1", Owner: "owner", Repo: "repo-a", OldCommit: strings.Repeat("a", 40), Class: evidencerepin.ClassFileIdentical},
			{RulePack: packPath, RuleID: "rule-a", Project: "proj-a", SourceID: "rule-a-src2", Owner: "owner", Repo: "repo-a", OldCommit: strings.Repeat("a", 40), Class: evidencerepin.ClassContentChanged},
		},
		Summary: evidencerepin.Summary{TotalCitations: 2, Classified: 2, Pending: 0},
	}

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 {
		t.Fatalf("expected the whole rule excluded on one bad citation, got %+v", result.Statement.Rules)
	}
	if len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != evidencerepin.ClassContentChanged {
		t.Fatalf("expected worstClass CONTENT_CHANGED, got %+v", result.Statement.NotExtended)
	}
}

func TestPrepareExcludesRangedRule(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	spec.ranged = true
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 || result.Statement.NotExtended[0].WorstClass != reasonRangedRule {
		t.Fatalf("expected the ranged rule excluded, got rules=%+v notExtended=%+v", result.Statement.Rules, result.Statement.NotExtended)
	}
}

func TestPrepareExcludesWithdrawnState(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	spec.state = "withdrawn"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 || result.Statement.NotExtended[0].WorstClass != reasonInactiveOrWithdrawn {
		t.Fatalf("expected the withdrawn rule excluded, got %+v / %+v", result.Statement.Rules, result.Statement.NotExtended)
	}
}

func TestPrepareExcludesEntireProjectOnCorpusDigestMismatch(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	clean := freshSpec("rule-a", "proj-a", baseNow)
	mismatch := freshSpec("rule-b", "proj-a", baseNow)
	mismatch.class = evidencerepin.ClassCorpusDigestMismatch
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{clean, mismatch})

	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.Rules) != 0 {
		t.Fatalf("expected both rules excluded (project-wide E7 gate), got %+v", result.Statement.Rules)
	}
	found := map[string]string{}
	for _, ne := range result.Statement.NotExtended {
		found[ne.RuleID] = ne.WorstClass
	}
	if found["rule-a"] != reasonCorpusMismatchProject {
		t.Fatalf("expected rule-a excluded by project-wide corpus mismatch, got %+v", found)
	}
}

// A pending citation of a rule that is not in the pack renews nothing and
// excludes nothing else, but is recorded.
func TestPrepareRecordsPendingCitationOfUnknownRule(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})
	wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
		RulePack: packPath, RuleID: "rule-x", Project: "proj-a", SourceID: "rule-x-src",
		Owner: "owner", Repo: "repo-x", Class: evidencerepin.ClassPending,
	})
	wl.Summary.Pending = 0 // hand-edited to look clean: the citations decide
	result := prepareSingle(t, wl, pack, packPath)
	if len(result.Statement.Rules) != 1 || len(result.Statement.NotExtended) != 0 {
		t.Fatalf("rule-a must keep its verdict: %+v / %+v", result.Statement.Rules, result.Statement.NotExtended)
	}
	if got := result.Statement.PendingCitations; len(got) != 1 || got[0] != (PendingCitation{Repo: "owner/repo-x", RuleID: "rule-x", SourceID: "rule-x-src"}) {
		t.Fatalf("pending citation not recorded: %+v", got)
	}
}

// ---------------------------------------------------------------------
// Verify: tampered and unbound statements
// ---------------------------------------------------------------------

// singleRuleSetup prepares one eligible rule in a pack padded with rules
// whose validUntil values sit in distinct ISO weeks, with a review record
// supplied for it.
func singleRuleSetup(t *testing.T, mut func(*evidencerepin.Worklist)) (res PrepareResult, pack, wlRaw []byte, now time.Time, packPath string) {
	t.Helper()
	now = baseNow
	packPath = "/p/rules.json"
	spec := freshSpec("rule-a", "proj-a", now)
	wl, rawPack := buildWorklistAndPack(t, packPath, now, []ruleSpec{spec})
	rawPack = padPackWithSpreadRules(t, rawPack, 12)
	if mut != nil {
		mut(&wl)
	}
	wlRaw = marshalWorklist(t, wl)
	result, _ := prepareWithSample(t, PrepareOptions{
		WorklistRaw: wlRaw, PackName: PackCNCF, PackPath: packPath, PackRaw: rawPack,
		Wave: 1, AttestedAt: now, Now: now, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	return result, rawPack, wlRaw, now, packPath
}

func defaultVerifyOptions(t *testing.T, now time.Time) VerifyOptions {
	t.Helper()
	return VerifyOptions{
		AttestedAtNow: now.Add(time.Hour), Chain: &Chain{}, BaseChain: &Chain{},
		// These tests check the structural invariants of a statement
		// that has not been appended to a chain yet.
		PreSign: true,
	}
}

func assertVerifyRejects(t *testing.T, opts VerifyOptions, wantPrefix string) {
	t.Helper()
	_, err := Verify(opts)
	if err == nil {
		t.Fatal("Verify accepted a statement it must reject")
	}
	if wantPrefix != "" && !strings.Contains(err.Error(), wantPrefix) {
		t.Fatalf("expected an error containing %q, got %v", wantPrefix, err)
	}
}

// A citation actually classified CONTENT_CHANGED (and stale) must never be
// renewed, no matter what a cached verdict might have said.
func TestPrepareExcludesContentChangedCitation(t *testing.T) {
	res, _, _, _, _ := singleRuleSetup(t, func(wl *evidencerepin.Worklist) {
		wl.Citations[0].Class = evidencerepin.ClassContentChanged
		wl.Citations[0].Stale = true
	})
	for _, ra := range res.Statement.Rules {
		if ra.RuleID == "rule-a" {
			t.Fatalf("CONTENT_CHANGED/stale citation renewed: %+v", res.Statement.Rules)
		}
	}
	found := false
	for _, ne := range res.Statement.NotExtended {
		if ne.RuleID == "rule-a" {
			found = true
			if ne.WorstClass != evidencerepin.ClassContentChanged {
				t.Fatalf("expected rule-a excluded with worstClass CONTENT_CHANGED, got %+v", ne)
			}
		}
	}
	if !found {
		t.Fatalf("rule-a missing from notExtended entirely: %+v", res.Statement.NotExtended)
	}
}

// A rule with zero citations for its source must never be renewed.
func TestPrepareExcludesUncitedSource(t *testing.T) {
	res, _, _, _, _ := singleRuleSetup(t, func(wl *evidencerepin.Worklist) {
		wl.Citations = nil
	})
	if len(res.Statement.Rules) != 0 {
		t.Fatalf("rule with zero checked citations renewed: %+v", res.Statement.Rules)
	}
}

// Smuggling content into an unlisted rule (and altering a listed
// entry's non-rule fields), then re-pointing the statement's declared next
// pack digests at the tampered bytes, must fail Verify.
func TestVerifyRejectsSmuggledUnlistedRuleChange(t *testing.T) {
	res, pack, wlRaw, now, pp := singleRuleSetup(t, nil)
	var doc packDocument
	if err := json.Unmarshal(res.NextPack, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Entries {
		var r map[string]any
		_ = json.Unmarshal(doc.Entries[i].Rule, &r)
		if r["id"] == "pad-rule-3" {
			r["reasonCode"] = "SMUGGLED"
			b, _ := json.Marshal(r)
			doc.Entries[i].Rule = b
		}
		if doc.Entries[i].Project == "proj-a" {
			doc.Entries[i].RequiredFacts = json.RawMessage(`["smuggled"]`)
		}
	}
	next, _ := buildNextPack(doc)
	st := res.Statement
	st.Pack.Next.PackDigest = packDigest(next)
	st.Pack.Next.RuleSetDigest, _ = ruleSetDigest(doc)
	raw, _ := CanonicalStatement(st)

	opts := defaultVerifyOptions(t, now)
	opts.StatementRaw = raw
	opts.PriorPackRaw = pack
	opts.ReviewRecords = singleRecords(t, pack)
	opts.NextPackRaw = next
	opts.WorklistRaw = wlRaw
	opts.PackName = PackCNCF
	opts.PackPath = pp
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	// The tamper touches both the statement's declared next-pack digests
	// and the next pack bytes themselves, so whichever half
	// checkV1AndV3 compares first is free to fire; both are correct
	// rejections of the same smuggled change.
	assertVerifyRejects(t, opts, "")
}

// A statement with a wrong engineCapabilityDigest / worklist digest and
// dropped citations must fail once Verify recomputes everything from the
// caller's own trusted inputs instead of trusting the statement's fields.
func TestVerifyRejectsUnboundDigests(t *testing.T) {
	res, pack, wlRaw, now, pp := singleRuleSetup(t, nil)
	st := res.Statement
	st.Pack.EngineCapabilityDigest = "sha256:" + strings.Repeat("99", 32)
	st.Worklist.Digest = "sha256:" + strings.Repeat("98", 32)
	st.Rules[0].Citations = nil
	st.Rules[0].LastIndividualReviewAt = "2020-01-01T00:00:00Z"
	raw, _ := CanonicalStatement(st)

	opts := defaultVerifyOptions(t, now)
	opts.StatementRaw = raw
	opts.PriorPackRaw = pack
	opts.ReviewRecords = singleRecords(t, pack)
	opts.NextPackRaw = res.NextPack
	opts.WorklistRaw = wlRaw
	opts.PackName = PackCNCF
	opts.PackPath = pp
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	assertVerifyRejects(t, opts, "V3:")
}

// A statement whose sampled rule has no recorded review must fail Verify
// itself, not only Sign.
func TestVerifyRejectsUnreviewedSample(t *testing.T) {
	packPath := "/p"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})
	pack = padPackWithSpreadRules(t, pack, 12)
	wlRaw := marshalWorklist(t, wl)
	res, err := Prepare(PrepareOptions{
		WorklistRaw: wlRaw, PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "r2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Statement.SampledForFullReview[0].ReviewRecordDigest != "" {
		t.Fatal("test setup: expected an unreviewed sample")
	}

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = res.StatementCanonical
	opts.PriorPackRaw = pack
	opts.NextPackRaw = res.NextPack
	opts.WorklistRaw = wlRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	assertVerifyRejects(t, opts, "has no recorded individual review")
}

// A trust root's digest must come from the caller's own independent
// knowledge, never be derived from the root bytes being checked.
func TestSignAndVerifySignatureRequirePinnedTrustRoot(t *testing.T) {
	res, _, _, _, _ := singleRuleSetup(t, nil)
	key, root, _ := generateTestKey(t, []byte("correct horse battery staple"))

	// No expected digest at all.
	if _, err := Sign(SignOptions{Role: RoleHuman, Statement: res.StatementCanonical, TrustRoot: root, EncryptedKey: key, Passphrase: []byte("correct horse battery staple"), Now: baseNow.Add(time.Hour)}); err == nil {
		t.Fatal("Sign accepted a trust root with no pinned expected digest")
	}
	if _, err := VerifySignature(VerifySignatureOptions{Statement: res.StatementCanonical, Envelope: []byte("{}"), TrustRoot: root}); err == nil {
		t.Fatal("VerifySignature accepted a trust root with no pinned expected digest")
	}

	// A digest that does not match the actual root is also rejected.
	wrongDigest := "sha256:" + strings.Repeat("ff", 32)
	if _, err := Sign(SignOptions{Role: RoleHuman,
		Statement: res.StatementCanonical, TrustRoot: root, EncryptedKey: key,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: wrongDigest, Now: baseNow.Add(time.Hour),
	}); err == nil {
		t.Fatal("expected Sign to reject a mismatched expected trust root digest")
	}
}

// The wave slot cycle must not run out: for every wave and a full
// year's worth of attestedAt instants, the next slot is within the lease
// cap.
func TestSlotDateAlwaysWithinLeaseCap(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for day := 0; day < 366; day++ {
		at := start.AddDate(0, 0, day)
		for wave := minWave; wave <= maxWave; wave++ {
			slot, err := SlotDate(wave, at)
			if err != nil {
				t.Fatalf("day %d wave %d: %v", day, wave, err)
			}
			if !slot.After(at) {
				t.Fatalf("day %d wave %d: slot %s is not after attestedAt %s", day, wave, slot, at)
			}
			if slot.Sub(at) > maxLease {
				t.Fatalf("day %d wave %d: slot %s exceeds the lease cap from attestedAt %s", day, wave, slot, at)
			}
		}
	}
}

// ---------------------------------------------------------------------
// Verify: structural invariants, padded so V7 never masks another check
// ---------------------------------------------------------------------

func prepareOnePassResult(t *testing.T, now time.Time, packPath string, spec ruleSpec) (PrepareResult, []byte, []byte) {
	t.Helper()
	wl, pack := buildWorklistAndPack(t, packPath, now, []ruleSpec{spec})
	pack = padPackWithSpreadRules(t, pack, 12)
	worklistRaw := marshalWorklist(t, wl)
	result, _ := prepareWithSample(t, PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: now, Now: now, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	return result, pack, worklistRaw
}

func TestVerifyHappyPath(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, pack, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = result.StatementCanonical
	opts.PriorPackRaw = pack
	opts.ReviewRecords = singleRecords(t, pack)
	opts.NextPackRaw = result.NextPack
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	if _, err := Verify(opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedNextPack(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, priorPack, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)

	var nextDoc map[string]any
	if err := json.Unmarshal(result.NextPack, &nextDoc); err != nil {
		t.Fatal(err)
	}
	entries := nextDoc["entries"].([]any)
	entry := entries[0].(map[string]any)
	rule := entry["rule"].(map[string]any)
	rule["reasonCode"] = "TAMPERED" // content smuggled in alongside the dates
	tampered, err := json.Marshal(nextDoc)
	if err != nil {
		t.Fatal(err)
	}

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = result.StatementCanonical
	opts.PriorPackRaw = priorPack
	opts.ReviewRecords = singleRecords(t, priorPack)
	opts.NextPackRaw = tampered
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	assertVerifyRejects(t, opts, "V1:")
}

func TestVerifyRejectsUnlistedRuleTamperedAloneWithoutStatementChange(t *testing.T) {
	// Same as above, but the statement itself is untouched: only the next
	// pack gains an extra change on an unlisted rule. V1 (via the
	// recomputation byte-check) must still catch it because the
	// recomputed next pack cannot reproduce the tampered bytes.
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, priorPack, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)

	var nextDoc map[string]any
	if err := json.Unmarshal(result.NextPack, &nextDoc); err != nil {
		t.Fatal(err)
	}
	entries := nextDoc["entries"].([]any)
	for _, e := range entries {
		entry := e.(map[string]any)
		var r map[string]any
		raw, _ := json.Marshal(entry["rule"])
		_ = json.Unmarshal(raw, &r)
		if r["id"] == "pad-rule-0" {
			r["reasonCode"] = "TAMPERED"
			entry["rule"] = r
		}
	}
	tampered, err := json.Marshal(nextDoc)
	if err != nil {
		t.Fatal(err)
	}

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = result.StatementCanonical
	opts.PriorPackRaw = priorPack
	opts.ReviewRecords = singleRecords(t, priorPack)
	opts.NextPackRaw = tampered
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	assertVerifyRejects(t, opts, "V1:")
}

func TestVerifyRejectsExpiredLease(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	// A wave whose slot, from "now", is already far beyond the 90-day cap:
	// use the slot the cycle would pick roughly two cycles out by starting
	// "now" just after a slot and asking for that same wave (SlotDate
	// always returns the *next* occurrence, which is within-cap by
	// construction, so to exercise V2's cap we instead hand-edit the
	// statement's own validUntil far past attestedAt+90d).
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, priorPack, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)
	statement := result.Statement
	statement.ValidUntil = rfc3339(baseNow.Add(200 * 24 * time.Hour))
	statement.Statement = FixedStatementText(statement.Worklist.GeneratedAt, statement.ValidUntil)
	raw, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = raw
	opts.PriorPackRaw = priorPack
	opts.ReviewRecords = singleRecords(t, priorPack)
	opts.NextPackRaw = result.NextPack
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	assertVerifyRejects(t, opts, "90-day cap")
}

func TestVerifyRejectsWrongPackBinding(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, _, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)

	otherSpec := freshSpec("rule-a", "proj-a", baseNow)
	_, otherPack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{otherSpec})
	otherPack = padPackWithSpreadRules(t, otherPack, 12)
	// Make otherPack byte-distinct from the pack the statement was
	// actually prepared against (same fixture inputs would otherwise
	// reproduce identical bytes and prove nothing).
	var otherDoc map[string]any
	if err := json.Unmarshal(otherPack, &otherDoc); err != nil {
		t.Fatal(err)
	}
	otherDoc["revision"] = "rev-other"
	otherPack, err := json.Marshal(otherDoc)
	if err != nil {
		t.Fatal(err)
	}

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = result.StatementCanonical
	opts.PriorPackRaw = otherPack
	opts.ReviewRecords = singleRecords(t, otherPack)
	opts.NextPackRaw = result.NextPack
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	// The recomputation itself will already fail (V3/V1) since Prepare is
	// rerun against otherPack; that is an acceptable, still-correct
	// rejection of a replayed/mismatched pack.
	if _, err := Verify(opts); err == nil {
		t.Fatal("expected Verify to reject a prior pack that does not match the declared digest")
	}
}

func TestVerifyRejectsChainWithoutPreviousStatement(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, priorPack, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)

	digest := "sha256:" + strings.Repeat("11", 32)
	statement := result.Statement
	statement.PreviousAttestationDigest = &digest
	tampered, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = tampered
	opts.PriorPackRaw = priorPack
	opts.ReviewRecords = singleRecords(t, priorPack)
	opts.NextPackRaw = result.NextPack
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	// V3 rejects first here (the recomputed statement has no previous
	// digest at all), which is a correct, if earlier, rejection.
	_, err = Verify(opts)
	if err == nil {
		t.Fatal("expected Verify to reject a declared chain with no supplied previous statement")
	}
}

func TestVerifyRejectsEmptyWorklist(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, priorPack, _ := prepareOnePassResult(t, baseNow, packPath, spec)

	opts := defaultVerifyOptions(t, baseNow)
	opts.StatementRaw = result.StatementCanonical
	opts.PriorPackRaw = priorPack
	opts.ReviewRecords = singleRecords(t, priorPack)
	opts.NextPackRaw = result.NextPack
	opts.WorklistRaw = nil
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	if _, err := Verify(opts); err == nil {
		t.Fatal("expected Verify to reject an empty worklist")
	}
}

func TestVerifyRejectsFutureAttestedAt(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, priorPack, worklistRaw := prepareOnePassResult(t, baseNow, packPath, spec)

	opts := defaultVerifyOptions(t, baseNow)
	opts.AttestedAtNow = baseNow.Add(-time.Hour) // verifier's clock is BEFORE the statement's attestedAt
	opts.StatementRaw = result.StatementCanonical
	opts.PriorPackRaw = priorPack
	opts.ReviewRecords = singleRecords(t, priorPack)
	opts.NextPackRaw = result.NextPack
	opts.WorklistRaw = worklistRaw
	opts.PackName = PackCNCF
	opts.PackPath = packPath
	opts.EngineCapabilityDigest = testEngineCapabilityDigest
	if _, err := Verify(opts); err == nil {
		t.Fatal("expected Verify to reject a statement whose attestedAt is after the verifier's own clock")
	}
}

// --- Sign / trust root ---

func generateTestKey(t *testing.T, passphrase []byte) (encryptedKey, trustRoot []byte, keyID string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err = keyIdentity(public)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err = knowledgesign.EncryptedKeyPEM(private, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{
		SchemaVersion: TrustRootSchema, Purpose: Purpose, Expires: rfc3339(time.Now().UTC().Add(365 * 24 * time.Hour)),
		Threshold: 1, Keys: []TrustKey{{KeyID: keyID, KeyType: "ed25519", Scheme: "ed25519", PublicKey: hex.EncodeToString(public), Role: RoleHuman}},
	}
	trustRoot, err = canonicalBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	return encryptedKey, trustRoot, keyID
}

func TestSignAndVerifySignatureRoundTrip(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, _, _ := prepareOnePassResult(t, baseNow, packPath, spec)

	encryptedKey, trustRoot, keyID := generateTestKey(t, []byte("correct horse battery staple"))
	expectedDigest := sourcecorpus.SHA(trustRoot)
	envelope, err := Sign(SignOptions{Role: RoleHuman,
		Statement: result.StatementCanonical, TrustRoot: trustRoot, EncryptedKey: encryptedKey,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: expectedDigest, Now: baseNow.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifyResult, err := VerifySignature(VerifySignatureOptions{
		Statement: result.StatementCanonical, Envelope: envelope, TrustRoot: trustRoot, ExpectedTrustRootDigest: expectedDigest,
	})
	if err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if len(verifyResult.SignerKeyIDs) != 1 || verifyResult.SignerKeyIDs[0] != keyID {
		t.Fatalf("unexpected signer set: %+v", verifyResult.SignerKeyIDs)
	}
}

func TestSignRefusesUnreviewedSample(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{spec})
	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
		// deliberately no ReviewRecordDigests: the sampled rule stays unreviewed.
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(result.Statement.SampledForFullReview) == 0 {
		t.Fatal("test setup: expected at least one sampled rule")
	}

	encryptedKey, trustRoot, _ := generateTestKey(t, []byte("correct horse battery staple"))
	_, err = Sign(SignOptions{Role: RoleHuman,
		Statement: result.StatementCanonical, TrustRoot: trustRoot, EncryptedKey: encryptedKey,
		Passphrase: []byte("correct horse battery staple"), ExpectedTrustRootDigest: sourcecorpus.SHA(trustRoot), Now: baseNow.Add(time.Hour),
	})
	if err == nil || !strings.Contains(err.Error(), "has no recorded individual review") {
		t.Fatalf("expected Sign to refuse a statement with an unreviewed sampled rule, got %v", err)
	}
}

func TestParseTrustRootRejectsExpired(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := keyIdentity(public)
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{
		SchemaVersion: TrustRootSchema, Purpose: Purpose, Expires: rfc3339(time.Now().UTC().Add(-time.Hour)), // already expired
		Threshold: 1, Keys: []TrustKey{{KeyID: keyID, KeyType: "ed25519", Scheme: "ed25519", PublicKey: hex.EncodeToString(public)}},
	}
	raw, err := canonicalBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrustRoot(raw, sourcecorpus.SHA(raw), time.Now().UTC()); err == nil {
		t.Fatal("expected an expired trust root to be rejected")
	}
}

func TestParseTrustRootRejectsWrongPurpose(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := keyIdentity(public)
	if err != nil {
		t.Fatal(err)
	}
	root := TrustRoot{
		SchemaVersion: TrustRootSchema, Purpose: "community-release-integrity", // wrong purpose
		Expires: rfc3339(time.Now().UTC().Add(365 * 24 * time.Hour)), Threshold: 1,
		Keys: []TrustKey{{KeyID: keyID, KeyType: "ed25519", Scheme: "ed25519", PublicKey: hex.EncodeToString(public)}},
	}
	raw, err := canonicalBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrustRoot(raw, sourcecorpus.SHA(raw), time.Now().UTC()); err == nil {
		t.Fatal("expected a trust root with the wrong purpose to be rejected")
	}
}

func TestParseStatementRejectsWrongSchema(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	spec := freshSpec("rule-a", "proj-a", baseNow)
	result, _, _ := prepareOnePassResult(t, baseNow, packPath, spec)

	statement := result.Statement
	statement.Schema = "prufyx.io/some-other-schema/v1"
	raw, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStatement(raw); err == nil {
		t.Fatal("expected a statement with the wrong schema to be rejected")
	}
}

// ---------------------------------------------------------------------
// Eligibility: one test per E1/E4 exclusion reason
// ---------------------------------------------------------------------

func prepareSingle(t *testing.T, wl evidencerepin.Worklist, pack []byte, packPath string) PrepareResult {
	t.Helper()
	result, err := Prepare(PrepareOptions{
		WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return result
}

func assertOnlyExclusion(t *testing.T, result PrepareResult, ruleID, reason string) {
	t.Helper()
	if len(result.Statement.Rules) != 0 {
		t.Fatalf("expected %s excluded, got rules %+v", ruleID, result.Statement.Rules)
	}
	if len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].RuleID != ruleID || result.Statement.NotExtended[0].WorstClass != reason {
		t.Fatalf("expected %s excluded with %s, got %+v", ruleID, reason, result.Statement.NotExtended)
	}
}

func TestPrepareExcludesCitationNotPinnedToSourceRevision(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	wl.Citations[0].OldCommit = strings.Repeat("b", 40)
	assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonCitationCommitMismatch)
}

func TestPrepareExcludesDuplicateCitationForSource(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	wl.Citations = append(wl.Citations, wl.Citations[0])
	assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonDuplicateCitation)
}

func TestPrepareExcludesCitationWithoutSource(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	extra := wl.Citations[0]
	extra.SourceID = "rule-a-unknown-src"
	wl.Citations = append(wl.Citations, extra)
	assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonUnknownCitation)
}

func TestPrepareExcludesStaleCitation(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	wl.Citations[0].Stale = true
	assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
}

func TestPrepareExcludesEverythingOnOldWorklist(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	wl.GeneratedAt = rfc3339(baseNow.Add(-100 * time.Hour)) // older than the 72h bound; repos stay fresh
	assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
}

func TestPrepareExcludesRuleWithNoSources(t *testing.T) {
	packPath := "/p/rules.json"
	wl, _ := buildWorklistAndPack(t, packPath, baseNow, nil)
	pack := testPack(t, testEntry("proj-a", testRule("rule-a", "active", rfc3339(baseNow.Add(-30*24*time.Hour)), rfc3339(baseNow.Add(60*24*time.Hour)), false)))
	assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonUncoveredSource)
}

// ---------------------------------------------------------------------
// Individual invariant checks, called directly so each is exercised on
// its own even where the byte-for-byte recomputation would also fail
// ---------------------------------------------------------------------

func TestCheckV4RejectsUnboundPackBytes(t *testing.T) {
	result, prior, _ := prepareOnePassResult(t, baseNow, "/p/rules.json", freshSpec("rule-a", "proj-a", baseNow))
	priorDoc, err := loadPack(prior)
	if err != nil {
		t.Fatal(err)
	}
	nextDoc, err := loadPack(result.NextPack)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV4(result.Statement, prior, result.NextPack, priorDoc, nextDoc); err != nil {
		t.Fatalf("honest binding rejected: %v", err)
	}
	// Same documents, different bytes: the digest binding must notice.
	reformatted := append(append([]byte(nil), prior...), ' ')
	if err := checkV4(result.Statement, reformatted, result.NextPack, priorDoc, nextDoc); err == nil || !strings.Contains(err.Error(), "V4: prior pack binding") {
		t.Fatalf("expected a V4 prior pack binding error, got %v", err)
	}
	if err := checkV4(result.Statement, prior, append(append([]byte(nil), result.NextPack...), ' '), priorDoc, nextDoc); err == nil || !strings.Contains(err.Error(), "V4: next pack binding") {
		t.Fatalf("expected a V4 next pack binding error, got %v", err)
	}
	statement := result.Statement
	statement.Pack.PolicyDigest = "sha256:" + strings.Repeat("00", 32)
	if err := checkV4(statement, prior, result.NextPack, priorDoc, nextDoc); err == nil || !strings.Contains(err.Error(), "V4: policy/schema binding") {
		t.Fatalf("expected a V4 policy binding error, got %v", err)
	}
}

func ruleJSON(t *testing.T, id, reviewedAt, validUntil string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(testRule(id, "active", reviewedAt, validUntil, false))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCheckV6RejectsUncoveredDateChangeAndOneSidedRule(t *testing.T) {
	old := ruleJSON(t, "rule-a", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")
	renewed := ruleJSON(t, "rule-a", "2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z")
	prior := map[string]json.RawMessage{"rule-a": old}
	next := map[string]json.RawMessage{"rule-a": renewed}
	empty := Statement{}

	if err := checkV6(prior, next, empty, nil, true); err == nil || !strings.Contains(err.Error(), "V6:") || !strings.Contains(err.Error(), "no covering attestation") {
		t.Fatalf("expected a V6 uncovered date change error, got %v", err)
	}
	if err := checkV6(prior, next, empty, map[string]string{"rule-a": "sha256:" + strings.Repeat("ee", 32)}, true); err != nil {
		t.Fatalf("date change covered by a review record rejected: %v", err)
	}
	covering := Statement{AttestedAt: "2026-02-01T00:00:00Z", ValidUntil: "2026-04-01T00:00:00Z", Rules: []RuleAttestation{{RuleID: "rule-a"}}}
	if err := checkV6(prior, next, covering, nil, true); err != nil {
		t.Fatalf("date change covered by the statement rejected: %v", err)
	}
	next["rule-b"] = ruleJSON(t, "rule-b", "2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z")
	if err := checkV6(prior, next, covering, nil, true); err == nil || !strings.Contains(err.Error(), "V6:") || !strings.Contains(err.Error(), "only one of the prior and next packs") {
		t.Fatalf("expected a V6 one-sided rule error, got %v", err)
	}
}

func TestCheckV7ChecksOnlyWeeksTheBatchRenewsInto(t *testing.T) {
	// 20 rules: cap is floor(15% of 20) = 3.
	slot := time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC)   // ISO week 2026-W49
	cluster := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC) // ISO week 2026-W23
	next := map[string]json.RawMessage{}
	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("cluster-%02d", i)
		next[id] = ruleJSON(t, id, "2026-04-01T00:00:00Z", rfc3339(cluster))
	}
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("spread-%02d", i)
		next[id] = ruleJSON(t, id, "2025-01-01T00:00:00Z", rfc3339(time.Date(2025, 1, 8+7*i, 12, 0, 0, 0, time.UTC)))
	}
	batch := Statement{}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("batch-%02d", i)
		next[id] = ruleJSON(t, id, "2026-10-01T00:00:00Z", rfc3339(slot))
		batch.Rules = append(batch.Rules, RuleAttestation{RuleID: id})
	}
	if err := checkV7(Statement{}, next); err != nil {
		t.Fatalf("an empty batch must not be failed by a pre-existing cluster: %v", err)
	}
	if err := checkV7(batch, next); err != nil {
		t.Fatalf("a batch within the cap in its own week must pass despite a cluster elsewhere: %v", err)
	}
	// A fourth rule renewed into the slot week (replacing a spread rule, so
	// the pack still holds 20) puts it over the cap.
	delete(next, "spread-06")
	next["batch-03"] = ruleJSON(t, "batch-03", "2026-10-01T00:00:00Z", rfc3339(slot))
	batch.Rules = append(batch.Rules, RuleAttestation{RuleID: "batch-03"})
	if err := checkV7(batch, next); err == nil || !strings.Contains(err.Error(), "V7:") {
		t.Fatalf("expected a V7 error for a slot week over the cap, got %v", err)
	}
}

func TestStaggerCapFloorsAtOne(t *testing.T) {
	for total, want := range map[int]int{1: 1, 6: 1, 7: 1, 13: 1, 14: 2, 20: 3, 34: 5, 60: 9, 100: 15, 191: 28} {
		if got := staggerCap(total); got != want {
			t.Fatalf("staggerCap(%d) = %d, want %d", total, got, want)
		}
	}
}

// ---------------------------------------------------------------------
// Statement chain (V5): signed append-only log, shared derivation
// ---------------------------------------------------------------------

const testPassphrase = "correct horse battery staple"

// chainFixture holds a throwaway, in-memory signing key and trust root and
// the signed statement chain built with it.
type chainFixture struct {
	t       *testing.T
	key     []byte
	root    []byte
	digest  string
	entries []ChainEntry
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	key, root, _ := generateTestKey(t, []byte(testPassphrase))
	return &chainFixture{t: t, key: key, root: root, digest: sourcecorpus.SHA(root)}
}

func (f *chainFixture) chain() *Chain {
	return &Chain{Entries: append([]ChainEntry(nil), f.entries...), TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
}

// sign signs statementRaw with f's key, with the signer's clock an hour
// after the statement's own attestedAt.
func (f *chainFixture) sign(statementRaw []byte) []byte {
	f.t.Helper()
	var statement Statement
	if err := json.Unmarshal(statementRaw, &statement); err != nil {
		f.t.Fatal(err)
	}
	envelope, err := Sign(SignOptions{Role: RoleHuman,
		Statement: statementRaw, TrustRoot: f.root, EncryptedKey: f.key,
		Passphrase: []byte(testPassphrase), ExpectedTrustRootDigest: f.digest, Now: mustParse(statement.AttestedAt).Add(time.Hour),
	})
	if err != nil {
		f.t.Fatalf("Sign: %v", err)
	}
	return envelope
}

func (f *chainFixture) append(name string, statementRaw []byte) {
	f.t.Helper()
	f.entries = append(f.entries, ChainEntry{Name: name, Statement: statementRaw, Envelope: f.sign(statementRaw)})
}

// testReviewRecord renders a structurally valid individual review record
// (maintainer/reviewrecord's format) for ruleID, bound to the rule's exact
// version in packRaw, decided at decidedAt. maintainer only varies the
// record's bytes.
func testReviewRecord(t *testing.T, packRaw []byte, ruleID string, decidedAt time.Time, maintainer string) []byte {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	project, ruleDigest := "", ""
	for _, entry := range doc.Entries {
		fields, _ := parseRuleFields(entry.Rule)
		if fields.ID == ruleID {
			project = entry.Project
			ruleDigest, _, _, err = ruleDigestAndEvidence(entry.Rule)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if project == "" {
		t.Fatalf("testReviewRecord: rule %s not in pack", ruleID)
	}
	other := "sha256:" + strings.Repeat("d", 64)
	raw, err := json.Marshal(map[string]any{
		"schema": reviewrecord.RecordSchema,
		"decision": map[string]any{
			"authority": "DECLARED_MAINTAINER_DECISION_NOT_AUTHENTICATED", "state": "ACCEPTED_FOR_SIGNING_REVIEW",
			"maintainer": maintainer, "decidedAt": rfc3339(decidedAt), "scope": "ONE_RULE_CONSISTENCY_ONLY",
		},
		"subject": map[string]any{"project": project, "ruleId": ruleID, "knowledgeRevision": "1", "evaluationAt": rfc3339(decidedAt)},
		"bindings": map[string]any{
			"packetDigest": other, "packetReceiptDigest": other, "sourceReceiptDigest": other, "sourceCorpusManifestDigest": other,
			"sourceCorpusReceiptDigest": other, "vectorFileDigest": other, "selectedVectorGroupDigest": other, "targetDigest": other,
			"engineCapabilityDigest": other, "ruleDigest": ruleDigest, "ruleEvidenceDigest": other,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

// singleRecords is the review record the single-rule fixtures supply for
// their one sampled rule, rule-a.
func singleRecords(t *testing.T, packRaw []byte) map[string][]byte {
	t.Helper()
	if cached, ok := singleRecordCache[sourcecorpus.SHA(packRaw)]; ok {
		out := map[string][]byte{}
		for id, raw := range cached {
			out[id] = raw
		}
		return out
	}
	return map[string][]byte{"rule-a": testReviewRecord(t, packRaw, "rule-a", baseNow.Add(-time.Hour), "Test Reviewer")}
}

// padPackWithPastRules adds n rules whose validUntil values sit in distinct
// ISO weeks of 2023-2024, far from any slot week used by these tests.
func padPackWithPastRules(t *testing.T, packRaw []byte, n int) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(packRaw, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["entries"].([]any)
	base := time.Date(2023, 1, 4, 12, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		validUntil := base.AddDate(0, 0, 7*i)
		source := testSource(fmt.Sprintf("past-src-%d", i), "owner", "pastrepo", strings.Repeat("f", 40), "VERSION", "sha256:"+strings.Repeat("cd", 32), 1, 1)
		entries = append(entries, testEntry("proj-past", testRule(fmt.Sprintf("past-%03d", i), "active", rfc3339(validUntil.Add(-60*24*time.Hour)), rfc3339(validUntil), false, source)))
	}
	doc["entries"] = entries
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const chainPackPath = "/p/rules.json"

// cycleSpacing is the time between consecutive chain test cycles: one full
// wave cycle, so each cycle's wave-1 slot date is strictly later than the
// previous cycle's and every rule renewed last cycle is eligible again.
const cycleSpacing = slotCycleDays * 24 * time.Hour

func cycleSpecs(n int, at time.Time) []ruleSpec {
	specs := make([]ruleSpec, 0, n)
	for i := 0; i < n; i++ {
		specs = append(specs, freshSpec(fmt.Sprintf("rule-%02d", i), fmt.Sprintf("proj-%02d", i), at))
	}
	return specs
}

type cycle struct {
	res         PrepareResult
	worklistRaw []byte
	prior       []byte
	at          time.Time
	reviews     map[string][]byte
}

// prepareCycle prepares one batch against f's chain. It runs Prepare once
// to learn the seeded sample, then again with a new review record for
// every sampled rule (plus one for each rule in extraReviews), exactly as
// a maintainer would after reviewing the sample. Every record is bound to
// the rule's version in prior and decided an hour before at.
func prepareCycle(t *testing.T, f *chainFixture, prior []byte, at time.Time, specs []ruleSpec, revision string, extraReviews []string) cycle {
	t.Helper()
	return prepareCycleWithRecords(t, f, prior, at, specs, revision, extraReviews, nil)
}

// prepareCycleWithRecords is prepareCycle with extra, caller-built review
// records added to the supplied directory as they are.
func prepareCycleWithRecords(t *testing.T, f *chainFixture, prior []byte, at time.Time, specs []ruleSpec, revision string, extraReviews []string, records map[string][]byte) cycle {
	t.Helper()
	wl, _ := buildWorklistAndPack(t, chainPackPath, at, specs)
	worklistRaw := marshalWorklist(t, wl)
	reviews := map[string][]byte{}
	for id, raw := range records {
		reviews[id] = raw
	}
	for _, id := range extraReviews {
		reviews[id] = testReviewRecord(t, prior, id, at.Add(-time.Hour), "Individual Reviewer")
	}
	opts := PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: f.chain(),
		Wave: 1, AttestedAt: at, Now: at, NextRevision: revision, EngineCapabilityDigest: testEngineCapabilityDigest,
		ReviewRecords: reviews,
	}
	first, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare %s: %v", revision, err)
	}
	opts = withSampleRecords(t, opts)
	reviews = opts.ReviewRecords
	res, err := Prepare(opts)
	if err != nil {
		t.Fatalf("Prepare %s: %v", revision, err)
	}
	if renewedIDs(res) != renewedIDs(first) {
		t.Fatalf("recording the sample's reviews changed which rules were renewed")
	}
	return cycle{res: res, worklistRaw: worklistRaw, prior: prior, at: at, reviews: reviews}
}

func renewedIDs(result PrepareResult) string {
	ids := make([]string, 0, len(result.Statement.Rules))
	for _, ra := range result.Statement.Rules {
		ids = append(ids, ra.RuleID)
	}
	return strings.Join(ids, ",")
}

// verifyCycle verifies c against chain, with chain minus c's own
// statement (if present) as the base branch's chain.
func verifyCycle(c cycle, chain *Chain) error {
	base := &Chain{TrustRoot: chain.TrustRoot, ExpectedTrustRootDigest: chain.ExpectedTrustRootDigest}
	for _, entry := range chain.Entries {
		if string(entry.Statement) != string(c.res.StatementCanonical) {
			base.Entries = append(base.Entries, entry)
		}
	}
	return verifyCycleAgainstBase(c, base, chain)
}

func verifyCycleAgainstBase(c cycle, base, chain *Chain) error {
	_, err := Verify(VerifyOptions{
		StatementRaw: c.res.StatementCanonical, PriorPackRaw: c.prior, NextPackRaw: c.res.NextPack,
		WorklistRaw: c.worklistRaw, Chain: chain, BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: c.at.Add(time.Hour), ReviewRecords: c.reviews,
		// A statement the chain does not carry yet is checked in the
		// pre-sign structural mode; one it carries is checked strictly.
		PreSign: !chainContains(chain, c.res.StatementCanonical),
	})
	return err
}

func cyclesOf(c cycle, ruleID string) int {
	for _, ra := range c.res.Statement.Rules {
		if ra.RuleID == ruleID {
			return ra.ConsecutiveBatchCycles
		}
	}
	return -1
}

func worstClassOf(c cycle, ruleID string) string {
	for _, ne := range c.res.Statement.NotExtended {
		if ne.RuleID == ruleID {
			return ne.WorstClass
		}
	}
	return ""
}

// twoCycleChain runs two honest, signed, verified batch cycles over 12
// eligible rules (in a pack padded to 92 rules so the stagger cap of 13
// never defers any of them) and returns a rule renewed by batch in both
// cycles without ever being sampled: its count is now at the cap.
func twoCycleChain(t *testing.T) (f *chainFixture, c1, c2 cycle, target string, t3 time.Time) {
	t.Helper()
	f = newChainFixture(t)
	t1 := baseNow
	_, pack := buildWorklistAndPack(t, chainPackPath, t1, cycleSpecs(12, t1))
	pack = padPackWithPastRules(t, pack, 80)

	c1 = prepareCycle(t, f, pack, t1, cycleSpecs(12, t1), "rev-2", nil)
	if len(c1.res.Statement.Rules) != 12 {
		t.Fatalf("cycle 1: expected all 12 rules renewed, got %d (%+v)", len(c1.res.Statement.Rules), c1.res.Statement.NotExtended)
	}
	if err := verifyCycle(c1, f.chain()); err != nil {
		t.Fatalf("cycle 1 verify: %v", err)
	}
	f.append("0001", c1.res.StatementCanonical)

	t2 := t1.Add(cycleSpacing)
	c2 = prepareCycle(t, f, c1.res.NextPack, t2, cycleSpecs(12, t2), "rev-3", nil)
	if err := verifyCycle(c2, f.chain()); err != nil {
		t.Fatalf("cycle 2 verify: %v", err)
	}
	f.append("0002", c2.res.StatementCanonical)
	for _, ra := range c2.res.Statement.Rules {
		if ra.ConsecutiveBatchCycles == 2 {
			target = ra.RuleID
			break
		}
	}
	if target == "" {
		t.Fatal("setup: no rule reached two consecutive batch cycles")
	}
	return f, c1, c2, target, t2.Add(cycleSpacing)
}

func TestChainCapsThirdConsecutiveBatchRenewal(t *testing.T) {
	f, _, c2, target, t3 := twoCycleChain(t)
	c3 := prepareCycle(t, f, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	if cyclesOf(c3, target) != -1 || worstClassOf(c3, target) != reasonConsecutiveCycleCap {
		t.Fatalf("expected %s excluded with %s, got cycles=%d reason=%q", target, reasonConsecutiveCycleCap, cyclesOf(c3, target), worstClassOf(c3, target))
	}
	if err := verifyCycle(c3, f.chain()); err != nil {
		t.Fatalf("cycle 3 verify: %v", err)
	}
}

func TestVerifyRejectsCycleResetByUnrelatedPackEdit(t *testing.T) {
	f, _, c2, target, t3 := twoCycleChain(t)
	// An unrelated rule change merged between cycles changes the prior
	// pack's digest; it must not reset any rule's count.
	var doc packDocument
	if err := json.Unmarshal(c2.res.NextPack, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.Entries {
		fields, _ := parseRuleFields(doc.Entries[i].Rule)
		if fields.ID == "past-005" {
			var rule map[string]any
			_ = json.Unmarshal(doc.Entries[i].Rule, &rule)
			rule["reasonCode"] = "UNRELATED_INDIVIDUAL_EDIT"
			doc.Entries[i].Rule, _ = json.Marshal(rule)
		}
	}
	edited, err := buildNextPack(doc)
	if err != nil {
		t.Fatal(err)
	}
	honest := prepareCycle(t, f, edited, t3, cycleSpecs(12, t3), "rev-4", nil)
	if worstClassOf(honest, target) != reasonConsecutiveCycleCap {
		t.Fatalf("pack edit reset %s's count: cycles=%d reason=%q", target, cyclesOf(honest, target), worstClassOf(honest, target))
	}
	if err := verifyCycle(honest, f.chain()); err != nil {
		t.Fatalf("honest cycle 3 verify: %v", err)
	}

	// A statement prepared as if the chain were empty renews the capped
	// rule at cycle 1; against the real chain it must be rejected.
	reset := prepareCycle(t, newChainFixture(t), edited, t3, cycleSpecs(12, t3), "rev-4", nil)
	if cyclesOf(reset, target) != 1 {
		t.Fatalf("setup: expected the reset statement to renew %s at cycle 1", target)
	}
	if err := verifyCycle(reset, f.chain()); err == nil {
		t.Fatal("Verify accepted a statement that resets a rule's consecutive batch cycles")
	}
	state, err := deriveChainState(f.chain(), PackCNCF, t3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkV5(reset.res.Statement, state); err == nil || !strings.Contains(err.Error(), "V5:") {
		t.Fatalf("expected a V5 error for the reset statement, got %v", err)
	}
}

func TestVerifyRejectsTruncatedStatementChain(t *testing.T) {
	f, _, c2, _, t3 := twoCycleChain(t)
	honest := prepareCycle(t, f, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	truncated := f.chain()
	truncated.Entries = truncated.Entries[:1] // the latest statement is dropped

	if err := verifyCycle(honest, truncated); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected a V5 truncated-chain error, got %v", err)
	}
	_, err := Prepare(PrepareOptions{
		WorklistRaw: honest.worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: c2.res.NextPack, Chain: truncated,
		Wave: 1, AttestedAt: t3, Now: t3, NextRevision: "rev-4", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: honest.reviews,
	})
	if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected Prepare to refuse a truncated chain with a V5 error, got %v", err)
	}
}

func TestChainRejectsUnsignedOrUntrustedEntries(t *testing.T) {
	f, _, c2, _, t3 := twoCycleChain(t)
	forged := c2.res.Statement
	forged.Rules = append([]RuleAttestation(nil), forged.Rules...)
	forged.Rules[0].ConsecutiveBatchCycles = -5
	forgedRaw, err := CanonicalStatement(forged)
	if err != nil {
		t.Fatal(err)
	}
	untrusted := newChainFixture(t)
	for name, entry := range map[string]ChainEntry{
		"unsigned":        {Name: "0000-forged", Statement: forgedRaw},
		"garbage-sig":     {Name: "0000-forged", Statement: forgedRaw, Envelope: []byte("{}")},
		"untrusted-key":   {Name: "0000-forged", Statement: forgedRaw, Envelope: untrusted.sign(forgedRaw)},
		"other-statement": {Name: "0000-forged", Statement: forgedRaw, Envelope: f.entries[1].Envelope},
	} {
		chain := f.chain()
		chain.Entries = append([]ChainEntry{entry}, chain.Entries...)
		if _, err := deriveChainState(chain, PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "no valid signature") {
			t.Fatalf("%s: expected a V5 signature error, got %v", name, err)
		}
	}
	// The trust root pin is required as soon as the chain has an entry.
	chain := f.chain()
	chain.ExpectedTrustRootDigest = ""
	if _, err := deriveChainState(chain, PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "pinned trust root is required") {
		t.Fatalf("expected a missing trust root pin to be rejected, got %v", err)
	}
	if _, err := deriveChainState(nil, PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") {
		t.Fatalf("expected a missing chain to be rejected, got %v", err)
	}
}

func TestChainRejectsSignedEntryWithCycleCountBelowOne(t *testing.T) {
	f, c1, _, _, t3 := twoCycleChain(t)
	forged := c1.res.Statement
	forged.Rules = append([]RuleAttestation(nil), forged.Rules...)
	forged.Rules[0].ConsecutiveBatchCycles = -5
	forgedRaw, err := CanonicalStatement(forged)
	if err != nil {
		t.Fatal(err)
	}
	signedForged := newChainFixture(t)
	signedForged.key, signedForged.root, signedForged.digest = f.key, f.root, f.digest
	signedForged.append("0001", forgedRaw)
	if _, err := deriveChainState(signedForged.chain(), PackCNCF, t3, ""); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "below 1") {
		t.Fatalf("expected a V5 below-1 error, got %v", err)
	}
}

func TestChainRejectsForksGapsDuplicatesAndOtherPacks(t *testing.T) {
	f, c1, c2, _, t3 := twoCycleChain(t)
	c3 := prepareCycle(t, f, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", nil)
	f.append("0003", c3.res.StatementCanonical)
	if _, err := deriveChainState(f.chain(), PackCNCF, t3.Add(time.Hour), ""); err != nil {
		t.Fatalf("honest three-entry chain rejected: %v", err)
	}
	signed := func(name string, statement Statement) ChainEntry {
		raw, err := CanonicalStatement(statement)
		if err != nil {
			t.Fatal(err)
		}
		return ChainEntry{Name: name, Statement: raw, Envelope: f.sign(raw)}
	}
	fork := c2.res.Statement
	fork.Pack.Next.Revision = "rev-3-fork"
	secondGenesis := c1.res.Statement
	secondGenesis.Pack.Next.Revision = "rev-2-other"
	otherPack := c1.res.Statement
	otherPack.Pack.Name = PackCommunity
	e := f.entries
	for name, tc := range map[string]struct {
		entries []ChainEntry
		want    string
	}{
		"fork":          {[]ChainEntry{e[0], e[1], e[2], signed("0002-fork", fork)}, "forks"},
		"gap":           {[]ChainEntry{e[0], e[2]}, "not linked to its genesis"},
		"no-genesis":    {[]ChainEntry{e[1], e[2]}, "exactly one genesis entry, found 0"},
		"two-genesis":   {[]ChainEntry{e[0], signed("0001-other", secondGenesis), e[1]}, "exactly one genesis entry, found 2"},
		"duplicate":     {[]ChainEntry{e[0], e[1], e[1]}, "duplicates"},
		"other-pack":    {[]ChainEntry{signed("0001", otherPack)}, "belongs to another pack"},
		"order-by-name": {[]ChainEntry{e[2], e[0], e[1]}, ""},
		"renamed-chain": {[]ChainEntry{{Name: "zzz", Statement: e[0].Statement, Envelope: e[0].Envelope}, e[1], e[2]}, ""},
	} {
		chain := &Chain{Entries: tc.entries, TrustRoot: f.root, ExpectedTrustRootDigest: f.digest}
		_, err := deriveChainState(chain, PackCNCF, t3.Add(time.Hour), "")
		if tc.want == "" {
			if err != nil {
				t.Fatalf("%s: chain order must come from links, not names: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: expected a V5 error containing %q, got %v", name, tc.want, err)
		}
	}
}

func TestVerifyAcceptsStatementAlreadyAppendedAsChainHead(t *testing.T) {
	f, c1, c2, _, _ := twoCycleChain(t)
	if err := verifyCycle(c2, f.chain()); err != nil {
		t.Fatalf("a statement already appended as the chain head must still verify: %v", err)
	}
	late := c1
	late.at = c2.at // a verifier clock at which every chain entry is in the past
	if err := verifyCycle(late, f.chain()); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "already recorded in the chain, and not as its head") {
		t.Fatalf("expected a V5 error for a statement recorded mid-chain, got %v", err)
	}
}

// A rule ineligible in one cycle (a transiently stale repo resolution) and
// eligible in the next must be renewed at the count the chain derivation
// gives it, and Verify must accept exactly what Prepare produced.
func TestPrepareAndVerifyAgreeAfterRuleWasIneligibleLastCycle(t *testing.T) {
	f := newChainFixture(t)
	t1 := baseNow
	specs1 := cycleSpecs(2, t1)
	specs1[1].repoResolvedAt = rfc3339(t1.Add(-100 * time.Hour))
	_, pack := buildWorklistAndPack(t, chainPackPath, t1, specs1)
	pack = padPackWithPastRules(t, pack, 20)
	c1 := prepareCycle(t, f, pack, t1, specs1, "rev-2", nil)
	if cyclesOf(c1, "rule-01") != -1 || cyclesOf(c1, "rule-00") != 1 {
		t.Fatalf("setup: rule-00 renewed=%d rule-01 renewed=%d", cyclesOf(c1, "rule-00"), cyclesOf(c1, "rule-01"))
	}
	if err := verifyCycle(c1, f.chain()); err != nil {
		t.Fatalf("cycle 1 verify: %v", err)
	}
	f.append("0001", c1.res.StatementCanonical)
	t2 := t1.Add(cycleSpacing)
	c2 := prepareCycle(t, f, c1.res.NextPack, t2, cycleSpecs(2, t2), "rev-3", nil)
	if cyclesOf(c2, "rule-01") != 1 {
		t.Fatalf("expected rule-01 renewed at cycle 1, got %d (%+v)", cyclesOf(c2, "rule-01"), c2.res.Statement.NotExtended)
	}
	if err := verifyCycle(c2, f.chain()); err != nil {
		t.Fatalf("Verify rejected what Prepare produced: %v", err)
	}
}

func TestNewIndividualReviewResetsConsecutiveCycles(t *testing.T) {
	f, _, c2, target, t3 := twoCycleChain(t)
	c3 := prepareCycle(t, f, c2.res.NextPack, t3, cycleSpecs(12, t3), "rev-4", []string{target})
	if cyclesOf(c3, target) != 1 {
		t.Fatalf("expected a new review to reset %s to cycle 1, got %d (reason %q)", target, cyclesOf(c3, target), worstClassOf(c3, target))
	}
	for _, ra := range c3.res.Statement.Rules {
		if ra.RuleID == target && ra.LastIndividualReviewAt != c3.res.Statement.AttestedAt {
			t.Fatalf("lastIndividualReviewAt = %q, want %q", ra.LastIndividualReviewAt, c3.res.Statement.AttestedAt)
		}
	}
	found := false
	for _, review := range c3.res.Statement.IndividualReviews {
		found = found || review.RuleID == target
	}
	if !found {
		t.Fatalf("expected %s in individualReviews, got %+v", target, c3.res.Statement.IndividualReviews)
	}
	if err := verifyCycle(c3, f.chain()); err != nil {
		t.Fatalf("cycle 3 verify: %v", err)
	}
}

// chainStateAt returns a state whose head was attested at the given time
// and that has recorded batch renewals for rule-a since its last review.
func chainStateAt(t *testing.T, headAttestedAt string, batchSinceReview int) chainState {
	t.Helper()
	state := newChainState()
	head := "sha256:" + strings.Repeat("12", 32)
	state.headDigest = &head
	at, err := parseUTC(headAttestedAt)
	if err != nil {
		t.Fatal(err)
	}
	state.headAttestedAt = at
	state.batchSinceReview["rule-a"] = batchSinceReview
	state.lastReviewAt["rule-a"] = "2026-01-01T00:00:00Z"
	return state
}

func TestChainApplyEnforcesContinuityAndCap(t *testing.T) {
	head := "sha256:" + strings.Repeat("12", 32)
	statementWith := func(cycles int) Statement {
		return Statement{
			PreviousAttestationDigest: &head, AttestedAt: "2026-10-06T12:00:00Z",
			Rules: []RuleAttestation{{RuleID: "rule-a", ConsecutiveBatchCycles: cycles, PriorReviewedAt: "2026-08-01T00:00:00Z", LastIndividualReviewAt: "2026-01-01T00:00:00Z"}},
		}
	}
	state := chainStateAt(t, "2026-08-20T12:00:00Z", 1)
	if err := checkV5(statementWith(2), state); err != nil {
		t.Fatalf("correct continuation rejected: %v", err)
	}
	if err := checkV5(statementWith(1), state); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "does not continue the chain") {
		t.Fatalf("expected a V5 continuity error, got %v", err)
	}
	if err := checkV5(statementWith(0), state); err == nil || !strings.Contains(err.Error(), "below 1") {
		t.Fatalf("expected a V5 below-1 error, got %v", err)
	}
	capped := chainStateAt(t, "2026-08-20T12:00:00Z", 2)
	if err := checkV5(statementWith(3), capped); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "exceeds the consecutive-batch-cycle cap") {
		t.Fatalf("expected a V5 cap error, got %v", err)
	}
	wrongHead := statementWith(2)
	other := "sha256:" + strings.Repeat("34", 32)
	wrongHead.PreviousAttestationDigest = &other
	if err := checkV5(wrongHead, state); err == nil || !strings.Contains(err.Error(), "does not match the head") {
		t.Fatalf("expected a V5 head mismatch error, got %v", err)
	}
	noHead := statementWith(2)
	noHead.PreviousAttestationDigest = nil
	if err := checkV5(noHead, state); err == nil || !strings.Contains(err.Error(), "declares no previousAttestationDigest") {
		t.Fatalf("expected a V5 missing link error, got %v", err)
	}
	stale := statementWith(2)
	stale.Rules[0].LastIndividualReviewAt = "2026-08-01T00:00:00Z"
	if err := checkV5(stale, state); err == nil || !strings.Contains(err.Error(), "lastIndividualReviewAt") {
		t.Fatalf("expected a V5 lastIndividualReviewAt error, got %v", err)
	}
}

func TestPriorPackRuleReviewedAfterChainHeadNeedsNewReviewRecord(t *testing.T) {
	state := chainStateAt(t, "2026-08-20T12:00:00Z", 1)
	rule := ruleFields{ID: "rule-a"}
	rule.Evidence.ReviewedAt = "2026-09-01T00:00:00Z"
	if _, err := state.checkPriorPackCovered([]ruleFields{rule}, nil, false); err == nil || !strings.Contains(err.Error(), "V5:") || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected a V5 error for a rule reviewed after the chain head with no review record, got %v", err)
	}
	if _, err := state.checkPriorPackCovered([]ruleFields{rule}, map[string]string{"rule-a": "sha256:" + strings.Repeat("ee", 32)}, false); err != nil {
		t.Fatalf("a new review record must account for the later reviewedAt: %v", err)
	}
	rule.Evidence.ReviewedAt = "2026-08-20T12:00:00Z"
	if _, err := state.checkPriorPackCovered([]ruleFields{rule}, nil, false); err != nil {
		t.Fatalf("a rule renewed by the chain head itself must pass: %v", err)
	}
}

// ---------------------------------------------------------------------
// Stagger cap (V7) on Prepare's output
// ---------------------------------------------------------------------

func TestPrepareDefersRulesOverStaggerCap(t *testing.T) {
	f := newChainFixture(t)
	specs := cycleSpecs(12, baseNow)
	for i := range specs {
		// Current validUntil runs opposite to rule ID order, so the cap
		// must pick by validUntil first.
		specs[i].validUntil = rfc3339(baseNow.Add(time.Duration(20-i) * 24 * time.Hour))
	}
	specs[5].validUntil = specs[4].validUntil // tie: broken by rule ID
	_, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 8) // 20 rules: cap 3
	c := prepareCycle(t, f, pack, baseNow, specs, "rev-2", nil)
	var renewed []string
	for _, ra := range c.res.Statement.Rules {
		renewed = append(renewed, ra.RuleID)
	}
	if strings.Join(renewed, ",") != "rule-09,rule-10,rule-11" {
		t.Fatalf("expected the three earliest-expiring rules renewed, got %v", renewed)
	}
	deferred := 0
	for _, ne := range c.res.Statement.NotExtended {
		if ne.WorstClass == reasonStaggerDeferred {
			deferred++
		}
	}
	if deferred != 9 {
		t.Fatalf("expected 9 rules deferred with %s, got %d (%+v)", reasonStaggerDeferred, deferred, c.res.Statement.NotExtended)
	}
	if len(c.res.Statement.SampledForFullReview) != 1 {
		t.Fatalf("the sample must be drawn from the capped batch (ceil(10%% of 3) = 1), got %+v", c.res.Statement.SampledForFullReview)
	}
	if err := verifyCycle(c, f.chain()); err != nil {
		t.Fatalf("Verify rejected a stagger-capped batch: %v", err)
	}
}

// Every citation in the real embedded packs marked mechanically unchanged:
// Prepare must cap the batch to the stagger cap and Verify must accept it.
func TestPrepareAndVerifyStayWithinStaggerCapOnRealPacks(t *testing.T) {
	for _, tc := range []struct{ pack, path string }{
		{PackCNCF, filepath.Join("..", "..", "cncfcheck", "data", "rules.json")},
		{PackCommunity, filepath.Join("..", "..", "projectcheck", "data", "rules.json")},
	} {
		raw, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := loadPack(raw)
		if err != nil {
			t.Fatal(err)
		}
		// Late enough that every wave's slot date is later than the
		// packs' current validUntil values, so only V7 limits the batch.
		at := time.Date(2026, 12, 14, 12, 0, 0, 0, time.UTC)
		wl := evidencerepin.Worklist{
			Schema: evidencerepin.Schema, Authority: evidencerepin.Authority, GeneratedAt: rfc3339(at),
			Scope: evidencerepin.WorklistScope{RulePacks: []string{tc.path}},
			Repos: []evidencerepin.RepoResolution{{Owner: "o", Repo: "r", Status: "RESOLVED", CurrentTag: "v1", ResolvedAt: rfc3339(at.Add(-time.Hour))}},
		}
		reviews := map[string][]byte{}
		for _, entry := range doc.Entries {
			fields, _ := parseRuleFields(entry.Rule)
			for _, source := range fields.Evidence.Sources {
				wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
					RulePack: tc.path, RuleID: fields.ID, Project: entry.Project, SourceID: source.ID,
					Owner: "o", Repo: "r", OldCommit: source.Revision, NewCommit: source.Revision, Class: evidencerepin.ClassFileIdentical,
				})
			}
		}
		worklistRaw := marshalWorklist(t, wl)
		for wave := minWave; wave <= maxWave; wave++ {
			prepared := withSampleRecords(t, PrepareOptions{
				WorklistRaw: worklistRaw, PackName: tc.pack, PackPath: tc.path, PackRaw: raw, Chain: &Chain{},
				Wave: wave, AttestedAt: at, Now: at, NextRevision: "next", EngineCapabilityDigest: testEngineCapabilityDigest, ReviewRecords: reviews,
			})
			res, err := Prepare(prepared)
			if err != nil {
				t.Fatalf("%s wave %d: Prepare: %v", tc.pack, wave, err)
			}
			if res.EligibleRuleCount > staggerCap(len(doc.Entries)) {
				t.Fatalf("%s wave %d: %d rules renewed, over the cap of %d", tc.pack, wave, res.EligibleRuleCount, staggerCap(len(doc.Entries)))
			}
			if _, err := Verify(VerifyOptions{
				StatementRaw: res.StatementCanonical, PriorPackRaw: raw, NextPackRaw: res.NextPack, WorklistRaw: worklistRaw,
				Chain: &Chain{}, BaseChain: &Chain{}, PackName: tc.pack, PackPath: tc.path, EngineCapabilityDigest: testEngineCapabilityDigest,
				AttestedAtNow: at.Add(time.Hour), ReviewRecords: prepared.ReviewRecords, PreSign: true,
			}); err != nil {
				t.Fatalf("%s wave %d: Verify rejected Prepare's own output (%d renewed): %v", tc.pack, wave, res.EligibleRuleCount, err)
			}
			t.Logf("%s wave %d: renewed %d of %d rules, not extended %d, cap %d", tc.pack, wave, res.EligibleRuleCount, len(doc.Entries), res.NotExtendedRuleCount, staggerCap(len(doc.Entries)))
			if wave == 3 && res.EligibleRuleCount == 0 {
				t.Fatalf("%s: expected at least one rule renewed", tc.pack)
			}
		}
	}
}
