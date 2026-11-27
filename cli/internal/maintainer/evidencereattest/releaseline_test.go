// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// lineWorklist turns the single fresh citation of a one-rule worklist into
// a release-line citation backed by a matching line record. The repository's
// own latest release (v1.2.3 in the shared fixture) is on a different line
// than the compared tag, as in a real pinned-pair citation.
func lineWorklist(t *testing.T, packPath string) (evidencerepin.Worklist, []byte) {
	t.Helper()
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	commit := strings.Repeat("c", 40)
	c := &wl.Citations[0]
	c.NewCommit = commit
	c.Baseline = evidencerepin.BaselineReleaseLine
	c.BaselineMode = evidencerepin.BaselineModeReleaseLine
	c.BaselineLine = "0.9"
	c.PinnedTag = "v0.9.0"
	c.BaselineTag = "v0.9.4"
	wl.Lines = []evidencerepin.LineResolution{{
		Owner: "owner", Repo: "repo-rule-a", Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: commit,
		ResolvedAt: rfc3339(baseNow.Add(-time.Hour)),
	}}
	return wl, pack
}

func TestPrepareAcceptsVerifiedReleaseLineBaselineAndRecordsIt(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := lineWorklist(t, packPath)
	result := prepareSingle(t, wl, pack, packPath)
	if len(result.Statement.Rules) != 1 {
		t.Fatalf("a verified release-line citation must be eligible: %+v", result.Statement.NotExtended)
	}
	got := result.Statement.Rules[0].Citations[0]
	if got.ComparedTag != "v0.9.4" || got.Baseline != evidencerepin.BaselineReleaseLine || got.BaselineLine != "0.9" || got.PinnedTag != "v0.9.0" {
		t.Fatalf("statement must record the line baseline, not the repository's latest tag: %+v", got)
	}
	if rel := result.Statement.UpstreamReleasesSincePrior; len(rel) != 1 || len(rel[0].Tags) != 1 || rel[0].Tags[0] != "v0.9.4" {
		t.Fatalf("acknowledged releases must be the compared tags: %+v", rel)
	}
	if _, err := ParseStatement(result.StatementCanonical); err != nil {
		t.Fatalf("statement must round-trip: %v", err)
	}
}

func TestPrepareLatestCitationStatementIsUnchangedByBaselineFields(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	wl.Citations[0].Baseline = evidencerepin.BaselineLatest
	wl.Citations[0].BaselineMode = evidencerepin.BaselineModeReleaseLine
	got := prepareSingle(t, wl, pack, packPath).Statement.Rules[0].Citations[0]
	if got.ComparedTag != "v1.2.3" || got.Baseline != "" || got.BaselineLine != "" || got.PinnedTag != "" {
		t.Fatalf("a latest-baseline citation must be attested exactly as before: %+v", got)
	}
}

// Earlier worklist schemas record no digest and were classified without the
// current proof: no statement and no sample review comes from them.
func TestPrepareRefusesOlderAndUnknownWorklistSchemas(t *testing.T) {
	packPath := "/p/rules.json"
	for schema, want := range map[string]string{
		evidencerepin.SchemaV2:                 "older than the current schema",
		evidencerepin.SchemaV1:                 "older than the current schema",
		"prufyx.io/evidence-repin-worklist/v4": "decode worklist",
		"":                                     "decode worklist",
	} {
		wl, pack := lineWorklist(t, packPath)
		opts := PrepareOptions{
			WorklistRaw: marshalWorklist(t, wl), PackName: PackCNCF, PackPath: packPath, PackRaw: pack,
			Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest, Chain: &Chain{},
		}
		if _, err := Prepare(opts); err != nil {
			t.Fatalf("control: the current schema must be accepted: %v", err)
		}
		wl.Schema = schema
		opts.WorklistRaw = marshalWorklist(t, wl)
		if _, err := Prepare(opts); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: Prepare must refuse, got %v", schema, err)
		}
		if _, err := worklistCitationAttestations(opts.WorklistRaw, packPath, ruleCandidate{RuleID: "rule-a"}); err == nil || !strings.Contains(err.Error(), "current worklist schema") {
			t.Errorf("%q: a sample review must refuse, got %v", schema, err)
		}
	}
}

// A statement over a v2 worklist, which records no digest, is recomputed only
// with no independent worklist and outside pre-sign, which is never the
// publish gate.
func TestVerifyReadsAnOlderRetainedWorklistOnlyAsAnAudit(t *testing.T) {
	f := newRoleFixture(t)
	wl, _ := buildWorklistAndPack(t, chainPackPath, baseNow, cycleSpecs(12, baseNow))
	lineBaselined(&wl)
	current := marshalWorklist(t, wl)
	wl.Schema = evidencerepin.SchemaV2
	for i := range wl.Citations {
		wl.Citations[i].OldDigest = ""
	}
	older := marshalWorklist(t, wl)
	prior := automatedPack(t, baseNow)
	prepare := PrepareOptions{
		Mode: ModeAutomated, WorklistRaw: older, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: prior, Chain: &Chain{},
		AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	}
	if _, err := Prepare(prepare); err == nil || !strings.Contains(err.Error(), "current-schema worklist") {
		t.Fatalf("Prepare must refuse a v2 worklist, got %v", err)
	}
	// The statement a build of that schema's time prepared.
	prepare.historicWorklist = true
	res, err := Prepare(prepare)
	if err != nil || len(res.Statement.Rules) != 12 {
		t.Fatalf("fixture: %v %+v", err, res.Statement.NotExtended)
	}
	base := f.chain()
	f.appendAutomated("0001", res.StatementCanonical)
	audit := VerifyOptions{
		StatementRaw: res.StatementCanonical, PriorPackRaw: prior, NextPackRaw: res.NextPack,
		WorklistRaw: older, Chain: f.chain(), BaseChain: base, PackName: PackCNCF, PackPath: chainPackPath,
		EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: baseNow.Add(time.Hour),
	}
	if _, err := Verify(audit); err != nil {
		t.Fatalf("a signed statement over a v2 worklist must still verify: %v", err)
	}
	for name, mutate := range map[string]func(*VerifyOptions){
		"pre-sign":                     func(o *VerifyOptions) { o.PreSign = true },
		"older independent worklist":   func(o *VerifyOptions) { o.IndependentWorklistRaw = older },
		"current independent worklist": func(o *VerifyOptions) { o.IndependentWorklistRaw = current },
	} {
		gate := audit
		mutate(&gate)
		if _, err := Verify(gate); err == nil || !strings.Contains(err.Error(), "V3") {
			t.Errorf("%s: Verify must refuse an older retained worklist, got %v", name, err)
		}
	}

	// A human statement may rest on a v2 or a v1 worklist, on the same terms.
	for _, schema := range []string{evidencerepin.SchemaV2, evidencerepin.SchemaV1} {
		h := newRoleFixture(t)
		wl, pack := buildWorklistAndPack(t, chainPackPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		pack = padPackWithSpreadRules(t, pack, 12)
		wl.Schema = schema
		for i := range wl.Citations {
			wl.Citations[i].OldDigest = ""
		}
		raw := marshalWorklist(t, wl)
		res, records := prepareWithSample(t, PrepareOptions{
			WorklistRaw: raw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{}, Wave: 1,
			AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
			historicWorklist: true,
		})
		if len(res.Statement.Rules) != 1 {
			t.Fatalf("%s fixture: %+v", schema, res.Statement.NotExtended)
		}
		before := h.chain()
		h.append("0001", res.StatementCanonical)
		audit := VerifyOptions{
			StatementRaw: res.StatementCanonical, PriorPackRaw: pack, NextPackRaw: res.NextPack,
			WorklistRaw: raw, Chain: h.chain(), BaseChain: before, PackName: PackCNCF, PackPath: chainPackPath,
			EngineCapabilityDigest: testEngineCapabilityDigest, AttestedAtNow: baseNow.Add(time.Hour), ReviewRecords: records,
		}
		if _, err := Verify(audit); err != nil {
			t.Fatalf("a signed human statement over a %s worklist must still verify: %v", schema, err)
		}
		for name, mutate := range map[string]func(*VerifyOptions){
			"pre-sign":             func(o *VerifyOptions) { o.PreSign = true },
			"independent worklist": func(o *VerifyOptions) { o.IndependentWorklistRaw = raw },
		} {
			gate := audit
			mutate(&gate)
			if _, err := Verify(gate); err == nil || !strings.Contains(err.Error(), "V3") {
				t.Errorf("%s %s: Verify must refuse an older retained worklist, got %v", schema, name, err)
			}
		}
	}
}

// The independent worklist is the verifying job's own run: an earlier schema
// is refused.
func TestIndependentWorklistMustBeTheCurrentSchema(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := lineWorklist(t, packPath)
	statement := prepareSingle(t, wl, pack, packPath).Statement
	if err := checkIndependentWorklist(statement, packPath, marshalWorklist(t, wl)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, schema := range []string{evidencerepin.SchemaV2, evidencerepin.SchemaV1} {
		wl.Schema = schema
		if err := checkIndependentWorklist(statement, packPath, marshalWorklist(t, wl)); err == nil || !strings.Contains(err.Error(), "current worklist schema") {
			t.Errorf("%s: must be refused, got %v", schema, err)
		}
	}
}

func TestPrepareRefusesUnverifiedReleaseLineBaselines(t *testing.T) {
	packPath := "/p/rules.json"
	cases := map[string]struct {
		mutate func(*evidencerepin.Worklist)
		reason string
	}{
		"no line record":                   {func(w *evidencerepin.Worklist) { w.Lines = nil }, reasonLineBaselineUnverified},
		"line record names another commit": {func(w *evidencerepin.Worklist) { w.Lines[0].Commit = strings.Repeat("d", 40) }, reasonLineBaselineUnverified},
		"line record names another tag":    {func(w *evidencerepin.Worklist) { w.Lines[0].Tag = "v0.9.5" }, reasonLineBaselineUnverified},
		"line record not resolved":         {func(w *evidencerepin.Worklist) { w.Lines[0].Status = "UNDERIVABLE" }, reasonLineBaselineUnverified},
		"missing pinned tag":               {func(w *evidencerepin.Worklist) { w.Citations[0].PinnedTag = "" }, reasonLineBaselineUnverified},
		"compared tag older than pinned":   {func(w *evidencerepin.Worklist) { w.Citations[0].PinnedTag = "v0.9.7" }, reasonLineBaselineUnverified},
		"tags on different lines":          {func(w *evidencerepin.Worklist) { w.Citations[0].PinnedTag = "v0.8.0" }, reasonLineBaselineUnverified},
		"pre-release compared tag": {func(w *evidencerepin.Worklist) {
			w.Citations[0].BaselineTag, w.Lines[0].Tag = "v0.9.4-rc1", "v0.9.4-rc1"
		}, reasonLineBaselineUnverified},
		"unknown baseline value": {func(w *evidencerepin.Worklist) { w.Citations[0].Baseline = "newest" }, reasonLineBaselineUnverified},
		"stale line record": {func(w *evidencerepin.Worklist) {
			w.Lines[0].ResolvedAt = rfc3339(baseNow.Add(-100 * time.Hour))
		}, reasonStaleBaseline},
		"line record flagged stale": {func(w *evidencerepin.Worklist) { w.Lines[0].Stale = true }, reasonStaleBaseline},
		"line record from the future": {func(w *evidencerepin.Worklist) {
			w.Lines[0].ResolvedAt = rfc3339(baseNow.Add(time.Hour))
		}, reasonStaleBaseline},
		"tag fallback marker still refuses": {func(w *evidencerepin.Worklist) { w.Citations[0].Resolution = resolutionTagFallback }, reasonTagFallbackBaseline},
		"changed class still refuses":       {func(w *evidencerepin.Worklist) { w.Citations[0].Class = evidencerepin.ClassContentChanged }, evidencerepin.ClassContentChanged},
	}
	for name, tc := range cases {
		wl, pack := lineWorklist(t, packPath)
		tc.mutate(&wl)
		result := prepareSingle(t, wl, pack, packPath)
		if len(result.Statement.Rules) != 0 || len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != tc.reason {
			t.Errorf("%s: expected exclusion %s, got rules=%d notExtended=%+v", name, tc.reason, len(result.Statement.Rules), result.Statement.NotExtended)
		}
	}
}

// A repository that definitively publishes no releases or tags leaves its
// citation NO_RELEASE_BASELINE. That class must not hold the whole pack's
// batch back the way PENDING does, and the rule citing it must not be
// renewed in batch.
func TestPrepareNoReleaseBaselineExcludesOnlyItsOwnRule(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	good := freshSpec("rule-a", "proj-a", baseNow)
	bare := freshSpec("rule-b", "proj-b", baseNow)
	bare.class = evidencerepin.ClassNoReleaseBaseline
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{good, bare})
	result := prepareSingle(t, wl, pack, packPath)
	if len(result.Statement.Rules) != 1 || result.Statement.Rules[0].RuleID != "rule-a" {
		t.Fatalf("the unaffected rule must still be batch-renewable: rules %+v, notExtended %+v", result.Statement.Rules, result.Statement.NotExtended)
	}
	found := map[string]string{}
	for _, ne := range result.Statement.NotExtended {
		found[ne.RuleID] = ne.WorstClass
	}
	if found["rule-b"] != evidencerepin.ClassNoReleaseBaseline {
		t.Fatalf("the rule citing a repository without releases must be excluded with its class: %+v", found)
	}
}

// PENDING next to a NO_RELEASE_BASELINE citation is still recorded.
func TestPrepareNoReleaseBaselineDoesNotMaskPending(t *testing.T) {
	packPath := "/repo/cli/internal/cncfcheck/data/rules.json"
	bare := freshSpec("rule-b", "proj-b", baseNow)
	bare.class = evidencerepin.ClassNoReleaseBaseline
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow), bare})
	wl.Citations = append(wl.Citations, evidencerepin.ClassResult{
		RulePack: packPath, RuleID: "rule-x", Project: "proj-a", SourceID: "rule-x-src",
		Owner: "owner", Repo: "repo-x", Class: evidencerepin.ClassPending,
	})
	result := prepareSingle(t, wl, pack, packPath)
	if len(result.Statement.PendingCitations) != 1 {
		t.Fatalf("a PENDING citation must be recorded next to a NO_RELEASE_BASELINE one: %+v", result.Statement.PendingCitations)
	}
	for _, ne := range result.Statement.NotExtended {
		if ne.RuleID == "rule-b" && ne.WorstClass != evidencerepin.ClassNoReleaseBaseline {
			t.Fatalf("rule-b keeps its own reason: %+v", ne)
		}
	}
}
