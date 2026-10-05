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

func TestPrepareAcceptsSchemaV1Worklist(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	wl.Schema = evidencerepin.SchemaV1
	if got := prepareSingle(t, wl, pack, packPath); len(got.Statement.Rules) != 1 {
		t.Fatalf("a v1 worklist must still validate: %+v", got.Statement.NotExtended)
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
