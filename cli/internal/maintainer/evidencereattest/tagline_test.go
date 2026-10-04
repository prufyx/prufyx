// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// tagLineWorklist is lineWorklist for a repository without GitHub Releases:
// the citation was compared on a line derived from git tags (go1.21.4 ->
// go1.21.13), backed by a line record whose basis is git_tags.
func tagLineWorklist(t *testing.T, packPath string) (evidencerepin.Worklist, []byte) {
	t.Helper()
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	commit := strings.Repeat("c", 40)
	c := &wl.Citations[0]
	c.NewCommit = commit
	c.Baseline = evidencerepin.BaselineTagLine
	c.BaselineMode = evidencerepin.BaselineModeReleaseLine
	c.BaselineLine = "1.21"
	c.PinnedTag = "go1.21.4"
	c.BaselineTag = "go1.21.13"
	c.Resolution = ""
	wl.Lines = []evidencerepin.LineResolution{{
		Owner: "owner", Repo: "repo-rule-a", Prefix: "go", Line: "1.21", Status: "RESOLVED", Tag: "go1.21.13", Commit: commit,
		Basis: evidencerepin.LineBasisGitTags, ResolvedAt: rfc3339(baseNow.Add(-time.Hour)),
	}}
	return wl, pack
}

func TestPrepareAcceptsVerifiedTagLineBaselineAndRecordsIt(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := tagLineWorklist(t, packPath)
	result := prepareSingle(t, wl, pack, packPath)
	if len(result.Statement.Rules) != 1 {
		t.Fatalf("a verified tag-line citation must be eligible in human mode: %+v", result.Statement.NotExtended)
	}
	got := result.Statement.Rules[0].Citations[0]
	if got.ComparedTag != "go1.21.13" || got.Baseline != evidencerepin.BaselineTagLine || got.BaselineLine != "1.21" || got.PinnedTag != "go1.21.4" {
		t.Fatalf("statement must record the tag-line baseline: %+v", got)
	}
	if _, err := ParseStatement(result.StatementCanonical); err != nil {
		t.Fatalf("statement must round-trip: %v", err)
	}
}

func TestPrepareRefusesUnverifiedTagLineBaselines(t *testing.T) {
	packPath := "/p/rules.json"
	cases := map[string]struct {
		mutate func(*evidencerepin.Worklist)
		reason string
	}{
		"no line record":                    {func(w *evidencerepin.Worklist) { w.Lines = nil }, reasonLineBaselineUnverified},
		"line record proven by Releases":    {func(w *evidencerepin.Worklist) { w.Lines[0].Basis = "" }, reasonLineBaselineUnverified},
		"line record with an unknown basis": {func(w *evidencerepin.Worklist) { w.Lines[0].Basis = "branches" }, reasonLineBaselineUnverified},
		"line record names another commit":  {func(w *evidencerepin.Worklist) { w.Lines[0].Commit = strings.Repeat("d", 40) }, reasonLineBaselineUnverified},
		"line record names another tag":     {func(w *evidencerepin.Worklist) { w.Lines[0].Tag = "go1.21.12" }, reasonLineBaselineUnverified},
		"line record not resolved":          {func(w *evidencerepin.Worklist) { w.Lines[0].Status = "UNDERIVABLE" }, reasonLineBaselineUnverified},
		"compared tag older than pinned":    {func(w *evidencerepin.Worklist) { w.Citations[0].PinnedTag = "go1.21.14" }, reasonLineBaselineUnverified},
		"tags on different lines":           {func(w *evidencerepin.Worklist) { w.Citations[0].PinnedTag = "go1.20.4" }, reasonLineBaselineUnverified},
		"pre-release compared tag": {func(w *evidencerepin.Worklist) {
			w.Citations[0].BaselineTag, w.Lines[0].Tag = "go1.21rc4", "go1.21rc4"
		}, reasonLineBaselineUnverified},
		"a Releases line claimed for go tags": {func(w *evidencerepin.Worklist) {
			w.Citations[0].Baseline, w.Lines[0].Basis = evidencerepin.BaselineReleaseLine, ""
		}, reasonLineBaselineUnverified},
		"stale line record": {func(w *evidencerepin.Worklist) {
			w.Lines[0].ResolvedAt = rfc3339(baseNow.Add(-100 * time.Hour))
		}, reasonStaleBaseline},
		"tag fallback marker still refuses": {func(w *evidencerepin.Worklist) { w.Citations[0].Resolution = resolutionTagFallback }, reasonTagFallbackBaseline},
		"changed class still refuses":       {func(w *evidencerepin.Worklist) { w.Citations[0].Class = evidencerepin.ClassContentChanged }, evidencerepin.ClassContentChanged},
	}
	for name, tc := range cases {
		wl, pack := tagLineWorklist(t, packPath)
		tc.mutate(&wl)
		result := prepareSingle(t, wl, pack, packPath)
		if len(result.Statement.Rules) != 0 || len(result.Statement.NotExtended) != 1 || result.Statement.NotExtended[0].WorstClass != tc.reason {
			t.Errorf("%s: expected exclusion %s, got rules=%d notExtended=%+v", name, tc.reason, len(result.Statement.Rules), result.Statement.NotExtended)
		}
	}
}

// A Releases line record never backs a tag line, and the reverse.
func TestReleaseLineNotBackedByTagLineRecord(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := lineWorklist(t, packPath)
	wl.Lines[0].Basis = evidencerepin.LineBasisGitTags
	result := prepareSingle(t, wl, pack, packPath)
	if len(result.Statement.Rules) != 0 || result.Statement.NotExtended[0].WorstClass != reasonLineBaselineUnverified {
		t.Fatalf("a git-tags line record must not back a release_line citation: %+v", result.Statement.NotExtended)
	}
}

// Automated renewal is approved for lines proven by GitHub Releases only.
func TestAutomatedPrepareExcludesTagLineBaselines(t *testing.T) {
	f := newRoleFixture(t)
	specs := cycleSpecs(2, baseNow)
	wl, pack := buildWorklistAndPack(t, chainPackPath, baseNow, specs)
	pack = padPackWithPastRules(t, pack, 40)
	lineBaselined(&wl)
	for i := range wl.Citations {
		if wl.Citations[i].RuleID == "rule-01" {
			c := &wl.Citations[i]
			c.Baseline, c.BaselineLine, c.PinnedTag, c.BaselineTag = evidencerepin.BaselineTagLine, "1.21", "go1.21.4", "go1.21.13"
			for j := range wl.Lines {
				if wl.Lines[j].Owner == c.Owner && wl.Lines[j].Repo == c.Repo {
					wl.Lines[j].Prefix, wl.Lines[j].Line, wl.Lines[j].Tag, wl.Lines[j].Basis = "go", "1.21", "go1.21.13", evidencerepin.LineBasisGitTags
				}
			}
		}
	}
	worklistRaw := marshalWorklist(t, wl)
	c := prepareAutomatedWith(t, f.chainFixture, pack, baseNow, worklistRaw, "rev-2", nil)
	if renewedIDs(c.res) != "rule-00" || worstClassOf(c, "rule-01") != reasonTagLineNotAutomatable {
		t.Fatalf("expected rule-01 excluded as %s, got renewed=%s notExtended=%+v", reasonTagLineNotAutomatable, renewedIDs(c.res), c.res.Statement.NotExtended)
	}
	human, err := Prepare(PrepareOptions{
		WorklistRaw: worklistRaw, PackName: PackCNCF, PackPath: chainPackPath, PackRaw: pack, Chain: &Chain{},
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewedIDs(human) != "rule-00,rule-01" {
		t.Fatalf("human mode must renew the tag-line rule, got %s (%+v)", renewedIDs(human), human.Statement.NotExtended)
	}
}

// V8: an automated statement carrying a tag-line citation is refused however
// it was produced.
func TestVerifyRejectsAutomatedStatementWithTagLineCitation(t *testing.T) {
	f := newRoleFixture(t)
	c := prepareAutomated(t, f.chainFixture, automatedPack(t, baseNow), baseNow, cycleSpecs(12, baseNow), "rev-2", nil)
	statement := c.res.Statement
	statement.Rules = append([]RuleAttestation(nil), statement.Rules...)
	statement.Rules[0].Citations = append([]CitationAttestation(nil), statement.Rules[0].Citations...)
	statement.Rules[0].Citations[0].Baseline = evidencerepin.BaselineTagLine
	priorDoc, err := loadPack(c.prior)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(priorDoc)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRolePolicy(statement, candidatesByID(candidates)); err == nil || !strings.Contains(err.Error(), "V8:") {
		t.Fatalf("V8 must refuse a tag-line citation in an automated statement, got %v", err)
	}
}

// V9: the independent worklist must re-derive the same tag line.
func TestIndependentWorklistMustAgreeOnTagLine(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := tagLineWorklist(t, packPath)
	statement := prepareSingle(t, wl, pack, packPath).Statement
	if len(statement.Rules) != 1 {
		t.Fatalf("setup: %+v", statement.NotExtended)
	}
	if err := checkIndependentWorklist(statement, packPath, marshalWorklist(t, wl)); err != nil {
		t.Fatalf("an identical independent worklist must pass: %v", err)
	}
	cases := map[string]func(w *evidencerepin.Worklist){
		"latest instead of tag line":   func(w *evidencerepin.Worklist) { w.Citations[0].Baseline = evidencerepin.BaselineLatest },
		"release line instead":         func(w *evidencerepin.Worklist) { w.Citations[0].Baseline = evidencerepin.BaselineReleaseLine },
		"different line":               func(w *evidencerepin.Worklist) { w.Citations[0].BaselineLine = "1.26" },
		"different pinned tag":         func(w *evidencerepin.Worklist) { w.Citations[0].PinnedTag = "go1.21.5" },
		"different compared tag":       func(w *evidencerepin.Worklist) { w.Citations[0].BaselineTag = "go1.21.12" },
		"different compared commit":    func(w *evidencerepin.Worklist) { w.Citations[0].NewCommit = strings.Repeat("9", 40) },
		"line record missing":          func(w *evidencerepin.Worklist) { w.Lines = nil },
		"line record of another basis": func(w *evidencerepin.Worklist) { w.Lines[0].Basis = "" },
	}
	for name, mutate := range cases {
		var mutated evidencerepin.Worklist
		raw, _ := json.Marshal(wl)
		if err := json.Unmarshal(raw, &mutated); err != nil {
			t.Fatal(err)
		}
		mutate(&mutated)
		if err := checkIndependentWorklist(statement, packPath, marshalWorklist(t, mutated)); err == nil || !strings.Contains(err.Error(), "V9:") {
			t.Errorf("%s: expected a V9 failure, got %v", name, err)
		}
	}

	// A statement that claims the latest baseline is refused when the
	// independent run derived a tag line.
	latestStatement := statement
	latestStatement.Rules = append([]RuleAttestation(nil), statement.Rules...)
	latestStatement.Rules[0].Citations = append([]CitationAttestation(nil), statement.Rules[0].Citations...)
	latestStatement.Rules[0].Citations[0].Baseline = ""
	if err := checkIndependentWorklist(latestStatement, packPath, marshalWorklist(t, wl)); err == nil || !strings.Contains(err.Error(), "V9:") {
		t.Errorf("a latest claim against an independent tag line must fail V9, got %v", err)
	}
}
