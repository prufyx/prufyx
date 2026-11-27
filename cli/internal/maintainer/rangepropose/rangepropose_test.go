// SPDX-License-Identifier: AGPL-3.0-only

package rangepropose

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

func TestStableOnBothSidesIsAnUnreviewedProposal(t *testing.T) {
	f := newFixture(t, standard())
	r := run(t, options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", f.both())))
	p := wantProposal(t, r)
	if p.Status != StatusUnreviewed || p.Candidate.ReviewStatus != StatusUnreviewed {
		t.Fatalf("status: %+v", p)
	}
	got := marshal(t, p.Candidate)
	want := `{"reviewStatus":"unreviewed-proposal","from":{"gte":"1.4.0","lt":"1.5.0"},"to":{"gte":"1.5.0","lt":"1.6.0"},"bounds":[` +
		`{"bound":"from.gte","basis":"PREVIOUS_MINOR_LINE","sourceId":"old-flags"},{"bound":"from.lt","basis":"REVIEWER_MUST_DECIDE"},` +
		`{"bound":"to.gte","basis":"REVIEWER_MUST_DECIDE"},{"bound":"to.lt","basis":"TARGET_SERIES","sourceId":"new-flags"}]}`
	if got != want {
		t.Fatalf("candidate\n%s\nwant\n%s", got, want)
	}
	if p.BasisNote == "" || len(p.Sources) != 2 || len(p.Sources[0].Observations) != 3 || len(p.Sources[1].Observations) != 2 {
		t.Fatalf("evaluated: %s", marshal(t, p))
	}
	high := p.Sources[0].Highest
	if high == nil || high.Tag != "v1.4.2" || high.Commit != f.commits["v1.4.2"] || high.FirstLine != 3 || high.LastLine != 5 ||
		high.URL != "https://github.com/acme/demo/blob/"+f.commits["v1.4.2"]+"/flags.go" {
		t.Fatalf("highest reference: %+v", high)
	}
	if len(p.TagSets) != 2 || p.TagSets[0].TagCount != 3 || p.TagSets[0].HighestTag != "v1.4.2" || p.TagSets[1].HighestTag != "v1.5.1" ||
		p.TagSets[0].ExpectedListGiven || p.TagSets[0].TagListDigest == p.TagSets[1].TagListDigest || p.BaseEntryDigest == "" {
		t.Fatalf("binding: %s", marshal(t, p))
	}
}

// candidateInEngine puts an emitted candidate into a rule as its range and
// asks the engine to parse it.
func candidateInEngine(t *testing.T, base map[string]any, candidate map[string]any) error {
	t.Helper()
	registry, err := constraintengine.NewRegistry([]constraintengine.FactDefinition{{ID: testFact, Component: testComponent, Type: "bool"}})
	if err != nil {
		t.Fatal(err)
	}
	base["range"] = candidate
	// The engine requires sources in ascending id order, as a pack holds them.
	sources := base["evidence"].(map[string]any)["sources"].([]src)
	slices.SortFunc(sources, func(a, b src) int { return strings.Compare(a["id"].(string), b["id"].(string)) })
	doc := `{"schema":"` + constraintengine.RulesSchemaRanged + `","revision":"1","policyId":"community-local","policyDigest":"` +
		digest(nil) + `","rules":[` + marshal(t, base) + `]}`
	_, err = constraintengine.ParseRuleSet([]byte(doc), registry)
	return err
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(marshal(t, v)), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEngineRejectsTheAdjacentCandidateAsWritten(t *testing.T) {
	f := newFixture(t, standard())
	base := rule("flag-removed", "1.4.1", "1.5.0", f.both())
	p := wantProposal(t, run(t, options(t, f.bare(), base)))
	candidate := asMap(t, p.Candidate)
	if err := candidateInEngine(t, base, candidate); err == nil {
		t.Fatal("the engine accepted the candidate as written")
	}
	// Even without the status field the unset boundary refuses it.
	delete(candidate, "reviewStatus")
	if err := candidateInEngine(t, base, candidate); err == nil {
		t.Fatal("the engine accepted an adjacent candidate without a release boundary")
	}
	// Control: once a reviewer sets the boundary, the same shape parses.
	for _, i := range []int{1, 2} {
		bound := candidate["bounds"].([]any)[i].(map[string]any)
		bound["basis"], bound["sourceId"] = constraintengine.BasisRemovedInRelease, "new-flags"
	}
	if err := candidateInEngine(t, base, candidate); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestNonAdjacentCandidateIsRefusedByItsStatusField(t *testing.T) {
	for name, target := range map[string]string{"skipped minor": "1.6", "new major": "2.0"} {
		t.Run(name, func(t *testing.T) {
			releases := standard()[:3]
			releases = append(releases, release{"v" + target + ".0", files{"flags.go": newCode}})
			f := newFixture(t, releases)
			base := rule("flag-removed", "1.4.1", target+".0", []src{
				f.source("old-flags", "v1.4.1", "flags.go", 3, 5), f.source("new-flags", "v"+target+".0", "flags.go", 3, 5)})
			p := wantProposal(t, run(t, options(t, f.bare(), base)))
			var bases []string
			for _, b := range p.Candidate.Bounds {
				bases = append(bases, b.Basis+":"+b.SourceID)
			}
			if strings.Join(bases, " ") != "UPGRADE_FROM_SERIES:old-flags UPGRADE_FROM_SERIES:old-flags TARGET_SERIES:new-flags TARGET_SERIES:new-flags" ||
				!strings.Contains(strings.Join(p.Flags, ","), "non-adjacent-lines") {
				t.Fatalf("bounds %v flags %v", bases, p.Flags)
			}
			candidate := asMap(t, p.Candidate)
			if err := candidateInEngine(t, base, candidate); err == nil {
				t.Fatal("the engine accepted the candidate as written")
			}
			delete(candidate, "reviewStatus")
			if err := candidateInEngine(t, base, candidate); err != nil {
				t.Fatalf("control: %v", err)
			}
		})
	}
}

func TestARuleWithoutSourcesIsRefused(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	empty := rule("empty", "1.4.1", "1.5.0", []src{})
	wantRefused(t, run(t, options(t, clone, empty)), CodeNoSources)
	omitted := rule("omitted", "1.4.1", "1.5.0", nil)
	delete(omitted["evidence"].(map[string]any), "sources")
	wantRefused(t, run(t, options(t, clone, omitted)), CodeNoSources)
}

func TestASideWithoutACountedSourceNeedsReview(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	notes := []src{f.source("old-notes", "v1.4.1", "CHANGELOG.md", 1, 1), f.source("new-notes", "v1.5.0", "CHANGELOG.md", 1, 1)}
	for name, tc := range map[string]struct {
		sources []src
		code    string
	}{
		"notes only":  {notes, ReasonNoCountedSource},
		"target only": {[]src{notes[0], f.both()[1]}, ReasonTargetOnly},
		"from only":   {[]src{f.both()[0], notes[1]}, ReasonFromOnly},
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, options(t, clone, rule("flag-removed", "1.4.1", "1.5.0", tc.sources)))
			v := wantReview(t, r, tc.code)
			out, err := Files(r)
			if err != nil {
				t.Fatal(err)
			}
			if v.Status != StatusNeedsReview || bytes.Contains(out[ReviewFile], []byte("candidateRange")) || bytes.Contains(out[ReviewFile], []byte(`"bounds"`)) {
				t.Fatalf("a review carries a range: %s", out[ReviewFile])
			}
		})
	}
}

func TestReleaseNotesAreListedAndDoNotCount(t *testing.T) {
	f := newFixture(t, with(standard(), "v1.5.1", "CHANGELOG.md", "- changed\n"))
	sources := append(f.both(), f.source("notes", "v1.5.0", "CHANGELOG.md", 1, 1),
		sourceAt("site-notes", "acme/website", strings.Repeat("a", 40), "release-notes/v1.5.md", "x\n", 1, 1))
	p := wantProposal(t, run(t, options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", sources))))
	if marshal(t, p.Listed) != `[{"citedSourceId":"notes","why":"release-notes"},{"citedSourceId":"site-notes","why":"release-notes"}]` {
		t.Fatalf("listed: %s", marshal(t, p.Listed))
	}
}

func TestAnUncheckableSourceSendsTheRuleToReview(t *testing.T) {
	releases := append(standard(), release{"v1.3.0", files{"flags.go": oldCode + "// 1.3\n"}},
		release{"v1.5.2-rc.1", files{"flags.go": newCode + "// rc\n"}})
	f := newFixture(t, releases)
	untaggedTree := files{"flags.go": newCode + "// untagged\n", "doc.md": "text\n"}
	untagged := f.commit("untagged", untaggedTree)
	clone := f.bare()
	for name, tc := range map[string]struct {
		extra src
		why   string
	}{
		"other repository":      {sourceAt("extra", "acme/other", strings.Repeat("a", 40), "main.go", "x\n", 1, 1), "other-repository"},
		"untagged":              {sourceAt("extra", "acme/demo", untagged, "flags.go", untaggedTree["flags.go"], 3, 5), "untagged-revision"},
		"untagged document":     {sourceAt("extra", "acme/demo", untagged, "doc.md", untaggedTree["doc.md"], 1, 1), "untagged-revision"},
		"pre-release revision":  {f.source("extra", "v1.5.2-rc.1", "flags.go", 3, 5), "untagged-revision"},
		"outside both lines":    {f.source("extra", "v1.3.0", "flags.go", 3, 5), "revision-outside-both-lines"},
		"notes look-alike code": {sourceAt("extra", "acme/demo", untagged, "flags.go", untaggedTree["flags.go"], 1, 1), "untagged-revision"},
	} {
		t.Run(name, func(t *testing.T) {
			v := wantReview(t, run(t, options(t, clone, rule("flag-removed", "1.4.1", "1.5.0", append(f.both(), tc.extra)))), ReasonUncheckedSource)
			if len(v.Listed) != 1 || v.Listed[0].Why != tc.why {
				t.Fatalf("listed: %+v", v.Listed)
			}
		})
	}
}

func TestReleaseNoteClassificationIsClosed(t *testing.T) {
	for path, want := range map[string]bool{
		"CHANGELOG.md": true, "CHANGELOG-1.24.md": true, "docs/CHANGES.rst": true, "NEWS": true, "HISTORY.txt": true,
		"changelogs/current.yaml": false, "changelogs/1.2.md": true, "release-notes/v1.md": true, "site/releasenotes/a.adoc": true,
		"pkg/changelog/changelog.go": false, "changelog.go": false, "history.py": false, "release-notes.yaml": false,
		"docs/upgrade.md": false, "notes/v1.md": false, "changes/config.md": false, "newsfeed.md": false, "release-notes": true,
		"cmd/history/main.go": false,
	} {
		if got := isReleaseNotes(path); got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
}

func TestAnythingButTheSameFileAtEveryTagNeedsReview(t *testing.T) {
	span := "func flags() {\n\treject(\"--legacy\")\n}\n"
	for name, tc := range map[string]struct{ content, result string }{
		"differing":                {oldCode, resultDiffers},
		"commented out mid-line":   {"package demo\n\n// func flags() {\n\treject(\"--legacy\")\n}\n", resultDiffers},
		"suffix on the first line": {"package demo\n\nfunc flags() { // off\n\treject(\"--legacy\")\n}\n", resultDiffers},
		"no final newline":         {strings.TrimSuffix(newCode, "\n"), resultDiffers},
		"carriage returns":         {strings.ReplaceAll(newCode, "\n", "\r\n"), resultDiffers},
		"moved":                    {"// moved\n" + newCode, resultMoved},
		"file changed elsewhere":   {newCode + "// more\n", resultFileChanged},
		"duplicated":               {newCode + span, resultAmbiguous},
		"duplicated and moved":     {"/*\n" + span + "*/\n" + span, resultAmbiguous},
		"absent":                   {"", resultAbsent},
		"symlink":                  {"->other.go", fileNotRegular},
		"binary":                   {newCode + "\x00", fileBinary},
		"lfs pointer":              {"version https://git-lfs.github.com/spec/v1\noid sha256:0\n", filePointer},
		"too large":                {newCode + strings.Repeat("x\n", maxFileBytes/2), fileTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			// The differing tag sits in the middle of the line.
			releases := append(standard(), release{"v1.5.2", files{"flags.go": newCode}})
			f := newFixture(t, with(releases, "v1.5.1", "flags.go", tc.content))
			v := wantReview(t, run(t, options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", f.both()))), ReasonSpanNotStable)
			if len(v.Reasons) != 1 || v.Reasons[0].Side != sideTo || !strings.Contains(v.Reasons[0].Detail, "v1.5.1: "+tc.result) {
				t.Fatalf("reasons: %+v", v.Reasons)
			}
			if seen := v.Sources[1].Observations; len(seen) != 3 || seen[0].Result != resultSameFile || seen[1].Result != tc.result ||
				seen[2].Result != resultSameFile || v.Sources[1].Highest != nil {
				t.Fatalf("observations: %+v", seen)
			}
		})
	}
}

func TestASpanRepeatedInTheCitedFileIsAmbiguous(t *testing.T) {
	twice := newCode + "\nfunc flags() {\n\treject(\"--legacy\")\n}\n"
	releases := with(with(standard(), "v1.5.0", "flags.go", twice), "v1.5.1", "flags.go", twice)
	f := newFixture(t, releases)
	v := wantReview(t, run(t, options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", f.both()))), ReasonSpanNotStable)
	if v.Sources[1].Observations[0].Result != resultAmbiguous {
		t.Fatalf("observations: %+v", v.Sources[1].Observations)
	}
}

func TestEveryCountedSourceOfASideMustBeStable(t *testing.T) {
	releases := with(with(standard(), "v1.5.0", "extra.go", "a\n"), "v1.5.1", "extra.go", "b\n")
	f := newFixture(t, releases)
	sources := append(f.both(), f.source("extra", "v1.5.0", "extra.go", 1, 1))
	wantReview(t, run(t, options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", sources))), ReasonSpanNotStable)
}

func TestOccurrencesCountsOverlaps(t *testing.T) {
	if got := occurrences([]byte("a\na\na\n"), splitLines([]byte("a\na\n"))); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestTheCitedReferenceIsVerified(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	change := func(key string, value any) []src {
		s := f.both()
		s[1][key] = value
		return s
	}
	commit := f.commits["v1.5.0"]
	moved := f.both()
	moved[1]["url"] = "https://github.com/acme/demo/blob/" + f.commits["v1.5.1"] + "/flags.go"
	gone := f.both()
	gone[1] = sourceAt("new-flags", "acme/demo", commit, "gone.go", newCode, 3, 5)
	unknown := f.both()
	unknown[1] = sourceAt("new-flags", "acme/demo", strings.Repeat("b", 40), "flags.go", newCode, 3, 5)
	repeated := f.both()
	repeated[1]["id"] = "old-flags"
	for name, tc := range map[string]struct {
		sources []src
		code    string
	}{
		"digest":               {change("contentDigest", digest([]byte("other"))), CodeSourceDigest},
		"no digest":            {change("contentDigest", ""), CodeSourceDigest},
		"start below one":      {change("startLine", 0), CodeSourceInvalid},
		"end before start":     {change("endLine", 2), CodeSourceInvalid},
		"end past the file":    {change("endLine", 6), CodeSourceInvalid},
		"path not at revision": {gone, CodeSourceInvalid},
		"repeated id":          {repeated, CodeSourceInvalid},
		"url commit differs":   {moved, CodeSourceURL},
		"url not pinned":       {change("url", "https://github.com/acme/demo/blob/main/flags.go"), CodeSourceURL},
		"revision missing":     {unknown, CodeObjectMissing},
	} {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, run(t, options(t, clone, rule("flag-removed", "1.4.1", "1.5.0", tc.sources))), tc.code)
		})
	}
}

func TestSourceURLForms(t *testing.T) {
	c := strings.Repeat("c", 40)
	for _, good := range []string{"https://github.com/o/r/blob/" + c + "/a/b.go", "https://raw.githubusercontent.com/o/r/" + c + "/a/b.go"} {
		if loc, ok := parseSourceURL(good); !ok || loc.repo != "o/r" || loc.commit != c || loc.path != "a/b.go" {
			t.Errorf("%s: %+v %v", good, loc, ok)
		}
	}
	base := "https://github.com/o/r/blob/" + c + "/"
	for _, bad := range []string{
		base + "a.go?x=1", base + "a.go#L1", base + "%2e%2e/a.go", base + "../a.go", base + "./a.go", base + "a//b.go", base,
		base + "a\n.go", base + "a‮.go", base + "a b.go", base + `a\b.go`,
		"http://github.com/o/r/blob/" + c + "/a.go", "https://example.com/o/r/blob/" + c + "/a.go",
		"https://github.com/o/r/tree/" + c + "/a.go", "https://github.com/o/r/blob/v1.0.0/a.go",
		"https://raw.githubusercontent.com/o/r/main/a.go",
	} {
		if loc, ok := parseSourceURL(bad); ok {
			t.Errorf("accepted %q: %+v", bad, loc)
		}
	}
}

func TestAnchorsAndShapes(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	crossing := rule("x", "1.4.1", "1.5.0", f.both())
	crossing["crossing"] = map[string]any{"at": "1.5.0"}
	chart := rule("x", "1.4.1", "1.5.0", f.both())
	chart["subject"].(map[string]any)["chart"] = map[string]any{"name": "demo"}
	for name, tc := range map[string]struct {
		rule map[string]any
		code string
	}{
		"same line":    {rule("x", "1.5.0", "1.5.1", f.both()), CodeNotLineUpgrade},
		"downgrade":    {rule("x", "1.5.0", "1.4.1", f.both()), CodeNotLineUpgrade},
		"pre-release":  {rule("x", "1.4.1", "1.5.0-rc.1", f.both()), CodeAnchorNotRelease},
		"two parts":    {rule("x", "1.4", "1.5.0", f.both()), CodeAnchorNotRelease},
		"crossing":     {crossing, CodeUnsupportedShape},
		"chart":        {chart, CodeUnsupportedShape},
		"empty line":   {rule("x", "1.4.1", "1.6.0", f.both()), CodeNoReleaseTags},
		"anchor above": {rule("x", "1.4.7", "1.5.0", f.both()), CodeAnchorTagMissing},
	} {
		t.Run(name, func(t *testing.T) {
			wantRefused(t, run(t, options(t, clone, tc.rule)), tc.code)
		})
	}
	o := options(t, clone, rule("x", "1.4.1", "1.5.0", f.both()))
	o.Config = Config{Projects: map[string]Project{"another": o.Config.Projects["demo"]}}
	wantRefused(t, run(t, o), CodeRepoNotProvided)
}

func TestRangedAndInactiveRulesAreNotCandidates(t *testing.T) {
	f := newFixture(t, standard())
	ranged := rule("ranged", "1.4.1", "1.5.0", f.both())
	ranged["range"] = map[string]any{"from": map[string]any{"gte": "1.4.1", "lt": "1.4.2"}, "to": map[string]any{"gte": "1.5.0", "lt": "1.5.1"}}
	ranged["condition"].(map[string]any)["factId"] = "component.demo.other"
	withdrawn := rule("withdrawn", "1.4.1", "1.5.0", f.both())
	withdrawn["evidence"].(map[string]any)["state"] = "withdrawn"
	r := run(t, options(t, f.bare(), ranged, withdrawn))
	if len(r.Proposals)+len(r.NeedsReview)+len(r.Refused) != 0 || r.AlreadyRanged != 1 || r.NotActive != 1 {
		t.Fatalf("report: %s", marshal(t, r))
	}
}

func TestSameKeyOverlapIsRefused(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	a := rule("a", "1.4.1", "1.5.0", f.both())
	sibling := rule("b", "1.4.2", "1.5.1", f.both())
	r := run(t, options(t, clone, a, sibling))
	if len(r.Proposals) != 0 || len(r.Refused) != 2 || r.Refused[0].Code != CodeOverlap || r.Refused[1].Code != CodeOverlap {
		t.Fatalf("two colliding candidates: %s", marshal(t, r))
	}
	// An exact rule the tool cannot widen still occupies its anchor.
	exact := rule("b", "1.4.2", "1.5.1", []src{f.source("n", "v1.4.1", "CHANGELOG.md", 1, 1)})
	r = run(t, options(t, clone, a, exact))
	if len(r.Proposals) != 0 || len(r.Refused) != 1 || r.Refused[0].Code != CodeOverlap || len(r.NeedsReview) != 1 {
		t.Fatalf("collision with an exact rule: %s", marshal(t, r))
	}
	ranged := rule("b", "1.4.2", "1.5.1", f.both())
	ranged["range"] = map[string]any{"from": map[string]any{"gte": "1.4.2", "lt": "1.5.0"}, "to": map[string]any{"gte": "1.5.1", "lt": "1.6.0"}}
	wantRefused(t, run(t, options(t, clone, a, ranged)), CodeOverlap)
	// Another fact, or disjoint set members, constrain something else.
	other := rule("b", "1.4.2", "1.5.1", f.both())
	other["condition"].(map[string]any)["factId"] = "component.demo.other"
	if r = run(t, options(t, clone, a, other)); len(r.Proposals) != 2 {
		t.Fatalf("different facts: %s", marshal(t, r))
	}
	set := func(id, member string) map[string]any {
		s := rule(id, "1.4.1", "1.5.0", f.both())
		delete(s, "condition")
		s["operator"] = "forbid_set_member"
		s["setCondition"] = map[string]any{"side": "proposed", "component": testComponent, "factId": testFact, "members": []string{member}}
		return s
	}
	if r = run(t, options(t, clone, set("a", "x"), set("b", "y"))); len(r.Proposals) != 2 {
		t.Fatalf("disjoint members: %s", marshal(t, r))
	}
	if r = run(t, options(t, clone, set("a", "x"), set("b", "x"))); len(r.Proposals) != 0 || len(r.Refused) != 2 {
		t.Fatalf("shared member: %s", marshal(t, r))
	}
}

// keys collects every object key of a JSON document.
func keys(v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			into[k] = true
			keys(child, into)
		}
	case []any:
		for _, child := range x {
			keys(child, into)
		}
	}
}

func TestOutputIsNotPackShapedAndIsReproducible(t *testing.T) {
	f := newFixture(t, standard())
	o := options(t, f.bare(), rule("flag-removed", "1.4.1", "1.5.0", f.both()))
	first, err := Files(run(t, o))
	if err != nil {
		t.Fatal(err)
	}
	// A second clone at another path gives the same bytes.
	o.Config = config(f.bare())
	second, err := Files(run(t, o))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ProposalsFile, ReviewFile, SummaryFile} {
		if len(first[name]) == 0 || !bytes.Equal(first[name], second[name]) {
			t.Fatalf("%s differs between runs:\n%s\n%s", name, first[name], second[name])
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(first[ProposalsFile], &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema"] != CandidatesSchema || doc["status"] != StatusUnreviewed || doc["disclaimer"] != Disclaimer {
		t.Fatalf("header: %v", doc)
	}
	binding := doc["binding"].(map[string]any)
	if binding["rulesCommit"] != o.RulesCommit || binding["rulesFileDigest"] == "" || binding["toolRevision"] != "test" {
		t.Fatalf("binding: %v", binding)
	}
	all := map[string]bool{}
	keys(doc, all)
	for _, forbidden := range []string{"range", "rule", "rules", "entries", "evidence", "state", "reviewedAt", "validUntil", "sources",
		"url", "revision", "contentDigest", "startLine", "endLine"} {
		if all[forbidden] {
			t.Errorf("the output has the pack key %q", forbidden)
		}
	}
	if !bytes.Contains(first[SummaryFile], []byte("span-stable only; behaviour, absence of reintroduction and decision impact not checked")) {
		t.Fatalf("summary: %s", first[SummaryFile])
	}
}

func TestSummaryHasNoControlCharacters(t *testing.T) {
	s := Summary(Report{Refused: []Refused{{RuleID: "a\x1b[2J\nunreviewed-proposal b", Status: StatusRefused, Code: CodeGit, Detail: "x\r‮y"}}})
	if strings.ContainsAny(s, "\x1b\r‮") || strings.Contains(s, "\nunreviewed-proposal b") {
		t.Fatalf("summary: %q", s)
	}
}

func TestGapListOrdersAndIsStrict(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	var rules []map[string]any
	for _, id := range []string{"c", "a", "b"} {
		r := rule(id, "1.4.1", "1.5.0", f.both())
		r["condition"].(map[string]any)["factId"] = "component.demo." + id
		rules = append(rules, r)
	}
	o := options(t, clone, rules...)
	gaps, err := ParseGaps([]byte("# order\n\nc\n"))
	if err != nil {
		t.Fatal(err)
	}
	o.Gaps = gaps
	r := run(t, o)
	if len(r.Proposals) != 3 || r.Proposals[0].RuleID != "c" || r.Proposals[1].RuleID != "a" || r.Proposals[2].RuleID != "b" {
		t.Fatalf("order: %s", marshal(t, r))
	}
	o.Gaps = []string{"nothing"}
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("an unknown gap id was accepted")
	}
	if _, err := ParseGaps([]byte("a\na\n")); err == nil {
		t.Fatal("a repeated gap id was accepted")
	}
}

func TestInputsAreStrict(t *testing.T) {
	f := newFixture(t, standard())
	clone := f.bare()
	good := packJSON(t, rule("a", "1.4.1", "1.5.0", f.both()))
	for name, pack := range map[string]string{
		"duplicate key":    strings.Replace(good, `"id":"a"`, `"id":"a","id":"a"`, 1),
		"case variant key": strings.Replace(good, `"id":"a"`, `"ID":"z","id":"a"`, 1),
		"trailing data":    good + "{}",
		"duplicate rule":   packJSON(t, rule("a", "1.4.1", "1.5.0", f.both()), rule("a", "1.4.1", "1.5.0", f.both())),
		"no entries":       `{"entries":[]}`,
		"rule id":          packJSON(t, rule("a\nb", "1.4.1", "1.5.0", f.both())),
	} {
		repo, commit := rulesRepo(t, pack)
		if _, err := Run(context.Background(), Options{RulesRepo: repo, RulesCommit: commit, Config: config(clone)}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	repo, commit := rulesRepo(t, good)
	for _, bad := range []string{"HEAD", commit[:12], strings.Repeat("0", 40)} {
		if _, err := Run(context.Background(), Options{RulesRepo: repo, RulesCommit: bad, Config: config(clone)}); err == nil {
			t.Errorf("commit %q accepted", bad)
		}
	}
	sha := strings.Repeat("a", 40)
	entry := `{"projects":{"demo":{"repo":"acme/demo","path":"/x","tagPrefix":"v","tags":[{"tag":"v1.4.0","commit":"` + sha + `"}]}}}`
	if _, err := DecodeConfig([]byte(entry)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, raw := range map[string]string{
		"duplicate project": `{"projects":{"demo":{"repo":"a/b","path":"/x"},"demo":{"repo":"a/c","path":"/x"}}}`,
		"duplicate field":   strings.Replace(entry, `"path":"/x"`, `"path":"/x","path":"/y"`, 1),
		"unknown field":     strings.Replace(entry, `"path":"/x"`, `"path":"/x","ignoreTags":[]`, 1),
		"trailing":          entry + "[]",
		"short commit":      strings.Replace(entry, sha, "abc", 1),
		"pre-release tag":   strings.Replace(entry, "v1.4.0", "v1.4.0-rc.1", 1),
		"other prefix":      strings.Replace(entry, "v1.4.0", "1.4.0", 1),
		"repeated tag":      strings.Replace(entry, `[{`, `[{"tag":"v1.4.0","commit":"`+sha+`"},{`, 1),
		"repo form":         strings.Replace(entry, "acme/demo", "https://github.com/acme/demo", 1),
		"empty":             `{"projects":{}}`,
	} {
		if _, err := DecodeConfig([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
