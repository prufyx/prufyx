// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// ---------------------------------------------------------------------
// Fixture: rules whose cited span of a.go only moved
// ---------------------------------------------------------------------

func movedLines() []string {
	lines := make([]string, 0, 40)
	for i := 1; i <= 40; i++ {
		lines = append(lines, fmt.Sprintf("context line %02d keeps its text", i))
	}
	lines[9], lines[10], lines[11] = "    if opts.Mode == \"strict\" {", "        return errStrictMode", "    }"
	lines[19], lines[20], lines[21] = "    if opts.Retry > limit {", "        return errTooManyRetries", "    }"
	return lines
}

func movedJoin(lines []string) []byte { return []byte(strings.Join(lines, "\n")) }

func movedPrepend(n int, lines []string) []string {
	out := make([]string, 0, n+len(lines))
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("added line %d", i))
	}
	return append(out, lines...)
}

// extraSource is a second cited span of the same file in every rule.
type extraSource struct {
	start, end int
	class      string
	to         *evidencerepin.MovedTo
}

type movedFix struct {
	t        *testing.T
	ids      []string
	oldLines []string
	newLines []string
	newStart int
	extra    []extraSource
	pad      int

	packPath         string
	oldData, newData []byte
	wl               evidencerepin.Worklist
	pack             []byte
	blobs            map[string][]byte
}

var movedCommit = strings.Repeat("c", 40)

func newMovedFix(t *testing.T, ids ...string) *movedFix {
	return &movedFix{t: t, ids: ids, oldLines: movedLines(), newLines: movedPrepend(5, movedLines()), newStart: 15, pad: 40, packPath: "/p/rules.json"}
}

func (f *movedFix) newTo() *evidencerepin.MovedTo {
	return &evidencerepin.MovedTo{Commit: movedCommit, Path: "a.go", StartLine: f.newStart, EndLine: f.newStart + 2, ContentDigest: sourcecorpus.SHA(f.newData)}
}

// build assembles the pack, the worklist and the retained files. Tests change
// the fixture before it, or f.wl and f.blobs after it.
func (f *movedFix) build() *movedFix {
	f.t.Helper()
	f.oldData, f.newData = movedJoin(f.oldLines), movedJoin(f.newLines)
	oldDigest := sourcecorpus.SHA(f.oldData)
	specs := make([]ruleSpec, 0, len(f.ids))
	for _, id := range f.ids {
		spec := freshSpec(id, "proj-"+id, baseNow)
		spec.path = "a.go"
		specs = append(specs, spec)
	}
	wl, _ := buildWorklistAndPack(f.t, f.packPath, baseNow, specs)
	var entries []map[string]any
	var citations []evidencerepin.ClassResult
	wl.Lines = nil
	for i, spec := range specs {
		repo := "repo-" + spec.id
		sources := []map[string]any{testSource(spec.id+"-src", "owner", repo, spec.commit, "a.go", oldDigest, 10, 12)}
		base := wl.Citations[i]
		main := base
		main.Class, main.OldStart, main.OldEnd, main.NewStart, main.NewEnd = evidencerepin.ClassSpanMoved, 10, 12, f.newStart, f.newStart+2
		main.OldDigest = oldDigest
		main.NewCommit, main.MovedTo = movedCommit, f.newTo()
		citations = append(citations, main)
		for n, extra := range f.extra {
			id := fmt.Sprintf("%s-src-x%d", spec.id, n)
			sources = append(sources, testSource(id, "owner", repo, spec.commit, "a.go", oldDigest, extra.start, extra.end))
			c := base
			c.SourceID, c.Class, c.OldStart, c.OldEnd, c.NewCommit, c.MovedTo = id, extra.class, extra.start, extra.end, movedCommit, extra.to
			c.OldDigest = oldDigest
			if extra.to != nil {
				c.NewStart, c.NewEnd = extra.to.StartLine, extra.to.EndLine
			}
			citations = append(citations, c)
		}
		entries = append(entries, testEntry(spec.project, testRule(spec.id, "active", spec.reviewedAt, spec.validUntil, false, sources...)))
		wl.Lines = append(wl.Lines, evidencerepin.LineResolution{
			Owner: "owner", Repo: repo, Prefix: "v", Line: "0.9", Status: "RESOLVED", Tag: "v0.9.4", Commit: movedCommit,
			ResolvedAt: rfc3339(baseNow.Add(-time.Hour)),
		})
	}
	for i := range citations {
		c := &citations[i]
		c.NewCommit = movedCommit
		c.Baseline, c.BaselineMode = evidencerepin.BaselineReleaseLine, evidencerepin.BaselineModeReleaseLine
		c.BaselineLine, c.PinnedTag, c.BaselineTag, c.LineStatus = "0.9", "v0.9.0", "v0.9.4", evidencerepin.LineStatusLaterReleases
	}
	wl.Citations = citations
	f.wl = wl
	f.pack = padPackWithSpreadRules(f.t, testPack(f.t, entries...), f.pad)
	f.blobs = map[string][]byte{oldDigest: f.oldData, sourcecorpus.SHA(f.newData): f.newData}
	return f
}

func (f *movedFix) options() PrepareOptions {
	return PrepareOptions{
		WorklistRaw: marshalWorklist(f.t, f.wl), PackName: PackCNCF, PackPath: f.packPath, PackRaw: f.pack,
		Wave: 1, AttestedAt: baseNow, Now: baseNow, NextRevision: "rev-2", EngineCapabilityDigest: testEngineCapabilityDigest,
		Chain: &Chain{}, MovedBlobs: f.blobs,
	}
}

// prepareOnly prepares without a sample review (enough to read eligibility).
func (f *movedFix) prepareOnly() PrepareResult {
	f.t.Helper()
	res, err := Prepare(f.options())
	if err != nil {
		f.t.Fatalf("Prepare: %v", err)
	}
	return res
}

func (f *movedFix) prepareSampled() (PrepareResult, PrepareOptions) {
	f.t.Helper()
	opts := withSampleRecords(f.t, f.options())
	res, err := Prepare(opts)
	if err != nil {
		f.t.Fatalf("Prepare: %v", err)
	}
	return res, opts
}

func (f *movedFix) verifyOptions(res PrepareResult, opts PrepareOptions) VerifyOptions {
	v := defaultVerifyOptions(f.t, baseNow)
	v.StatementRaw, v.PriorPackRaw, v.NextPackRaw = res.StatementCanonical, f.pack, res.NextPack
	v.WorklistRaw, v.IndependentWorklistRaw = opts.WorklistRaw, opts.WorklistRaw
	v.PackName, v.PackPath, v.EngineCapabilityDigest = PackCNCF, f.packPath, testEngineCapabilityDigest
	v.ReviewRecords, v.MovedBlobs = opts.ReviewRecords, f.blobs
	return v
}

func notExtendedReason(res PrepareResult, id string) string {
	for _, ne := range res.Statement.NotExtended {
		if ne.RuleID == id {
			return ne.WorstClass
		}
	}
	return ""
}

func assertNotRenewed(t *testing.T, name string, res PrepareResult, id, reason string) {
	t.Helper()
	if len(res.Statement.Rules) != 0 || notExtendedReason(res, id) != reason {
		t.Errorf("%s: want %s not renewed with %q, got rules=%d notExtended=%+v", name, id, reason, len(res.Statement.Rules), res.Statement.NotExtended)
	}
}

// ---------------------------------------------------------------------
// Rev 1.0 list
// ---------------------------------------------------------------------

// A unique moved span makes its rule eligible; the statement carries the move
// and the next pack differs from the prior one only in the listed fields.
func TestMovedUniqueSpanIsEligibleAndRewritesOnlyTheListedFields(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, opts := f.prepareSampled()
	if len(res.Statement.Rules) != 1 {
		t.Fatalf("a unique moved span must be eligible: %+v", res.Statement.NotExtended)
	}
	row := res.Statement.Rules[0].Citations[0]
	want := MovedAttestation{
		Path: "a.go", OldStartLine: 10, OldEndLine: 12, NewStartLine: 15, NewEndLine: 17,
		OldContentDigest: sourcecorpus.SHA(f.oldData), NewContentDigest: sourcecorpus.SHA(f.newData),
	}
	if row.Class != evidencerepin.ClassSpanMoved || row.Moved == nil || *row.Moved != want || row.ComparedCommit != movedCommit {
		t.Fatalf("the statement must carry the move: %+v", row)
	}
	if res.Statement.Statement != MovedStatementText(res.Statement.Worklist.GeneratedAt, res.Statement.ValidUntil) {
		t.Fatal("a statement with a moved citation carries the moved text")
	}
	if summary := string(res.Summary); !strings.Contains(summary, "moved citations") || !strings.Contains(summary, "a.go lines 10-12 -> 15-17 at "+movedCommit) {
		t.Fatalf("the summary a human reads must list the move:\n%s", summary)
	}
	diff := outsideAllowed(t, f.pack, res.NextPack, "rule-a")
	if diff != "" {
		t.Fatalf("the next pack differs outside the moved fields and the dates: %s", diff)
	}
	next := ruleGeneric(t, res.NextPack, "rule-a")
	source := next["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)
	if source["revision"] != movedCommit || source["url"] != "https://github.com/owner/repo-rule-a/blob/"+movedCommit+"/a.go" ||
		source["contentDigest"] != sourcecorpus.SHA(f.newData) || fmt.Sprint(source["startLine"]) != "15" || fmt.Sprint(source["endLine"]) != "17" {
		t.Fatalf("the moved source is not rewritten: %+v", source)
	}
	if _, err := Verify(f.verifyOptions(res, opts)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func ruleGeneric(t *testing.T, packRaw []byte, id string) map[string]any {
	t.Helper()
	var doc struct {
		Entries []struct {
			Rule map[string]any `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(packRaw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc.Entries {
		if e.Rule["id"] == id {
			return e.Rule
		}
	}
	t.Fatalf("rule %s not in pack", id)
	return nil
}

// outsideAllowed substitutes, in the prior rule, exactly the fields a moved
// renewal may change and returns "" when nothing else differs from the next.
func outsideAllowed(t *testing.T, prior, next []byte, id string) string {
	t.Helper()
	p, n := ruleGeneric(t, prior, id), ruleGeneric(t, next, id)
	pe, ne := p["evidence"].(map[string]any), n["evidence"].(map[string]any)
	for _, k := range []string{"reviewedAt", "validUntil"} {
		pe[k] = ne[k]
	}
	ps, ns := pe["sources"].([]any), ne["sources"].([]any)
	for i := range ps {
		pm, nm := ps[i].(map[string]any), ns[i].(map[string]any)
		if pm["revision"] != nm["revision"] {
			for _, k := range []string{"revision", "url", "contentDigest", "startLine", "endLine"} {
				pm[k] = nm[k]
			}
		}
	}
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(n)
	if string(a) != string(b) {
		return string(a) + " != " + string(b)
	}
	return ""
}

func TestMovedTwoOccurrencesNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.newLines = append(movedPrepend(5, movedLines()), movedLines()[9:12]...)
	res := f.build().prepareOnly()
	assertNotRenewed(t, "two occurrences", res, "rule-a", reasonMovedUnverified)
}

func TestMovedPartialOrShiftedBytesNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.newLines = movedPrepend(5, movedLines())
	f.newLines[16] = "        return errStrictModeChanged"
	// The worklist still claims the move; the bytes do not back it.
	res := f.build().prepareOnly()
	assertNotRenewed(t, "partial bytes", res, "rule-a", reasonMovedUnverified)
}

func TestMovedPlusContentChangedInOneRuleNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.extra = []extraSource{{start: 30, end: 31, class: evidencerepin.ClassContentChanged}}
	res := f.build().prepareOnly()
	assertNotRenewed(t, "moved + content changed", res, "rule-a", evidencerepin.ClassContentChanged)
}

func TestMovedVerifyRefusesAStatementWhoseMovedDigestOrUniquenessDoesNotRecompute(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, opts := f.prepareSampled()
	statement, err := ParseStatement(res.StatementCanonical)
	if err != nil {
		t.Fatal(err)
	}
	statement.Rules[0].Citations[0].Moved.NewContentDigest = "sha256:" + strings.Repeat("9", 64)
	tampered, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	v := f.verifyOptions(res, opts)
	v.StatementRaw = tampered
	assertVerifyRejects(t, v, "V3:")

	// A second occurrence added to the new file after the statement was made:
	// the retained bytes no longer make the span unique.
	g := newMovedFix(t, "rule-a").build()
	res2, opts2 := g.prepareSampled()
	dup := movedJoin(append(movedPrepend(5, movedLines()), movedLines()[9:12]...))
	v2 := g.verifyOptions(res2, opts2)
	v2.MovedBlobs = map[string][]byte{sourcecorpus.SHA(g.oldData): g.oldData, sourcecorpus.SHA(g.newData): dup}
	assertVerifyRejects(t, v2, "V3:")
}

// A move holds only for the record it was classified from: a worklist digest
// or span the pack source does not record is not renewed.
func TestMovedCitationOfAnotherRecordNotEligible(t *testing.T) {
	for name, tc := range map[string]struct {
		edit   func(c *evidencerepin.ClassResult)
		reason string
	}{
		"no digest":    {func(c *evidencerepin.ClassResult) { c.OldDigest = "" }, reasonCitationRecordMismatch},
		"other digest": {func(c *evidencerepin.ClassResult) { c.OldDigest = "sha256:" + strings.Repeat("9", 64) }, reasonCitationRecordMismatch},
		// The moved guard runs first and already refuses another span.
		"other span": {func(c *evidencerepin.ClassResult) { c.OldStart, c.OldEnd = 20, 22 }, reasonMovedUnverified},
	} {
		f := newMovedFix(t, "rule-a").build()
		tc.edit(&f.wl.Citations[0])
		assertNotRenewed(t, name, f.prepareOnly(), "rule-a", tc.reason)
	}
}

// ---------------------------------------------------------------------
// Amendment guards
// ---------------------------------------------------------------------

// A1 context
func TestMovedContextMismatchNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.newLines = movedPrepend(5, movedLines())
	f.newLines[13] = "context line 09 was rewritten"
	assertNotRenewed(t, "context", f.build().prepareOnly(), "rule-a", reasonMovedUnverified)
}

// A1 shift
func TestMovedShiftOverTwoHundredNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.newLines, f.newStart = movedPrepend(201, movedLines()), 211
	assertNotRenewed(t, "shift", f.build().prepareOnly(), "rule-a", reasonMovedUnverified)
}

// A1 order: another span of the same file, unmoved, was after this one and is
// now before it.
func TestMovedOrderSwapNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	base := movedLines()
	// The first span, with its context, now sits after the second span.
	f.newLines = append(append(append(append([]string{}, base[:6]...), base[15:27]...), base[6:15]...), base[27:]...)
	f.newStart = 22
	f.extra = []extraSource{{start: 20, end: 22, class: evidencerepin.ClassSpanIdentical}}
	assertNotRenewed(t, "order swap", f.build().prepareOnly(), "rule-a", reasonMovedUnverified)

	// Control: the same file with the second span also moving along keeps
	// the order and is eligible.
	g := newMovedFix(t, "rule-a")
	g.extra = []extraSource{{start: 20, end: 22, class: evidencerepin.ClassSpanIdentical}}
	g.newLines = movedPrepend(5, movedLines())
	// The unmoved claim is wrong for a shifted file but keeps the order only
	// when the first span stays before it: it is at 15-17, before 20.
	if res := g.build().prepareOnly(); len(res.Statement.Rules) != 1 {
		t.Fatalf("an unswapped order must stay eligible: %+v", res.Statement.NotExtended)
	}
}

// A1 comment
func TestMovedIntoACommentNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.newLines = movedPrepend(5, movedLines())
	f.newLines[2] = "/* disabled for now"
	assertNotRenewed(t, "comment", f.build().prepareOnly(), "rule-a", reasonMovedUnverified)
}

// A2 two byte occurrences
func TestMovedSecondByteOccurrenceNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.newLines = append(movedPrepend(5, movedLines()), "x    if opts.Mode == \"strict\" {\n        return errStrictMode\n    }")
	assertNotRenewed(t, "byte occurrence", f.build().prepareOnly(), "rule-a", reasonMovedUnverified)
}

// A2 minimum size
func TestMovedShortSpanNotEligible(t *testing.T) {
	f := newMovedFix(t, "rule-a")
	f.oldLines = movedLines()
	f.oldLines[9], f.oldLines[10] = "x := 1", "y := 2" // 19 bytes with the closing brace
	f.newLines = movedPrepend(5, f.oldLines)
	res := f.build()
	assertNotRenewed(t, "short span", res.prepareOnly(), "rule-a", reasonMovedUnverified)
}

// A3 line head
func TestMovedNotOnTheLineHeadNotEligible(t *testing.T) {
	cases := map[string]func(f *movedFix){
		"movedTo names another commit": func(f *movedFix) { f.wl.Citations[0].MovedTo.Commit = strings.Repeat("d", 40) },
		"line record names another commit": func(f *movedFix) {
			f.wl.Lines[0].Commit = strings.Repeat("d", 40)
		},
		"latest baseline": func(f *movedFix) {
			f.wl.Citations[0].Baseline, f.wl.Citations[0].BaselineLine, f.wl.Citations[0].PinnedTag = evidencerepin.BaselineLatest, "", ""
		},
		"pinned is the line head": func(f *movedFix) { f.wl.Citations[0].LineStatus = evidencerepin.LineStatusPinnedIsLatest },
		"movedTo path changed":    func(f *movedFix) { f.wl.Citations[0].MovedTo.Path = "other/a.go" },
		"movedTo digest wrong": func(f *movedFix) {
			f.wl.Citations[0].MovedTo.ContentDigest = "sha256:" + strings.Repeat("8", 64)
		},
		"movedTo range differs from the citation": func(f *movedFix) { f.wl.Citations[0].NewStart = 16 },
	}
	for name, mutate := range cases {
		f := newMovedFix(t, "rule-a").build()
		mutate(f)
		res := f.prepareOnly()
		if len(res.Statement.Rules) != 0 {
			t.Errorf("%s: a move off the line head or off its record must not be eligible", name)
		}
	}
	// Control.
	if res := newMovedFix(t, "rule-a").build().prepareOnly(); len(res.Statement.Rules) != 1 {
		t.Fatalf("control: %+v", res.Statement.NotExtended)
	}
}

func TestMovedRefusesWithoutRetainedFiles(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	f.blobs = nil
	assertNotRenewed(t, "no files", f.prepareOnly(), "rule-a", reasonMovedUnverified)
	g := newMovedFix(t, "rule-a").build()
	delete(g.blobs, sourcecorpus.SHA(g.newData))
	assertNotRenewed(t, "no new file", g.prepareOnly(), "rule-a", reasonMovedUnverified)
	h := newMovedFix(t, "rule-a").build()
	delete(h.blobs, sourcecorpus.SHA(h.oldData))
	assertNotRenewed(t, "no old file", h.prepareOnly(), "rule-a", reasonMovedUnverified)
}

// A4 field tampering
func TestMovedVerifyRefusesAnExtraFieldChangeAndAWrongURL(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, opts := f.prepareSampled()
	for _, mutate := range map[string]func(rule map[string]any){
		"claim byte": func(rule map[string]any) { rule["reasonCode"] = "TAMPERED" },
		"wrong url": func(rule map[string]any) {
			setSourceField(rule, "url", "https://github.com/owner/repo-rule-a/blob/"+strings.Repeat("e", 40)+"/a.go")
		},
		"wrong digest": func(rule map[string]any) { setSourceField(rule, "contentDigest", "sha256:"+strings.Repeat("7", 64)) },
		"wrong lines":  func(rule map[string]any) { setSourceField(rule, "startLine", json.Number("16")) },
	} {
		tampered := tamperRule(t, res.NextPack, "rule-a", mutate)
		v := f.verifyOptions(res, opts)
		v.NextPackRaw = tampered
		assertVerifyRejects(t, v, "V1:")
	}
}

func setSourceField(rule map[string]any, key string, value any) {
	rule["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)[key] = value
}

func tamperRule(t *testing.T, packRaw []byte, id string, mutate func(rule map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(string(packRaw)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	for _, e := range doc["entries"].([]any) {
		rule := e.(map[string]any)["rule"].(map[string]any)
		if rule["id"] == id {
			mutate(rule)
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// V13 holds the rewrite to the listed fields independently of the recomputation.
func TestMovedRewriteCheckRefusesAnythingOutsideTheListedFields(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, _ := f.prepareSampled()
	doc, err := loadPack(f.pack)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	priorRaw, nextRaw := ruleRaw(t, f.pack, "rule-a"), ruleRaw(t, res.NextPack, "rule-a")
	row := res.Statement.Rules[0]
	if err := checkMovedRewrite(row, priorRaw, nextRaw, candidatesByID(candidates)["rule-a"]); err != nil {
		t.Fatalf("the honest rewrite must pass: %v", err)
	}
	for name, mutate := range map[string]func(rule map[string]any){
		"claim": func(rule map[string]any) { rule["reasonCode"] = "TAMPERED" },
		"url": func(rule map[string]any) {
			setSourceField(rule, "url", "https://github.com/owner/repo-rule-a/blob/"+strings.Repeat("e", 40)+"/a.go")
		},
		"id":      func(rule map[string]any) { setSourceField(rule, "id", "other") },
		"subject": func(rule map[string]any) { rule["subject"].(map[string]any)["to"] = "9.9.9" },
	} {
		tampered := ruleRaw(t, tamperRule(t, res.NextPack, "rule-a", mutate), "rule-a")
		if err := checkMovedRewrite(row, priorRaw, tampered, candidatesByID(candidates)["rule-a"]); err == nil {
			t.Errorf("%s: a change outside the listed fields must be refused", name)
		}
	}
}

func ruleRaw(t *testing.T, packRaw []byte, id string) json.RawMessage {
	t.Helper()
	doc, err := loadPack(packRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc.Entries {
		if fields, _ := parseRuleFields(entry.Rule); fields.ID == id {
			return entry.Rule
		}
	}
	t.Fatalf("no rule %s", id)
	return nil
}

func TestMovedVerifyNeedsTheIndependentWorklistAndItsAgreement(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, opts := f.prepareSampled()
	v := f.verifyOptions(res, opts)
	v.IndependentWorklistRaw = nil
	assertVerifyRejects(t, v, "V13:")

	other := f.wl
	other.Citations = append([]evidencerepin.ClassResult(nil), f.wl.Citations...)
	moved := *other.Citations[0].MovedTo
	moved.ContentDigest = "sha256:" + strings.Repeat("6", 64)
	other.Citations[0].MovedTo = &moved
	v = f.verifyOptions(res, opts)
	v.IndependentWorklistRaw = marshalWorklist(t, other)
	assertVerifyRejects(t, v, "V13:")

	noMove := f.wl
	noMove.Citations = append([]evidencerepin.ClassResult(nil), f.wl.Citations...)
	noMove.Citations[0].MovedTo = nil
	v = f.verifyOptions(res, opts)
	v.IndependentWorklistRaw = marshalWorklist(t, noMove)
	assertVerifyRejects(t, v, "V13:")
}

func TestMovedVerifyFailsClosedWithoutTheRetainedFiles(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, opts := f.prepareSampled()
	v := f.verifyOptions(res, opts)
	v.MovedBlobs = nil
	assertVerifyRejects(t, v, "V3:")
}

// A5 automated mode
func TestMovedAutomatedModeRefusesAndNoAutomatedStatementCarriesAMove(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	opts := f.options()
	opts.Mode, opts.Wave = ModeAutomated, 0
	res, err := Prepare(opts)
	if err != nil {
		t.Fatal(err)
	}
	assertNotRenewed(t, "automated", res, "rule-a", reasonMovedNotAutomatable)

	human, _ := f.prepareSampled()
	statement, err := ParseStatement(human.StatementCanonical)
	if err != nil {
		t.Fatal(err)
	}
	statement.SignerRole = RoleAutomation
	statement.Authority = AuthorityAutomated
	statement.Wave, statement.SampledForFullReview = 0, nil
	statement.Statement = AutomatedStatementText(statement.Worklist.GeneratedAt, statement.ValidUntil)
	for i := range statement.Rules {
		statement.Rules[i].ValidUntil = statement.ValidUntil
	}
	raw, err := CanonicalStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStatement(raw); err == nil {
		t.Fatal("an automated statement must never carry a moved row")
	}
}

func TestMovedStatementRowContract(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, _ := f.prepareSampled()
	base, err := ParseStatement(res.StatementCanonical)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(s *Statement){
		"moved row on a plain class": func(s *Statement) { s.Rules[0].Citations[0].Class = evidencerepin.ClassSpanIdentical },
		"SPAN_MOVED without a row":   func(s *Statement) { s.Rules[0].Citations[0].Moved = nil },
		"same place": func(s *Statement) {
			s.Rules[0].Citations[0].Moved.NewStartLine, s.Rules[0].Citations[0].Moved.NewEndLine = 10, 12
		},
		"different length": func(s *Statement) { s.Rules[0].Citations[0].Moved.NewEndLine = 20 },
		"no line baseline": func(s *Statement) { s.Rules[0].Citations[0].Baseline = "" },
		"old digest is not the source": func(s *Statement) {
			s.Rules[0].Citations[0].Moved.OldContentDigest = "sha256:" + strings.Repeat("5", 64)
		},
		"fixed text": func(s *Statement) { s.Statement = FixedStatementText(s.Worklist.GeneratedAt, s.ValidUntil) },
		"pinning":    func(s *Statement) { s.Rules[0].Lease = "pinned" },
	} {
		s := base
		s.Rules = append([]RuleAttestation(nil), base.Rules...)
		s.Rules[0].Citations = append([]CitationAttestation(nil), base.Rules[0].Citations...)
		if base.Rules[0].Citations[0].Moved != nil {
			m := *base.Rules[0].Citations[0].Moved
			s.Rules[0].Citations[0].Moved = &m
		}
		mutate(&s)
		raw, err := CanonicalStatement(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseStatement(raw); err == nil {
			t.Errorf("%s: the statement must not parse", name)
		}
	}
}

func TestMovedPinningStatementRefusesMovedRules(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	opts := f.options()
	opts.Pin = true
	if _, err := Prepare(opts); err == nil {
		t.Fatal("a pinning batch with only a moved rule has nothing it may pin")
	}
}

// A5 sample and cycle cap
func TestMovedRulesAreForcedIntoTheSample(t *testing.T) {
	f := newMovedFix(t, "rule-a", "rule-b", "rule-c", "rule-d").build()
	res := f.prepareOnly()
	if len(res.Statement.Rules) != 4 {
		t.Fatalf("all four moved rules must be eligible: %+v", res.Statement.NotExtended)
	}
	// ceil(10% of 4) is 1; every moved rule is in the sample regardless.
	if len(res.Statement.SampledForFullReview) != 4 {
		t.Fatalf("every moved rule must be in the sample: %+v", res.Statement.SampledForFullReview)
	}
}

func TestMovedRulesFillTheSeededSampleWithOthersToItsUsualSize(t *testing.T) {
	// One moved rule among rules that did not move: the moved one is in the
	// sample, and the sample keeps its usual size.
	f := newMovedFix(t, "rule-a")
	f.pad = 130
	f.build()
	ids := []string{"rule-a"}
	for i := 0; i < 19; i++ {
		id := fmt.Sprintf("rule-p%02d", i)
		spec := freshSpec(id, "proj-"+id, baseNow)
		wl, pack := buildWorklistAndPack(t, f.packPath, baseNow, []ruleSpec{spec})
		_ = pack
		f.wl.Citations = append(f.wl.Citations, wl.Citations...)
		f.wl.Repos = append(f.wl.Repos, wl.Repos...)
		ids = append(ids, id)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(f.pack, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["entries"].([]any)
	for _, id := range ids[1:] {
		spec := freshSpec(id, "proj-"+id, baseNow)
		entries = append(entries, testEntry("proj-"+id, testRule(id, "active", spec.reviewedAt, spec.validUntil, false,
			testSource(id+"-src", "owner", "repo-"+id, spec.commit, "VERSION", "sha256:"+strings.Repeat("cd", 32), 1, 1))))
	}
	doc["entries"] = entries
	var err error
	if f.pack, err = json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	res := f.prepareOnly()
	if len(res.Statement.Rules) != 20 {
		t.Fatalf("20 eligible rules expected: %+v", res.Statement.NotExtended)
	}
	sampled := map[string]bool{}
	for _, s := range res.Statement.SampledForFullReview {
		sampled[s.RuleID] = true
	}
	if !sampled["rule-a"] || len(sampled) != 2 {
		t.Fatalf("the moved rule plus one seeded rule (10%% of 20): %v", sampled)
	}
}

func TestMovedRuleCountsAgainstTheConsecutiveCycleCap(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	doc, err := loadPack(f.pack)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	var candidate ruleCandidate
	for _, c := range candidates {
		if c.RuleID == "rule-a" {
			candidate = c
		}
	}
	for _, c := range f.wl.Citations {
		candidate.Citations = append(candidate.Citations, c)
	}
	repos := map[string]evidencerepin.RepoResolution{}
	for _, r := range f.wl.Repos {
		repos[r.Owner+"/"+r.Repo] = r
	}
	if reason, ok := evaluateEligibility(candidate, true, true, baseNow, repos, f.wl.Lines, nil, maxConsecutiveBatchCycles, false, nil, false, f.blobs); !ok {
		t.Fatalf("a moved rule on its last allowed cycle is eligible: %s", reason)
	}
	if reason, ok := evaluateEligibility(candidate, true, true, baseNow, repos, f.wl.Lines, nil, maxConsecutiveBatchCycles+1, false, nil, false, f.blobs); ok || reason != reasonConsecutiveCycleCap {
		t.Fatalf("a moved rule past the cap must be refused with the cap reason: %q %v", reason, ok)
	}
	res := f.prepareOnly()
	if got := res.Statement.Rules[0].ConsecutiveBatchCycles; got != 1 {
		t.Fatalf("a moved renewal is one batch cycle, not a review: %d", got)
	}
}

// V8 holds the sample independently of the recomputation.
func TestMovedRolePolicyRequiresTheRuleInTheSample(t *testing.T) {
	f := newMovedFix(t, "rule-a").build()
	res, _ := f.prepareSampled()
	doc, err := loadPack(f.pack)
	if err != nil {
		t.Fatal(err)
	}
	candidates, _, err := packCandidates(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRolePolicy(res.Statement, candidatesByID(candidates)); err != nil {
		t.Fatalf("the honest statement passes V8: %v", err)
	}
	s := res.Statement
	s.SampledForFullReview = []SampledEntry{{RuleID: "pad-rule-0", ReviewRecordDigest: "sha256:" + strings.Repeat("4", 64)}}
	if err := checkRolePolicy(s, candidatesByID(candidates)); err == nil {
		t.Fatal("a moved rule outside the sample must be refused")
	}
	s = res.Statement
	s.Rules = append([]RuleAttestation(nil), res.Statement.Rules...)
	s.Rules[0].Citations = append([]CitationAttestation(nil), res.Statement.Rules[0].Citations...)
	moved := *s.Rules[0].Citations[0].Moved
	moved.OldStartLine, moved.OldEndLine = 11, 13
	s.Rules[0].Citations[0].Moved = &moved
	if err := checkRolePolicy(s, candidatesByID(candidates)); err == nil {
		t.Fatal("a moved row whose old place is not the prior pack's source must be refused")
	}
}

func TestLoadMovedBlobsIsContentAddressedAndRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	data := []byte("some file")
	if err := os.WriteFile(filepath.Join(dir, "any-name"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadMovedBlobs(dir)
	if err != nil || string(got[sourcecorpus.SHA(data)]) != string(data) || len(got) != 1 {
		t.Fatalf("blobs are keyed by their own digest, not their name: %v %v", got, err)
	}
	if err := os.Symlink("any-name", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMovedBlobs(dir); err == nil {
		t.Fatal("a link in the blob directory must be refused")
	}
}

func TestLegacyStatementBytesAreUnchangedByTheMovedColumn(t *testing.T) {
	packPath := "/p/rules.json"
	wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
	res := prepareSingle(t, wl, pack, packPath)
	if strings.Contains(string(res.StatementCanonical), "moved") {
		t.Fatal("a statement with no moved citation must not mention the moved column")
	}
}
