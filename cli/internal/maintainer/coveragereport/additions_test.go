// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const tagsK8s = "refs/tags/v1.29.0\nrefs/tags/v1.30.0\nrefs/tags/v1.30.1\nrefs/tags/v1.31.0\nrefs/tags/v1.31.0-rc.1\n"

func sealed(t *testing.T, slug, tags, on string) AdditionEntry {
	t.Helper()
	e, err := SealAddition(slug, []byte(tags), on, false, "")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func additionsJSON(t *testing.T, entries map[string]AdditionEntry) []byte {
	t.Helper()
	raw, err := MarshalAdditions(AdditionsFile{Additions: entries})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// pinnedLines is a snapshot with one pinned project, captured and evaluated on
// the given dates.
func pinnedLines(captured, pinned string) []byte {
	p := ""
	if pinned != "" {
		p = fmt.Sprintf(`"pinnedOn":%q,`, pinned)
	}
	return []byte(fmt.Sprintf(`{"schema":%q,"capturedOn":%q,%s"projects":{"other":{"lines":["1.0","1.1"]}}}`, LinesSchema, captured, p))
}

func TestAbsentAndEmptyAdditionsAreTheEmptySet(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string][]byte{
		"nil": nil, "zero bytes": {}, "whitespace": []byte(" \n\t"),
		"empty object": []byte(`{"schema":"` + AdditionsSchema + `","additions":{}}`),
	} {
		f, err := ParseAdditions(raw)
		if err != nil || len(f.Additions) != 0 {
			t.Errorf("%s: %v %v", name, f, err)
		}
	}
}

// An absent or empty additions file changes no number: the report is
// byte-identical to one computed without the input.
func TestAbsentOrEmptyAdditionsChangeNothing(t *testing.T) {
	t.Parallel()
	in := Input{Pack: read(t, "testdata/pack-cncf-2026-09-13.4-reduced.json"), Lines: read(t, "testdata/lines-2026-10-08.json"), Now: baselineNow}
	want, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := want.JSON()
	for name, add := range map[string][]byte{"absent": nil, "empty": []byte(""), "empty set": []byte(`{"schema":"` + AdditionsSchema + `","additions":{}}`)} {
		in.Additions = add
		got, err := Compute(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		gotJSON, _ := got.JSON()
		if !bytes.Equal(gotJSON, wantJSON) || got.Additions != nil || !bytes.Equal(got.Markdown(), want.Markdown()) {
			t.Errorf("%s: the report changed", name)
		}
	}
}

func TestParseAdditionsRefusals(t *testing.T) {
	t.Parallel()
	good := sealed(t, "kubernetes", tagsK8s, "2026-11-10")
	mut := func(f func(e *AdditionEntry)) []byte {
		e := good
		f(&e)
		raw, _ := json.Marshal(AdditionsFile{Schema: AdditionsSchema, Additions: map[string]AdditionEntry{"kubernetes": e}})
		return raw
	}
	resealed := func(f func(e *AdditionEntry)) []byte {
		return mut(func(e *AdditionEntry) { f(e); e.EntryDigest = EntryDigestOf(*e) })
	}
	if _, err := ParseAdditions(mut(func(*AdditionEntry) {})); err != nil {
		t.Fatalf("the good entry is refused: %v", err)
	}
	cases := map[string][]byte{
		"capturedOn missing":    resealed(func(e *AdditionEntry) { e.CapturedOn = "" }),
		"capturedOn not a date": resealed(func(e *AdditionEntry) { e.CapturedOn = "2026-13-45" }),
		"capturedOn spelling":   resealed(func(e *AdditionEntry) { e.CapturedOn = "10.11.2026" }),
		"tag sha missing":       resealed(func(e *AdditionEntry) { e.TagFileSha256 = "" }),
		"tag sha malformed":     resealed(func(e *AdditionEntry) { e.TagFileSha256 = "sha256:abc" }),
		"digest missing":        mut(func(e *AdditionEntry) { e.EntryDigest = "" }),
		"digest wrong":          mut(func(e *AdditionEntry) { e.EntryDigest = "sha256:" + strings.Repeat("0", 64) }),
		"line edited":           mut(func(e *AdditionEntry) { e.Lines = append([]string{"1.28"}, e.Lines...) }),
		"no lines":              resealed(func(e *AdditionEntry) { e.Lines, e.Releases = []string{}, nil }),
		"lines descending":      resealed(func(e *AdditionEntry) { e.Lines = []string{"1.31", "1.30"}; e.Releases = nil }),
		"unknown scheme":        resealed(func(e *AdditionEntry) { e.Scheme = "nope" }),
		"unknown schema":        []byte(`{"schema":"x","additions":{}}`),
		"additions member gone": []byte(`{"schema":"` + AdditionsSchema + `"}`),
		"unknown member":        []byte(`{"schema":"` + AdditionsSchema + `","additions":{},"x":1}`),
		"trailing data":         []byte(`{"schema":"` + AdditionsSchema + `","additions":{}} {}`),
		"bad slug":              []byte(strings.Replace(string(mut(func(*AdditionEntry) {})), `"kubernetes"`, `"Bad_Slug"`, 1)),
	}
	for name, raw := range cases {
		if _, err := ParseAdditions(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAdditionKeysMustBeDisjoint(t *testing.T) {
	t.Parallel()
	add := additionsJSON(t, map[string]AdditionEntry{"other": sealed(t, "other", tagsK8s, "2026-11-10")})
	_, err := Compute(Input{Pack: pack(nil, nil), Lines: pinnedLines("2026-11-07", ""), Additions: add, Now: baselineNow})
	if err == nil || !strings.Contains(err.Error(), "never overrides") {
		t.Fatalf("a key in both files was accepted: %v", err)
	}
}

func TestSealAndRegenerateFromTags(t *testing.T) {
	t.Parallel()
	e := sealed(t, "kubernetes", tagsK8s, "2026-11-10")
	if got := strings.Join(e.Lines, ","); got != "1.29,1.30,1.31" {
		t.Fatalf("lines %s (a pre-release must add nothing beyond its final line)", got)
	}
	if err := VerifyAdditionFromTags("kubernetes", e, []byte(tagsK8s)); err != nil {
		t.Fatal(err)
	}
	// Omitting the newest patch release: the tag file differs from the bound digest.
	if err := VerifyAdditionFromTags("kubernetes", e, []byte(strings.Replace(tagsK8s, "refs/tags/v1.30.1\n", "", 1))); err == nil {
		t.Error("a changed tag file was accepted")
	}
	// An entry that is validly sealed but is not the reading of its tag file.
	forged := e
	forged.Releases = map[string][]string{"1.29": {"1.29.0"}, "1.30": {"1.30.0"}, "1.31": {"1.31.0"}}
	forged.EntryDigest = EntryDigestOf(forged)
	if err := VerifyAdditionFromTags("kubernetes", forged, []byte(tagsK8s)); err == nil {
		t.Error("an entry that omits a release was accepted")
	}
	// A priority flag cannot be flipped without the digest moving.
	flipped := e
	flipped.Priority = true
	if err := VerifyAdditionFromTags("kubernetes", flipped, []byte(tagsK8s)); err == nil {
		t.Error("an edit without a new digest was accepted")
	}
}

func TestEvaluationClock(t *testing.T) {
	t.Parallel()
	pinned := func(captured, on string) LinesFile { return LinesFile{CapturedOn: captured, PinnedOn: on} }
	add := func(dates ...string) AdditionsFile {
		f := AdditionsFile{Additions: map[string]AdditionEntry{}}
		for i, d := range dates {
			f.Additions[fmt.Sprintf("p%d", i)] = AdditionEntry{CapturedOn: d}
		}
		return f
	}
	for _, c := range []struct {
		name string
		p    LinesFile
		a    AdditionsFile
		want string
	}{
		{"no additions: the pinned date", pinned("2026-10-31", "2026-11-07"), add(), "2026-11-07"},
		{"no pin: capture date", pinned("2026-10-31", ""), add(), "2026-10-31"},
		{"additions later", pinned("2026-10-31", "2026-11-07"), add("2026-11-10", "2026-11-09"), "2026-11-10"},
		{"additions earlier never move it back", pinned("2026-10-31", "2026-11-07"), add("2026-11-01"), "2026-11-07"},
	} {
		got, err := EvaluationClockDate(c.p, c.a)
		if err != nil || got != c.want {
			t.Errorf("%s: %s %v, want %s", c.name, got, err, c.want)
		}
	}
	clock, err := EvaluationClock(pinned("2026-10-31", "2026-11-07"), add("2026-11-10"))
	if err != nil || !clock.Equal(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("clock %v %v", clock, err)
	}
	if _, err := EvaluationClockDate(LinesFile{}, add("2026-11-10")); err == nil {
		t.Error("a pinned snapshot without a date gave a clock")
	}
}

// The measure is the union, and an addition keeps its own component and date.
func TestComputeMeasuresTheUnion(t *testing.T) {
	t.Parallel()
	e := sealed(t, "kubernetes", "v1.30.0\nv1.31.0\n", "2026-10-08")
	e.Component = k8s
	e.EntryDigest = EntryDigestOf(e)
	add := additionsJSON(t, map[string]AdditionEntry{"kubernetes": e})
	p := pack(nil, []string{attJSON("1.31", valid)})
	pinned := pinnedLines("2026-10-08", "")
	with, err := Compute(Input{Pack: p, Lines: pinned, Additions: add, Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	without, err := Compute(Input{Pack: p, Lines: pinned, Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	if with.Fleet.Projects != without.Fleet.Projects+1 || with.Fleet.A != 1 || without.Fleet.A != 0 {
		t.Fatalf("union: projects %d -> %d, A %d -> %d", without.Fleet.Projects, with.Fleet.Projects, without.Fleet.A, with.Fleet.A)
	}
	if with.Additions == nil || with.Additions.Entries != 1 || with.Additions.ClockOn != "2026-10-08" || with.Additions.Digest != digestOf(add) || with.Lines.Digest != digestOf(pinned) {
		t.Fatalf("two digests expected: %+v / %s", with.Additions, with.Lines.Digest)
	}
}

// An addition whose attestations are reviewed after the clock decides nothing:
// 0 decided pairs, and the project is disclosed as attested but not counted.
func TestAdditionReviewedAfterTheClockDecidesNothing(t *testing.T) {
	t.Parallel()
	e := sealed(t, "kubernetes", "v1.30.0\nv1.31.0\n", "2026-10-08")
	e.Component = k8s
	e.EntryDigest = EntryDigestOf(e)
	add := additionsJSON(t, map[string]AdditionEntry{"kubernetes": e})
	late := strings.Replace(attJSON("1.31", valid), "2026-09-01T00:00:00Z", "2026-10-09T00:00:00Z", 1)
	r, err := Compute(Input{Pack: pack(nil, []string{late}), Lines: pinnedLines("2026-10-08", ""), Additions: add, Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	if r.Fleet.A+r.Fleet.B != 0 {
		t.Fatalf("decided %d, want 0", r.Fleet.A+r.Fleet.B)
	}
	if len(r.AttestedAfterClock) != 1 || r.AttestedAfterClock[0] != "kubernetes" {
		t.Fatalf("attested after the clock = %v", r.AttestedAfterClock)
	}
	// The same attestation reviewed before the clock counts.
	r, err = Compute(Input{Pack: pack(nil, []string{attJSON("1.31", valid)}), Lines: pinnedLines("2026-10-08", ""), Additions: add, Now: baselineNow})
	if err != nil || r.Fleet.A != 1 || len(r.AttestedAfterClock) != 0 {
		t.Fatalf("A %d, after-clock %v, %v", r.Fleet.A, r.AttestedAfterClock, err)
	}
}

// The complete predicate judges an added project by its own capturedOn.
func TestCompleteUsesTheEntryCaptureDate(t *testing.T) {
	t.Parallel()
	pinned := pinnedLines("2026-10-08", "")
	reasonsOf := func(on string) []string {
		e := sealed(t, "kubernetes", "v1.30.0\nv1.31.0\n", on)
		add := additionsJSON(t, map[string]AdditionEntry{"kubernetes": e})
		r, err := Compute(Input{Pack: pack(nil, nil), Lines: pinned, Additions: add, Now: allNow, All: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range r.Projects {
			if p.Project == "kubernetes" && p.Completion != nil {
				return p.Completion.Reasons
			}
		}
		t.Fatal("no completion for the added project")
		return nil
	}
	has := func(rs []string, want string) bool {
		for _, r := range rs {
			if r == want {
				return true
			}
		}
		return false
	}
	if !has(reasonsOf("2026-10-09"), whySnapshotFuture) {
		t.Error("an addition captured after the clock is not snapshot-future")
	}
	if !has(reasonsOf("2026-09-01"), whySnapshotStale) {
		t.Error("an old addition is not snapshot-stale by its own date")
	}
	if has(reasonsOf("2026-10-08"), whySnapshotFuture) || has(reasonsOf("2026-10-08"), whySnapshotStale) {
		t.Error("a current addition has a snapshot reason")
	}
}

func readmeFixture(r Report) (string, error) {
	r.Projects = []Project{{Project: "kubernetes", Window: []string{"1.30", "1.31"}}}
	inv := `{"counts":{"cncfSourceRules":1,"cncfRuleProjects":1,"cncfSourceRulesWithdrawn":0,"communityProjectSourceRules":1,"communityProjectRuleProjects":1,"executableProjects":1,"selectedSourceProjects":1,"selectedSourceOnlyProjects":0}}`
	return RenderREADMEBlock(r, []byte(inv), baselineNow)
}

// The disclosure appears only with additions; without them the block is the
// one that was published before, whatever the lists hold.
func TestReadmeDisclosureOnlyWithAdditions(t *testing.T) {
	t.Parallel()
	r := Report{WithoutLines: []string{"alpha"}, AttestedAfterClock: []string{"beta"}}
	r.Lines.CapturedOn, r.Lines.PinnedOn = "2026-10-31", "2026-11-07"
	plain, err := readmeFixture(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"alpha", "beta", "appended", "not yet counted"} {
		if strings.Contains(plain, s) {
			t.Errorf("the block without additions mentions %q", s)
		}
	}
	r.Additions = &AdditionsInfo{Entries: 2, ClockOn: "2026-11-10"}
	got, err := readmeFixture(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"alpha", "no release lines in the snapshot", "beta", "attested but not yet counted", "evaluated on 2026-11-10"} {
		if !strings.Contains(got, s) {
			t.Errorf("the block with additions lacks %q", s)
		}
	}
	// Empty lists print nothing even with additions.
	r.WithoutLines, r.AttestedAfterClock = nil, nil
	quiet, _ := readmeFixture(r)
	if strings.Contains(quiet, "not yet counted") || strings.Contains(quiet, "no release lines") {
		t.Error("an empty list is printed")
	}
}

func TestAdditionComponentMustBeUnowned(t *testing.T) {
	t.Parallel()
	withComponent := func(slug, component string) AdditionEntry {
		e := sealed(t, slug, tagsK8s, "2026-11-10")
		e.Component = component
		e.EntryDigest = EntryDigestOf(e)
		return e
	}
	pinned := []byte(fmt.Sprintf(`{"schema":%q,"capturedOn":"2026-11-07","projects":{"other":{"component":"pkg:github/o/other","lines":["1.0","1.1"]}}}`, LinesSchema))
	run := func(entries map[string]AdditionEntry) error {
		_, err := Compute(Input{Pack: pack(nil, nil), Lines: pinned, Additions: additionsJSON(t, entries), Now: baselineNow})
		return err
	}
	if err := run(map[string]AdditionEntry{"zz": withComponent("zz", "pkg:github/o/zz")}); err != nil {
		t.Fatalf("a unique component is refused: %v", err)
	}
	if err := run(map[string]AdditionEntry{"zz": withComponent("zz", "pkg:github/o/other")}); err == nil || !strings.Contains(err.Error(), "already owned by other") {
		t.Fatalf("an addition with a pinned component was accepted: %v", err)
	}
	same := map[string]AdditionEntry{"aa": withComponent("aa", "pkg:github/o/x"), "bb": withComponent("bb", "pkg:github/o/x")}
	for i := 0; i < 20; i++ { // deterministic, whatever the map order
		if err := run(same); err == nil || !strings.Contains(err.Error(), "already owned by aa") {
			t.Fatalf("two additions with one component: %v", err)
		}
	}
}
