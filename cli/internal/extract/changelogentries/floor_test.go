// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const fRepo = "github.com/example/notes"

// fSrc serves in-memory files and a tag list.
type fSrc struct {
	memReader
	tags []extract.Tag
}

func (f *fSrc) Tags(extract.RepoRef) ([]extract.Tag, error) { return f.tags, nil }

var fRow = Target{Component: "notes", Repo: extract.RepoRef{Key: fRepo}, Form: FormPerVersionFile, Path: "docs/releases/v{version}.md"}

var bigCaps = Caps{Tags: 200, Blobs: 400, Bytes: 1 << 30}

// fix builds a mirror with a per-version changelog for every tag and the
// matching upstream list. lines are "major.minor" newest first; each has the
// patches 0 and 1.
type fix struct {
	src *fSrc
	up  UpstreamList
	ids map[string]int
}

func newFix(lines ...string) *fix {
	f := &fix{src: &fSrc{memReader: memReader{files: map[string][]byte{}}}, up: UpstreamList{}, ids: map[string]int{}}
	for i := len(lines) - 1; i >= 0; i-- {
		for _, patch := range []string{"0", "1"} {
			f.add("v" + lines[i] + "." + patch)
		}
	}
	return f
}

func (f *fix) commit(name string) string {
	if _, ok := f.ids[name]; !ok {
		f.ids[name] = len(f.ids) + 1
	}
	return fmt.Sprintf("%040x", f.ids[name])
}

func (f *fix) add(name string) {
	c := f.commit(name)
	f.src.tags = append(f.src.tags, extract.Tag{Name: name, Commit: c})
	f.up[fRepo] = append(f.up[fRepo], UpstreamTag{Name: name, ObjectID: c})
	f.src.files[fRepo+"@"+c+":docs/releases/"+name+".md"] = []byte(pvBody)
}

func (f *fix) dropFile(name string) {
	delete(f.src.files, fRepo+"@"+f.commit(name)+":docs/releases/"+name+".md")
}

func (f *fix) dropMirror(name string) {
	var out []extract.Tag
	for _, t := range f.src.tags {
		if t.Name != name {
			out = append(out, t)
		}
	}
	f.src.tags = out
}

func (f *fix) derive(t *testing.T, row Target, caps Caps) *Run {
	t.Helper()
	r, err := DeriveRun(f.src, f.up, row, caps)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ten() []string {
	return []string{"1.10", "1.9", "1.8", "1.7", "1.6", "1.5", "1.4", "1.3", "1.2", "1.1"}
}

func TestParseFloorGrammar(t *testing.T) {
	for _, ok := range []string{"0.16", "0.153", "0.0", "1.2", "1.20", "10.0", "99.9999", "2.10"} {
		if _, err := ParseFloor(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"00.16", "0.0153", "01.20", "1.020", " 1.20", "1.20 ", "1.20\n", "1.20.0", "since:1.20", "SINCE:1.20",
		"１.２０", "١.٢", "newest5", "", "2024.05", "2024.5", "100.1", "1.10000", "-1.2", "+1.2", "1.", ".2", "1", "v1.2", "1.2\x00"} {
		if _, err := ParseFloor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFloorNumericOrderNotText(t *testing.T) {
	a, _ := ParseFloor("0.153")
	b, _ := ParseFloor("0.16")
	c, _ := ParseFloor("0.9")
	if !(b.Less(a) && c.Less(b) && !a.Less(b)) {
		t.Fatal("lines are not ordered numerically")
	}
	if !(Line{1, 2}.Less(Line{2, 0})) {
		t.Fatal("major order")
	}
}

func doc(row string) []byte {
	return []byte(`{"schema":"` + TargetsSchema + `","rows":[` + row + `]}`)
}

func TestLoaderFloor(t *testing.T) {
	base := `"component":"notes","repo":"github.com/example/notes","form":"changelog-per-version-file","path":"docs/v{version}.md"`
	tg, err := parseTargets(doc(`{` + base + `,"floor":"0.153"}`))
	if err != nil || tg[0].Floor != "0.153" {
		t.Fatalf("%v %+v", err, tg)
	}
	tg, err = parseTargets(doc(`{` + base + `}`))
	if err != nil || tg[0].Floor != "" {
		t.Fatalf("absent floor: %v %+v", err, tg)
	}
	for _, bad := range []string{`""`, `"newest5"`, `"since:1.20"`, `"1.20.0"`, `"01.20"`, `" 1.20"`, `"1.20\n"`, `"00.16"`, `"0.0153"`, `"2024.05"`, `null`, `1.2`, `"１.２"`} {
		if _, err := parseTargets(doc(`{` + base + `,"floor":` + bad + `}`)); err == nil && bad != `null` {
			t.Errorf("floor %s accepted", bad)
		}
	}
	// A row of a form that is not read never has a floor.
	if _, err := parseTargets(doc(`{"component":"notes","repo":"github.com/example/notes","form":"post-tag","floor":"1.8"}`)); err == nil {
		t.Error("floor on an unread form accepted")
	}
	// A directly built Target with a bad floor does not compile.
	bad := fRow
	bad.Floor = "01.2"
	if _, err := bad.compile(); err == nil {
		t.Error("Target with a bad floor compiled")
	}
}

// Golden: a row without a floor marshals and canonicalises exactly as before,
// and no embedded reviewed row has one.
func TestAbsentFloorCanonicalisesAsBefore(t *testing.T) {
	b, err := json.Marshal(rowData{Component: "a", Repo: "github.com/x/y", Form: FormPerVersionFile, Path: "docs/v{version}.md"})
	want := `{"component":"a","repo":"github.com/x/y","form":"changelog-per-version-file","path":"docs/v{version}.md"}`
	if err != nil || string(b) != want {
		t.Fatalf("%v %s", err, b)
	}
	if LoadError() != nil || len(Reviewed) == 0 {
		t.Fatal(LoadError())
	}
	for _, r := range Reviewed {
		if r.Floor != "" {
			t.Errorf("reviewed row %s has a floor", r.Component)
		}
	}
	if strings.Contains(string(targetsJSON), `"floor"`) {
		t.Error("targets.json carries a floor")
	}
}

func TestTagSetDigestIncludesObjectID(t *testing.T) {
	a := []UpstreamTag{{"v1.0.0", sha('a')}, {"v1.0.1", sha('b')}}
	b := []UpstreamTag{{"v1.0.1", sha('b')}, {"v1.0.0", sha('a')}}
	if TagSetDigest(a) != TagSetDigest(b) {
		t.Fatal("order matters")
	}
	re := []UpstreamTag{{"v1.0.0", sha('c')}, {"v1.0.1", sha('b')}}
	if TagSetDigest(a) == TagSetDigest(re) {
		t.Fatal("a retag does not change the digest")
	}
	if TagSetDigest(a) == TagSetDigest(a[:1]) {
		t.Fatal("a missing tag does not change the digest")
	}
	// Replays identically, with no network.
	if TagSetDigest(a) != TagSetDigest(append([]UpstreamTag(nil), a...)) {
		t.Fatal("not deterministic")
	}
}

func TestDeriveRunFloor(t *testing.T) {
	f := newFix(ten()...)
	r := f.derive(t, fRow, bigCaps)
	if len(r.Lines) != 10 || r.Floor != "1.1" || r.FailLine != "" {
		t.Fatalf("%+v", r)
	}
	if r.Lines[0] != "1.10" || r.Lines[1] != "1.9" {
		t.Fatalf("lines are not in numeric order: %v", r.Lines)
	}
}

func TestDeriveRunOfFiveIsAbsent(t *testing.T) {
	f := newFix(ten()[:5]...)
	if r := f.derive(t, fRow, bigCaps); len(r.Lines) != 5 || r.Floor != "" {
		t.Fatalf("%+v", r)
	}
	f = newFix(ten()[:6]...)
	if r := f.derive(t, fRow, bigCaps); r.Floor != "1.5" {
		t.Fatalf("%+v", r)
	}
	f = newFix(ten()[:3]...)
	if r := f.derive(t, fRow, bigCaps); r.Floor != "" {
		t.Fatalf("%+v", r)
	}
}

func TestDeriveRunStopsAtFirstFailingLine(t *testing.T) {
	f := newFix(ten()...)
	f.dropFile("v1.4.1")
	r := f.derive(t, fRow, bigCaps)
	if r.Floor != "1.5" || r.FailLine != "1.4" || !strings.HasPrefix(r.FailReason, "TAG_UNLOCATED:v1.4.1") {
		t.Fatalf("%+v", r)
	}
	// Older lines that would locate are never used: no L beyond a gap.
	for _, l := range r.Lines {
		if l == "1.3" || l == "1.2" || l == "1.1" {
			t.Fatalf("a line beyond the gap is in the run: %v", r.Lines)
		}
	}
}

func TestDeriveRunUpstreamTagMissingFromMirror(t *testing.T) {
	f := newFix(ten()...)
	f.dropMirror("v1.6.1")
	r := f.derive(t, fRow, bigCaps)
	if r.FailLine != "1.6" || !strings.HasPrefix(r.FailReason, "TAG_NOT_LOCATED:v1.6.1") || len(r.Lines) != 4 || r.Floor != "" {
		t.Fatalf("a missing mirror tag shrank or skipped the window: %+v", r)
	}
}

func TestDeriveRunMirrorOnlyTag(t *testing.T) {
	f := newFix(ten()...)
	c := f.commit("v1.7.9")
	f.src.tags = append(f.src.tags, extract.Tag{Name: "v1.7.9", Commit: c})
	f.src.files[fRepo+"@"+c+":docs/releases/v1.7.9.md"] = []byte(pvBody)
	r := f.derive(t, fRow, bigCaps)
	if r.FailLine != "1.7" || r.FailReason != "MIRROR_ONLY_TAG" {
		t.Fatalf("%+v", r)
	}
	// A mirror line the upstream list lacks entirely also stops the run.
	f = newFix(ten()...)
	c = f.commit("v1.99.0")
	f.src.tags = append(f.src.tags, extract.Tag{Name: "v1.99.0", Commit: c})
	if r := f.derive(t, fRow, bigCaps); len(r.Lines) != 0 || r.FailLine != "1.99" {
		t.Fatalf("%+v", r)
	}
}

func TestDeriveRunOddTagsNeverCountedLocated(t *testing.T) {
	f := newFix(ten()...)
	// A prerelease, a non-semver tag and a tag with a build suffix upstream:
	// excluded from the set, absent from the mirror, never counted located and
	// never breaking or extending the run.
	for _, n := range []string{"v1.5.2-rc.1", "latest", "v1.2.3+build", "v1.0.0-alpha.1"} {
		f.up[fRepo] = append(f.up[fRepo], UpstreamTag{Name: n, ObjectID: sha('e')})
	}
	r := f.derive(t, fRow, bigCaps)
	if len(r.Lines) != 10 || r.Floor != "1.1" {
		t.Fatalf("%+v", r)
	}
	// A line that has only a prerelease is not a line.
	f = newFix(ten()[:6]...)
	f.up[fRepo] = append(f.up[fRepo], UpstreamTag{Name: "v1.4.0-rc.1", ObjectID: sha('e')})
	if r := f.derive(t, fRow, bigCaps); len(r.AllLines) != 6 || r.Floor != "1.5" {
		t.Fatalf("%+v", r)
	}
	// A prerelease that the mirror also holds is not a final tag: not scored.
	f = newFix(ten()...)
	f.add("v1.3.5-rc.1")
	f.dropFile("v1.3.5-rc.1")
	if r := f.derive(t, fRow, bigCaps); r.Floor != "1.1" {
		t.Fatalf("%+v", r)
	}
}

func TestDeriveRunNumericLineOrderAndZeroMajor(t *testing.T) {
	f := newFix("0.153", "0.16", "0.15", "0.12", "0.9", "0.8", "0.7")
	r := f.derive(t, fRow, bigCaps)
	want := []string{"0.153", "0.16", "0.15", "0.12", "0.9", "0.8", "0.7"}
	if strings.Join(r.Lines, ",") != strings.Join(want, ",") || r.Floor != "0.7" {
		t.Fatalf("%+v", r)
	}
}

func TestDeriveRunCalverStops(t *testing.T) {
	f := newFix("2024.5", "1.4", "1.3", "1.2", "1.1", "1.0", "0.9")
	r := f.derive(t, fRow, bigCaps)
	if len(r.Lines) != 0 || r.FailReason != "LINE_OUTSIDE_GRAMMAR" || r.Floor != "" {
		t.Fatalf("%+v", r)
	}
}

func TestDeriveRunInputRefusals(t *testing.T) {
	f := newFix(ten()...)
	if _, err := DeriveRun(f.src, nil, fRow, bigCaps); err == nil {
		t.Error("no upstream list accepted")
	}
	if _, err := DeriveRun(f.src, UpstreamList{"github.com/other/repo": nil}, fRow, bigCaps); err == nil {
		t.Error("a list without the repo accepted")
	}
	f.up[fRepo] = append(f.up[fRepo], f.up[fRepo][0])
	if _, err := DeriveRun(f.src, f.up, fRow, bigCaps); err == nil {
		t.Error("an upstream tag listed twice accepted")
	}
	f = newFix(ten()...)
	f.src.tags = append(f.src.tags, f.src.tags[0])
	if _, err := DeriveRun(f.src, f.up, fRow, bigCaps); err == nil {
		t.Error("a mirror tag recorded twice accepted")
	}
	f = newFix(ten()...)
	f.src.err = errors.New("disk")
	if _, err := DeriveRun(f.src, f.up, fRow, bigCaps); err == nil {
		t.Error("a read failure was read as an unlocated line")
	}
	pt := Target{Component: "notes", Repo: fRow.Repo, Form: FormPostTag}
	if _, err := DeriveRun(f.src, f.up, pt, bigCaps); err == nil {
		t.Error("an unread form derived a floor")
	}
}

// Retag and a new patch tag make the window digest differ (the record is stale).
func TestWindowDigestMovesWithRetagAndNewTag(t *testing.T) {
	f := newFix(ten()...)
	d0, _ := f.derive(t, fRow, bigCaps).WindowDigest("1.1")
	f.up[fRepo][0].ObjectID = sha('f')
	d1, _ := f.derive(t, fRow, bigCaps).WindowDigest("1.1")
	if d0 == d1 {
		t.Fatal("retag of an older final tag left the digest")
	}
	f = newFix(ten()...)
	f.add("v1.9.2")
	d2, _ := f.derive(t, fRow, bigCaps).WindowDigest("1.1")
	if d0 == d2 {
		t.Fatal("a new patch tag left the digest")
	}
	if _, err := f.derive(t, fRow, bigCaps).WindowDigest("7.7"); err == nil {
		t.Fatal("digest of a window of an unknown line")
	}
	// The window ends at the floor: a tag below it is not in the digest.
	f = newFix(ten()...)
	a, _ := f.derive(t, fRow, bigCaps).WindowDigest("1.5")
	f.up[fRepo][0].ObjectID = sha('f') // v1.1.0, below the floor 1.5
	b, _ := f.derive(t, fRow, bigCaps).WindowDigest("1.5")
	if a != b {
		t.Fatal("a tag below the floor changed the window digest")
	}
}

func withFloor(t Target, floor string) Target {
	t.Floor = floor
	return t
}

func TestVerifyFloor(t *testing.T) {
	f := newFix(ten()...)
	f.dropFile("v1.3.0") // run 1.10..1.4, derived floor 1.4
	pass := func(floor string) {
		t.Helper()
		if fc, why := VerifyFloor(f.src, f.up, withFloor(fRow, floor), bigCaps); len(why) != 0 || fc.WindowDigest == "" || fc.Derived != "1.4" {
			t.Fatalf("%s: %v %+v", floor, why, fc)
		}
	}
	fail := func(floor, want string) {
		t.Helper()
		_, why := VerifyFloor(f.src, f.up, withFloor(fRow, floor), bigCaps)
		if len(why) != 1 || !strings.Contains(why[0], want) {
			t.Fatalf("%s: %v", floor, why)
		}
	}
	pass("1.4") // equal
	pass("1.5") // newer (narrower), still older than the 5th newest line 1.6
	fail("1.3", "older than the re-derived floor 1.4")
	fail("1.1", "older than the re-derived floor 1.4")
	fail("1.6", "not older than the oldest of the newest 5") // the 5th newest line: second spelling of absent
	fail("1.8", "not older than the oldest of the newest 5") // narrower than the default
	fail("1.0", "not a release line")                        // not in the upstream set
	fail("3.3", "not a release line")
	if _, why := VerifyFloor(f.src, nil, withFloor(fRow, "1.4"), bigCaps); len(why) == 0 || !strings.Contains(why[0], "upstream") {
		t.Fatalf("a floor row without an upstream list passed: %v", why)
	}
	if _, why := VerifyFloor(f.src, f.up, withFloor(fRow, "01.4"), bigCaps); len(why) == 0 {
		t.Fatal("an unparsable stored floor passed")
	}
	// A floor where only the newest 5 lines are provable is wider than provable.
	g := newFix(ten()...)
	g.dropFile("v1.5.1")
	if _, why := VerifyFloor(g.src, g.up, withFloor(fRow, "1.5"), bigCaps); len(why) != 1 || !strings.Contains(why[0], "wider than provable") {
		t.Fatalf("%v", why)
	}
}

// A line the single-file era of which differs from the newest layout is never
// read with the newest layout, and a floor on it fails; it is not shrunk.
func TestVerifyFloorPerEraNoFallback(t *testing.T) {
	f := newFix(ten()...)
	// 1.2 and 1.1 keep their changelog in another place than the row's template.
	for _, n := range []string{"v1.2.0", "v1.2.1", "v1.1.0", "v1.1.1"} {
		f.dropFile(n)
		f.src.files[fRepo+"@"+f.commit(n)+":CHANGELOG.md"] = []byte("## " + strings.TrimPrefix(n, "v") + "\n\n- x\n")
	}
	_, why := VerifyFloor(f.src, f.up, withFloor(fRow, "1.2"), bigCaps)
	if len(why) != 1 || !strings.Contains(why[0], "older than the re-derived floor 1.3") {
		t.Fatalf("%v", why)
	}
	if r := f.derive(t, fRow, bigCaps); r.Floor != "1.3" || r.FailLine != "1.2" {
		t.Fatalf("%+v", r)
	}
}

func TestCapsAtCapAndOver(t *testing.T) {
	f := newFix(ten()...) // 20 tags, 20 blobs, 20*len(pvBody) bytes
	size := len(pvBody) * 20
	cases := []struct {
		name string
		caps Caps
		want string
	}{
		{"at every cap", Caps{20, 20, size}, ""},
		{"tags + 1", Caps{19, 400, 1 << 30}, "WANTS_TOO_LARGE:tags"},
		{"blobs + 1", Caps{200, 19, 1 << 30}, "WANTS_TOO_LARGE:blobs"},
		{"bytes + 1", Caps{200, 400, size - 1}, "WANTS_TOO_LARGE:bytes"},
		{"blobs over with tags under", Caps{200, 3, 1 << 30}, "WANTS_TOO_LARGE:blobs"},
		{"tags unset", Caps{0, 400, 1 << 30}, "WANTS_TOO_LARGE:tags"},
		{"blobs unset", Caps{200, 0, 1 << 30}, "WANTS_TOO_LARGE:blobs"},
		{"bytes unset", Caps{200, 400, 0}, "WANTS_TOO_LARGE:bytes"},
		{"bytes negative", Caps{200, 400, -1}, "WANTS_TOO_LARGE:bytes"},
		{"order: tags before blobs and bytes", Caps{1, 0, 0}, "WANTS_TOO_LARGE:tags"},
		{"order: blobs before bytes", Caps{200, 0, 0}, "WANTS_TOO_LARGE:blobs"},
		{"bytes exceeded first while reading", Caps{200, 2, 1}, "WANTS_TOO_LARGE:bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := DeriveRun(f.src, f.up, fRow, c.caps)
			if c.want == "" {
				if err != nil || r.Floor != "1.1" {
					t.Fatalf("%v %+v", err, r)
				}
				return
			}
			var nr *NoRow
			if !errors.As(err, &nr) || nr.Reason != c.want || r != nil {
				t.Fatalf("want %s, got %v %+v", c.want, err, r)
			}
		})
	}
}

// The constants refuse until the byte cap is measured: never unlimited.
func TestDefaultCapsRefuseWhileBytesUnset(t *testing.T) {
	if MaxWindowTags != 200 || MaxWindowBlobs != 400 || MaxWindowBytes != 0 {
		t.Fatalf("cap constants changed: %d %d %d", MaxWindowTags, MaxWindowBlobs, MaxWindowBytes)
	}
	f := newFix(ten()...)
	_, err := DeriveRun(f.src, f.up, fRow, DefaultCaps())
	var nr *NoRow
	if !errors.As(err, &nr) || nr.Reason != "WANTS_TOO_LARGE:bytes" {
		t.Fatalf("%v", err)
	}
	if _, why := VerifyFloor(f.src, f.up, withFloor(fRow, "1.1"), DefaultCaps()); len(why) != 1 || !strings.Contains(why[0], "WANTS_TOO_LARGE:bytes") {
		t.Fatalf("%v", why)
	}
}

func TestResolveFloorRetriesAreCappedAndEndInNoRow(t *testing.T) {
	var lines []string
	for i := 22; i >= 1; i-- {
		lines = append(lines, fmt.Sprintf("1.%d", i))
	}
	run := &Run{Lines: lines, Floor: "1.1"}
	var tried []string
	floor, err := ResolveFloor(run, func(f string) (bool, error) { tried = append(tried, f); return false, nil })
	var nr *NoRow
	if !errors.As(err, &nr) || nr.Reason != NoRowFloorRetriesExhausted || floor != "" {
		t.Fatalf("%q %v", floor, err)
	}
	if strings.Join(tried, ",") != "1.1,1.2,1.3,1.4" || len(tried) != 1+MaxFloorRetries {
		t.Fatalf("attempts %v", tried)
	}
	// The first retry that passes wins; it is a narrower floor.
	n := 0
	floor, err = ResolveFloor(run, func(f string) (bool, error) { n++; return n == 3, nil })
	if err != nil || floor != "1.3" {
		t.Fatalf("%q %v", floor, err)
	}
	// An error of the check is not an acceptance.
	if _, err := ResolveFloor(run, func(string) (bool, error) { return false, errors.New("io") }); err == nil {
		t.Fatal("check error accepted")
	}
	// Stepping into the newest 5 lines is the absent floor, once, and then ends.
	short := &Run{Lines: lines[:8], Floor: "1.15"}
	tried = nil
	floor, err = ResolveFloor(short, func(f string) (bool, error) { tried = append(tried, f); return f == "", nil })
	if err != nil || floor != "" || strings.Join(tried, ",") != "1.15,1.16,1.17," {
		t.Fatalf("%q %v %v", floor, err, tried)
	}
	// A run without a floor needs no resolving and never calls the check.
	floor, err = ResolveFloor(&Run{Lines: lines[:5]}, func(string) (bool, error) { t.Fatal("called"); return false, nil })
	if err != nil || floor != "" {
		t.Fatal(err)
	}
}

func TestParseUpstreamList(t *testing.T) {
	oid := sha('a')
	line := func(r, o, n string) string { return r + "\t" + o + "\t" + n + "\n" }
	ok := line(fRepo, oid, "v1.0.0") + line(fRepo, sha('b'), "v1.0.1") + line(fRepo, sha('c'), "v1.0.1^{}")
	l, err := ParseUpstreamList([]byte(ok))
	if err != nil || len(l[fRepo]) != 2 {
		t.Fatalf("%v %+v", err, l)
	}
	if _, err := l.UpstreamTags(extract.RepoRef{Key: "github.com/other/x"}); err == nil {
		t.Fatal("a repo without entry gave an empty list")
	}
	bad := map[string]string{
		"empty":            "",
		"no newline":       strings.TrimSuffix(ok, "\n"),
		"two fields":       fRepo + "\tv1.0.0\n",
		"four fields":      fRepo + "\t" + oid + "\tv1.0.0\tx\n",
		"short oid":        line(fRepo, "abc", "v1.0.0"),
		"upper oid":        line(fRepo, strings.ToUpper(oid), "v1.0.0"),
		"bad repo":         line("example/notes", oid, "v1.0.0"),
		"non canonical":    line("github.com/Example/Notes", oid, "v1.0.0"),
		"duplicate":        line(fRepo, oid, "v1.0.0") + line(fRepo, sha('b'), "v1.0.0"),
		"odd name":         line(fRepo, oid, "v1.0.0 x"),
		"name starts dash": line(fRepo, oid, "-v1"),
		"blank line":       line(fRepo, oid, "v1.0.0") + "\n",
		"crlf":             fRepo + "\t" + oid + "\tv1.0.0\r\n",
		"only peeled":      line(fRepo, oid, "v1.0.0^{}"),
	}
	for name, d := range bad {
		if _, err := ParseUpstreamList([]byte(d)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseUpstreamList(make([]byte, MaxUpstreamListBytes+1)); err == nil {
		t.Error("oversize list accepted")
	}
}

func withCaps(t *testing.T, c Caps) {
	t.Helper()
	old := floorCaps
	floorCaps = func() Caps { return c }
	t.Cleanup(func() { floorCaps = old })
}

func TestProposeRowFloorEndToEnd(t *testing.T) {
	withCaps(t, bigCaps)
	f := newFix(ten()...)
	p, err := ProposeRowFloor(f.src, f.up, "notes", fRepo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Floor != "1.1" || p.Row.Floor == nil || *p.Row.Floor != "1.1" || p.WindowDigest == "" {
		t.Fatalf("%+v", p)
	}
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"floor":"1.1"`) || !strings.Contains(string(b), `"windowTagsDigest":"`+p.WindowDigest+`"`) {
		t.Fatalf("%s", b)
	}
	// The proposed row loads through the strict loader and passes the check.
	var out struct{ Row json.RawMessage }
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	tg, err := parseTargets(doc(string(out.Row)))
	if err != nil || tg[0].Floor != "1.1" {
		t.Fatalf("%v %+v", err, tg)
	}
	if fc, why := VerifyFloor(f.src, f.up, tg[0], bigCaps); len(why) != 0 || fc.WindowDigest != p.WindowDigest {
		t.Fatalf("%v %+v", why, fc)
	}
	// Floor 1.2 (narrower than provable) passes; the stored row with an
	// older value than provable cannot exist: a gap fails it.
	f.dropFile("v1.2.1")
	if _, why := VerifyFloor(f.src, f.up, tg[0], bigCaps); len(why) != 1 {
		t.Fatalf("%v", why)
	}
	// Re-proposing over the gap narrows the floor, never keeps the old one.
	p2, err := ProposeRowFloor(f.src, f.up, "notes", fRepo, nil)
	if err != nil || p2.Floor != "1.3" {
		t.Fatalf("%+v", p2)
	}
}

func TestProposeRowFloorAbsentWithoutUpstreamOrRun(t *testing.T) {
	withCaps(t, bigCaps)
	f := newFix(ten()[:5]...)
	plain, err := ProposeRow(f.src, "notes", fRepo, nil)
	if err != nil {
		t.Fatal(err)
	}
	with, err := ProposeRowFloor(f.src, f.up, "notes", fRepo, nil)
	if err != nil || with.Floor != "" || with.Row.Floor != nil {
		t.Fatalf("%v %+v", err, with)
	}
	if with.WindowDigest == "" {
		t.Fatal("the newest-5 window digest is not pinned")
	}
	pb, _ := json.Marshal(plain)
	wb, _ := json.Marshal(with)
	if strings.Contains(string(pb), "windowTagsDigest") || strings.Contains(string(pb), "floor") {
		t.Fatalf("output without an upstream list changed: %s", pb)
	}
	if !strings.HasPrefix(string(wb), strings.TrimSuffix(string(pb), "}")) {
		t.Fatalf("absent floor changed the row:\n%s\n%s", pb, wb)
	}
	if _, err := ProposeRowFloor(f.src, f.up, "notes", fRepo, []string{"v1.1.0"}); err == nil {
		t.Fatal("explicit tags with an upstream list accepted")
	}
}

func TestProposeRowFloorRefusesWithUnsetByteCap(t *testing.T) {
	f := newFix(ten()...)
	_, err := ProposeRowFloor(f.src, f.up, "notes", fRepo, nil)
	var nr *NoRow
	if !errors.As(err, &nr) || nr.Reason != "WANTS_TOO_LARGE:bytes" {
		t.Fatalf("%v", err)
	}
	withCaps(t, Caps{Tags: 5, Blobs: 400, Bytes: 1 << 30})
	if _, err := ProposeRowFloor(f.src, f.up, "notes", fRepo, nil); !errors.As(err, &nr) || nr.Reason != "WANTS_TOO_LARGE:tags" {
		t.Fatalf("%v", err)
	}
}

// Two heading styles of the closed table reading one tag are an ambiguity:
// the line fails, whatever the order of the row's styles.
func TestStyleAmbiguityAndOrderIndependence(t *testing.T) {
	file := "## 1.5.0\n\n- a\n\n## [1.5.0]\n\n- b\n\n## 1.4.0\n\n- c\n"
	row := Target{Component: "notes", Repo: fRow.Repo, Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern: headingStyles["version-plain"], BoundaryPatterns: []string{boundaryStyles["unreleased"], boundaryStyles["prerelease-plain"]}}
	rev := row
	rev.BoundaryPatterns = []string{boundaryStyles["prerelease-plain"], boundaryStyles["unreleased"]}
	var res []string
	for _, rw := range []Target{row, rev} {
		c := testCommit
		src := &fSrc{memReader: memReader{files: map[string][]byte{fRepo + "@" + c + ":CHANGELOG.md": []byte(file)}}, tags: []extract.Tag{{Name: "v1.5.0", Commit: c}}}
		reason, err := evalLine(&capReader{inner: src, caps: bigCaps, seen: map[string]capRead{}}, rw, "1.5",
			[]UpstreamTag{{"v1.5.0", c}}, map[string]extract.Tag{"v1.5.0": src.tags[0]}, false)
		if err != nil {
			t.Fatal(err)
		}
		res = append(res, reason)
	}
	if res[0] != res[1] || res[0] == "" {
		t.Fatalf("a tag read by two styles locates, or order matters: %v", res)
	}
	// One style only: the same tag with a single heading locates.
	one := "## 1.5.0\n\n- a\n"
	c := testCommit
	src := &fSrc{memReader: memReader{files: map[string][]byte{fRepo + "@" + c + ":CHANGELOG.md": []byte(one)}}, tags: []extract.Tag{{Name: "v1.5.0", Commit: c}}}
	reason, err := evalLine(&capReader{inner: src, caps: bigCaps, seen: map[string]capRead{}}, row, "1.5",
		[]UpstreamTag{{"v1.5.0", c}}, map[string]extract.Tag{"v1.5.0": src.tags[0]}, false)
	if err != nil || reason != "" {
		t.Fatalf("%q %v", reason, err)
	}
}

func TestStyleAmbiguousBranch(t *testing.T) {
	// A single heading that two distinct styles both read as the version: the
	// closed table has no such pair, so the branch is exercised with a row whose
	// own pattern is a different string for the same heading.
	row := Target{Component: "notes", Repo: fRow.Repo, Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   `^(?P<version>[0-9]+[.][0-9]+[.][0-9]+)$`, // same reading as "version-plain", other spelling
		BoundaryPatterns: []string{boundaryStyles["unreleased"]}}
	c := testCommit
	src := &fSrc{memReader: memReader{files: map[string][]byte{fRepo + "@" + c + ":CHANGELOG.md": []byte("## 1.5.0\n\n- a\n")}}, tags: []extract.Tag{{Name: "v1.5.0", Commit: c}}}
	reason, err := evalLine(&capReader{inner: src, caps: bigCaps, seen: map[string]capRead{}}, row, "1.5",
		[]UpstreamTag{{"v1.5.0", c}}, map[string]extract.Tag{"v1.5.0": src.tags[0]}, false)
	if err != nil || !strings.HasPrefix(reason, "STYLE_AMBIGUOUS:v1.5.0:version-plain") {
		t.Fatalf("%q %v", reason, err)
	}
}
