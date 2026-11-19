// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// memSource is a memReader with recorded tags.
type memSource struct {
	*memReader
	tags []extract.Tag
}

func (m memSource) Tags(extract.RepoRef) ([]extract.Tag, error) { return m.tags, nil }

// memBlobs serves blobs by id; a nil entry is a fetch error.
type memBlobs map[string][]byte

func (m memBlobs) FetchBlob(id string) ([]byte, error) {
	b, ok := m[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

func commitN(n int) string { return fmt.Sprintf("%040x", n) }

// synth builds a passing prometheus-shaped row over three tags and returns the
// row, its digest, the fixture built from it and the blobs the fixture pins.
func synth(t *testing.T) (Target, string, *RowFixture, memBlobs) {
	t.Helper()
	row, err := Lookup(Reviewed, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	digests, err := RowDigests()
	if err != nil {
		t.Fatal(err)
	}
	src := memSource{memReader: &memReader{files: map[string][]byte{}}}
	blobs := memBlobs{}
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		c := commitN(i + 1)
		file := "# Changelog\n\n## main / unreleased\n\n* [FEATURE] new\n\n## " + v + " / 2026-01-02\n\n* [BUGFIX] fix " + v + "\n\n## 0.9.0 / 2025-01-01\n\n* [BUGFIX] old\n"
		src.files[row.Repo.Key+"@"+c+":"+row.Path] = []byte(file)
		src.tags = append(src.tags, extract.Tag{Name: "v" + v, Commit: c})
		blobs[GitBlobID([]byte(file))] = []byte(file)
	}
	src.tags = append(src.tags, extract.Tag{Name: "v1.3.0-rc.0", Commit: commitN(9)})
	fx, err := BuildRowFixture(src, row, digests["prometheus"], zeroDigest)
	if err != nil {
		t.Fatal(err)
	}
	return row, digests["prometheus"], fx, blobs
}

func roundTrip(t *testing.T, fx *RowFixture) []byte {
	t.Helper()
	b, err := fx.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRowFixture(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRowFixtureRecheckPassesAndHoldsNoText(t *testing.T) {
	row, digest, fx, blobs := synth(t)
	b := roundTrip(t, fx)
	if strings.Contains(string(b), "BUGFIX") || strings.Contains(string(b), "Changelog") {
		t.Fatalf("fixture holds changelog text: %s", b)
	}
	if len(fx.Tags) != 3 || fx.Window != 3 || fx.Status != RowPass {
		t.Fatalf("fixture %+v", fx)
	}
	if err := RecheckRowFixture(fx, row, digest, blobs, zeroDigest); err != nil {
		t.Fatal(err)
	}
}

// A bot-written fixture is never trusted: every field a bot could edit is
// recomputed or re-verified, and the loader is strict.
func TestRowFixtureLoaderStrict(t *testing.T) {
	_, _, fx, _ := synth(t)
	good := string(roundTrip(t, fx))
	edit := func(from, to string) string {
		if !strings.Contains(good, from) {
			t.Fatalf("no %q in fixture", from)
		}
		return strings.Replace(good, from, to, 1)
	}
	cases := map[string]string{
		"unknown field":      edit(`"component"`, `"readerDigest": "sha256:`+strings.Repeat("0", 64)+`", "component"`),
		"duplicate key":      edit(`"form": "changelog-file",`, `"form": "changelog-file", "form": "changelog-file",`),
		"trailing data":      good + "{}",
		"wrong schema":       edit(RowFixtureSchema, "prufyx.io/changelog-row-fixture/v2"),
		"bad row digest":     edit(fx.RowDigest, "sha256:xyz"),
		"count mismatch":     edit(`"located": 3`, `"located": 2`),
		"status not pass":    edit(`"status": "PASS"`, `"status": "FAIL"`),
		"text as path":       edit(`"path": "CHANGELOG.md"`, `"path": "## 1.0.0 / 2026 fix"`),
		"dotdot path":        edit(`"path": "CHANGELOG.md"`, `"path": "a/../b.md"`),
		"non-final tag":      edit(`"name": "v1.0.0"`, `"name": "v1.0.0-rc.1"`),
		"tag with text":      edit(`"name": "v1.0.0"`, `"name": "v1.0.0 fixed things"`),
		"short commit":       edit(`"commit": "`+commitN(1)+`"`, `"commit": "abc"`),
		"outcome unknown":    edit(`"outcome": "located"`, `"outcome": "maybe"`),
		"located with code":  edit(`"outcome": "located"`, `"outcome": "located", "code": "ENTRY_MISSING"`),
		"empty withheld nil": edit(`"withheld": {}`, `"withheld": null`),
		"withheld in pass":   edit(`"outcome": "located"`, `"outcome": "withheld", "code": "ENTRY_MISSING"`),
		"bad blob id":        edit(`"blobId": "`+fx.Tags[0].Reads[0].BlobID+`"`, `"blobId": "ZZ"`),
		"window wrong":       edit(`"window": 3`, `"window": 2`),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRowFixture([]byte(doc)); err == nil {
				t.Fatalf("accepted: %s", name)
			}
		})
	}
	// Tags out of order, duplicate tag and a text-bearing extra file are refused.
	var raw map[string]any
	if err := json.Unmarshal([]byte(good), &raw); err != nil {
		t.Fatal(err)
	}
	tags := raw["tags"].([]any)
	tags[0], tags[1] = tags[1], tags[0]
	b, _ := json.Marshal(raw)
	if _, err := ParseRowFixture(b); err == nil {
		t.Fatal("unsorted tags accepted")
	}
	tags[0], tags[1] = tags[1], tags[0]
	tags[1] = tags[0]
	b, _ = json.Marshal(raw)
	if _, err := ParseRowFixture(b); err == nil {
		t.Fatal("duplicate tag accepted")
	}
}

func TestRowFixtureRefusesRowDigestDrift(t *testing.T) {
	row, digest, fx, blobs := synth(t)
	if err := RecheckRowFixture(fx, row, "sha256:"+strings.Repeat("1", 64), blobs, zeroDigest); err == nil {
		t.Fatal("a row digest that is not the fixture's was accepted")
	}
	if err := RecheckRowFixture(fx, row, "", blobs, zeroDigest); err == nil {
		t.Fatal("an empty row digest was accepted")
	}
	wrongForm := row
	wrongForm.Form = FormGithubRelease
	if err := fx.MatchRow(wrongForm, digest); err == nil {
		t.Fatal("a fixture of another form was accepted")
	}
	wrongName := row
	wrongName.Component = "other"
	if err := fx.MatchRow(wrongName, digest); err == nil {
		t.Fatal("a fixture of another component was accepted")
	}
	// A bot that edits the row and the fixture digest together still fails the
	// re-run: the blobs the fixture pins do not locate at the other path.
	fx2 := *fx
	fx2.RowDigest = strings.Repeat("2", 64)
	if err := RecheckRowFixture(&fx2, row, digest, blobs, zeroDigest); err == nil {
		t.Fatal("a self-consistent but unrecomputed digest was accepted")
	}
}

// C1: a re-run that needs blobs fetches them by pinned id, verifies the hash
// and fails closed.
func TestRowsCheckFixtureRefusesUnverifiedBlob(t *testing.T) {
	row, digest, fx, blobs := synth(t)
	id := fx.Tags[0].Reads[0].BlobID
	altered := func() memBlobs {
		m := memBlobs{}
		for k, v := range blobs {
			m[k] = v
		}
		return m
	}
	cases := map[string]BlobFetcher{
		"no fetcher": nil,
		"blob absent": func() BlobFetcher {
			m := altered()
			delete(m, id)
			return m
		}(),
		"content altered": func() BlobFetcher {
			m := altered()
			m[id] = append([]byte("x"), m[id]...)
			return m
		}(),
		"content truncated": func() BlobFetcher {
			m := altered()
			m[id] = m[id][:len(m[id])-1]
			return m
		}(),
		"empty blob": func() BlobFetcher {
			m := altered()
			m[id] = []byte{}
			return m
		}(),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			err := RecheckRowFixture(fx, row, digest, f, zeroDigest)
			if !errors.Is(err, ErrUnverifiedBlob) {
				t.Fatalf("want ErrUnverifiedBlob, got %v", err)
			}
		})
	}
	// The sha256 and the size are checked on their own, not only the git id.
	bad := *fx
	bad.Tags = append([]RowFixtureTag(nil), fx.Tags...)
	bad.Tags[0].Reads = append([]RowFixtureRead(nil), fx.Tags[0].Reads...)
	bad.Tags[0].Reads[0].SHA256 = "sha256:" + strings.Repeat("3", 64)
	if err := RecheckRowFixture(&bad, row, digest, blobs, zeroDigest); !errors.Is(err, ErrUnverifiedBlob) {
		t.Fatalf("sha256 mismatch: %v", err)
	}
	bad.Tags[0].Reads[0].SHA256 = fx.Tags[0].Reads[0].SHA256
	bad.Tags[0].Reads[0].Size++
	if err := RecheckRowFixture(&bad, row, digest, blobs, zeroDigest); !errors.Is(err, ErrUnverifiedBlob) {
		t.Fatalf("size mismatch: %v", err)
	}
	// A blob that verifies but whose outcome differs from the record is refused.
	flip := *fx
	flip.Tags = append([]RowFixtureTag(nil), fx.Tags...)
	flip.Tags[0].Outcome, flip.Tags[0].Code = OutcomeWithheld, string(EntryMissing)
	if err := RecheckRowFixture(&flip, row, digest, blobs, zeroDigest); err == nil {
		t.Fatal("a differing recorded outcome was accepted")
	}
	// A read the fixture did not record is an error, never "absent".
	rd, _, err := OpenFixtureSourceFor(fx, row.Repo, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Read(row.Repo, fx.Tags[0].Commit, "other.md"); err == nil || errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("unrecorded read: %v", err)
	}
	if _, err := rd.Read(row.Repo, commitN(77), row.Path); err == nil || errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("unrecorded commit: %v", err)
	}
}

func TestDirBlobFetcherRefusesNonIds(t *testing.T) {
	d := DirBlobFetcher{Dir: t.TempDir()}
	for _, id := range []string{"", "../etc/passwd", strings.Repeat("g", 40), strings.Repeat("a", 39), strings.Repeat("A", 40)} {
		if _, err := d.FetchBlob(id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	if _, err := d.FetchBlob(strings.Repeat("a", 40)); err == nil {
		t.Fatal("a blob that is not there was served")
	}
}

func TestBuildRowFixtureRefusesRowThatDoesNotPass(t *testing.T) {
	row, err := Lookup(Reviewed, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	src := memSource{memReader: &memReader{files: map[string][]byte{}}, tags: []extract.Tag{{Name: "v1.0.0", Commit: commitN(1)}}}
	if _, err := BuildRowFixture(src, row, row.RowDigest(), zeroDigest); err == nil {
		t.Fatal("a tag without the file gave a fixture")
	}
	src.memReader.err = errReadBoom
	if _, err := BuildRowFixture(src, row, row.RowDigest(), zeroDigest); err == nil {
		t.Fatal("a read failure gave a fixture")
	}
}

// shipped loads the shipped table, row digests and fixtures.
func shipped(t *testing.T) ([]Target, map[string]string, map[string]*RowFixture) {
	t.Helper()
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	digests, err := RowDigests()
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := LoadRowFixtures(os.DirFS("testdata"), RowFixtureDir, Reviewed, digests)
	if err != nil {
		t.Fatal(err)
	}
	return Reviewed, digests, fixtures
}

func fixtureFS(t *testing.T, fx ...*RowFixture) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	for _, f := range fx {
		m[RowFixtureDir+"/"+f.Component+".json"] = &fstest.MapFile{Data: roundTrip(t, f)}
	}
	return m
}

func fixtureList(fixtures map[string]*RowFixture, skip string) []*RowFixture {
	var out []*RowFixture
	for _, c := range sortedKeys(fixtures) {
		if c != skip {
			out = append(out, fixtures[c])
		}
	}
	return out
}

func sortedKeys(m map[string]*RowFixture) []string {
	var k []string
	for c := range m {
		k = append(k, c)
	}
	sort.Strings(k)
	return k
}

func without(rows []Target, comp string) []Target {
	var out []Target
	for _, r := range rows {
		if r.Component != comp {
			out = append(out, r)
		}
	}
	return out
}

func copyFixture(fx *RowFixture) *RowFixture {
	c := *fx
	c.Tags = append([]RowFixtureTag(nil), fx.Tags...)
	c.Withheld = map[string]int{}
	for k, v := range fx.Withheld {
		c.Withheld[k] = v
	}
	return &c
}

// B1: the fixture row digest is the one Target.RowDigest, bare hex, the same
// value a receipt carries.
func TestFixtureRowDigestIsTargetRowDigest(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	for _, r := range rows {
		if got := fixtures[r.Component].RowDigest; got != r.RowDigest() || digests[r.Component] != r.RowDigest() || len(got) != 64 || strings.Contains(got, ":") {
			t.Fatalf("%s: fixture digest %q, row digest %q", r.Component, got, r.RowDigest())
		}
	}
}

// A3: a fixture holds the newest 8 versions and every final tag of the newest
// 5 lines, no more and no fewer.
func TestFixtureScopeIsPinned(t *testing.T) {
	var finals []string
	for minor := 0; minor <= 6; minor++ {
		for patch := 0; patch <= 2; patch++ {
			finals = append(finals, fmt.Sprintf("v1.%d.%d", minor, patch))
		}
	}
	// A line with many patches keeps all of them, beyond the newest 8 versions.
	for patch := 3; patch <= 12; patch++ {
		finals = append(finals, fmt.Sprintf("v1.6.%d", patch))
	}
	got := fixtureScope(finals)
	want := map[string]bool{}
	for _, n := range finals {
		var minor int
		fmt.Sscanf(n, "v1.%d.", &minor)
		if minor >= 2 {
			want[n] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("scope has %d tags, want %d: %v", len(got), len(want), got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected %s in scope", n)
		}
	}
	// Idempotent: the scope of a scope is itself.
	if again := fixtureScope(got); strings.Join(again, ",") != strings.Join(got, ",") {
		t.Fatal("scope is not idempotent")
	}
	// The builder records exactly that scope.
	row, err := Lookup(Reviewed, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	var file strings.Builder
	file.WriteString("# Changelog\n\n## main / unreleased\n\n* [FEATURE] x\n\n")
	src := memSource{memReader: &memReader{files: map[string][]byte{}}}
	for _, n := range finals {
		fmt.Fprintf(&file, "## %s / 2026-01-02\n\n* [BUGFIX] f\n\n", strings.TrimPrefix(n, "v"))
	}
	for i, n := range finals {
		c := commitN(i + 1)
		src.files[row.Repo.Key+"@"+c+":"+row.Path] = []byte(file.String())
		src.tags = append(src.tags, extract.Tag{Name: n, Commit: c})
	}
	fx, err := BuildRowFixture(src, row, row.RowDigest(), zeroDigest)
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.Tags) != len(want) {
		t.Fatalf("fixture has %d tags, want %d", len(fx.Tags), len(want))
	}
	roundTrip(t, fx)
	// A fixture that adds a tag of an older line is not the scope and is
	// refused. A fixture cannot prove it has every tag of a line (that is the
	// builder's and the blob re-run's job); a dropped tag is caught offline by
	// the fixture digest (TestOfflineHiddenTagInFixtureFails).
	for name, mutate := range map[string]func(*RowFixture){
		"older line tag": func(f *RowFixture) {
			tg := f.Tags[0]
			tg.Name = "v1.0.0"
			f.Tags = append([]RowFixtureTag{tg}, f.Tags...)
			f.Located++
		},
	} {
		bad := copyFixture(fx)
		mutate(bad)
		b, err := bad.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRowFixture(b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// A4: a read-form row with a SKIP fixture fails, however the fixture is built.
func TestReadFormRowWithSkipFixtureFails(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	prom, _ := Lookup(rows, "prometheus")
	skip := &RowFixture{Schema: RowFixtureSchema, Component: "prometheus", RowDigest: digests["prometheus"], Form: FormFile, Status: RowSkip, Withheld: map[string]int{}, Tags: []RowFixtureTag{}}
	b, _ := skip.Bytes()
	if _, err := ParseRowFixture(b); err == nil {
		t.Fatal("a SKIP fixture of a read form parsed")
	}
	// A skip-form body filed under the read row: the form differs from the row.
	skip.Form = FormPostTag
	m := fixtureFS(t, fixtureList(fixtures, "prometheus")...)
	m[RowFixtureDir+"/prometheus.json"] = &fstest.MapFile{Data: mustBytes(t, skip)}
	if _, err := LoadRowFixtures(m, RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a read-form row with a skip-form fixture loaded")
	}
	// And offline, a fixture map holding it is refused as well.
	fixtures2 := map[string]*RowFixture{}
	for k, v := range fixtures {
		fixtures2[k] = v
	}
	fixtures2["prometheus"] = skip
	if err := CheckRowsOffline([]Target{prom}, digests, fixtures2, rowsRechecked); err == nil {
		t.Fatal("offline accepted a read-form row with a skip fixture")
	}
}

// A1: offline, a read-form row passes only at the digests it was re-checked at.
func TestOfflineForgedNewRowAndFixtureFails(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	prom, _ := Lookup(rows, "prometheus")
	forged := prom
	forged.Component, forged.Repo = "forged-component", extract.RepoRef{Key: "github.com/example/forged"}
	fx := copyFixture(fixtures["prometheus"])
	fx.Component, fx.RowDigest = forged.Component, forged.RowDigest()
	// The forgery is self-consistent: the strict loader and the digest accept it.
	b, _ := fx.Bytes()
	if _, err := ParseRowFixture(b); err != nil {
		t.Fatalf("forgery must be self-consistent to prove the point: %v", err)
	}
	all := append(append([]Target(nil), rows...), forged)
	d2 := map[string]string{forged.Component: forged.RowDigest()}
	f2 := map[string]*RowFixture{forged.Component: fx}
	for k, v := range digests {
		d2[k] = v
	}
	for k, v := range fixtures {
		f2[k] = v
	}
	if err := CheckRowsOffline(rows, digests, fixtures, rowsRechecked); err != nil {
		t.Fatalf("the shipped rows must pass offline: %v", err)
	}
	if err := CheckRowsOffline(all, d2, f2, rowsRechecked); err == nil {
		t.Fatal("a forged new row with its fixture passed offline")
	}
}

// A1: a fixture edited to hide a tag (status still PASS, strict loader happy)
// fails offline, because the fixture digest is no longer the re-checked one.
func TestOfflineHiddenTagInFixtureFails(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	fx := copyFixture(fixtures["prometheus"])
	fx.Tags = fx.Tags[1:] // the newest tag is dropped
	fx.Located = len(fx.Tags)
	fx.Window = len(newestVersions(tagNames(fx), DefaultMinLocatedNewest))
	fx.WindowLocated = fx.Window
	b, _ := fx.Bytes()
	parsed, err := ParseRowFixture(b)
	if err != nil {
		t.Fatalf("the edit must stay self-consistent: %v", err)
	}
	if parsed.Status != RowPass {
		t.Fatal("status changed")
	}
	f2 := map[string]*RowFixture{}
	for k, v := range fixtures {
		f2[k] = v
	}
	f2["prometheus"] = parsed
	if err := CheckRowsOffline(rows, digests, f2, rowsRechecked); err == nil {
		t.Fatal("an edited fixture passed offline")
	}
	// A changed row (new path) with its fixture digest updated fails as well.
	prom, _ := Lookup(rows, "prometheus")
	moved := prom
	moved.Path = "docs/CHANGELOG.md"
	g := copyFixture(fixtures["prometheus"])
	g.RowDigest = moved.RowDigest()
	rows2 := append(without(rows, "prometheus"), moved)
	d2 := map[string]string{}
	for k, v := range digests {
		d2[k] = v
	}
	d2["prometheus"] = moved.RowDigest()
	f3 := map[string]*RowFixture{}
	for k, v := range fixtures {
		f3[k] = v
	}
	f3["prometheus"] = g
	if err := CheckRowsOffline(rows2, d2, f3, rowsRechecked); err == nil {
		t.Fatal("a changed row passed offline")
	}
}

func tagNames(fx *RowFixture) []string {
	var n []string
	for _, tg := range fx.Tags {
		n = append(n, tg.Name)
	}
	return n
}

// fixtureSource.Read matches repo and commit.
func TestFixtureSourceBindsRepo(t *testing.T) {
	row, _, fx, blobs := synth(t)
	rd, tags, err := OpenFixtureSourceFor(fx, row.Repo, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Read(row.Repo, fx.Tags[0].Commit, row.Path); err != nil {
		t.Fatal(err)
	}
	other := extract.RepoRef{Key: "github.com/example/other"}
	if _, err := rd.Read(other, fx.Tags[0].Commit, row.Path); err == nil {
		t.Fatal("a read for another repo was served")
	}
	if _, err := tags.Tags(other); err == nil {
		t.Fatal("tags of another repo were served")
	}
}

func TestRowFixtureDirectoryIsOneToOne(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	all := fixtureList(fixtures, "")
	if _, err := LoadRowFixtures(fixtureFS(t, all...), RowFixtureDir, rows, digests); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRowFixtures(fixtureFS(t, fixtureList(fixtures, "prometheus")...), RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a read row without a fixture passed")
	}
	if _, err := LoadRowFixtures(fixtureFS(t, all...), RowFixtureDir, without(rows, "prometheus"), digests); err == nil {
		t.Fatal("an orphan fixture passed")
	}
	m := fixtureFS(t, all...)
	m[RowFixtureDir+"/zzz.json"] = m[RowFixtureDir+"/prometheus.json"]
	if _, err := LoadRowFixtures(m, RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a fixture under another name passed")
	}
	m = fixtureFS(t, all...)
	m[RowFixtureDir+"/README.md"] = &fstest.MapFile{Data: []byte("# notes")}
	if _, err := LoadRowFixtures(m, RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a stray file passed")
	}
	m = fixtureFS(t, all...)
	m[RowFixtureDir+"/sub/x.json"] = &fstest.MapFile{Data: []byte("{}")}
	if _, err := LoadRowFixtures(m, RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a subdirectory passed")
	}
	stale := copyFixture(fixtures["prometheus"])
	stale.RowDigest = strings.Repeat("4", 64)
	m = fixtureFS(t, append(fixtureList(fixtures, "prometheus"), stale)...)
	if _, err := LoadRowFixtures(m, RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a stale row digest passed")
	}
}

func mustBytes(t *testing.T, fx *RowFixture) []byte {
	t.Helper()
	b, err := fx.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pinsDocBytes(t *testing.T, pins ...rowPin) []byte {
	t.Helper()
	b, err := json.Marshal(pinsDoc{Schema: RowPinsSchema, Pins: pins})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A pin adds no row: a read-form row with a pin and no fixture still fails,
// and a pin for a component without a fixture is refused.
func TestPinsFileCannotAddRowWithoutFixtureCheck(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	rest := map[string]*RowFixture{}
	for k, v := range fixtures {
		if k != "prometheus" {
			rest[k] = v
		}
	}
	if _, err := LoadRowFixtures(fixtureFS(t, fixtureList(fixtures, "prometheus")...), RowFixtureDir, rows, digests); err == nil {
		t.Fatal("a pinned row without a fixture passed the fixture check")
	}
	pin := pinsDocBytes(t, rowPin{Component: "prometheus", RowDigest: digests["prometheus"]})
	if err := CheckRowPins(pin, rest, digests); err == nil {
		t.Fatal("a pin without a fixture was accepted")
	}
	if err := CheckRowPins(pinsDocBytes(t, rowPin{Component: "ghost", RowDigest: digests["prometheus"]}), fixtures, digests); err == nil {
		t.Fatal("a pin without a row was accepted")
	}
	good := rowPin{Component: "alertmanager", RowDigest: digests["alertmanager"]}
	for name, doc := range map[string][]byte{
		"wrong digest": pinsDocBytes(t, rowPin{Component: "alertmanager", RowDigest: strings.Repeat("0", 64)}),
		"duplicate":    pinsDocBytes(t, good, good),
		"unsorted":     pinsDocBytes(t, rowPin{Component: "prometheus", RowDigest: digests["prometheus"]}, good),
		"trailing":     append(pinsDocBytes(t, good), []byte("{}")...),
		"bad schema":   []byte(`{"schema":"x","pins":[]}`),
		"empty":        []byte(""),
	} {
		if err := CheckRowPins(doc, fixtures, digests); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := CheckRowPins(pinsDocBytes(t, good), fixtures, digests); err != nil {
		t.Fatal(err)
	}
	if err := CheckRowPins(nil, fixtures, digests); err != nil {
		t.Fatal(err)
	}
}

// A pin holds the row digest only. A reader digest in a pin is refused, and the
// reader code digest, which only labels manifests, decides no outcome: the
// per-tag results of the re-run are equal under any value of it. The row
// digest itself does depend on the resolved style patterns, so a pattern
// change stales the pin and the fixture (they are regenerated together).
func TestPinsIgnoreReaderDigestDrift(t *testing.T) {
	row, digest, fx, blobs := synth(t)
	withReader := []byte(`{"schema":"` + RowPinsSchema + `","pins":[{"component":"prometheus","rowDigest":"` + digest + `","readerDigest":"` + zeroDigest + `"}]}`)
	fixtures := map[string]*RowFixture{"prometheus": fx}
	digests := map[string]string{"prometheus": digest}
	if err := CheckRowPins(withReader, fixtures, digests); err == nil {
		t.Fatal("a pin holding a reader digest was accepted")
	}
	rd, tags, err := OpenFixtureSourceFor(fx, row.Repo, blobs)
	if err != nil {
		t.Fatal(err)
	}
	src := struct {
		extract.PinnedReader
		extract.TagSource
	}{rd, tags}
	var first []string
	for _, reader := range []string{zeroDigest, "sha256:" + strings.Repeat("9", 64)} {
		var got []string
		for _, tg := range fx.Tags {
			m, err := BuildManifest(src, row, extract.Tag{Name: tg.Name, Commit: tg.Commit}, reader)
			if err != nil {
				t.Fatal(err)
			}
			if m.Extractor.CodeDigest != reader {
				t.Fatal("the reader digest is only a label and must be carried as given")
			}
			if m.Entry == nil {
				got = append(got, tg.Name+":withheld")
			} else {
				got = append(got, tg.Name+":"+m.Entry.Version)
			}
		}
		if first == nil {
			first = got
		} else if strings.Join(first, ",") != strings.Join(got, ",") {
			t.Fatal("the reader digest changed an outcome")
		}
		if err := RecheckRowFixture(fx, row, digest, blobs, reader); err != nil {
			t.Fatal(err)
		}
	}
	moved := row
	moved.HeadingPattern = `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`
	if moved.RowDigest() == digest {
		t.Fatal("a pattern change must change the row digest")
	}
	if err := RecheckRowFixture(fx, moved, moved.RowDigest(), blobs, zeroDigest); err == nil {
		t.Fatal("a fixture was accepted for a row it was not recorded for")
	}
}

// C2: a removal deletes row, fixture and pin together; any one left behind is
// refused. The row removed is a read-form row of the shipped table.
func TestRemovalPRLeavesNoOrphanFixture(t *testing.T) {
	rows, digests, fixtures := shipped(t)
	const gone = "alertmanager"
	if r, _ := Lookup(rows, gone); !readsForm(r.Form) {
		t.Fatalf("%s must be a read-form row for this test", gone)
	}
	rest := without(rows, gone)
	restFx := fixtureList(fixtures, gone)
	restMap := map[string]*RowFixture{}
	for _, f := range restFx {
		restMap[f.Component] = f
	}
	restDigests := map[string]string{}
	for _, r := range rest {
		restDigests[r.Component] = digests[r.Component]
	}
	pin := func(comps ...string) []byte {
		var ps []rowPin
		for _, c := range comps {
			ps = append(ps, rowPin{Component: c, RowDigest: digests[c]})
		}
		return pinsDocBytes(t, ps...)
	}
	if _, err := LoadRowFixtures(fixtureFS(t, fixtureList(fixtures, "")...), RowFixtureDir, rest, restDigests); err == nil {
		t.Fatal("the fixture of a removed row was left behind and passed")
	}
	if err := CheckRowPins(pin(gone), restMap, restDigests); err == nil {
		t.Fatal("the pin of a removed row was left behind and passed")
	}
	got, err := LoadRowFixtures(fixtureFS(t, restFx...), RowFixtureDir, rest, restDigests)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRowPins(pin("prometheus"), got, restDigests); err != nil {
		t.Fatal(err)
	}
	if err := CheckRowsOffline(rest, restDigests, got, rowsRechecked); err != nil {
		t.Fatalf("a clean removal must pass offline: %v", err)
	}
}
