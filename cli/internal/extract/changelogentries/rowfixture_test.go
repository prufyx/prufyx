// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"fmt"
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
	fx2.RowDigest = "sha256:" + strings.Repeat("2", 64)
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
	rd, _, err := OpenFixtureSource(fx, blobs)
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
	if _, err := BuildRowFixture(src, row, zeroDigest, zeroDigest); err == nil {
		t.Fatal("a tag without the file gave a fixture")
	}
	src.memReader.err = errReadBoom
	if _, err := BuildRowFixture(src, row, zeroDigest, zeroDigest); err == nil {
		t.Fatal("a read failure gave a fixture")
	}
}

// loadShipped loads the shipped fixtures as a file system keyed like the
// directory.
func shippedTable(t *testing.T) ([]Target, map[string]string) {
	t.Helper()
	if err := LoadError(); err != nil {
		t.Fatal(err)
	}
	digests, err := RowDigests()
	if err != nil {
		t.Fatal(err)
	}
	return Reviewed, digests
}

func fixtureFS(t *testing.T, fx ...*RowFixture) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	for _, f := range fx {
		m[RowFixtureDir+"/"+f.Component+".json"] = &fstest.MapFile{Data: roundTrip(t, f)}
	}
	return m
}

func skipFixture(t *testing.T, row Target, digest string) *RowFixture {
	t.Helper()
	fx, err := BuildRowFixture(nil, row, digest, zeroDigest)
	if err != nil {
		t.Fatal(err)
	}
	return fx
}

func TestRowFixtureDirectoryIsOneToOne(t *testing.T) {
	rows, digests := shippedTable(t)
	var all []*RowFixture
	for _, r := range rows {
		if readsForm(r.Form) {
			continue
		}
		all = append(all, skipFixture(t, r, digests[r.Component]))
	}
	// Only non-read rows here: build a table of just those.
	var sub []Target
	for _, r := range rows {
		if !readsForm(r.Form) {
			sub = append(sub, r)
		}
	}
	if _, err := LoadRowFixtures(fixtureFS(t, all...), RowFixtureDir, sub, digests); err != nil {
		t.Fatal(err)
	}
	// A row without a fixture.
	if _, err := LoadRowFixtures(fixtureFS(t, all[1:]...), RowFixtureDir, sub, digests); err == nil {
		t.Fatal("a row without a fixture passed")
	}
	// An orphan fixture (no row).
	if _, err := LoadRowFixtures(fixtureFS(t, all...), RowFixtureDir, sub[1:], digests); err == nil {
		t.Fatal("an orphan fixture passed")
	}
	// A fixture filed under another name, a stray file, a subdirectory.
	m := fixtureFS(t, all...)
	m[RowFixtureDir+"/zzz.json"] = m[RowFixtureDir+"/"+all[0].Component+".json"]
	if _, err := LoadRowFixtures(m, RowFixtureDir, sub, digests); err == nil {
		t.Fatal("a fixture under another name passed")
	}
	m = fixtureFS(t, all...)
	m[RowFixtureDir+"/README.md"] = &fstest.MapFile{Data: []byte("# notes")}
	if _, err := LoadRowFixtures(m, RowFixtureDir, sub, digests); err == nil {
		t.Fatal("a stray file passed")
	}
	m = fixtureFS(t, all...)
	m[RowFixtureDir+"/sub/x.json"] = &fstest.MapFile{Data: []byte("{}")}
	if _, err := LoadRowFixtures(m, RowFixtureDir, sub, digests); err == nil {
		t.Fatal("a subdirectory passed")
	}
	// A fixture whose digest is not the row's recomputed digest.
	stale := *all[0]
	stale.RowDigest = "sha256:" + strings.Repeat("4", 64)
	m = fixtureFS(t, append([]*RowFixture{&stale}, all[1:]...)...)
	if _, err := LoadRowFixtures(m, RowFixtureDir, sub, digests); err == nil {
		t.Fatal("a stale row digest passed")
	}
	// A skip fixture must be an empty skip: a read row cannot hide behind one.
	hide := *all[0]
	hide.Form = FormFile
	if _, err := ParseRowFixture(mustBytes(t, &hide)); err == nil {
		t.Fatal("a read form with an empty skip body passed")
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

// A pin adds no row: a row with a pin and no fixture still fails, and a pin
// for a component without a fixture is refused.
func TestPinsFileCannotAddRowWithoutFixtureCheck(t *testing.T) {
	rows, digests := shippedTable(t)
	var sub []Target
	var all []*RowFixture
	for _, r := range rows {
		if !readsForm(r.Form) {
			sub = append(sub, r)
			all = append(all, skipFixture(t, r, digests[r.Component]))
		}
	}
	victim := sub[0]
	// Row present, fixture absent, pin present: the fixture check refuses.
	m := fixtureFS(t, all[1:]...)
	if _, err := LoadRowFixtures(m, RowFixtureDir, sub, digests); err == nil {
		t.Fatal("a pinned row without a fixture passed the fixture check")
	}
	// The pin on its own is refused as well.
	fixtures := map[string]*RowFixture{}
	for _, f := range all[1:] {
		fixtures[f.Component] = f
	}
	pin := pinsDocBytes(t, rowPin{Component: victim.Component, RowDigest: digests[victim.Component]})
	if err := CheckRowPins(pin, fixtures, digests); err == nil {
		t.Fatal("a pin without a fixture was accepted")
	}
	// A pin for a component with no row at all.
	if err := CheckRowPins(pinsDocBytes(t, rowPin{Component: "ghost", RowDigest: zeroDigest}), fixtures, digests); err == nil {
		t.Fatal("a pin without a row was accepted")
	}
	// A pin with the wrong digest, duplicates, unsorted, trailing data.
	f0 := all[1]
	for name, doc := range map[string][]byte{
		"wrong digest": pinsDocBytes(t, rowPin{Component: f0.Component, RowDigest: zeroDigest}),
		"duplicate":    pinsDocBytes(t, rowPin{Component: f0.Component, RowDigest: digests[f0.Component]}, rowPin{Component: f0.Component, RowDigest: digests[f0.Component]}),
		"trailing":     append(pinsDocBytes(t, rowPin{Component: f0.Component, RowDigest: digests[f0.Component]}), []byte("{}")...),
		"bad schema":   []byte(`{"schema":"x","pins":[]}`),
		"empty":        []byte(""),
	} {
		if err := CheckRowPins(doc, fixtures, digests); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A good pin is accepted and changes nothing: no pins file is fine too.
	if err := CheckRowPins(pinsDocBytes(t, rowPin{Component: f0.Component, RowDigest: digests[f0.Component]}), fixtures, digests); err != nil {
		t.Fatal(err)
	}
	if err := CheckRowPins(nil, fixtures, digests); err != nil {
		t.Fatal(err)
	}
}

// The reader digest is not in a pin and does not enter any check: a pin that
// carries one is refused, and a changed reader digest changes no result.
func TestPinsIgnoreReaderDigestDrift(t *testing.T) {
	row, digest, fx, blobs := synth(t)
	withReader := []byte(`{"schema":"` + RowPinsSchema + `","pins":[{"component":"prometheus","rowDigest":"` + digest + `","readerDigest":"` + zeroDigest + `"}]}`)
	fixtures := map[string]*RowFixture{"prometheus": fx}
	digests := map[string]string{"prometheus": digest}
	if err := CheckRowPins(withReader, fixtures, digests); err == nil {
		t.Fatal("a pin holding a reader digest was accepted")
	}
	pin := pinsDocBytes(t, rowPin{Component: "prometheus", RowDigest: digest})
	other := "sha256:" + strings.Repeat("9", 64)
	for _, reader := range []string{zeroDigest, other} {
		if err := RecheckRowFixture(fx, row, digest, blobs, reader); err != nil {
			t.Fatalf("reader digest %s changed the result: %v", reader, err)
		}
		if err := CheckRowPins(pin, fixtures, digests); err != nil {
			t.Fatal(err)
		}
	}
	// The row digest does not depend on the reader: it is the data row only.
	if d, _ := RowDigests(); d["prometheus"] != digest {
		t.Fatal("row digest is not stable")
	}
}

// C2: a removal deletes row, fixture and pin together; any one left behind is
// refused.
func TestRemovalPRLeavesNoOrphanFixture(t *testing.T) {
	rows, digests := shippedTable(t)
	var sub []Target
	var all []*RowFixture
	for _, r := range rows {
		if !readsForm(r.Form) {
			sub = append(sub, r)
			all = append(all, skipFixture(t, r, digests[r.Component]))
		}
	}
	if len(sub) < 2 {
		t.Skip("needs two non-read rows")
	}
	gone := sub[0].Component
	var rest []Target
	for _, r := range sub {
		if r.Component != gone {
			rest = append(rest, r)
		}
	}
	pin := func(comps ...string) []byte {
		var ps []rowPin
		for _, c := range comps {
			ps = append(ps, rowPin{Component: c, RowDigest: digests[c]})
		}
		return pinsDocBytes(t, ps...)
	}
	fixtures := func(skip string) map[string]*RowFixture {
		m := map[string]*RowFixture{}
		for _, f := range all {
			if f.Component != skip {
				m[f.Component] = f
			}
		}
		return m
	}
	// Row removed, fixture left behind.
	if _, err := LoadRowFixtures(fixtureFS(t, all...), RowFixtureDir, rest, digests); err == nil {
		t.Fatal("the fixture of a removed row was left behind and passed")
	}
	// Row and fixture removed, pin left behind.
	if err := CheckRowPins(pin(gone), fixtures(gone), map[string]string{rest[0].Component: digests[rest[0].Component]}); err == nil {
		t.Fatal("the pin of a removed row was left behind and passed")
	}
	// Row and pin removed, fixture left behind is the first case; all three
	// removed together is clean.
	var keep []*RowFixture
	for _, f := range all {
		if f.Component != gone {
			keep = append(keep, f)
		}
	}
	got, err := LoadRowFixtures(fixtureFS(t, keep...), RowFixtureDir, rest, digests)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRowPins(pin(rest[0].Component), got, digests); err != nil {
		t.Fatal(err)
	}
}
