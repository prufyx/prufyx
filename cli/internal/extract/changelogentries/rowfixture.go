// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

// A row fixture is the recorded outcome of checking one row of targets.json:
// the tags of the check window, for each the files the reader read (path, git
// blob id, sha256 and size, or "absent") and the outcome of the reader (located
// or a typed withheld code). It holds no changelog text, only names, ids,
// digests and counts. Its schema id is prufyx.io/changelog-row-fixture/v1.
//
// The fixture is never trusted:
//
//   - its row digest is recomputed from targets.json and must match;
//   - its counts and status are recomputed from its own tag outcomes;
//   - when blobs are available, the check is re-run with the one reader over
//     blobs fetched by the pinned id and verified (git blob id, sha256, size);
//     a blob that is absent, unreadable or does not verify refuses the check;
//   - a row with no fixture fails, whatever else says it passed. An optional
//     pins file holds only component and row digest; it is compared, never
//     believed, and carries no reader digest.
//
// The reader code digest is not part of any of it: a change of the reader
// stales nothing stored in the repository.

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git blob ids are sha1; the sha256 below is the authority
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Schema ids and directory of the row fixtures.
const (
	RowFixtureSchema = "prufyx.io/changelog-row-fixture/v1"
	RowPinsSchema    = "prufyx.io/changelog-row-pins/v1"
	// RowFixtureDir is the directory of the fixtures under testdata/, and
	// RowPinsFile the optional pins file beside it.
	RowFixtureDir = "rows"
	RowPinsFile   = "rows-pins.json"
)

// Fixture tag outcomes.
const (
	OutcomeLocated  = "located"
	OutcomeWithheld = "withheld"
)

// MaxFixtureTags bounds the tags of one fixture.
const MaxFixtureTags = 64

var (
	hex40RE      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	fixtureTagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

// ErrUnverifiedBlob is returned when a blob needed for a fixture re-run cannot
// be fetched by its pinned id or does not verify against the pinned hashes.
var ErrUnverifiedBlob = errors.New("blob is not verified against the fixture")

// RowFixtureRead is one file the reader read at a tag. BlobID is empty for a
// path the reader found absent; then SHA256 is empty and Size is 0.
type RowFixtureRead struct {
	Path   string `json:"path"`
	BlobID string `json:"blobId,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int    `json:"size"`
}

// RowFixtureTag is the recorded outcome at one final tag.
type RowFixtureTag struct {
	Name    string           `json:"name"`
	Commit  string           `json:"commit"`
	Reads   []RowFixtureRead `json:"reads"`
	Outcome string           `json:"outcome"`
	Code    string           `json:"code,omitempty"`
}

// RowFixture is the snapshot of one row's check.
type RowFixture struct {
	Schema        string          `json:"schema"`
	Component     string          `json:"component"`
	RowDigest     string          `json:"rowDigest"`
	Form          string          `json:"form"`
	Status        string          `json:"status"`
	Window        int             `json:"window"`
	WindowLocated int             `json:"windowLocated"`
	Located       int             `json:"located"`
	Withheld      map[string]int  `json:"withheld"`
	Tags          []RowFixtureTag `json:"tags"`
}

// readsForm reports whether the form is read by the reader (and so needs
// recorded tags and blobs); the other forms have nothing to prove.
func readsForm(form string) bool {
	switch form {
	case FormFile, FormPerLineFile, FormPerVersionFile:
		return true
	}
	return false
}

// RowDigest is the digest of a row as written in targets.json: the canonical
// encoding of its data fields (style names, not the patterns they map to, so
// that a reader change stales nothing).
func RowDigest(r rowData) string {
	b, _ := json.Marshal(r) // fixed struct order; cannot fail on these types
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// RowDigests recomputes the digest of every row of the embedded targets data.
func RowDigests() (map[string]string, error) {
	if loadErr != nil {
		return nil, loadErr
	}
	return rowDigestsOf(targetsJSON)
}

func rowDigestsOf(data []byte) (map[string]string, error) {
	var doc targetsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.Rows))
	for _, r := range doc.Rows {
		out[r.Component] = RowDigest(r)
	}
	return out, nil
}

// ParseRowFixture reads one fixture strictly: unknown fields, duplicate keys
// and trailing data are refused, every value must have the closed form of its
// field, and the counts and status must equal those recomputed from the tags.
func ParseRowFixture(data []byte) (*RowFixture, error) {
	if err := noDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("row fixture: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var fx RowFixture
	if err := dec.Decode(&fx); err != nil {
		return nil, fmt.Errorf("row fixture: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("row fixture: data after the document")
	}
	if err := fx.validate(); err != nil {
		return nil, fmt.Errorf("row fixture %q: %w", fx.Component, err)
	}
	return &fx, nil
}

func (fx *RowFixture) validate() error {
	if fx.Schema != RowFixtureSchema {
		return fmt.Errorf("schema %q, want %q", fx.Schema, RowFixtureSchema)
	}
	if len(fx.Component) > 63 || !componentSlugRE.MatchString(fx.Component) {
		return errors.New("component is not a slug")
	}
	if !digestRE.MatchString(fx.RowDigest) {
		return errors.New("rowDigest is not a sha256 digest")
	}
	known := false
	for _, f := range []string{FormFile, FormPerLineFile, FormPerVersionFile, FormGithubRelease, FormPostTag, FormDocsPage, FormMonorepo} {
		known = known || f == fx.Form
	}
	if !known {
		return fmt.Errorf("form %q is not known", fx.Form)
	}
	if fx.Withheld == nil {
		return errors.New("withheld must be present (an empty object when none)")
	}
	if !readsForm(fx.Form) {
		if fx.Status != RowSkip || fx.Window != 0 || fx.WindowLocated != 0 || fx.Located != 0 || len(fx.Withheld) != 0 || len(fx.Tags) != 0 {
			return fmt.Errorf("form %q is not read: the fixture must be an empty SKIP", fx.Form)
		}
		return nil
	}
	if len(fx.Tags) == 0 || len(fx.Tags) > MaxFixtureTags {
		return fmt.Errorf("%d tags, want 1..%d", len(fx.Tags), MaxFixtureTags)
	}
	closed := map[Code]bool{}
	for _, c := range Codes() {
		closed[c] = true
	}
	located := 0
	withheld := map[string]int{}
	prev := ""
	for i, tg := range fx.Tags {
		if i > 0 && tg.Name <= prev {
			return fmt.Errorf("tag %q is not sorted strictly after %q", tg.Name, prev)
		}
		prev = tg.Name
		if !fixtureTagRE.MatchString(tg.Name) {
			return fmt.Errorf("tag name %q is not a plain tag name", tg.Name)
		}
		if _, ok := tagVersion(tg.Name); !ok {
			return fmt.Errorf("tag %q is not a final release tag", tg.Name)
		}
		if !hex40RE.MatchString(tg.Commit) {
			return fmt.Errorf("tag %q: commit is not a full sha", tg.Name)
		}
		if err := validateReads(tg); err != nil {
			return err
		}
		switch tg.Outcome {
		case OutcomeLocated:
			if tg.Code != "" {
				return fmt.Errorf("tag %q: a located tag has no code", tg.Name)
			}
			located++
		case OutcomeWithheld:
			if !closed[Code(tg.Code)] {
				return fmt.Errorf("tag %q: code %q is not a known code", tg.Name, tg.Code)
			}
			withheld[tg.Code]++
		default:
			return fmt.Errorf("tag %q: outcome %q", tg.Name, tg.Outcome)
		}
	}
	if fx.Located != located || !equalCounts(fx.Withheld, withheld) {
		return errors.New("located/withheld counts differ from the tag outcomes")
	}
	// The fixture holds exactly the newest window: every tag of the newest
	// version groups, and a stored fixture is a passing one.
	names := make([]string, 0, len(fx.Tags))
	for _, tg := range fx.Tags {
		names = append(names, tg.Name)
	}
	groups := newestVersions(names, DefaultMinLocatedNewest)
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	if n != len(fx.Tags) || fx.Window != len(groups) {
		return fmt.Errorf("window %d over %d tags is not the newest %d versions", fx.Window, len(fx.Tags), DefaultMinLocatedNewest)
	}
	if fx.Window != fx.WindowLocated || located != len(fx.Tags) || fx.Status != RowPass {
		return errors.New("a stored fixture must be a passing one: every tag of the window located, status PASS")
	}
	return nil
}

func validateReads(tg RowFixtureTag) error {
	if len(tg.Reads) > 8 {
		return fmt.Errorf("tag %q: too many reads", tg.Name)
	}
	prev := ""
	for i, rd := range tg.Reads {
		if i > 0 && rd.Path <= prev {
			return fmt.Errorf("tag %q: reads are not sorted strictly by path", tg.Name)
		}
		prev = rd.Path
		if len(rd.Path) > 200 || !templateCharsetRE.MatchString(rd.Path) || hasDotDotElement(rd.Path) {
			return fmt.Errorf("tag %q: read path %q is not a plain repository path", tg.Name, rd.Path)
		}
		if rd.BlobID == "" {
			if rd.SHA256 != "" || rd.Size != 0 {
				return fmt.Errorf("tag %q: an absent path has no digest or size", tg.Name)
			}
			continue
		}
		if !hex40RE.MatchString(rd.BlobID) || !digestRE.MatchString(rd.SHA256) || rd.Size < 0 {
			return fmt.Errorf("tag %q: read %q has a malformed blob id, digest or size", tg.Name, rd.Path)
		}
	}
	return nil
}

func equalCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// MatchRow requires the fixture to describe exactly this row: same component
// and form, and the row digest recomputed from the data equals the fixture's.
func (fx *RowFixture) MatchRow(row Target, digest string) error {
	if fx.Component != row.Component || fx.Form != row.Form {
		return fmt.Errorf("fixture %q/%q is not for row %q/%q", fx.Component, fx.Form, row.Component, row.Form)
	}
	if digest == "" || fx.RowDigest != digest {
		return fmt.Errorf("fixture of %q holds row digest %s, the row is %s", row.Component, fx.RowDigest, digest)
	}
	return nil
}

// LoadRowFixtures reads every fixture in dir of fsys and requires a one-to-one
// match with the rows: a file per row named <component>.json, no other entry,
// no fixture without a row (orphan), no row without a fixture, and every row
// digest recomputed from the data. It returns the fixtures by component.
func LoadRowFixtures(fsys fs.FS, dir string, rows []Target, digests map[string]string) (map[string]*RowFixture, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("row fixtures: %w", err)
	}
	byRow := map[string]Target{}
	for _, r := range rows {
		byRow[r.Component] = r
	}
	out := map[string]*RowFixture{}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("row fixtures: %q is not a fixture file", name)
		}
		comp := strings.TrimSuffix(name, ".json")
		row, ok := byRow[comp]
		if !ok {
			return nil, fmt.Errorf("row fixtures: orphan fixture %q has no row", name)
		}
		data, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("row fixtures: %w", err)
		}
		fx, err := ParseRowFixture(data)
		if err != nil {
			return nil, err
		}
		if fx.Component != comp {
			return nil, fmt.Errorf("row fixtures: %q holds component %q", name, fx.Component)
		}
		if err := fx.MatchRow(row, digests[comp]); err != nil {
			return nil, fmt.Errorf("row fixtures: %w", err)
		}
		out[comp] = fx
	}
	for _, r := range rows {
		if out[r.Component] == nil {
			return nil, fmt.Errorf("row fixtures: row %q has no fixture", r.Component)
		}
	}
	return out, nil
}

type pinsDoc struct {
	Schema string   `json:"schema"`
	Pins   []rowPin `json:"pins"`
}

type rowPin struct {
	Component string `json:"component"`
	RowDigest string `json:"rowDigest"`
}

// CheckRowPins reads an optional pins file and compares it with the rows and
// fixtures. A pin is only the row digest of a component that has a row and a
// fixture; it never makes a row pass. Unknown fields (a reader digest, for
// one), duplicates, orphans and any digest other than the recomputed one are
// refused. Empty data is no pins file.
func CheckRowPins(data []byte, fixtures map[string]*RowFixture, digests map[string]string) error {
	if data == nil {
		return nil
	}
	if err := noDuplicateKeys(data); err != nil {
		return fmt.Errorf("row pins: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc pinsDoc
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("row pins: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("row pins: data after the document")
	}
	if doc.Schema != RowPinsSchema {
		return fmt.Errorf("row pins: schema %q, want %q", doc.Schema, RowPinsSchema)
	}
	prev := ""
	for i, p := range doc.Pins {
		if i > 0 && p.Component <= prev {
			return fmt.Errorf("row pins: %q is not sorted strictly after %q", p.Component, prev)
		}
		prev = p.Component
		want, hasRow := digests[p.Component]
		if !hasRow {
			return fmt.Errorf("row pins: orphan pin %q has no row", p.Component)
		}
		if fixtures[p.Component] == nil {
			return fmt.Errorf("row pins: pin %q has no fixture; a pin adds no row", p.Component)
		}
		if p.RowDigest != want {
			return fmt.Errorf("row pins: pin %q digest %s, the row is %s", p.Component, p.RowDigest, want)
		}
	}
	return nil
}

// BlobFetcher fetches a blob by its git blob id. The caller does not trust
// what it returns.
type BlobFetcher interface {
	FetchBlob(id string) ([]byte, error)
}

// DirBlobFetcher serves blobs from a directory of files named by blob id.
type DirBlobFetcher struct{ Dir string }

// FetchBlob implements BlobFetcher.
func (d DirBlobFetcher) FetchBlob(id string) ([]byte, error) {
	if !hex40RE.MatchString(id) {
		return nil, fmt.Errorf("blob id %q is not a full sha", id)
	}
	f, err := os.Open(filepath.Join(d.Dir, id))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, errors.New("blob is over the file bound")
	}
	return data, nil
}

// GitBlobID is the git object id of a blob with the given content.
func GitBlobID(data []byte) string {
	h := sha1.New() //nolint:gosec // git object id
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fixtureSource serves the tags and the verified blobs of one fixture. A read
// that the fixture did not record is an error, never "absent".
type fixtureSource struct {
	fx    *RowFixture
	blobs map[string][]byte // by blob id, verified
}

// OpenFixtureSource fetches every blob the fixture pins by id and verifies it
// (git blob id, sha256, size). A nil fetcher, a fetch error or a mismatch
// refuses the whole fixture: nothing partial is served.
func OpenFixtureSource(fx *RowFixture, f BlobFetcher) (extract.PinnedReader, extract.TagSource, error) {
	if f == nil {
		return nil, nil, fmt.Errorf("%w: no blob source", ErrUnverifiedBlob)
	}
	s := &fixtureSource{fx: fx, blobs: map[string][]byte{}}
	for _, tg := range fx.Tags {
		for _, rd := range tg.Reads {
			if rd.BlobID == "" {
				continue
			}
			if _, done := s.blobs[rd.BlobID]; done {
				continue
			}
			data, err := f.FetchBlob(rd.BlobID)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %s: %v", ErrUnverifiedBlob, rd.BlobID, err)
			}
			if GitBlobID(data) != rd.BlobID || sha256Digest(data) != rd.SHA256 || len(data) != rd.Size {
				return nil, nil, fmt.Errorf("%w: %s", ErrUnverifiedBlob, rd.BlobID)
			}
			s.blobs[rd.BlobID] = data
		}
	}
	return s, s, nil
}

func (s *fixtureSource) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	out := make([]extract.Tag, 0, len(s.fx.Tags))
	for _, tg := range s.fx.Tags {
		out = append(out, extract.Tag{Name: tg.Name, Commit: tg.Commit})
	}
	return out, nil
}

func (s *fixtureSource) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	for _, tg := range s.fx.Tags {
		if tg.Commit != commit {
			continue
		}
		for _, rd := range tg.Reads {
			if rd.Path != p {
				continue
			}
			if rd.BlobID == "" {
				return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
			}
			return s.blobs[rd.BlobID], nil
		}
	}
	return nil, fmt.Errorf("read of %s at %s is not recorded in the fixture", p, commit)
}

func (s *fixtureSource) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("List is not recorded in a row fixture")
}

// RecheckRowFixture re-runs the one reader for the row over blobs fetched by
// the fixture's pinned ids, verified, and requires the result to equal the
// fixture's recorded outcomes tag by tag. It fails closed: an unverified blob,
// a differing outcome or a failing row is an error. codeDigest only labels the
// manifests the reader builds; it is not compared with anything stored.
func RecheckRowFixture(fx *RowFixture, row Target, digest string, f BlobFetcher, codeDigest string) error {
	if err := fx.MatchRow(row, digest); err != nil {
		return err
	}
	if !readsForm(row.Form) {
		return nil
	}
	rd, tags, err := OpenFixtureSource(fx, f)
	if err != nil {
		return err
	}
	src := struct {
		extract.PinnedReader
		extract.TagSource
	}{rd, tags}
	res := CheckRowMin(src, row, codeDigest, DefaultMinLocatedNewest)
	if res.Status != RowPass {
		return fmt.Errorf("row %q fails over the pinned blobs: %s", row.Component, strings.Join(res.Reasons, "; "))
	}
	for _, tg := range fx.Tags {
		m, err := BuildManifest(src, row, extract.Tag{Name: tg.Name, Commit: tg.Commit}, codeDigest)
		if err != nil {
			return err
		}
		got, code := OutcomeLocated, ""
		if m.Entry == nil {
			got, code = OutcomeWithheld, string(m.Withheld.Code)
		}
		if got != tg.Outcome || code != tg.Code {
			return fmt.Errorf("tag %q: reader gives %s %s, fixture records %s %s", tg.Name, got, code, tg.Outcome, tg.Code)
		}
	}
	if res.Located != fx.Located || res.Window != fx.Window || res.WindowLocated != fx.WindowLocated || res.Tags != len(fx.Tags) {
		return fmt.Errorf("row %q: counts over the pinned blobs differ from the fixture", row.Component)
	}
	return nil
}

// recordingReader logs every read for BuildRowFixture.
type recordingReader struct {
	inner extract.PinnedReader
	reads map[string]map[string]RowFixtureRead // commit -> path
	err   error
}

func (r *recordingReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	data, err := r.inner.Read(repo, commit, p)
	if r.reads[commit] == nil {
		r.reads[commit] = map[string]RowFixtureRead{}
	}
	switch {
	case err == nil:
		r.reads[commit][p] = RowFixtureRead{Path: p, BlobID: GitBlobID(data), SHA256: sha256Digest(data), Size: len(data)}
	case errors.Is(err, extract.ErrNotFound):
		r.reads[commit][p] = RowFixtureRead{Path: p}
	default:
		r.err = err
	}
	return data, err
}

func (r *recordingReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	return r.inner.List(repo, commit, dir)
}

// BuildRowFixture records the fixture of a row from a source that has the
// blobs: the newest DefaultMinLocatedNewest versions of the final tags, every
// read and the reader's outcome per tag. It refuses a row that does not pass
// its own bar; a fixture is only ever a passing one. digest is the row digest
// recomputed from the data.
func BuildRowFixture(src interface {
	extract.PinnedReader
	extract.TagSource
}, row Target, digest, codeDigest string) (*RowFixture, error) {
	fx := &RowFixture{Schema: RowFixtureSchema, Component: row.Component, RowDigest: digest, Form: row.Form, Withheld: map[string]int{}, Tags: []RowFixtureTag{}}
	if !readsForm(row.Form) {
		fx.Status = RowSkip
		return fx, fx.validate()
	}
	tags, err := src.Tags(row.Repo)
	if err != nil {
		return nil, err
	}
	commit := map[string]string{}
	var finals []string
	for _, tg := range tags {
		if _, ok := tagVersion(tg.Name); !ok {
			continue
		}
		if _, dup := commit[tg.Name]; dup {
			return nil, fmt.Errorf("tag %q is recorded twice", tg.Name)
		}
		commit[tg.Name] = tg.Commit
		finals = append(finals, tg.Name)
	}
	var names []string
	for _, g := range newestVersions(finals, DefaultMinLocatedNewest) {
		names = append(names, g...)
	}
	sort.Strings(names)
	rec := &recordingReader{inner: src, reads: map[string]map[string]RowFixtureRead{}}
	fx.Window = len(newestVersions(names, DefaultMinLocatedNewest))
	for _, n := range names {
		m, err := BuildManifest(rec, row, extract.Tag{Name: n, Commit: commit[n]}, codeDigest)
		if err != nil {
			return nil, err
		}
		if rec.err != nil {
			return nil, rec.err
		}
		tg := RowFixtureTag{Name: n, Commit: commit[n], Reads: []RowFixtureRead{}, Outcome: OutcomeLocated}
		for _, rd := range rec.reads[commit[n]] {
			tg.Reads = append(tg.Reads, rd)
		}
		sort.Slice(tg.Reads, func(i, j int) bool { return tg.Reads[i].Path < tg.Reads[j].Path })
		if m.Entry != nil {
			fx.Located++
		} else {
			tg.Outcome, tg.Code = OutcomeWithheld, string(m.Withheld.Code)
			fx.Withheld[tg.Code]++
		}
		fx.Tags = append(fx.Tags, tg)
	}
	if fx.Located != len(fx.Tags) {
		return nil, fmt.Errorf("row %q does not pass its bar over the newest %d versions: %d of %d tags located", row.Component, DefaultMinLocatedNewest, fx.Located, len(fx.Tags))
	}
	fx.WindowLocated, fx.Status = fx.Window, RowPass
	return fx, fx.validate()
}

// Bytes renders the fixture: indented JSON in struct order, one trailing LF.
func (fx *RowFixture) Bytes() ([]byte, error) {
	b, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
