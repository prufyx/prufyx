// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

// The older-line floor. A row may carry an optional "floor": the oldest
// release line (major.minor) whose every final tag is located by the row,
// joined without a gap to the newest lines. Absent means the newest 5 lines,
// and absence is the only way to say that. A floor is never chosen by hand:
// propose-rows computes it from an injected UPSTREAM tag list (never the
// trimmed mirror), and rows-check re-derives it and fails a stored floor that
// is older than the re-derived one.
//
// Fail closed everywhere: a malformed floor, a malformed or missing upstream
// list, an unset cap, a tag that is not located by exactly one style, a final
// tag the mirror lacks, a mirror final tag the upstream list lacks, all stop
// the run at that line (or refuse the derivation); nothing is guessed.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// floorRE is the canonical floor: major (0 or 1-99, no leading zero) and minor
// (0 or 1-9999, no leading zero), ASCII digits, nothing else. Go's "$" without
// the multi-line flag matches only at the end of the text, so a trailing
// newline is refused.
var floorRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,1})\.(0|[1-9][0-9]{0,3})$`)

// Line is a release line, compared as a numeric (major, minor) tuple, never as
// text.
type Line struct{ Major, Minor int }

// ParseFloor reads a canonical floor, or refuses it.
func ParseFloor(s string) (Line, error) {
	if !floorRE.MatchString(s) {
		return Line{}, fmt.Errorf("floor %q is not a canonical major.minor", s)
	}
	return parseLine(s)
}

func parseLine(s string) (Line, error) {
	a, b, ok := strings.Cut(s, ".")
	if !ok {
		return Line{}, fmt.Errorf("line %q has no minor", s)
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return Line{}, fmt.Errorf("line %q is not numeric", s)
	}
	return Line{x, y}, nil
}

// Less orders lines numerically (0.153 is newer than 0.16).
func (l Line) Less(o Line) bool {
	if l.Major != o.Major {
		return l.Major < o.Major
	}
	return l.Minor < o.Minor
}

// NewestLines is how many of the newest lines the default (absent) floor
// covers. A floor must be strictly older than the oldest of them.
const NewestLines = 5

// Caps of one derivation. They are constants; an unset (zero) cap refuses,
// it never means unlimited.
const (
	MaxWindowTags  = 200
	MaxWindowBlobs = 400
	// MaxWindowBytes is deliberately unset: single-file changelogs grow with
	// age and the value comes from measurement. While it is unset every floor
	// derivation refuses with WANTS_TOO_LARGE:bytes.
	MaxWindowBytes = 0
)

// MaxFloorRetries is how many times a failed row steps to the next newer line
// of the re-derived run before it is NO-ROW.
const MaxFloorRetries = 3

// Typed NO-ROW reasons of the floor.
const (
	// NoRowWantsTooLarge is the prefix of WANTS_TOO_LARGE:<tags|blobs|bytes>.
	NoRowWantsTooLarge = "WANTS_TOO_LARGE"
	// NoRowFloorRetriesExhausted: every capped retry failed; no floor, no L.
	NoRowFloorRetriesExhausted = "FLOOR_RETRIES_EXHAUSTED"
	// NoRowUpstreamTags: the upstream tag list is missing or unusable.
	NoRowUpstreamTags = "UPSTREAM_TAGS_UNUSABLE"
)

// Caps bounds one derivation; each cap is checked on its own, in the order
// tags, blobs, bytes.
type Caps struct{ Tags, Blobs, Bytes int }

// DefaultCaps returns the constant caps.
func DefaultCaps() Caps { return Caps{MaxWindowTags, MaxWindowBlobs, MaxWindowBytes} }

// floorCaps gives the caps every derivation of the package runs under. It
// is DefaultCaps; only the package tests replace it.
var floorCaps = DefaultCaps

func tooLarge(which string) *NoRow {
	return &NoRow{NoRowWantsTooLarge + ":" + which, "the floor window exceeds the " + which + " cap (or the cap is unset)"}
}

// check refuses an unset cap and a tag count over the cap, tags first, then
// blobs, then bytes. Exactly at the cap passes, one more fails.
func (c Caps) check(tags int) *NoRow {
	if c.Tags <= 0 || tags > c.Tags {
		return tooLarge("tags")
	}
	if c.Blobs <= 0 {
		return tooLarge("blobs")
	}
	if c.Bytes <= 0 {
		return tooLarge("bytes")
	}
	return nil
}

// UpstreamTag is one tag of the upstream list: its name and the object id the
// upstream resolves it to. Peeled is the commit an annotated tag peels to (the
// "^{}" line of the list); it is empty for a lightweight tag, whose ObjectID
// is the commit itself.
type UpstreamTag struct{ Name, ObjectID, Peeled string }

// commitID is the commit the upstream says the tag points at.
func (u UpstreamTag) commitID() string {
	if u.Peeled != "" {
		return u.Peeled
	}
	return u.ObjectID
}

// UpstreamTags yields the upstream tag list of a repository (the output of an
// upstream tag listing, injected; the mirror is never the source of it).
type UpstreamTags interface {
	UpstreamTags(repo extract.RepoRef) ([]UpstreamTag, error)
}

// Limits of the upstream list file.
const (
	MaxUpstreamListBytes = 8 << 20
	MaxUpstreamListLines = 50000
)

var (
	upstreamNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$`)
	upstreamOIDRE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// UpstreamList is an upstream tag list read from a file.
type UpstreamList map[string][]UpstreamTag

// UpstreamTags implements UpstreamTags. A repository the list does not name is
// an error, never an empty list.
func (u UpstreamList) UpstreamTags(repo extract.RepoRef) ([]UpstreamTag, error) {
	tags, ok := u[repo.Key]
	if !ok {
		return nil, fmt.Errorf("the upstream tag list has no entry for %s", repo.Key)
	}
	return tags, nil
}

// ParseUpstreamList reads the upstream list file: one line per tag,
// "<repo key>TAB<40 hex object id>TAB<tag name>", LF-terminated. A peeled line
// (name ending "^{}") gives the commit of the annotated tag named on the other
// line; it is kept as the tag's Peeled id and compared with the mirror. A tag
// name that is not a final version (a moving tag, a release candidate) is
// skipped: it never takes part in a floor. Anything else that does not parse
// is refused, as is a tag named twice for one repository, and a peeled line
// of a version tag that has no tag line.
func ParseUpstreamList(data []byte) (UpstreamList, error) {
	if len(data) == 0 || len(data) > MaxUpstreamListBytes {
		return nil, fmt.Errorf("upstream tag list size %d outside 1..%d", len(data), MaxUpstreamListBytes)
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("upstream tag list does not end with a newline")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > MaxUpstreamListLines {
		return nil, fmt.Errorf("upstream tag list has more than %d lines", MaxUpstreamListLines)
	}
	out := UpstreamList{}
	seen := map[string]bool{}
	peeled := map[string]string{}
	for i, ln := range lines {
		f := strings.Split(ln, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("upstream tag list line %d: want 3 tab-separated fields", i+1)
		}
		repo, oid, name := f[0], f[1], f[2]
		if p, err := extract.ParseRepo(repo); err != nil || p.Key != repo {
			return nil, fmt.Errorf("upstream tag list line %d: %q is not a canonical repository key", i+1, repo)
		}
		if !upstreamOIDRE.MatchString(oid) {
			return nil, fmt.Errorf("upstream tag list line %d: object id is not 40 lower-case hex", i+1)
		}
		if base, isPeeled := strings.CutSuffix(name, "^{}"); isPeeled {
			if !upstreamNameRE.MatchString(base) {
				return nil, fmt.Errorf("upstream tag list line %d: tag name %q is not allowed", i+1, base)
			}
			if _, dup := peeled[repo+"\x00"+base]; dup {
				return nil, fmt.Errorf("upstream tag list line %d: peeled tag %q of %s listed twice", i+1, base, repo)
			}
			peeled[repo+"\x00"+base] = oid
			continue
		}
		if !upstreamNameRE.MatchString(name) {
			return nil, fmt.Errorf("upstream tag list line %d: tag name %q is not allowed", i+1, name)
		}
		if seen[repo+"\x00"+name] {
			return nil, fmt.Errorf("upstream tag list line %d: tag %q of %s listed twice", i+1, name, repo)
		}
		seen[repo+"\x00"+name] = true
		if _, ok := tagVersion(name); !ok {
			continue
		}
		out[repo] = append(out[repo], UpstreamTag{Name: name, ObjectID: oid})
	}
	for key, oid := range peeled {
		repo, name, _ := strings.Cut(key, "\x00")
		if _, ok := tagVersion(name); !ok {
			continue
		}
		attached := false
		for i := range out[repo] {
			if out[repo][i].Name == name {
				out[repo][i].Peeled = oid
				attached = true
			}
		}
		if !attached {
			return nil, fmt.Errorf("upstream tag list: peeled line of %q of %s has no tag line", name, repo)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("upstream tag list names no tag")
	}
	return out, nil
}

// TagSetDigest hashes tag names plus object ids, sorted by name, so that a
// retag (same name, new object id) changes the digest.
func TagSetDigest(tags []UpstreamTag) string {
	s := append([]UpstreamTag(nil), tags...)
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	h := sha256.New()
	h.Write([]byte("prufyx.io/changelog-window-tags/v1\n"))
	for _, t := range s {
		if t.Peeled == "" {
			h.Write([]byte(t.Name + "\x00" + t.ObjectID + "\n"))
		} else {
			h.Write([]byte(t.Name + "\x00" + t.ObjectID + "\x00" + t.Peeled + "\n"))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// capReader counts the distinct blobs and the bytes read, caches every read,
// and records the first cap that is exceeded (blobs before bytes).
type capReader struct {
	inner extract.PinnedReader
	caps  Caps
	seen  map[string]capRead
	bytes int
	err   *NoRow
}

type capRead struct {
	data []byte
	err  error
}

func (c *capReader) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	key := repo.Key + "@" + commit + ":" + p
	if r, ok := c.seen[key]; ok {
		return r.data, r.err
	}
	if len(c.seen)+1 > c.caps.Blobs {
		c.err = tooLarge("blobs")
		return nil, c.err
	}
	data, err := c.inner.Read(repo, commit, p)
	c.seen[key] = capRead{data, err}
	c.bytes += len(data)
	if c.bytes > c.caps.Bytes {
		c.err = tooLarge("bytes")
		return nil, c.err
	}
	return data, err
}

func (c *capReader) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, errors.New("directory listing is not part of a floor derivation")
}

// Run is the result of a derivation.
type Run struct {
	// Lines is the gap-free run of fully located lines, newest first.
	Lines []string
	// Floor is the oldest line of the run when the run is longer than the
	// newest NewestLines lines; empty (absent) otherwise.
	Floor string
	// FailLine and FailReason say where and why the run stopped (empty when it
	// ran to the oldest line).
	FailLine, FailReason string
	// AllLines is every line known to the upstream list or the mirror, newest
	// first.
	AllLines []string
	byLine   map[string][]UpstreamTag
}

// WindowDigest is the tag-set digest of the window of the given floor: the
// upstream final tags of every line from the newest down to the floor (the
// newest NewestLines lines when the floor is empty). A floor that is not a
// line of the upstream list is refused.
func (r *Run) WindowDigest(floor string) (string, error) {
	n := NewestLines
	if floor != "" {
		i := indexOf(r.AllLines, floor)
		if i < 0 {
			return "", fmt.Errorf("floor %s is not a release line of the upstream tag list", floor)
		}
		n = i + 1
	}
	if n > len(r.AllLines) {
		n = len(r.AllLines)
	}
	var tags []UpstreamTag
	for _, l := range r.AllLines[:n] {
		tags = append(tags, r.byLine[l]...)
	}
	return TagSetDigest(tags), nil
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// DeriveRun computes the gap-free run of the row t over the upstream tag list.
// A line joins the run only if every upstream final tag of it is present in
// the mirror and is located by exactly one style (the row's own, and no other
// heading style of the closed table also locates it), with no mirror final tag
// of the line missing from upstream. The run starts at the newest line and
// stops at the first failing line. A *NoRow error is a typed refusal (caps);
// any other error is an input or read failure.
func DeriveRun(src interface {
	extract.PinnedReader
	extract.TagSource
}, up UpstreamTags, t Target, caps Caps) (*Run, error) {
	switch t.Form {
	case FormFile, FormPerLineFile, FormPerVersionFile:
	default:
		return nil, fmt.Errorf("form %q is not read: no floor", t.Form)
	}
	if up == nil {
		return nil, &NoRow{NoRowUpstreamTags, "no upstream tag list was given"}
	}
	upTags, err := up.UpstreamTags(t.Repo)
	if err != nil {
		return nil, &NoRow{NoRowUpstreamTags, err.Error()}
	}
	mirror, err := src.Tags(t.Repo)
	if err != nil {
		return nil, err
	}
	run := &Run{byLine: map[string][]UpstreamTag{}}
	upNames := map[string]bool{}
	for _, u := range upTags {
		if upNames[u.Name] {
			return nil, fmt.Errorf("upstream tag %q is listed twice", u.Name)
		}
		upNames[u.Name] = true
		if v, ok := tagVersion(u.Name); ok {
			run.byLine[lineOf(v)] = append(run.byLine[lineOf(v)], u)
		}
	}
	byName := map[string]extract.Tag{}
	mirrorOnly := map[string]bool{}
	lineSet := map[string]bool{}
	for l := range run.byLine {
		lineSet[l] = true
	}
	for _, m := range mirror {
		if _, dup := byName[m.Name]; dup {
			return nil, fmt.Errorf("tag %q is recorded twice", m.Name)
		}
		byName[m.Name] = m
		v, ok := tagVersion(m.Name)
		if !ok {
			continue
		}
		lineSet[lineOf(v)] = true
		if !upNames[m.Name] {
			mirrorOnly[lineOf(v)] = true
		}
	}
	for l := range lineSet {
		run.AllLines = append(run.AllLines, l)
	}
	sort.Slice(run.AllLines, func(i, j int) bool {
		a, e1 := parseLine(run.AllLines[i])
		b, e2 := parseLine(run.AllLines[j])
		if e1 != nil || e2 != nil {
			return run.AllLines[i] > run.AllLines[j]
		}
		return b.Less(a)
	})
	cr := &capReader{inner: src, caps: caps, seen: map[string]capRead{}}
	total := 0
	for _, ln := range run.AllLines {
		total += len(run.byLine[ln])
		if nr := caps.check(total); nr != nil {
			return nil, nr
		}
		reason, err := evalLine(cr, t, ln, run.byLine[ln], byName, mirrorOnly[ln])
		if cr.err != nil {
			return nil, cr.err
		}
		if err != nil {
			return nil, err
		}
		if reason != "" {
			run.FailLine, run.FailReason = ln, reason
			break
		}
		run.Lines = append(run.Lines, ln)
	}
	if len(run.Lines) > NewestLines {
		run.Floor = run.Lines[len(run.Lines)-1]
	}
	return run, nil
}

// evalLine returns "" when the line is fully located, else a typed reason.
func evalLine(r extract.PinnedReader, t Target, line string, ups []UpstreamTag, byName map[string]extract.Tag, mirrorOnly bool) (string, error) {
	if !floorRE.MatchString(line) {
		return "LINE_OUTSIDE_GRAMMAR", nil
	}
	if mirrorOnly {
		return "MIRROR_ONLY_TAG", nil
	}
	if len(ups) == 0 {
		return "NO_UPSTREAM_TAG", nil
	}
	for _, u := range ups {
		m, ok := byName[u.Name]
		if !ok {
			return "TAG_NOT_LOCATED:" + u.Name, nil
		}
		// The upstream list is bound to the pinned mirror: the commit the
		// upstream gives for the tag (its peeled id, or its own id when it
		// is lightweight) must be the commit the mirror pinned. A list made
		// up from the mirror's names with other ids, or a retag, stops here.
		if u.commitID() != m.Commit {
			return "TAG_OID_MISMATCH:" + u.Name, nil
		}
		if _, err := Locate(r, t, m); err != nil {
			c, typed := CodeOf(err)
			if !typed {
				return "", fmt.Errorf("tag %s: %w", u.Name, err)
			}
			return "TAG_UNLOCATED:" + u.Name + ":" + string(c), nil
		}
		// The row has one style. A tag locates only if no OTHER style of the
		// closed table locates it as well: two styles reading one tag is an
		// ambiguity, and the line fails. Table order plays no part.
		if t.Form == FormPerVersionFile {
			continue
		}
		for _, name := range headingOrder {
			pat := headingStyles[name]
			if pat == t.HeadingPattern {
				continue
			}
			alt := t
			alt.HeadingPattern = pat
			if _, err := Locate(r, alt, m); err != nil {
				if _, typed := CodeOf(err); !typed {
					return "", fmt.Errorf("tag %s: %w", u.Name, err)
				}
				continue
			}
			return "STYLE_AMBIGUOUS:" + u.Name + ":" + name, nil
		}
	}
	return "", nil
}

// FloorCheck is what rows-check proved about a stored floor.
type FloorCheck struct {
	// Derived is the re-derived floor ("" when none is provable).
	Derived string
	// WindowDigest is the tag-set digest of the stored floor's window.
	WindowDigest string
}

// VerifyFloor re-derives the run of the row t and checks its stored floor. It
// returns the reasons the row fails (empty when it passes). The stored floor
// fails when it is not a line of the upstream list, when it is not strictly
// older than the oldest of the newest NewestLines lines, when no run beyond
// them is provable, or when it is older than the re-derived floor.
func VerifyFloor(src interface {
	extract.PinnedReader
	extract.TagSource
}, up UpstreamTags, t Target, caps Caps) (FloorCheck, []string) {
	var fc FloorCheck
	stored, err := ParseFloor(t.Floor)
	if err != nil {
		return fc, []string{err.Error()}
	}
	run, err := DeriveRun(src, up, t, caps)
	if err != nil {
		return fc, []string{"floor re-derivation refused: " + err.Error()}
	}
	fc.Derived = run.Floor
	i := indexOf(run.AllLines, t.Floor)
	switch {
	case i < 0 || !hasLine(run, t.Floor):
		return fc, []string{fmt.Sprintf("floor %s is not a release line of the upstream tag list", t.Floor)}
	case i < NewestLines:
		return fc, []string{fmt.Sprintf("floor %s is not older than the oldest of the newest %d lines (absence is the only way to say newest %d)", t.Floor, NewestLines, NewestLines)}
	case run.Floor == "":
		return fc, []string{fmt.Sprintf("floor %s is wider than provable: no gap-free run beyond the newest %d lines (%s)", t.Floor, NewestLines, stopNote(run))}
	}
	d, _ := parseLine(run.Floor)
	if stored.Less(d) {
		return fc, []string{fmt.Sprintf("stored floor %s is older than the re-derived floor %s (%s)", t.Floor, run.Floor, stopNote(run))}
	}
	dig, err := run.WindowDigest(t.Floor)
	if err != nil {
		return fc, []string{err.Error()}
	}
	fc.WindowDigest = dig
	return fc, nil
}

func hasLine(r *Run, l string) bool { _, ok := r.byLine[l]; return ok }

func stopNote(r *Run) string {
	if r.FailLine == "" {
		return "run reaches the oldest line"
	}
	return fmt.Sprintf("run stops at line %s: %s", r.FailLine, r.FailReason)
}

// ResolveFloor returns the floor to commit for a derived run. accept says
// whether the row passes rows-check at a candidate floor. Attempt 0 is the
// derived floor (the oldest line of the run); attempt k is the line k steps
// newer. There are at most 1+MaxFloorRetries attempts. A candidate inside the
// newest NewestLines lines is the absent floor ("") and is the last attempt,
// since nothing narrower exists. When every attempt fails the result is a
// NO-ROW and no floor: a failed row never leaves a wider floor behind. A run
// with no floor needs no resolving.
func ResolveFloor(run *Run, accept func(floor string) (bool, error)) (string, error) {
	if run.Floor == "" {
		return "", nil
	}
	n := len(run.Lines)
	for attempt := 0; attempt <= MaxFloorRetries; attempt++ {
		idx := n - 1 - attempt
		cand := ""
		if idx >= NewestLines {
			cand = run.Lines[idx]
		}
		ok, err := accept(cand)
		if err != nil {
			return "", err
		}
		if ok {
			return cand, nil
		}
		if cand == "" {
			break
		}
	}
	return "", &NoRow{NoRowFloorRetriesExhausted, fmt.Sprintf("the row failed at the derived floor and at %d capped retries; no floor, no L", MaxFloorRetries)}
}
