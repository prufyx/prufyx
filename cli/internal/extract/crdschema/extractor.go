// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Extractor identity.
const (
	// IDPrefix is followed by the project slug: one extractor id per project.
	IDPrefix = "crd.schema-removal."
	// Version is bumped on any output change.
	Version = "1.0.0"

	// maxTagsPerLine bounds the release tags read for one line.
	maxTagsPerLine = 64

	// Ledger codes the wiring adds to the pair's Result.
	ReasonLineUnread   = "LINE_UNREAD"
	ReasonLineUnstable = "LINE_UNSTABLE"
)

// attestedFamily is the fact family the extractor attests lines of. No
// crd.schema family exists in the lineattest vocabulary yet (it is added
// with the C2-2 registry work), so it is empty: every pair is then recorded
// as not attested and no line attestation can be stated. Tests set the
// family on the extractor to prove the attested path.
const attestedFamily = ""

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Extractor wires Derive into the extract framework. A pair names the first
// release of a release line and the first release of the next minor line of
// the same major, and its Result is decided for the LINE: the Result of
// Derive(first, first) is the proof only when every other release of both
// lines has the same field and enum sets as the line's first release, shown
// by Derive in both directions. A line that is not stable, or whose tags
// cannot be read completely, carries a ledger entry, so the pair is not
// attested. Per-pair results are never unioned.
//
// The extractor emits no rule: a rule needs the crd_fields_set and
// crd_enum_values_set facts, which are registered by C2-2. It states an
// attestation (an empty rule list for the line) only when the Result is
// attestable and removes nothing.
type Extractor struct {
	slug      string
	target    Target
	component string
	family    string

	mu     sync.Mutex
	lines  map[string]*releaseLine
	lineOf map[string]string
}

// New returns the extractor of one project. component is the catalog
// component the attestations name.
func New(slug string, t Target, component string) (*Extractor, error) {
	if !slugRE.MatchString(slug) {
		return nil, fmt.Errorf("crdschema: project slug %q", slug)
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return &Extractor{slug: slug, target: t, component: component, family: attestedFamily, lines: map[string]*releaseLine{}, lineOf: map[string]string{}}, nil
}

// ID implements extract.Extractor.
func (x *Extractor) ID() string { return IDPrefix + x.slug }

// Version implements extract.Extractor.
func (x *Extractor) Version() string { return Version }

// Applies implements extract.Extractor.
func (x *Extractor) Applies(r extract.RepoRef) bool { return r == x.target.Repo }

// SourceFiles implements extract.CodeSource: this package and the shared
// member encoder it calls.
func (x *Extractor) SourceFiles() (string, fs.FS) {
	s := SourceSet()
	return s.Dir, s.Files
}

// AttestedFamilies implements extract.LineAttester.
func (x *Extractor) AttestedFamilies() []string {
	if x.family == "" {
		return []string{}
	}
	return []string{x.family}
}

// AttestedComponent implements extract.ComponentAttester.
func (x *Extractor) AttestedComponent() string { return x.component }

type releaseLine struct {
	Major, Minor int
	Tags         []extract.Tag // lowest patch first
	Versions     []string
	Problem      string
}

func (l *releaseLine) key() string { return fmt.Sprintf("%d.%d", l.Major, l.Minor) }

var (
	canonTagRE = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
	shapeTagRE = regexp.MustCompile(`^[vV]?([0-9]+)\.([0-9]+)(\.[0-9]+)*$`)
)

// releaseLines groups the final release tags (v1.2.3 or 1.2.3, canonical
// numbers only) by major.minor line. A tag of release shape that is not
// canonical, or a release tagged twice at different commits, or too many
// tags, marks its line as a problem, never silently skipped.
func releaseLines(index extract.ReleaseIndex) []*releaseLine {
	type rel struct {
		major, minor, patch int
		tag                 extract.Tag
		version             string
	}
	byVersion := map[string]rel{}
	problems := map[string]string{}
	allProblem := ""
	markLine := func(tag, why string) {
		lm := shapeTagRE.FindStringSubmatch(tag)
		maj, e1 := strconv.Atoi(lm[1])
		mnr, e2 := strconv.Atoi(lm[2])
		if e1 != nil || e2 != nil {
			allProblem = "a tag has the shape of a release but its numbers cannot be read"
			return
		}
		problems[fmt.Sprintf("%d.%d", maj, mnr)] = why
	}
	for _, t := range index.Tags {
		m := canonTagRE.FindStringSubmatch(t.Name)
		if m == nil {
			// Anything shaped like a release (any case of the v, two or more
			// numeric parts) that is not canonical is never skipped silently.
			// Prefixed tags (api/v1.2.3) and pre-releases are other modules'
			// or not final releases.
			if shapeTagRE.MatchString(t.Name) {
				markLine(t.Name, "a tag of the line has the shape of a release that is not canonical")
			}
			continue
		}
		if !extract.IsCommitSHA(t.Commit) {
			markLine(t.Name, "a release tag of the line has no pinned commit")
			continue
		}
		maj, _ := strconv.Atoi(m[1])
		mnr, _ := strconv.Atoi(m[2])
		pat, _ := strconv.Atoi(m[3])
		version := fmt.Sprintf("%d.%d.%d", maj, mnr, pat)
		if prev, dup := byVersion[version]; dup && prev.tag.Commit != t.Commit {
			problems[fmt.Sprintf("%d.%d", maj, mnr)] = "a release of the line is tagged twice, at different commits"
		}
		if prev, dup := byVersion[version]; dup && prev.tag.Name <= t.Name {
			continue
		}
		byVersion[version] = rel{maj, mnr, pat, t, version}
	}
	rels := make([]rel, 0, len(byVersion))
	for _, r := range byVersion {
		rels = append(rels, r)
	}
	sort.Slice(rels, func(i, j int) bool {
		a, b := rels[i], rels[j]
		if a.major != b.major {
			return a.major < b.major
		}
		if a.minor != b.minor {
			return a.minor < b.minor
		}
		return a.patch < b.patch
	})
	var out []*releaseLine
	byKey := map[string]*releaseLine{}
	for _, r := range rels {
		k := fmt.Sprintf("%d.%d", r.major, r.minor)
		l := byKey[k]
		if l == nil {
			l = &releaseLine{Major: r.major, Minor: r.minor}
			byKey[k] = l
			out = append(out, l)
		}
		l.Tags = append(l.Tags, r.tag)
		l.Versions = append(l.Versions, r.version)
	}
	for _, l := range out {
		switch {
		case allProblem != "":
			l.Problem = allProblem
		case problems[l.key()] != "":
			l.Problem = problems[l.key()]
		case len(l.Tags) > maxTagsPerLine:
			l.Problem = fmt.Sprintf("the line has more than %d release tags", maxTagsPerLine)
		}
	}
	return out
}

// Pairs implements extract.Extractor: every two release lines that follow
// each other as minor lines of one major. Each is named by the first final
// release of its line.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	lines := releaseLines(index)
	x.mu.Lock()
	x.lines, x.lineOf = map[string]*releaseLine{}, map[string]string{}
	for _, l := range lines {
		x.lines[l.key()] = l
		for _, t := range l.Tags {
			x.lineOf[t.Name] = l.key()
		}
	}
	x.mu.Unlock()
	var out []extract.VersionPair
	for i := 1; i < len(lines); i++ {
		a, b := lines[i-1], lines[i]
		if a.Major != b.Major || a.Minor+1 != b.Minor {
			continue
		}
		out = append(out, extract.VersionPair{
			Repo: index.Repo,
			From: a.Versions[0], FromTag: a.Tags[0].Name, FromCommit: a.Tags[0].Commit,
			To: b.Versions[0], ToTag: b.Tags[0].Name, ToCommit: b.Tags[0].Commit,
		})
	}
	return out
}

func (x *Extractor) lineFor(tag, commit string) (*releaseLine, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	k, ok := x.lineOf[tag]
	if !ok {
		return nil, fmt.Errorf("crdschema: tag %s was not seen by Pairs", tag)
	}
	l := x.lines[k]
	if l == nil || l.Tags[0].Name != tag || l.Tags[0].Commit != commit {
		return nil, fmt.Errorf("crdschema: tag %s is not the first release of its line", tag)
	}
	return l, nil
}

// faultResult is the Result of a pair whose line could not be read: empty
// incomplete facts and one ledger entry.
func faultResult(from, to, code, subject string) *Result {
	r := &Result{Schema: ResultSchema, From: from, To: to,
		Omissions: []Omission{{Reason: code, Subject: subject, Count: 1}}, Exclusions: []Omission{}}
	r.seal([]string{}, []string{}, defaultLedgerGuards())
	return r
}

// sameSets reports whether a Derive result shows no removal and nothing
// withheld.
func sameSets(r *Result) bool {
	return r.Attestable() && len(r.Fields.Members) == 0 && len(r.Enums.Members) == 0
}

// unstable counts the releases of the line (after the first) whose sets
// differ from the first release's, in either direction, or cannot be
// compared completely.
func (x *Extractor) unstable(ctx context.Context, r extract.PinnedReader, l *releaseLine) (int, error) {
	n := 0
	first := l.Tags[0].Commit
	for _, t := range l.Tags[1:] {
		if t.Commit == first {
			continue
		}
		fwd, err := Derive(ctx, r, x.target, first, t.Commit)
		if err != nil {
			return 0, err
		}
		back, err := Derive(ctx, r, x.target, t.Commit, first)
		if err != nil {
			return 0, err
		}
		if !sameSets(fwd) || !sameSets(back) {
			n++
		}
	}
	return n, nil
}

// Extract implements extract.Extractor.
func (x *Extractor) Extract(ctx context.Context, r extract.PinnedReader, p extract.VersionPair) (extract.Extraction, error) {
	a, err := x.lineFor(p.FromTag, p.FromCommit)
	if err != nil {
		return extract.Extraction{}, err
	}
	b, err := x.lineFor(p.ToTag, p.ToCommit)
	if err != nil {
		return extract.Extraction{}, err
	}
	for _, l := range []*releaseLine{a, b} {
		if l.Problem != "" {
			return extract.Extraction{Proof: faultResult(p.FromCommit, p.ToCommit, ReasonLineUnread, "line:"+l.key()),
				NotAttested: "the pair withheld items: a release line could not be read completely"}, nil
		}
	}
	// A read error on any release of either line aborts the run (fail
	// closed), it is never a quiet line.
	res, err := Derive(ctx, r, x.target, p.FromCommit, p.ToCommit)
	if err != nil {
		return extract.Extraction{}, err
	}
	for _, l := range []*releaseLine{a, b} {
		n, err := x.unstable(ctx, r, l)
		if err != nil {
			return extract.Extraction{}, err
		}
		if n > 0 {
			res.Omissions = append(res.Omissions, Omission{Reason: ReasonLineUnstable, Subject: "line:" + l.key(), Count: n})
		}
	}
	sort.Slice(res.Omissions, func(i, j int) bool {
		if res.Omissions[i].Reason != res.Omissions[j].Reason {
			return res.Omissions[i].Reason < res.Omissions[j].Reason
		}
		return res.Omissions[i].Subject < res.Omissions[j].Subject
	})
	res.seal(res.Fields.Members, res.Enums.Members, defaultLedgerGuards())

	e := extract.Extraction{Proof: res}
	switch {
	case !res.Attestable():
		e.NotAttested = "the pair withheld items"
	case len(res.Fields.Members) > 0 || len(res.Enums.Members) > 0:
		e.NotAttested = "the pair removes fields or enum values and no rule is emitted yet"
	case x.family == "":
		e.NotAttested = "no crd.schema fact family is registered yet"
	default:
		c, err := x.attestation(r, p, a, b)
		if err != nil {
			return extract.Extraction{}, err
		}
		e.Attestations = []extract.AttestationCandidate{c}
	}
	return e, nil
}

// citePath names one CRD file the derivation read at commit.
func (x *Extractor) citePath(r extract.PinnedReader, commit string) (string, error) {
	if len(x.target.Files) > 0 {
		return x.target.Files[0], nil
	}
	for _, d := range x.target.Dirs {
		entries, err := r.List(x.target.Repo, commit, d)
		if err != nil {
			return "", err
		}
		for _, en := range entries {
			if en.Type == "blob" && (strings.HasSuffix(en.Path, ".yaml") || strings.HasSuffix(en.Path, ".yml")) {
				return en.Path, nil
			}
		}
	}
	return "", errors.New("crdschema: no source file to cite")
}

func (x *Extractor) attestation(r extract.PinnedReader, p extract.VersionPair, a, b *releaseLine) (extract.AttestationCandidate, error) {
	line, ok := lineattest.LineOf(p.To)
	if !ok {
		return extract.AttestationCandidate{}, fmt.Errorf("crdschema: no line for %s", p.To)
	}
	path, err := x.citePath(r, p.FromCommit)
	if err != nil {
		return extract.AttestationCandidate{}, err
	}
	if _, err := r.Read(p.Repo, p.FromCommit, path); err != nil {
		return extract.AttestationCandidate{}, err
	}
	c := extract.AttestationCandidate{Component: x.component, Line: line, FactFamily: x.family, RuleIDs: []string{},
		Sources: []extract.SourceRef{{ID: "crd", Repo: p.Repo, Commit: p.FromCommit, Path: path}}}
	if fam, _ := lineattest.LookupFamily(x.family); fam.ReleaseScoped() {
		rl := &lineattest.Releases{}
		for i, t := range a.Tags {
			rl.From = append(rl.From, lineattest.Release{Version: a.Versions[i], Commit: t.Commit})
		}
		for i, t := range b.Tags {
			rl.To = append(rl.To, lineattest.Release{Version: b.Versions[i], Commit: t.Commit})
		}
		c.Releases = rl
	}
	return c, nil
}
