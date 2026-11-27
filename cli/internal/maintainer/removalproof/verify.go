// SPDX-License-Identifier: AGPL-3.0-only

// Package removalproof checks, from upstream source only, whether a command
// line flag name that one release line accepted can no longer be accepted by
// any release of the next line.
//
// It is report-only. It writes no rule and no fact, nothing reads its report
// to decide a verdict, and no result of it proves a removal on its own: the
// execution probe and the other items of Outstanding are not performed here.
//
// Every doubt refuses. A name passes the source checks only when the release
// set of both lines equals the lines snapshot and the pinned tags, every
// release of the older line registers the name in the stated binary, and every
// release of the newer line has no registration of it, no string literal of it
// in its tree or in any module its binary imports (each verified against
// go.sum, with any vendored copy equal to it), a resolved strict parser and no
// scan gap.
package removalproof

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/cliflags"
	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Schemas of the request and of the report.
const (
	RequestSchema = "prufyx.io/cli-flags-name-proof-request/v1"
	ReportSchema  = "prufyx.io/cli-flags-name-proof/v1"
)

// Verdicts of a name.
const (
	// VerdictRefused: at least one condition failed or could not be checked.
	VerdictRefused = "refused"
	// VerdictSourcePassed: every source condition this package checks held.
	// It is not a proof of removal: see Report.Outstanding.
	VerdictSourcePassed = "source-checks-passed"
)

// Refusal codes. A scan code follows its prefix after a colon.
const (
	CodeSnapshotMissing     = "RELEASE_SNAPSHOT_MISSING"
	CodeLinesNotAdjacent    = "RELEASE_LINES_NOT_ADJACENT"
	CodeTagMissing          = "RELEASE_TAG_MISSING"
	CodeTagMoved            = "RELEASE_TAG_MOVED"
	CodeTagNotPinned        = "RELEASE_TAG_NOT_PINNED"
	CodeTagDuplicate        = "RELEASE_TAG_DUPLICATE"
	CodeNotInSnapshot       = "RELEASE_NOT_IN_SNAPSHOT"
	CodeScanBlocking        = "SCAN_BLOCKING"
	CodeSiteUndisposed      = "SCAN_SITE_UNDISPOSED"
	CodeScanFaultUnrecorded = "SCAN_FAULT_UNRECORDED"
	CodeBinaryMissing       = "BINARY_MISSING"
	CodeNotAccepted         = "FROM_NOT_ACCEPTED"
	CodeFromWithheld        = "FROM_FLAG_WITHHELD"
	CodeFromSiteMissing     = "FROM_SITE_NOT_FOUND"
	CodeStillRegistered     = "TO_STILL_REGISTERED"
	CodeLiteralHit          = "TO_LITERAL_HIT"
	CodeSweepIncomplete     = "SWEEP_INCOMPLETE"
	CodeGoWork              = "GO_WORK_PRESENT"
	CodeGoModInvalid        = "GO_MOD_UNREADABLE"
	CodeOutsideReplace      = "REPLACE_OUTSIDE_TREE"
	CodeImportUnresolved    = "IMPORT_UNRESOLVED"
	CodeNestedModule        = "IMPORT_NESTED_MODULE"
	CodeModuleNoSum         = "MODULE_NOT_IN_GOSUM"
	CodeModuleUnavailable   = "MODULE_UNAVAILABLE"
	CodeModuleHash          = "MODULE_HASH_MISMATCH"
	CodeModuleUnreadable    = "MODULE_UNREADABLE"
	CodeVendorMismatch      = "VENDOR_DIFFERS_FROM_MODULE"
	CodeParserTolerant      = "PARSER_TOLERANT"
	CodeParserUnresolved    = "PARSER_UNRESOLVED"
	CodeNotChecked          = "RELEASES_NOT_ALL_CHECKED"
)

// siteCodes is the closed list of scan codes that an unrelated-gap argument
// could tolerate, and only with a disposition of every site: the site's
// constant parts must be shown incompatible with the name. This version makes
// no such disposition, so each of them still refuses, under its own code so
// that a reviewer sees which gaps are of this class. Every code that is not
// listed here, including any code added to the scanner later, blocks.
var siteCodes = map[string]bool{
	cliflags.ReasonDynamicRegistration:   true,
	cliflags.ReasonRegistrationInLoop:    true,
	cliflags.ReasonInitRegistration:      true,
	cliflags.ReasonDelegatedUnresolved:   true,
	cliflags.ReasonDuplicateRegistration: true,
	cliflags.ReasonGlobalFlagsetShared:   true,
	cliflags.ReasonIdiomUnsupported:      true,
}

// outstanding is what a passing name still lacks. It is in every report.
var outstanding = []string{
	"execution probe of every release of both lines, by image digest, with the random-name and retained-name controls",
	"per-site disposition of tolerated scan codes (not implemented: such a code refuses)",
	"independent re-derivation and independent probe re-run",
	"review of the parser check: a parse made inside a dependency, and registration that depends on configuration, environment or plugins, are not seen",
}

// Request is the reviewed candidate: one binary, two adjacent lines and the
// names claimed to be removed.
type Request struct {
	Schema     string   `json:"schema"`
	Project    string   `json:"project"`
	Repository string   `json:"repository"`
	FromLine   string   `json:"fromLine"`
	ToLine     string   `json:"toLine"`
	Binary     string   `json:"binary"`
	Names      []string `json:"names"`
}

var projectRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

const maxNames = 64

// ParseRequest strictly decodes and validates a request.
func ParseRequest(raw []byte) (Request, error) {
	var q Request
	if err := strictjson.Decode(raw, &q); err != nil {
		return Request{}, fmt.Errorf("removalproof: request: %w", err)
	}
	return q, q.validate()
}

func (q Request) validate() error {
	if q.Schema != RequestSchema {
		return errors.New("removalproof: request: unknown schema")
	}
	if !projectRE.MatchString(q.Project) {
		return errors.New("removalproof: request: bad project")
	}
	if r, err := extract.ParseRepo(q.Repository); err != nil || r.Key != q.Repository {
		return errors.New("removalproof: request: repository must be github.com/<owner>/<name> in lower case")
	}
	if q.FromLine == "" || q.ToLine == "" || q.FromLine == q.ToLine {
		return errors.New("removalproof: request: two different release lines are required")
	}
	if q.Binary != "." && (q.Binary == "" || q.Binary != path.Clean(q.Binary) || strings.HasPrefix(q.Binary, "/") || strings.HasPrefix(q.Binary, "..")) {
		return errors.New("removalproof: request: binary is not a clean repository directory")
	}
	if len(q.Names) == 0 || len(q.Names) > maxNames {
		return errors.New("removalproof: request: 1 to 64 names are required")
	}
	seen := map[string]bool{}
	for _, n := range q.Names {
		if cliflags.MemberCode(n) != "" || !constraintengine.ValidSetMember(n) || strings.HasPrefix(n, "-") || strings.Contains(n, "=") {
			return fmt.Errorf("removalproof: request: %q is not a long flag name", n)
		}
		if seen[norm(n)] {
			return fmt.Errorf("removalproof: request: %q is listed twice", n)
		}
		seen[norm(n)] = true
	}
	return nil
}

// Release is one release the check read.
type Release struct {
	Version string `json:"version"`
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
}

// Reason is one refusal, with the releases it was seen at.
type Reason struct {
	Code string `json:"code"`
	// Side is "release", "from" or "to".
	Side string `json:"side"`
	// Detail is the first detail seen (a path, module or code), never source
	// content.
	Detail string   `json:"detail,omitempty"`
	Tags   []string `json:"tags"`
}

// Site is a registration of a name at a release of the older line.
type Site struct {
	Tag    string `json:"tag"`
	Path   string `json:"path"`
	Line   int    `json:"line"`
	SHA256 string `json:"sha256"`
}

// NameResult is the outcome of one name.
type NameResult struct {
	Name    string   `json:"name"`
	Verdict string   `json:"verdict"`
	Reasons []Reason `json:"reasons"`
	// FromSites are the registrations found at the older line.
	FromSites []Site `json:"fromSites"`
}

// Report is the result of a run. ReportOnly is always true.
type Report struct {
	Schema     string    `json:"schema"`
	ReportOnly bool      `json:"reportOnly"`
	Request    Request   `json:"request"`
	From       []Release `json:"from"`
	To         []Release `json:"to"`
	// PairReasons apply to every name.
	PairReasons []Reason     `json:"pairReasons"`
	Names       []NameResult `json:"names"`
	Outstanding []string     `json:"outstanding"`
}

// Passed reports whether every name passed the source checks.
func (r *Report) Passed() bool {
	for _, n := range r.Names {
		if n.Verdict != VerdictSourcePassed {
			return false
		}
	}
	return len(r.Names) > 0
}

// Source reads the upstream repository: pinned bytes and the tags it holds.
type Source interface {
	extract.PinnedReader
	extract.TagSource
}

// Inputs is everything a run reads.
type Inputs struct {
	Source Source
	// Pins is an independent observation of the upstream tags (tag name to
	// commit), for example from git ls-remote --tags.
	Pins map[string]string
	// Lines is the lines snapshot.
	Lines coveragereport.LinesFile
	// Modules supplies module zips; they are verified against go.sum.
	Modules ModuleSource
}

type reasons map[string]*Reason

func (m reasons) add(code, side, detail, tag string) {
	k := side + "\x00" + code
	r := m[k]
	if r == nil {
		r = &Reason{Code: code, Side: side, Detail: clip(detail), Tags: []string{}}
		m[k] = r
	}
	if tag != "" && (len(r.Tags) == 0 || r.Tags[len(r.Tags)-1] != tag) {
		r.Tags = append(r.Tags, tag)
	}
}

func (m reasons) list() []Reason {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Reason, 0, len(keys))
	for _, k := range keys {
		out = append(out, *m[k])
	}
	return out
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

type run struct {
	ctx   context.Context
	in    Inputs
	q     Request
	repo  extract.RepoRef
	pair  reasons
	names map[string]reasons
	sites map[string][]Site
	sw    *sweeper
}

// Verify checks a request. A non-nil error means bytes could not be read or the
// input is invalid, and then there is no report; everything that cannot be
// decided is a refusal in the report.
func Verify(ctx context.Context, in Inputs, q Request) (*Report, error) {
	return verify(ctx, in, q, defaultLimits())
}

func verify(ctx context.Context, in Inputs, q Request, lim limits) (*Report, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	if in.Source == nil || in.Modules == nil {
		return nil, errors.New("removalproof: a source and a module source are required")
	}
	repo, err := extract.ParseRepo(q.Repository)
	if err != nil {
		return nil, err
	}
	v := &run{ctx: ctx, in: in, q: q, repo: repo, pair: reasons{}, names: map[string]reasons{}, sites: map[string][]Site{},
		sw: newSweeper(in.Modules, q.Names, lim)}
	for _, n := range q.Names {
		v.names[n] = reasons{}
	}
	from, to, want, err := v.releases()
	if err != nil {
		return nil, err
	}
	checked := 0
	for _, rel := range from {
		if err := v.fromRelease(rel); err != nil {
			return nil, fmt.Errorf("removalproof: %s: %w", rel.Tag, err)
		}
		checked++
	}
	for _, rel := range to {
		if err := v.toRelease(rel); err != nil {
			return nil, fmt.Errorf("removalproof: %s: %w", rel.Tag, err)
		}
		checked++
	}
	if len(from) == 0 || len(to) == 0 || checked != want {
		v.pair.add(CodeNotChecked, "release", fmt.Sprintf("%d of %d releases", checked, want), "")
	}
	rep := &Report{Schema: ReportSchema, ReportOnly: true, Request: q, From: from, To: to,
		PairReasons: v.pair.list(), Names: []NameResult{}, Outstanding: append([]string{}, outstanding...)}
	for _, n := range q.Names {
		nr := NameResult{Name: n, Verdict: VerdictRefused, Reasons: v.names[n].list(), FromSites: v.sites[n]}
		if nr.FromSites == nil {
			nr.FromSites = []Site{}
		}
		if len(nr.Reasons) == 0 && len(rep.PairReasons) == 0 {
			nr.Verdict = VerdictSourcePassed
		}
		rep.Names = append(rep.Names, nr)
	}
	return rep, nil
}

// releases matches the snapshot, the repository tags and the pins of both
// lines. It returns the releases that can be read and the number the snapshot
// requires.
func (v *run) releases() (from, to []Release, want int, err error) {
	from, to = []Release{}, []Release{}
	p, ok := v.in.Lines.Projects[v.q.Project]
	if !ok || len(p.Releases[v.q.FromLine]) == 0 || len(p.Releases[v.q.ToLine]) == 0 {
		v.pair.add(CodeSnapshotMissing, "release", v.q.Project, "")
		return from, to, 0, nil
	}
	adjacent := false
	for i := 1; i < len(p.Lines); i++ {
		if p.Lines[i-1] == v.q.FromLine && p.Lines[i] == v.q.ToLine {
			adjacent = true
		}
	}
	if !adjacent {
		v.pair.add(CodeLinesNotAdjacent, "release", v.q.FromLine+" "+v.q.ToLine, "")
	}
	tags, err := v.in.Source.Tags(v.repo)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("removalproof: tags: %w", err)
	}
	inLines := func(name string) (string, bool) {
		l, ok := coveragereport.LineOfTag(v.q.Project, name)
		return l, ok && (l == v.q.FromLine || l == v.q.ToLine)
	}
	have := map[string][]extract.Tag{}
	names := map[string]bool{}
	for _, t := range tags {
		if _, ok := inLines(t.Name); !ok {
			continue
		}
		names[t.Name] = true
		ver := strings.TrimPrefix(t.Name, "v")
		have[ver] = append(have[ver], t)
		pin, pinned := v.in.Pins[t.Name]
		switch {
		case !pinned:
			v.pair.add(CodeTagNotPinned, "release", t.Name, t.Name)
		case pin != t.Commit:
			v.pair.add(CodeTagMoved, "release", t.Name, t.Name)
		}
	}
	for name := range v.in.Pins {
		if _, ok := inLines(name); ok && !names[name] {
			v.pair.add(CodeTagMissing, "release", "pinned tag absent from the repository: "+name, "")
		}
	}
	listed := map[string]bool{}
	for _, side := range []struct {
		line string
		out  *[]Release
	}{{v.q.FromLine, &from}, {v.q.ToLine, &to}} {
		for _, ver := range p.Releases[side.line] {
			listed[ver] = true
			want++
			ts := have[ver]
			switch {
			case len(ts) == 0:
				v.pair.add(CodeTagMissing, "release", ver, ver)
				continue
			case len(ts) > 1:
				v.pair.add(CodeTagDuplicate, "release", ver, ver)
				continue
			case !extract.IsCommitSHA(ts[0].Commit):
				v.pair.add(CodeTagMissing, "release", "tag without a commit: "+ts[0].Name, ver)
				continue
			}
			*side.out = append(*side.out, Release{Version: ver, Tag: ts[0].Name, Commit: ts[0].Commit})
		}
	}
	for ver := range have {
		if !listed[ver] {
			v.pair.add(CodeNotInSnapshot, "release", ver, "")
		}
	}
	return from, to, want, nil
}

// scan runs the flag scanner on one release and records its gaps.
func (v *run) scan(rel Release, side string) (*cliflags.Binary, *cliflags.Result, error) {
	res, err := cliflags.Scan(v.ctx, v.in.Source, cliflags.Target{Repo: v.repo}, rel.Commit)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range res.Ledger {
		switch {
		case !siteCodes[e.Code]:
			v.pair.add(CodeScanBlocking+":"+e.Code, side, e.Item, rel.Tag)
		case side == "to":
			// On the older side the name is proven by its registration; a gap
			// there cannot add acceptance on the newer side.
			v.pair.add(CodeSiteUndisposed+":"+e.Code, side, e.Item, rel.Tag)
		}
	}
	var bin *cliflags.Binary
	for i := range res.Binaries {
		if res.Binaries[i].Dir == v.q.Binary {
			bin = &res.Binaries[i]
		}
	}
	if bin == nil {
		v.pair.add(CodeBinaryMissing, side, v.q.Binary, rel.Tag)
	} else if !bin.Set.Complete && len(res.Ledger) == 0 {
		v.pair.add(CodeScanFaultUnrecorded, side, v.q.Binary, rel.Tag)
	}
	return bin, res, nil
}

func (v *run) fromRelease(rel Release) error {
	bin, _, err := v.scan(rel, "from")
	if err != nil {
		return err
	}
	cl, err := v.sw.closure(v.ctx, v.in.Source, v.repo, rel.Commit, v.q.Binary, false)
	if err != nil {
		return err
	}
	for _, p := range cl.problems {
		v.pair.add(p.code, "from", p.detail, rel.Tag)
	}
	found := registrations(cl.files, v.q.Names)
	for _, n := range v.q.Names {
		if bin == nil {
			v.names[n].add(CodeNotAccepted, "from", "no scanned binary", rel.Tag)
			continue
		}
		accepted := false
		for _, f := range bin.Flags {
			if f.Name != n {
				continue
			}
			accepted = true
			for _, w := range f.Withheld {
				v.names[n].add(CodeFromWithheld+":"+w, "from", v.q.Binary, rel.Tag)
			}
		}
		if !accepted {
			v.names[n].add(CodeNotAccepted, "from", v.q.Binary, rel.Tag)
		}
		if len(found[n]) == 0 {
			v.names[n].add(CodeFromSiteMissing, "from", v.q.Binary, rel.Tag)
		}
		for _, s := range found[n] {
			s.Tag = rel.Tag
			v.sites[n] = append(v.sites[n], s)
		}
	}
	return nil
}

func (v *run) toRelease(rel Release) error {
	_, res, err := v.scan(rel, "to")
	if err != nil {
		return err
	}
	for _, n := range v.q.Names {
		for i := range res.Binaries {
			// Every spelling a library may treat alike, and the negated form.
			for _, f := range res.Binaries[i].Flags {
				if got := norm(f.Name); got == norm(n) || got == "no-"+norm(n) {
					v.names[n].add(CodeStillRegistered, "to", res.Binaries[i].Dir+":"+f.Name, rel.Tag)
				}
			}
		}
	}
	cl, err := v.sw.closure(v.ctx, v.in.Source, v.repo, rel.Commit, v.q.Binary, true)
	if err != nil {
		return err
	}
	for _, p := range cl.problems {
		v.pair.add(p.code, "to", p.detail, rel.Tag)
	}
	for _, p := range checkParser(cl.files, v.q.Binary) {
		v.pair.add(p.code, "to", p.detail, rel.Tag)
	}
	hits, problems, err := v.sw.sweep(v.ctx, v.in.Source, v.repo, rel.Commit, cl.modules)
	if err != nil {
		return err
	}
	for _, p := range problems {
		v.pair.add(p.code, "to", p.detail, rel.Tag)
	}
	for n, where := range hits {
		v.names[n].add(CodeLiteralHit, "to", where, rel.Tag)
	}
	return nil
}
