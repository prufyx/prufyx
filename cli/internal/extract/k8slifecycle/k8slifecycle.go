// SPDX-License-Identifier: AGPL-3.0-only

// Package k8slifecycle scans the API type sources of a pinned Kubernetes tree
// (staging/src/k8s.io/api/<group>/<version>/types.go) for lifecycle markers
// and field deprecations. It is inert: nothing in the registry, the data or
// the factory calls it yet.
//
// What is NEW here, against what the tree already yields:
//
//   - k8s.served-api-removal (package k8sservedapis) reads the GENERATED
//     zz_generated.prerelease-lifecycle.go files and takes only the
//     APILifecycleRemoved release of each kind. It never reads introduced,
//     deprecated or replacement, and it never reads types.go.
//   - k8s.feature-gate-removal (package k8sfeaturegates) reads feature gate
//     tables, not API types.
//   - This package reads the SOURCE markers in types.go:
//     +k8s:prerelease-lifecycle-gen:introduced, :deprecated, :removed and
//     :replacement per type, which give the introduced and deprecated
//     releases the generated files do not carry, and the removed release as
//     an independent second reading of the same fact; and it reads what no
//     existing extractor reads at all: +k8s:deprecated and +k8s:removed
//     markers and "Deprecated:" paragraphs in the doc comments of exported
//     struct fields.
//
// The removed release of a type is the one overlap with k8sservedapis. It is
// a SECOND source next to k8s.served-api-removal, never a replacement. The
// accessor MechanicalLifecycles therefore takes a read-only view of the
// served-API removals and hands out nothing on any mismatch or missing entry;
// k8sservedapis does not export such a view yet (a later change must). "Mechanical"
// here only means that the markers parsed completely and consistently; it is
// not a line attestation (Attestable is always false), and the output stays
// inert evidence for review until a reviewed consumer exists.
//
// Core group. The core API group has the empty GroupName. Like
// k8sservedapis (whose gvk keeps "" and which uses "core" only in slugs),
// Group fields here keep "" exactly as upstream writes it. "core" appears only
// inside a Member (CoreMemberGroup), because the member encoder forces a
// non-empty group, and in ledger items. A replacement marker is validated
// and then kept verbatim (",v1,Pod" stays ",v1,Pod"). A GroupName that is not
// a plausible API group name withholds (LIFECYCLE_GROUP_UNKNOWN).
//
// Marker placement. Markers are read from the type's doc comment and from one
// comment block that starts in column one and ends exactly one blank line
// above the doc comment (or above the type when it has none), the second
// block upstream allows. Markers anywhere else (two blank lines away,
// indented and not a doc comment, above a function or a variable, in an
// unrelated floating comment) are ignored; they attach to no type.
// +k8s:prerelease-lifecycle-gen=false removes the type from the lifecycle
// list. Other Go files of a version directory are not scanned for lifecycles;
// one that declares a type carrying any lifecycle or deprecation signal is
// withheld (LIFECYCLE_TYPES_OUTSIDE). That makes a version directory with
// marked types outside types.go incomplete, which is acceptable for an inert
// scanner; before any consumer exists, all non-generated, non-test files of
// the version package must be scanned as one unit.
//
// Stable versions. Deprecated is legal on a stable version (core/v1
// ComponentStatus is introduced 1.0 and deprecated 1.19 there); only a removal
// declared on a stable version is skew and withholds.
//
// Bounds. The reader gives no file size before the bytes, so each file is
// checked against the per-file bound right after it is read, every byte read
// counts against an aggregate cap, and nothing more is read once it is
// passed.
//
// Basis. A type whose introduced, deprecated and removed markers all parse as
// "1.<minor>", appear exactly once, are ordered (introduced <= deprecated <
// removed) and sit in a non-stable version directory is a mechanical
// lifecycle. A clean but partial set (introduced alone, or introduced and
// deprecated) is a draft. Field-level and type-level deprecation markers and
// "Deprecated:" paragraphs are always DRAFT, need review, and can never be
// mechanical: a deprecation is a warning, not a removal, and a doc comment is
// prose. Anything the scanner cannot read completely (a malformed or
// conflicting marker, an unknown lifecycle marker, removed before deprecated,
// a package that is not its version directory, a stable version carrying a
// removal, a generated or build-constrained types.go, a duplicate type, a
// bound exceeded, a refused member) adds a ledger entry, drops that item, and
// makes the whole result incomplete: MechanicalLifecycles then yields nothing.
//
// Reading is through an extract.PinnedReader, with go/parser only. Nothing is
// type-checked, compiled or executed. Ledger entries carry identifiers only,
// never comment text or marker values.
//
// Not covered: lifecycle markers outside staging/src/k8s.io/api (the
// apiextensions and aggregator trees stay with k8sservedapis), nested field
// paths (a field is recorded on the struct that declares it), build-constraint
// evaluation, markers in /* */ comments (they withhold), and the meaning of a
// +k8s:deprecated value (values are never retained).
package k8slifecycle

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// ResultSchema names the result layout.
const ResultSchema = "k8slifecycle.v1"

// Evidence bases.
const (
	BasisMechanical = "mechanical"
	BasisDraft      = "draft"
)

// Deprecation sources.
const (
	SourceDocComment = "doc"
	SourceDeprecated = "k8s:deprecated"
	SourceRemoved    = "k8s:removed"
)

// DefaultDir is the API tree this scanner is written for.
const DefaultDir = "staging/src/k8s.io/api"

// limits are the scan bounds; at the limit is accepted, over it is withheld.
type limits struct {
	groups, versions, versionsPerGroup, fileBytes, totalBytes, versionFiles, entries, markerLines int
}

func defaultLimits() limits {
	return limits{groups: 256, versions: 1024, versionsPerGroup: 64, fileBytes: 2 << 20, totalBytes: 128 << 20, versionFiles: 64, entries: 20000, markerLines: 32}
}

// Target names the API tree of one repository.
type Target struct {
	Repo extract.RepoRef
	Dir  string
}

func (t Target) validate() error {
	if t.Repo.Key == "" || t.Dir == "" || strings.HasPrefix(t.Dir, "/") || strings.Contains(t.Dir, "..") || strings.Contains(t.Dir, "\\") {
		return errors.New("k8slifecycle: bad target directory or repository")
	}
	return nil
}

// Lifecycle is the declared lifecycle of one type of one API version. A
// release is "1.<minor>", or empty when not declared. Group is the API group,
// with the core group (empty GroupName upstream) kept as "".
type Lifecycle struct {
	Group       string `json:"group"`
	Version     string `json:"version"`
	Kind        string `json:"kind"`
	Introduced  string `json:"introduced"`
	Deprecated  string `json:"deprecated"`
	Removed     string `json:"removed"`
	Replacement string `json:"replacement"`
	Basis       string `json:"basis"`
}

// Deprecation is a DRAFT deprecation signal: a field (or, with Field empty,
// a whole type) carrying a +k8s:deprecated or +k8s:removed marker, or a field
// whose doc comment holds a "Deprecated:" paragraph. It is never mechanical.
type Deprecation struct {
	Group       string `json:"group"`
	Version     string `json:"version"`
	Kind        string `json:"kind"`
	Field       string `json:"field"`
	Source      string `json:"source"`
	Member      string `json:"member"`
	Basis       string `json:"basis"`
	NeedsReview bool   `json:"needsReview"`
}

// Result is the canonical outcome of one scan.
type Result struct {
	Schema       string        `json:"schema"`
	Repo         string        `json:"repo"`
	Commit       string        `json:"commit"`
	Dir          string        `json:"dir"`
	Complete     bool          `json:"complete"`
	Versions     int           `json:"versions"`
	Lifecycles   []Lifecycle   `json:"lifecycles"`
	Deprecations []Deprecation `json:"deprecations"`
	Ledger       []LedgerEntry `json:"ledger"`
}

// Attestable is always false: source markers cannot back a line attestation
// (that stays with k8sservedapis).
func (r *Result) Attestable() bool { return false }

// MechanicalLifecycles returns the mechanical lifecycles of a complete,
// ledger-free scan, and only when every one of them is confirmed by a second
// source. served is a read-only view of the removal release that
// k8s.served-api-removal derives for (group, version, kind), in the same
// "1.<minor>" form, with the core group as "". It returns nil when the result
// is incomplete, when served is nil, and on ANY mechanical item that served
// does not know or reports differently: a mismatch withholds everything.
// Drafts are not asked about, since they legitimately differ.
//
// TODO (later change): k8sservedapis keeps its parsed lifecycle set
// unexported; a read-only view has to be exported there before any consumer
// can pass a real served.
func (r *Result) MechanicalLifecycles(served func(group, version, kind string) (release string, ok bool)) []Lifecycle {
	if r == nil || !r.Complete || len(r.Ledger) != 0 || served == nil {
		return nil
	}
	var out []Lifecycle
	for _, l := range r.Lifecycles {
		if l.Basis != BasisMechanical {
			continue
		}
		rel, ok := served(l.Group, l.Version, l.Kind)
		if !ok || rel != l.Removed {
			return nil
		}
		out = append(out, l)
	}
	return out
}

// guards are switched off only by tests (Scan passes the defaults).
type guards struct {
	ledger                                                                        ledgerGuards
	lim                                                                           limits
	limits, generated, constraint, skew, conflict, order, malformed, unknown, dup bool
	group, field, outside, genOff                                                 bool
}

func defaultGuards() guards {
	return guards{ledger: defaultLedgerGuards(), lim: defaultLimits(), limits: true, generated: true, constraint: true, skew: true,
		conflict: true, order: true, malformed: true, unknown: true, dup: true, group: true, field: true, outside: true, genOff: true}
}

var (
	versionDirRE = regexp.MustCompile(`^v[0-9]{1,3}((alpha|beta)[0-9]{1,3})?$`)
	stableRE     = regexp.MustCompile(`^v[0-9]{1,3}$`)
	releaseRE    = regexp.MustCompile(`^1\.(0|[1-9][0-9]{0,2})$`)
	groupRE      = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]{0,62})?$`)
	replaceRE    = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]{0,62})?,v[0-9]{1,3}((alpha|beta)[0-9]{1,3})?,[A-Za-z][A-Za-z0-9]{0,62}$`)
)

// Scan reads the API tree of the target at the pinned commit.
func Scan(ctx context.Context, r extract.PinnedReader, t Target, sha string) (*Result, error) {
	return scan(ctx, r, t, sha, defaultGuards())
}

func scan(ctx context.Context, r extract.PinnedReader, t Target, sha string, g guards) (*Result, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if !extract.IsCommitSHA(sha) {
		return nil, errors.New("k8slifecycle: sha must be a full 40-character commit SHA")
	}
	s := &scanner{g: g, r: r, t: t, sha: sha}
	if err := s.run(ctx); err != nil {
		return nil, err
	}
	res := &Result{Schema: ResultSchema, Repo: t.Repo.Key, Commit: sha, Dir: t.Dir, Versions: s.versions,
		Lifecycles: s.lifes, Deprecations: s.deps}
	if res.Lifecycles == nil {
		res.Lifecycles = []Lifecycle{}
	}
	if res.Deprecations == nil {
		res.Deprecations = []Deprecation{}
	}
	sort.Slice(res.Lifecycles, func(i, j int) bool {
		a, b := res.Lifecycles[i], res.Lifecycles[j]
		return a.Group+"\x00"+a.Version+"\x00"+a.Kind < b.Group+"\x00"+b.Version+"\x00"+b.Kind
	})
	sort.Slice(res.Deprecations, func(i, j int) bool {
		a, b := res.Deprecations[i], res.Deprecations[j]
		return strings.Join([]string{a.Group, a.Version, a.Kind, a.Field, a.Source}, "\x00") < strings.Join([]string{b.Group, b.Version, b.Kind, b.Field, b.Source}, "\x00")
	})
	res.Ledger = ledgerOf(s.led, g.ledger)
	res.Complete = len(res.Ledger) == 0 && s.versions > 0
	if !g.ledger.veto {
		res.Complete = true
	}
	return res, nil
}

type scanner struct {
	g        guards
	r        extract.PinnedReader
	t        Target
	sha      string
	versions int
	total    int
	over     bool
	lifes    []Lifecycle
	deps     []Deprecation
	led      []LedgerEntry
}

func (s *scanner) add(code, item string) { s.led = append(s.led, LedgerEntry{Code: code, Item: item}) }

func (s *scanner) dirs(dir string) ([]string, error) {
	entries, err := s.r.List(s.t.Repo, s.sha, dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type == "tree" {
			out = append(out, path.Base(e.Path))
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *scanner) run(ctx context.Context) error {
	groups, err := s.dirs(s.t.Dir)
	if err != nil {
		return err
	}
	if s.g.limits && len(groups) > s.g.lim.groups {
		s.add(ReasonTooMany, "groups")
		return nil
	}
	for _, grp := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.over {
			s.add(ReasonTooLarge, "total")
			return nil
		}
		subs, err := s.dirs(path.Join(s.t.Dir, grp))
		if err != nil {
			return err
		}
		var vers []string
		for _, v := range subs {
			if versionDirRE.MatchString(v) {
				vers = append(vers, v)
			}
		}
		if s.g.limits && len(vers) > s.g.lim.versionsPerGroup {
			s.add(ReasonTooMany, grp)
			continue
		}
		for _, v := range vers {
			if err := ctx.Err(); err != nil {
				return err
			}
			if s.g.limits && s.versions >= s.g.lim.versions {
				s.add(ReasonTooMany, "versions")
				return nil
			}
			s.versions++
			if s.over {
				s.add(ReasonTooLarge, "total")
				return nil
			}
			if err := s.version(ctx, grp, v); err != nil {
				return err
			}
			if s.over {
				s.add(ReasonTooLarge, "total")
				return nil
			}
			if s.g.limits && len(s.lifes)+len(s.deps) > s.g.lim.entries {
				s.add(ReasonTooMany, "entries")
				return nil
			}
		}
	}
	return nil
}

func parseSafe(fset *token.FileSet, name string, data []byte) (f *ast.File, err error) {
	defer func() {
		if r := recover(); r != nil {
			f, err = nil, errors.New("parser panic")
		}
	}()
	return parser.ParseFile(fset, name, data, parser.ParseComments|parser.SkipObjectResolution)
}

// read returns a file's bytes; missing reports an absent file.
func (s *scanner) read(p string) (data []byte, missing bool, err error) {
	data, err = s.r.Read(s.t.Repo, s.sha, p)
	if errors.Is(err, extract.ErrNotFound) {
		return nil, true, nil
	}
	// The reader gives no size before the bytes, so the per-file bound is
	// checked straight after the read and every byte read counts against an
	// aggregate cap; once it is passed nothing more is read.
	s.total += len(data)
	if s.g.limits && s.total > s.g.lim.totalBytes {
		s.over = true
	}
	return data, false, err
}

// groupName returns the GroupName constant of the version's register.go.
func groupName(f *ast.File) (string, bool) {
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if n.Name != "GroupName" || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", false
				}
				v, err := strconv.Unquote(lit.Value)
				return v, err == nil
			}
		}
	}
	return "", false
}

func isGenerated(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "// Code generated") && strings.HasSuffix(c.Text, "DO NOT EDIT.") {
				return true
			}
		}
	}
	return false
}

func hasConstraint(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:build") || strings.HasPrefix(c.Text, "// +build") {
				return true
			}
		}
	}
	return false
}

func (s *scanner) version(ctx context.Context, grp, ver string) (err error) {
	base := path.Join(s.t.Dir, grp, ver)
	item := grp + "/" + ver
	defer func() {
		if r := recover(); r != nil {
			s.add(ReasonPanic, item)
			err = nil
		}
	}()

	// The group name comes from register.go of the same version directory.
	group, ok := "", false
	reg, missing, rerr := s.read(path.Join(base, "register.go"))
	if rerr != nil {
		return rerr
	}
	if !missing && len(reg) <= s.g.lim.fileBytes {
		if rf, perr := parseSafe(token.NewFileSet(), "register.go", reg); perr == nil {
			group, ok = groupName(rf)
		}
	}
	if s.over {
		return nil // aggregate cap passed: types.go is not read
	}
	if ok && !groupRE.MatchString(group) {
		ok = false // a GroupName that is not a plausible API group is not read
	}
	if !ok && s.g.group {
		s.add(ReasonGroupUnknown, item)
		return nil
	}
	data, missing, rerr := s.read(path.Join(base, "types.go"))
	if rerr != nil {
		return rerr
	}
	if missing {
		s.add(ReasonTypesMissing, item)
		return nil
	}
	if s.g.limits && len(data) > s.g.lim.fileBytes {
		s.add(ReasonTooLarge, item)
		return nil
	}
	fset := token.NewFileSet()
	f, perr := parseSafe(fset, "types.go", data)
	if perr != nil {
		s.add(ReasonParse, item)
		return nil
	}
	if s.g.generated && isGenerated(f) {
		s.add(ReasonGenerated, item)
		return nil
	}
	if s.g.constraint && hasConstraint(f) {
		s.add(ReasonBuildConstr, item)
		return nil
	}
	if s.g.skew && f.Name.Name != ver {
		s.add(ReasonVersionSkew, item)
		return nil
	}
	if err := s.types(fset, f, group, ver); err != nil {
		return err
	}
	return s.outside(base, item, group, ver)
}

// CoreMemberGroup stands for the core group (empty GroupName upstream) inside
// a member, because the member encoder forces a non-empty group. It appears
// nowhere else: Group fields keep "".
const CoreMemberGroup = "core"

// itemGroup names the group in ledger items, which must not be empty.
func itemGroup(g string) string {
	if g == "" {
		return CoreMemberGroup
	}
	return g
}

// generatedName reports file names the code generators own; they hold no
// hand-written type declarations.
func generatedName(b string) bool {
	return strings.HasPrefix(b, "zz_generated") || strings.HasPrefix(b, "generated.") || strings.HasSuffix(b, "_generated.go")
}

// outside looks at the other Go files of the version directory. This scanner
// reads types.go only, so a file that declares a type carrying a lifecycle or
// deprecation signal would be missed silently; it is withheld instead. Types
// without any such signal in those files are harmless and not listed.
func (s *scanner) outside(base, item, group, ver string) error {
	entries, err := s.r.List(s.t.Repo, s.sha, base)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		b := path.Base(e.Path)
		if e.Type != "blob" || !strings.HasSuffix(b, ".go") || strings.HasSuffix(b, "_test.go") || b == "types.go" || b == "register.go" || generatedName(b) {
			continue
		}
		names = append(names, b)
	}
	sort.Strings(names)
	if s.g.limits && len(names) > s.g.lim.versionFiles {
		s.add(ReasonTooMany, item)
		return nil
	}
	for _, b := range names {
		if s.over {
			break // aggregate cap passed: nothing more is read
		}
		data, missing, err := s.read(path.Join(base, b))
		if err != nil {
			return err
		}
		if missing || s.over {
			continue // a file read past the cap is not parsed
		}
		bad := func() { s.add(ReasonTypesOutside, item) }
		if s.g.limits && len(data) > s.g.lim.fileBytes {
			bad()
			continue
		}
		fset := token.NewFileSet()
		f, perr := parseSafe(fset, b, data)
		if perr != nil || hasConstraint(f) || f.Name.Name != ver {
			if s.g.outside {
				bad()
			}
			continue
		}
		sub := &scanner{g: s.g, r: s.r, t: s.t, sha: s.sha}
		if err := sub.types(fset, f, group, ver); err != nil {
			return err
		}
		if (len(sub.lifes) > 0 || len(sub.deps) > 0 || len(sub.led) > 0) && s.g.outside {
			bad()
		}
	}
	return nil
}
