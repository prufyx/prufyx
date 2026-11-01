// SPDX-License-Identifier: AGPL-3.0-only

// Package cliflags reads, from the Go source of a project at one pinned
// commit, the long names of the command line flags each of its binaries
// registers. The result is one set per binary plus a ledger of everything the
// scanner could not decide.
//
// The scanner is one-sided on purpose: it names a flag only when it can see
// the registration, and it withholds (an incomplete set and a ledger entry)
// whenever the source holds something that could register, hide, rename or
// accept a flag without being seen. A withheld binary can therefore never
// turn into "no flag was removed".
//
// Method. Files are parsed with go/parser and walked with go/ast. There is no
// type checking, no build and no execution: a call counts as a registration
// only when its receiver is provably a flag set by syntax (rooted at the
// import name of a flag library, at a variable assigned from a recognised
// constructor or accessor, at a parameter declared with a library type, or at
// a parameter bound by a followed call). Every registration-shaped call on a
// receiver that cannot be proven is a withhold.
//
// Binaries are not configured: every directory of the module with a non-test
// package main at the pinned commit is one. A reviewed target can only
// exclude a directory, with a reason.
//
// Contract for the comparison of two scans (not in this package): the newer
// side counts every name for which Binary.Present is true as still accepted,
// including names withheld as unreachable or outside the member contract; the
// older side states a removal only for names for which Binary.Removable is
// true. Counting a withheld registration as absent on the newer side would
// turn an unproven reachability into a removal.
//
// Scope. Flag-level facts (shorthand, hidden, deprecated, name that cannot be
// a member) are listed on the flags of a binary. Pair-level decisions (a name
// still registered by another binary, a rename) belong to the code that
// compares two scans.
package cliflags

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// ResultSchema identifies the canonical JSON of a Result.
const ResultSchema = "prufyx.io/cli-flags-scan/v1"

// Collector classes: the dash forms a binary's flags are written with.
const (
	// ClassDoubleDash: flags are written --name only (pflag, cobra, kingpin).
	ClassDoubleDash = "double-dash"
	// ClassSingleDashLong: long names are also accepted with one dash
	// (-name): the standard library flag package and urfave/cli. A binary
	// that mixes libraries is in this class when any of them is.
	ClassSingleDashLong = "single-dash-long"
)

// Idiom names, as published in Binary.Idioms.
const (
	IdiomFlag    = "flag"
	IdiomPflag   = "pflag"
	IdiomKingpin = "kingpin"
	IdiomUrfave  = "urfave"
)

// Exclusion removes one directory from the scan, with the reason a reviewer
// gave. The directory is a binary (package main) directory, a nested-module
// directory or a submodule directory; "." is the repository root.
type Exclusion struct {
	Dir    string `json:"dir"`
	Reason string `json:"reason"`
}

// Target is the reviewed input of a scan. The binaries are not listed: a
// reviewer can only exclude.
type Target struct {
	Repo    extract.RepoRef
	Exclude []Exclusion
}

var exclusionReasonRE = regexp.MustCompile(`^[ -~]{1,200}$`)

func (t Target) validate() error {
	seen := map[string]bool{}
	for _, e := range t.Exclude {
		if e.Dir != "." && (e.Dir == "" || e.Dir != path.Clean(e.Dir) || strings.HasPrefix(e.Dir, "/") || e.Dir == ".." || strings.HasPrefix(e.Dir, "../")) {
			return fmt.Errorf("cliflags: exclusion directory %q is not a clean repository-relative path", e.Dir)
		}
		if !exclusionReasonRE.MatchString(e.Reason) || strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("cliflags: exclusion of %q needs a printable reason of at most 200 characters", e.Dir)
		}
		if seen[e.Dir] {
			return fmt.Errorf("cliflags: exclusion of %q is listed twice", e.Dir)
		}
		seen[e.Dir] = true
	}
	return nil
}

// Omission is one withheld item: a reason, the subject it concerns (a binary
// directory or a repository path, never source content), how many times it
// occurred and the first detail (an import path or file path).
type Omission struct {
	Reason  string `json:"reason"`
	Subject string `json:"subject"`
	Count   int    `json:"count"`
	Detail  string `json:"detail,omitempty"`
	// Global marks a fault about the inventory (a directory, the module, a
	// limit) rather than about one binary: whatever it hides could be part of
	// any binary, so it withholds every binary.
	Global bool `json:"global,omitempty"`
}

// Flag is one registered long name of a binary. Names that cannot be set
// members are listed too (with their reason), so that a later comparison sees
// the name as present.
type Flag struct {
	Name string `json:"name"`
	// Hidden: hidden on at least one registration (MarkHidden, Hidden(),
	// Hidden: true). A hidden flag is still accepted, so it stays a member.
	Hidden bool `json:"hidden"`
	// Deprecated: a MarkDeprecated call with this literal name exists. A
	// deprecated flag is still accepted, so it stays a member.
	Deprecated bool `json:"deprecated"`
	// Withheld lists the flag-level reasons that stop a removal of this name
	// from being stated. Sorted.
	Withheld []string `json:"withheld"`
}

// CountsAsPresent reports whether the flag counts as accepted by the binary
// when the scan is the newer side of a comparison ("still present"). It is
// true for every listed flag, including one that carries
// FLAG_REACHABILITY_UNPROVEN or a name that cannot be a set member: a name the
// source registers may be accepted, and over-counting the newer side only ever
// withholds a removal.
func (f Flag) CountsAsPresent() bool { return true }

// UsableForRemoval reports whether the flag may back a stated removal when the
// scan is the older side: only a flag with no flag-level reason (no shorthand,
// not unreachable, not builtin, not a name outside the member contract, ...).
// Whether the name is also absent from the newer scan is the caller's check.
func (f Flag) UsableForRemoval() bool { return len(f.Withheld) == 0 }

// Binary is the scan result of one package main directory.
type Binary struct {
	// Dir is the repository-relative directory ("." for the root).
	Dir string `json:"dir"`
	// Idioms are the flag libraries the binary's package set imports or
	// registers with, sorted.
	Idioms []string `json:"idioms"`
	// Class is the collector class (ClassDoubleDash, ClassSingleDashLong), or
	// empty when no flag library is involved.
	Class string `json:"class"`
	// Flags are all registered literal names, sorted by name.
	Flags []Flag `json:"flags"`
	// Set holds the member names (long names that satisfy the member
	// contract), sorted. It is complete only when the binary has no ledger
	// entry.
	Set constraintengine.SetValue `json:"set"`
}

// Result is what Scan returns.
type Result struct {
	Schema string `json:"schema"`
	Commit string `json:"commit"`
	// Module is the module path from go.mod.
	Module   string   `json:"module"`
	Binaries []Binary `json:"binaries"`
	// Excluded are the exclusions that matched a directory.
	Excluded []Exclusion `json:"excluded"`
	// Omissions are the withheld items, as report text.
	Omissions []Omission `json:"omissions"`
	// Ledger is the typed, canonical form of Omissions. A non-empty ledger
	// means the sets are incomplete and the scan is not attestable.
	Ledger []LedgerEntry `json:"ledger"`
}

// Present reports whether the binary registers name in any form the scanner
// saw (see Flag.CountsAsPresent). Use it for the newer side of a comparison.
func (b *Binary) Present(name string) bool {
	_, ok := b.flag(name)
	return ok
}

// Removable reports whether name may be stated as removed when it is absent
// from the newer scan: it is a member of this (older) binary's complete set
// and its flag carries no flag-level reason. Use it for the older side only.
func (b *Binary) Removable(name string) bool {
	f, ok := b.flag(name)
	if !ok || !b.Set.Complete || !f.UsableForRemoval() {
		return false
	}
	for _, m := range b.Set.Members {
		if m == name {
			return true
		}
	}
	return false
}

func (b *Binary) flag(name string) (Flag, bool) {
	for _, f := range b.Flags {
		if f.Name == name {
			return f, true
		}
	}
	return Flag{}, false
}

// Canonical returns the canonical JSON of the result.
func (r *Result) Canonical() ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// guards are switched off only by tests, to prove each guard is load bearing.
type guards struct {
	imports     bool // default-deny import allowlist
	dynamic     bool // non-literal names
	loop        bool
	buildTag    bool // //go:build, +build and GOOS/GOARCH file suffixes
	goos        bool // runtime.GOOS / runtime.GOARCH branches
	initReg     bool // init() and function-literal registrations
	tripwire    bool // registration-shaped calls on unprovable receivers
	escape      bool // flag sets that are returned, stored or passed on
	delegated   bool // unresolvable callees and other unfollowable flag sets
	depthLimit  bool // MaxFollowDepth
	normalize   bool
	global      bool // AddGoFlagSet, InitFlags
	duplicate   bool
	argsRewrite bool
	shorthand   bool // one-character aliases and P variants
	aliases     bool // urfave aliases longer than one character become members
	nameClass   bool // uppercase, one-character, charset and length of names
	negation    bool // kingpin no- names
	builtin     bool // help and version
	unlisted    bool // methods of a flag set that are not known to be harmless
	argsParser  bool // os.Args handed to a parser the walker can prove
	reach       bool // registrations in functions nothing reaches
	vendorMod   bool // replace directives and vendored replacements
	stdDeny     bool // standard library packages that register flags or load code
	hook        func(string)
	verbs       map[string]verbInfo // nil: regVerbs
	fileNames   bool                // files the go tool ignores by name
	urfaveElems bool                // unrecognised elements of a []cli.Flag literal
	declAll     bool                // fields and variables count as declared parsers
	urfaveWrap  bool                // only urfave packages wrap a flag
	reachDot    bool                // reachability through dot imports
	goWork      bool                // go.work replace and use
	urfaveGen   bool                // urfave v3 generic flag types
	excludeOnly bool                // an exclusion that matches nothing is a fault
	limits      bool
	lim         limits
	parse       bool // parse errors are faults
	ledger      ledgerGuards
}

// verb looks a registration method up in the guards' table (the default
// table unless a test replaced it).
func (g *guards) verb(name string) (verbInfo, bool) {
	if g.verbs != nil {
		v, ok := g.verbs[name]
		return v, ok
	}
	v, ok := regVerbs[name]
	return v, ok
}

func defaultGuards() guards {
	return guards{
		imports: true, dynamic: true, loop: true, buildTag: true, goos: true, initReg: true,
		tripwire: true, escape: true, delegated: true, depthLimit: true, normalize: true, global: true,
		duplicate: true, argsRewrite: true, shorthand: true, aliases: true, nameClass: true,
		negation: true, builtin: true, unlisted: true, argsParser: true, reach: true, vendorMod: true, stdDeny: true, fileNames: true, urfaveGen: true, reachDot: true, declAll: true, urfaveWrap: true, goWork: true, urfaveElems: true, excludeOnly: true, limits: true, lim: defaultLimits(), parse: true, ledger: defaultLedgerGuards(),
	}
}

// Scan reads the Go source of target at sha (a full 40-character commit)
// through r. A non-nil error means the run could not read pinned bytes
// (reader failure, cancelled context, bad input); anything the scanner cannot
// decide is in the result's omissions and ledger instead.
//
// The ledger must be carried into the pair record by the code that wires the
// scanner into the framework, which may attest only when Result.Attestable.
func Scan(ctx context.Context, r extract.PinnedReader, t Target, sha string) (*Result, error) {
	return scan(ctx, r, t, sha, defaultGuards())
}

func scan(ctx context.Context, r extract.PinnedReader, t Target, sha string, g guards) (*Result, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if !extract.IsCommitSHA(sha) {
		return nil, errors.New("cliflags: sha must be a full 40-character commit SHA")
	}
	s := &scanner{ctx: ctx, r: r, repo: t.Repo, sha: sha, g: g, fset: token.NewFileSet(),
		dirs: map[string]*dirListing{}, pkgs: map[string]*pkg{}, om: omset{}}
	res := &Result{Schema: ResultSchema, Commit: sha, Binaries: []Binary{}, Excluded: []Exclusion{}}
	if err := s.safeRun(t, res); err != nil {
		return nil, err
	}
	res.Omissions = s.omissions()
	res.seal(g.ledger)
	return res, nil
}

// safeRun runs the scan and turns a panic anywhere in it into a global
// fault: the result is then incomplete everywhere.
func (s *scanner) safeRun(t Target, res *Result) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.fault(ReasonPanic, "", "")
			err = nil
		}
	}()
	if s.g.hook != nil {
		s.g.hook("run")
	}
	return s.run(t, res)
}

type dirListing struct {
	entries []extract.TreeEntry
	missing bool
}

type scanner struct {
	ctx    context.Context
	r      extract.PinnedReader
	repo   extract.RepoRef
	sha    string
	g      guards
	fset   *token.FileSet
	module string
	// replaced are the module paths go.mod or vendor/modules.txt replaces:
	// imports under them are not the reviewed libraries.
	replaced []string
	dirs     map[string]*dirListing
	pkgs     map[string]*pkg
	files    int
	bytes    int
	om       omset
}

// omset collects omissions keyed by (reason, subject).
type omset map[[2]string]*Omission

func (m omset) add(reason, subject, detail string) {
	k := [2]string{reason, subject}
	o := m[k]
	if o == nil {
		o = &Omission{Reason: reason, Subject: subject}
		m[k] = o
	}
	o.Count++
	if len(detail) > MaxLedgerItemLen {
		detail = detail[:MaxLedgerItemLen]
	}
	if o.Detail == "" || (detail != "" && detail < o.Detail) {
		o.Detail = detail
	}
}

func (m omset) addGlobal(reason, subject, detail string) {
	m.add(reason, subject, detail)
	m[[2]string{reason, subject}].Global = true
}

func (m omset) merge(src omset) {
	for k, o := range src {
		d := m[k]
		if d == nil {
			c := *o
			m[k] = &c
			continue
		}
		d.Count += o.Count
		d.Global = d.Global || o.Global
		if d.Detail == "" || (o.Detail != "" && o.Detail < d.Detail) {
			d.Detail = o.Detail
		}
	}
}

func (m omset) list() []Omission {
	out := make([]Omission, 0, len(m))
	for _, o := range m {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func (s *scanner) omissions() []Omission { return s.om.list() }

func (s *scanner) fault(reason, dir, detail string) { s.om.addGlobal(reason, showDir(dir), detail) }

// showDir is the directory as it appears in results and ledger items.
func showDir(dir string) string {
	if dir == "" {
		return "."
	}
	return dir
}

func (s *scanner) read(p string) ([]byte, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	return s.r.Read(s.repo, s.sha, p)
}

func (s *scanner) list(dir string) (*dirListing, error) {
	if l, ok := s.dirs[dir]; ok {
		return l, nil
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := s.r.List(s.repo, s.sha, dir)
	l := &dirListing{}
	switch {
	case errors.Is(err, extract.ErrNotFound):
		l.missing = true
	case err != nil:
		return nil, fmt.Errorf("cliflags: list %s: %w", showDir(dir), err)
	default:
		l.entries = append([]extract.TreeEntry(nil), entries...)
		sort.Slice(l.entries, func(i, j int) bool { return l.entries[i].Path < l.entries[j].Path })
	}
	s.dirs[dir] = l
	return l, nil
}

var moduleLineRE = regexp.MustCompile(`^module\s+("?)([A-Za-z0-9][A-Za-z0-9._~/-]*)("?)\s*(//.*)?$`)

func (s *scanner) readModule() (bool, error) {
	data, err := s.read("go.mod")
	if errors.Is(err, extract.ErrNotFound) {
		s.fault(ReasonGoModMissing, "", "")
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cliflags: read go.mod: %w", err)
	}
	if len(data) > maxGoModBytes {
		s.fault(ReasonGoModInvalid, "", "too large")
		return false, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module") {
			continue
		}
		m := moduleLineRE.FindStringSubmatch(line)
		if m == nil || m[1] != m[3] {
			break
		}
		s.module = m[2]
		s.readReplaced(string(data))
		if err := s.readVendorReplaced(); err != nil {
			return false, err
		}
		if err := s.readWork(); err != nil {
			return false, err
		}
		return true, nil
	}
	s.fault(ReasonGoModInvalid, "", "")
	return false, nil
}

// readReplaced collects the old paths of go.mod replace directives, in both
// the single-line and the block form.
func (s *scanner) readReplaced(gomod string) {
	inBlock := false
	for _, line := range strings.Split(gomod, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case inBlock && f[0] == ")":
			inBlock = false
		case inBlock:
			s.noteReplaced(f)
		case f[0] == "replace" && len(f) > 1 && f[1] == "(":
			inBlock = true
		case f[0] == "replace":
			s.noteReplaced(f[1:])
		}
	}
}

func (s *scanner) noteReplaced(f []string) {
	for i, w := range f {
		if w == "=>" && i > 0 {
			s.replaced = append(s.replaced, strings.Trim(f[0], `"`))
			return
		}
	}
}

// readWork reads go.work when the repository has one: its replace directives
// count like go.mod's, and a use directive that leaves the repository means
// the build is not the module alone.
func (s *scanner) readWork() error {
	data, err := s.read("go.work")
	if errors.Is(err, extract.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cliflags: read go.work: %w", err)
	}
	if len(data) > maxGoModBytes {
		s.fault(ReasonGoModInvalid, "go.work", "too large")
		return nil
	}
	if !s.g.goWork {
		return nil
	}
	s.readReplaced(string(data))
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		var dirs []string
		switch {
		case len(f) == 0:
		case inBlock && f[0] == ")":
			inBlock = false
		case inBlock:
			dirs = f[:1]
		case f[0] == "use" && len(f) > 1 && f[1] == "(":
			inBlock = true
		case f[0] == "use" && len(f) > 1:
			dirs = f[1:2]
		}
		for _, d := range dirs {
			d = strings.Trim(d, `"`)
			if c := path.Clean(d); path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
				s.fault(ReasonGoModInvalid, "go.work", "use outside the module")
			}
		}
	}
	return nil
}

// readVendorReplaced reads the replacement markers ("# path version => dir")
// of vendor/modules.txt when the module vendors its dependencies. The vendored
// files themselves are not hashed by the go tool and cannot be checked here: a
// vendor tree patched without a replace directive is a residual risk.
func (s *scanner) readVendorReplaced() error {
	data, err := s.read("vendor/modules.txt")
	if errors.Is(err, extract.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cliflags: read vendor/modules.txt: %w", err)
	}
	if len(data) > maxGoModBytes {
		s.fault(ReasonGoModInvalid, "vendor", "modules.txt too large")
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[0] == "#" {
			for _, w := range f[2:] {
				if w == "=>" {
					s.replaced = append(s.replaced, f[1])
					break
				}
			}
		}
	}
	return nil
}

func (s *scanner) run(t Target, res *Result) error {
	ok, err := s.readModule()
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	res.Module = s.module
	mains, faultDirs, err := s.discover()
	if err != nil {
		return err
	}
	excluded := map[string]string{}
	for _, e := range t.Exclude {
		dir := e.Dir
		if dir == "." {
			dir = ""
		}
		excluded[dir] = e.Reason
	}
	matched := map[string]bool{}
	var kept []string
	for _, d := range mains {
		if _, ok := excluded[d]; ok {
			matched[d] = true
			continue
		}
		kept = append(kept, d)
	}
	for _, fd := range faultDirs {
		if _, ok := excluded[fd.dir]; ok {
			matched[fd.dir] = true
			continue
		}
		s.fault(fd.reason, fd.dir, "")
	}
	for _, e := range t.Exclude {
		dir := e.Dir
		if dir == "." {
			dir = ""
		}
		if matched[dir] {
			res.Excluded = append(res.Excluded, e)
		} else if s.g.excludeOnly {
			s.fault(ReasonExclusionUnknown, dir, "")
		}
	}
	sort.Slice(res.Excluded, func(i, j int) bool { return res.Excluded[i].Dir < res.Excluded[j].Dir })
	if len(kept) == 0 && len(res.Excluded) == 0 && !s.hasInventoryFault() {
		s.fault(ReasonNoBinary, "", "")
	}
	for _, d := range kept {
		b, err := s.binary(d)
		if err != nil {
			return err
		}
		res.Binaries = append(res.Binaries, *b)
	}
	sort.Slice(res.Binaries, func(i, j int) bool { return res.Binaries[i].Dir < res.Binaries[j].Dir })
	return nil
}

func (s *scanner) hasInventoryFault() bool { return len(s.om) > 0 }

type faultDir struct{ dir, reason string }

// skipDir reports directories the go tool ignores.
func skipDir(name string) bool {
	return name == "vendor" || name == "testdata" || name == "node_modules" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// discover walks the module tree and returns the directories holding a
// non-test package main, plus the directories it could not descend into.
func (s *scanner) discover() (mains []string, faults []faultDir, err error) {
	type item struct {
		dir   string
		depth int
	}
	queue := []item{{"", 0}}
	seen := 0
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		seen++
		if s.g.limits && seen > s.g.lim.dirs {
			s.fault(ReasonTooLarge, "", "directories")
			return mains, faults, nil
		}
		l, err := s.list(it.dir)
		if err != nil {
			return nil, nil, err
		}
		if l.missing {
			s.fault(ReasonTreeMissing, it.dir, "")
			continue
		}
		var goFiles []extract.TreeEntry
		var subdirs []extract.TreeEntry
		nested := false
		for _, e := range l.entries {
			base := path.Base(e.Path)
			switch {
			case e.Type == "tree":
				if !skipDir(base) {
					subdirs = append(subdirs, e)
				}
			case e.Type == "commit":
				if !skipDir(base) {
					faults = append(faults, faultDir{e.Path, ReasonSubmodule})
				}
			case base == "go.mod" && it.dir != "":
				nested = true
			case s.goSrc(base):
				if e.Type != "blob" || e.Mode == "120000" {
					faults = append(faults, faultDir{it.dir, ReasonSourceKind})
					continue
				}
				goFiles = append(goFiles, e)
			}
		}
		if nested {
			faults = append(faults, faultDir{it.dir, ReasonNestedModule})
			continue
		}
		if s.g.limits && len(goFiles) > s.g.lim.filesPerDir {
			s.fault(ReasonTooLarge, it.dir, "files")
			continue
		}
		if len(goFiles) > 0 {
			name, ok, err := s.packageName(it.dir, goFiles)
			if err != nil {
				return nil, nil, err
			}
			if ok && name == "main" {
				mains = append(mains, it.dir)
			}
		}
		if it.depth+1 > s.g.lim.depth && len(subdirs) > 0 && s.g.limits {
			s.fault(ReasonTooLarge, it.dir, "depth")
			continue
		}
		for _, sd := range subdirs {
			queue = append(queue, item{sd.Path, it.depth + 1})
		}
	}
	sort.Strings(mains)
	return mains, faults, nil
}

// packageName reads files in order until one that the go tool would build
// names the package.
func (s *scanner) packageName(dir string, files []extract.TreeEntry) (string, bool, error) {
	for _, e := range files {
		data, err := s.read(e.Path)
		if errors.Is(err, extract.ErrNotFound) {
			s.fault(ReasonPackageMissing, dir, e.Path)
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("cliflags: read %s: %w", e.Path, err)
		}
		if s.g.limits && len(data) > s.g.lim.fileBytes {
			s.fault(ReasonTooLarge, dir, e.Path)
			return "", false, nil
		}
		f, perr := parseSafe(s.fset, e.Path, data, parser.PackageClauseOnly|parser.ParseComments)
		if perr != nil || f == nil {
			if s.g.parse {
				s.fault(ReasonParseError, dir, e.Path)
			}
			return "", false, nil
		}
		if c := constraintOf(f, e.Path); c.ignored {
			continue
		}
		return f.Name.Name, true, nil
	}
	return "", false, nil
}

// parseSafe parses and never panics.
func parseSafe(fset *token.FileSet, name string, data []byte, mode parser.Mode) (f *ast.File, err error) {
	defer func() {
		if r := recover(); r != nil {
			f, err = nil, fmt.Errorf("parser panic: %v", r)
		}
	}()
	f, err = parser.ParseFile(fset, name, data, mode)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// fileConstraint says how the go tool selects a file.
type fileConstraint struct {
	constrained bool // a build line or a GOOS/GOARCH suffix
	ignored     bool // "ignore": never built
}

var knownOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true, "hurd": true,
	"illumos": true, "ios": true, "js": true, "linux": true, "nacl": true, "netbsd": true,
	"openbsd": true, "plan9": true, "solaris": true, "wasip1": true, "windows": true, "zos": true,
}

var knownArch = map[string]bool{
	"386": true, "amd64": true, "amd64p32": true, "arm": true, "armbe": true, "arm64": true, "arm64be": true,
	"loong64": true, "mips": true, "mipsle": true, "mips64": true, "mips64le": true, "mips64p32": true,
	"mips64p32le": true, "ppc": true, "ppc64": true, "ppc64le": true, "riscv": true, "riscv64": true,
	"s390": true, "s390x": true, "sparc": true, "sparc64": true, "wasm": true,
}

func constraintOf(f *ast.File, filename string) fileConstraint {
	var c fileConstraint
	base := strings.TrimSuffix(path.Base(filename), ".go")
	parts := strings.Split(base, "_")
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if knownOS[last] || knownArch[last] {
			c.constrained = true
		}
	}
	for _, cg := range f.Comments {
		if cg.End() >= f.Package {
			break
		}
		for _, cm := range cg.List {
			line := cm.Text
			if !constraint.IsGoBuild(line) && !constraint.IsPlusBuild(line) {
				continue
			}
			c.constrained = true
			if x, err := constraint.Parse(line); err == nil && x.String() == "ignore" {
				c.ignored = true
			}
		}
	}
	return c
}

// binary scans one package main directory.
func (s *scanner) binary(dir string) (*Binary, error) {
	bin := showDir(dir)
	b := &Binary{Dir: bin, Idioms: []string{}, Flags: []Flag{}}
	b.Set.Members = []string{}
	om := omset{}
	cl, err := s.closureOf(dir, bin, om)
	if err != nil {
		return nil, err
	}
	var aerr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				om.add(ReasonPanic, bin, "")
			}
		}()
		if s.g.hook != nil {
			s.g.hook("binary")
		}
		a := newAnalysis(s, bin, dir, cl, om)
		a.run()
		aerr = a.err
		a.fill(b)
	}()
	if aerr != nil {
		return nil, aerr
	}
	s.om.merge(om)
	return b, nil
}
