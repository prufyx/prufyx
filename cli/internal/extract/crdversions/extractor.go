// SPDX-License-Identifier: AGPL-3.0-only

// Package crdversions is the crd.version-removal extractor family. For one
// catalog project and each pair of consecutive release lines it parses
// every CustomResourceDefinition manifest under the project's listed paths
// at every final release tag of both lines, scans the whole repository at
// each of those tags for definitions outside the listed paths, and derives,
// per CRD, a forbid_set_member rule over the project's custom-resource
// version set listing the versions the earlier line serves and the later
// line no longer serves (absent, served: false, or the definition removed
// from the repository). When every tag of both lines is established
// completely the rule ranges over both whole lines; otherwise it holds for
// the pair of first releases only. Storage-version changes are recorded in
// the proof, never emitted. See docs/extractors/crd.version-removal.md for
// the public specification.
package crdversions

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Identity.
const (
	// IDPrefix is followed by the project slug: one extractor id per
	// project, since a run reads one repository.
	IDPrefix = "crd.version-removal."
	Version  = "2.0.0"
	// SourceDir is this package's directory under the module's internal/.
	SourceDir = "extract/crdversions"
)

// source is the package's code and its reviewed target table; both are
// covered by the code digest.
//
//go:embed *.go targets.json
var source embed.FS

const (
	reasonCode = "CRD_VERSION_NOT_SERVED"
	maxIDBytes = 128
	maxNext    = 256
	// maxTagsPerLine bounds the release tags read for one line.
	maxTagsPerLine = 64
)

// Removal reasons.
const (
	ReasonAbsent   = "absent"
	ReasonUnserved = "unserved"
)

// Extractor implements extract.Extractor for one target. It caches each
// commit's inventory and scan and each blob's summary; it is a pure
// function of pinned bytes.
type Extractor struct {
	target      Target
	concurrency int

	mu    sync.Mutex
	cache map[string]inventoryResult
	scans map[string]*ScanRecord
	blobs map[string]*blobInfo
	// surfaces holds each install-surface file's summary (see guard.go).
	surfaces map[string]*surfaceInfo
	// lines is the release lines of the last Pairs call, by line key.
	lines map[string]*releaseLine
	// lineOf maps a tag name to its line key.
	lineOf map[string]string
}

type inventoryResult struct {
	inv *Inventory
	err error
}

// New returns the extractor of a target.
func New(t Target) *Extractor { return NewConcurrent(t, 1) }

// NewConcurrent returns the extractor of a target that reads up to
// concurrency files at a time during the scan. Output never depends on it.
func NewConcurrent(t Target, concurrency int) *Extractor {
	return &Extractor{target: t, concurrency: max(concurrency, 1), cache: map[string]inventoryResult{}, scans: map[string]*ScanRecord{}, blobs: map[string]*blobInfo{}, surfaces: map[string]*surfaceInfo{}, lines: map[string]*releaseLine{}, lineOf: map[string]string{}}
}

// ID implements extract.Extractor.
func (x *Extractor) ID() string { return x.target.ExtractorID() }

// Version implements extract.Extractor.
func (x *Extractor) Version() string { return Version }

// SourceFiles implements extract.CodeSource.
func (x *Extractor) SourceFiles() (string, fs.FS) { return SourceDir, source }

// Applies implements extract.Extractor.
func (x *Extractor) Applies(repo extract.RepoRef) bool { return repo.Key == x.target.Repo }

// releaseLine is one major.minor line and its final release tags, lowest
// patch first. The anchor is the first tag.
type releaseLine struct {
	Major, Minor int
	Tags         []extract.Tag
	Versions     []string
	// Problem is set when a version is tagged under two prefixes at
	// different commits, or the line has too many tags.
	Problem string
}

func (l *releaseLine) key() string { return fmt.Sprintf("%d.%d", l.Major, l.Minor) }

// releaseLines groups the final release tags of the index by line.
func (x *Extractor) releaseLines(index extract.ReleaseIndex) []*releaseLine {
	type rel struct {
		major, minor, patch int
		tag                 extract.Tag
		version             string
	}
	byVersion := map[string]rel{}
	conflicts := map[string]bool{}
	for _, t := range index.Tags {
		if !extract.IsCommitSHA(t.Commit) {
			continue
		}
		for _, prefix := range x.target.TagPrefixes {
			m := finalTagRE(prefix).FindStringSubmatch(t.Name)
			if m == nil {
				continue
			}
			version := m[1] + "." + m[2] + "." + m[3]
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			patch, _ := strconv.Atoi(m[3])
			r := rel{major, minor, patch, t, version}
			if prev, dup := byVersion[version]; dup {
				if prev.tag.Commit != t.Commit {
					conflicts[fmt.Sprintf("%d.%d", major, minor)] = true
				}
				// Prefer the earlier prefix of the table.
				if prefixRank(x.target.TagPrefixes, prev.tag.Name, version) <= prefixRank(x.target.TagPrefixes, t.Name, version) {
					continue
				}
			}
			byVersion[version] = r
		}
	}
	lines := map[string]*releaseLine{}
	var rels []rel
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
	for _, r := range rels {
		k := fmt.Sprintf("%d.%d", r.major, r.minor)
		l := lines[k]
		if l == nil {
			l = &releaseLine{Major: r.major, Minor: r.minor}
			lines[k] = l
			out = append(out, l)
		}
		l.Tags = append(l.Tags, r.tag)
		l.Versions = append(l.Versions, r.version)
	}
	for _, l := range out {
		switch {
		case conflicts[l.key()]:
			l.Problem = "a release of the line is tagged twice, at different commits"
		case len(l.Tags) > maxTagsPerLine:
			l.Problem = fmt.Sprintf("the line has %d release tags, over the bound of %d", len(l.Tags), maxTagsPerLine)
		}
	}
	return out
}

func prefixRank(prefixes []string, tag, version string) int {
	for i, p := range prefixes {
		if tag == p+version {
			return i
		}
	}
	return len(prefixes)
}

func finalTagRE(prefix string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
}

// Pairs implements extract.Extractor: every two consecutive release lines
// (consecutive in version order, so a major release follows the last minor
// of the previous major, and a skipped minor number is skipped) whose
// earlier line is at or after MinFrom. Each pair is named by the first
// final release of each line. Release candidates never count.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	lines := x.releaseLines(index)
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
		from, to := lines[i-1], lines[i]
		if from.Major < x.target.MinFrom[0] || (from.Major == x.target.MinFrom[0] && from.Minor < x.target.MinFrom[1]) {
			continue
		}
		out = append(out, extract.VersionPair{
			Repo: index.Repo,
			From: from.Versions[0], FromTag: from.Tags[0].Name, FromCommit: from.Tags[0].Commit,
			To: to.Versions[0], ToTag: to.Tags[0].Name, ToCommit: to.Tags[0].Commit,
		})
	}
	return out
}

// lineFor returns the line of an anchor tag, or a one-tag line when the
// tag was not seen by Pairs (an inventory of a single commit).
func (x *Extractor) lineFor(tag, commit, version string) *releaseLine {
	x.mu.Lock()
	defer x.mu.Unlock()
	if k, ok := x.lineOf[tag]; ok {
		if l := x.lines[k]; l != nil && l.Tags[0].Name == tag && l.Tags[0].Commit == commit {
			return l
		}
	}
	l := &releaseLine{Tags: []extract.Tag{{Name: tag, Commit: commit}}, Versions: []string{version}}
	if m := regexp.MustCompile(`^([0-9]{1,4})\.([0-9]{1,4})\.`).FindStringSubmatch(version); m != nil {
		l.Major, _ = strconv.Atoi(m[1])
		l.Minor, _ = strconv.Atoi(m[2])
	}
	return l
}

// Inventory is every CRD under the listed paths at one commit: the proof
// of what each tag serves and stores.
type Inventory struct {
	Tag      string       `json:"tag"`
	Commit   string       `json:"commit"`
	Complete bool         `json:"complete"`
	Problem  string       `json:"problem,omitempty"`
	Paths    []PathRecord `json:"paths"`
	Files    []FileRecord `json:"files"`
	CRDs     []CRD        `json:"crds"`
	// Scan is the full-tree scan at the commit; absent when the inventory
	// is not complete.
	Scan *ScanRecord `json:"scan,omitempty"`
}

// PathRecord is one listed path and what was found there.
type PathRecord struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // "file", "directory" or "missing"
	// Files is the number of files read for it; Ignored the directory
	// entries whose names do not match (files) or that are not files.
	Files   int `json:"files"`
	Ignored int `json:"ignored"`
}

func (x *Extractor) inventory(r extract.PinnedReader, repo extract.RepoRef, tag, commit string) (*Inventory, error) {
	x.mu.Lock()
	res, ok := x.cache[commit]
	x.mu.Unlock()
	if ok {
		if res.inv != nil {
			cp := *res.inv
			cp.Tag = tag
			return &cp, res.err
		}
		return nil, res.err
	}
	inv, err := readInventory(r, repo, x.target, commit)
	if inv != nil {
		inv.Tag = tag
		inv.Complete = err == nil
		if p, ok := asProblem(err); ok {
			inv.Problem = p.msg
		}
	}
	if _, isProblem := asProblem(err); err == nil || isProblem {
		x.mu.Lock()
		x.cache[commit] = inventoryResult{inv, err}
		x.mu.Unlock()
	}
	return inv, err
}

func isNotFound(err error) bool { return errors.Is(err, extract.ErrNotFound) }

// listFiles lists a directory's matching files (recursively when asked).
func listFiles(r extract.PinnedReader, repo extract.RepoRef, commit string, p PathSpec, pr *PathRecord) ([]string, error) {
	var files []string
	dirs := []string{p.Path}
	for len(dirs) > 0 {
		dir := dirs[0]
		dirs = dirs[1:]
		entries, err := r.List(repo, commit, dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			name := e.Path[strings.LastIndex(e.Path, "/")+1:]
			if e.Type == "tree" && p.Recursive {
				dirs = append(dirs, e.Path)
				continue
			}
			if e.Type != "blob" || !p.Match.MatchString(name) {
				if p.Guard != nil && p.Guard.MatchString(name) && e.Type != "tree" {
					return nil, problemf("%s looks like a CRD manifest but is not read (its name does not match the listed pattern)", e.Path)
				}
				pr.Ignored++
				continue
			}
			if e.Mode == "120000" {
				return nil, problemf("%s is a symbolic link", e.Path)
			}
			pr.Files++
			files = append(files, e.Path)
		}
	}
	return files, nil
}

// readInventory reads every listed path at commit. On a problem it returns
// the partial inventory with the problem.
func readInventory(r extract.PinnedReader, repo extract.RepoRef, t Target, commit string) (*Inventory, error) {
	inv := &Inventory{Commit: commit, Paths: []PathRecord{}, Files: []FileRecord{}, CRDs: []CRD{}}
	var files []string
	for _, p := range t.Paths {
		if !p.Dir {
			if p.Optional {
				if _, err := r.Read(repo, commit, p.Path); isNotFound(err) {
					inv.Paths = append(inv.Paths, PathRecord{Path: p.Path, Kind: "missing"})
					continue
				} else if err != nil {
					return inv, err
				}
			}
			inv.Paths = append(inv.Paths, PathRecord{Path: p.Path, Kind: "file", Files: 1})
			files = append(files, p.Path)
			continue
		}
		pr := PathRecord{Path: p.Path, Kind: "directory"}
		found, err := listFiles(r, repo, commit, p, &pr)
		if isNotFound(err) {
			if p.Optional {
				inv.Paths = append(inv.Paths, PathRecord{Path: p.Path, Kind: "missing"})
				continue
			}
			return inv, problemf("listed directory %s does not exist", p.Path)
		}
		if err != nil {
			return inv, err
		}
		inv.Paths = append(inv.Paths, pr)
		if pr.Files == 0 {
			return inv, problemf("listed directory %s holds no CRD manifest file", p.Path)
		}
		files = append(files, found...)
	}
	sort.Strings(files)
	byName := map[string]string{}
	byKind := map[string]string{}
	for i, f := range files {
		if i > 0 && files[i-1] == f {
			return inv, problemf("%s is listed twice", f)
		}
		data, err := r.Read(repo, commit, f)
		if isNotFound(err) {
			return inv, problemf("listed file %s does not exist", f)
		}
		if err != nil {
			return inv, err
		}
		rec, crds, err := parseFile(f, data)
		inv.Files = append(inv.Files, rec)
		if err != nil {
			return inv, err
		}
		for _, c := range crds {
			if prev, dup := byName[c.Name]; dup {
				return inv, problemf("CustomResourceDefinition %s is defined in both %s and %s", c.Name, prev, c.Path)
			}
			gk := c.Group + "/" + c.Kind
			if prev, dup := byKind[gk]; dup {
				return inv, problemf("kind %s is defined by both %s and %s", gk, prev, c.Name)
			}
			byName[c.Name], byKind[gk] = c.Path, c.Name
			inv.CRDs = append(inv.CRDs, c)
			if len(inv.CRDs) > MaxCRDsPerTag {
				return inv, problemf("more than %d CustomResourceDefinitions", MaxCRDsPerTag)
			}
		}
	}
	if len(inv.CRDs) == 0 {
		return inv, problemf("no CustomResourceDefinition under the listed paths: an absence of removals cannot be told from a moved manifest")
	}
	sort.Slice(inv.CRDs, func(i, j int) bool { return inv.CRDs[i].Name < inv.CRDs[j].Name })
	return inv, nil
}

// Removal is one version served in the earlier line and not served in the
// later one.
type Removal struct {
	CRD     string `json:"crd"`
	Member  string `json:"member"`
	Version string `json:"version"`
	// Reason is "absent" (no longer listed) or "unserved" (served: false).
	Reason string `json:"reason"`
	// FromTag is the earlier-line release cited for the version.
	FromTag  string `json:"fromTag"`
	FromPath string `json:"fromPath"`
	// FromStartLine..FromEndLine is the version's entry at FromTag.
	FromStartLine int    `json:"fromStartLine"`
	FromEndLine   int    `json:"fromEndLine"`
	ToPath        string `json:"toPath"`
	// ToLine is the served: false line at the later anchor, 0 otherwise.
	ToLine int `json:"toServedLine"`
	// WasStorage: the version is the storage version of the CRD at some
	// release read (see storageHistory). Objects stored in it must be
	// migrated, and it must leave status.storedVersions, before an API
	// server accepts a definition without it.
	WasStorage bool `json:"wasStorage"`
}

// DefinitionRemoval is a CRD that a release of the later line defines
// nowhere in the repository (the listed paths hold no definition and the
// full-tree scan rules out a definition elsewhere), while an earlier
// release defines it: either the later anchor no longer defines a CRD of
// the earlier line, or a later release of the later line no longer defines
// a CRD of its anchor. It is never a rule: whether an upgraded cluster
// keeps the old definition (kubectl apply, Helm crds/) or deletes it with
// every object of it (Helm templates, GitOps pruning) depends on the
// install method and is not established. A pair with one is not
// attestable, and a removal at a later release keeps the pair's rules to
// the anchor pair.
type DefinitionRemoval struct {
	CRD     string   `json:"crd"`
	Members []string `json:"members"`
	// FromTag and FromPath are the latest release before the removal that
	// defines the CRD; AbsentAt the later-line releases that do not.
	FromTag  string   `json:"fromTag"`
	FromPath string   `json:"fromPath"`
	AbsentAt []string `json:"absentAt"`
}

// StorageHistory is every storage version one CRD has at the releases read.
type StorageHistory struct {
	CRD      string   `json:"crd"`
	Versions []string `json:"versions"`
}

// UnlistedRemoval is a version that a definition outside the listed paths
// (a file of class extra, such as Rook's deploy/examples/csi-operator.yaml)
// serves in the earlier line and that no file of the later line serves. It
// is recorded, never a rule: the file is not a listed path.
type UnlistedRemoval struct {
	Member  string `json:"member"`
	FromTag string `json:"fromTag"`
	Path    string `json:"path"`
}

// StorageChange records a CRD whose storage version differs between the
// anchors. It is never a removal by itself.
type StorageChange struct {
	CRD     string `json:"crd"`
	Earlier string `json:"from"`
	Later   string `json:"to"`
}

// PairProof is recorded in the run manifest for every pair.
type PairProof struct {
	Target         string          `json:"target"`
	FactID         string          `json:"factId"`
	From           *Inventory      `json:"from"`
	To             *Inventory      `json:"to"`
	Lines          *LinesRecord    `json:"lines,omitempty"`
	Removals       []Removal       `json:"removals"`
	StorageChanges []StorageChange `json:"storageChanges"`
	// DefinitionsRemoved are the CRDs a release of the later line no
	// longer defines.
	DefinitionsRemoved []DefinitionRemoval `json:"definitionsRemoved"`
	// StorageHistory is the storage versions of every CRD at the releases
	// read.
	StorageHistory []StorageHistory `json:"storageHistory"`
	// UnlistedRemovals are versions served outside the listed paths in the
	// earlier line and nowhere in the later line.
	UnlistedRemovals []UnlistedRemoval `json:"unlistedRemovals"`
	Completeness     *Completeness     `json:"completeness,omitempty"`
}

// LinesRecord is every release of both lines and whether the pair's rules
// hold for the whole lines.
type LinesRecord struct {
	From     LineRecord `json:"from"`
	To       LineRecord `json:"to"`
	LineWide bool       `json:"lineWide"`
	// NotLineWide says why the rules hold for the anchor pair only.
	NotLineWide []string `json:"notLineWide"`
}

// LineRecord is one line and each of its releases.
type LineRecord struct {
	Line string    `json:"line"`
	Tags []LineTag `json:"tags"`
}

// LineTag is one release of a line: its inventory and scan in brief, and
// how its served versions differ from the line's anchor.
type LineTag struct {
	Tag      string `json:"tag"`
	Commit   string `json:"commit"`
	Complete bool   `json:"complete"`
	Problem  string `json:"problem,omitempty"`
	CRDs     int    `json:"crds"`
	// Added and Dropped are served members relative to the anchor.
	Added   []string `json:"added"`
	Dropped []string `json:"dropped"`
	// ScanClean is the full-tree scan's verdict; ScanFindings its
	// findings other than copies.
	ScanClean    bool      `json:"scanClean"`
	ScanFindings []Finding `json:"scanFindings"`
}

// Hop shapes of a pair.
const (
	// HopPreviousMinor: consecutive minor lines of one major, M.(m-1) ->
	// M.m, the only shape a line attestation covers.
	HopPreviousMinor = "previous-minor"
	// HopMajor: the last line of one major to the first of the next.
	HopMajor = "major"
	// HopSkippedMinor: minor numbers are skipped within one major.
	HopSkippedMinor = "skipped-minor"
)

// Completeness is the account a line attestation of the later line would
// rest on (it is recorded, not acted on, by this version). It covers the
// repository's own files at every release of both lines, outside nothing:
// definitions from other repositories (Helm chart dependencies, remote
// kustomize resources), release assets and sources the scan does not read
// (ScanRecord.NotRead) are not established, and a pair that has them is
// not attestable when the scan sees them.
type Completeness struct {
	// Declared: every listed path was read completely at every release of
	// both lines.
	Declared bool `json:"declared"`
	// Scan: the full-tree scan is clean at every release of both lines.
	Scan bool `json:"scan"`
	// LineWide: every rule of the pair ranges over both whole lines.
	LineWide bool `json:"lineWide"`
	// Hop is the shape of the pair: previous-minor, major or
	// skipped-minor. Only previous-minor is attestable.
	Hop        string   `json:"hop"`
	Attestable bool     `json:"attestable"`
	Reasons    []string `json:"reasons"`
}

// tagState is everything read at one release.
type tagState struct {
	tag     extract.Tag
	version string
	inv     *Inventory
	err     error
	scan    *ScanRecord
	served  map[string]bool
	byName  map[string]*CRD
}

func (s *tagState) complete() bool { return s.err == nil && s.inv != nil && s.inv.Complete }

func (s *tagState) scanClean() bool { return s.complete() && s.scan.Clean() }

// gone reports that a CRD has no definition anywhere at this release: not
// under the listed paths, and a complete scan of the rest of the tree in
// which every CRD-like file was read and none defines it.
func (s *tagState) gone(name string) bool {
	return s.complete() && s.byName[name] == nil && !s.scan.holds(name)
}

func (x *Extractor) readTag(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, tag extract.Tag, version string) (*tagState, error) {
	st := &tagState{tag: tag, version: version, served: map[string]bool{}, byName: map[string]*CRD{}}
	st.inv, st.err = x.inventory(r, repo, tag.Name, tag.Commit)
	if st.err != nil {
		if _, ok := asProblem(st.err); !ok {
			return nil, st.err
		}
		return st, nil
	}
	sc, err := x.scan(ctx, r, repo, tag.Commit, st.inv)
	if err != nil {
		return nil, err
	}
	st.scan = sc
	inv := *st.inv
	inv.Scan = sc
	st.inv = &inv
	for i := range st.inv.CRDs {
		c := &st.inv.CRDs[i]
		st.byName[c.Name] = c
		for _, v := range c.Versions {
			if v.Served {
				st.served[member(c.Group, v.Name, c.Kind)] = true
			}
		}
	}
	return st, nil
}

// Extract implements extract.Extractor.
func (x *Extractor) Extract(ctx context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	if !x.Applies(pair.Repo) {
		return extract.Extraction{}, fmt.Errorf("repository %s", pair.Repo.Key)
	}
	proof := PairProof{Target: x.target.Project, FactID: x.target.FactID(), Removals: []Removal{}, StorageChanges: []StorageChange{}, DefinitionsRemoved: []DefinitionRemoval{}, StorageHistory: []StorageHistory{}, UnlistedRemovals: []UnlistedRemoval{}}
	withhold := func(err error) (extract.Extraction, error) {
		if p, ok := asProblem(err); ok {
			return extract.Extraction{}, &extract.Withheld{Reason: p.msg, Proof: proof}
		}
		return extract.Extraction{}, err
	}
	fromLine := x.lineFor(pair.FromTag, pair.FromCommit, pair.From)
	toLine := x.lineFor(pair.ToTag, pair.ToCommit, pair.To)
	// The anchors decide whether the pair is derived at all.
	fa, err := x.readTag(ctx, r, pair.Repo, fromLine.Tags[0], fromLine.Versions[0])
	if err != nil {
		return withhold(err)
	}
	proof.From = fa.inv
	if !fa.complete() {
		return withhold(problemf("at %s: %s", pair.FromTag, problemOf(fa)))
	}
	ta, err := x.readTag(ctx, r, pair.Repo, toLine.Tags[0], toLine.Versions[0])
	if err != nil {
		return withhold(err)
	}
	proof.To = ta.inv
	if !ta.complete() {
		return withhold(problemf("at %s: %s", pair.ToTag, problemOf(ta)))
	}
	for _, l := range []*releaseLine{fromLine, toLine} {
		if l.Problem != "" {
			return withhold(problemf("line %s: %s", l.key(), l.Problem))
		}
	}
	for _, st := range []*tagState{fa, ta} {
		if c := st.scan.conflicts(); len(c) > 0 {
			return withhold(problemf("at %s: %s defines %s differently from the listed paths (%s)", st.tag.Name, c[0].Path, strings.Join(c[0].CRDs, ", "), c[0].Detail))
		}
	}
	if err := sameIdentity([]*tagState{fa, ta}); err != nil {
		return withhold(err)
	}
	// Every other release of both lines.
	var fromTags, toTags []*tagState
	for i, l := range []*releaseLine{fromLine, toLine} {
		for j, t := range l.Tags {
			var st *tagState
			switch {
			case j == 0 && i == 0:
				st = fa
			case j == 0:
				st = ta
			default:
				if st, err = x.readTag(ctx, r, pair.Repo, t, l.Versions[j]); err != nil {
					return withhold(err)
				}
			}
			if i == 0 {
				fromTags = append(fromTags, st)
			} else {
				toTags = append(toTags, st)
			}
		}
	}
	lines := &LinesRecord{From: lineRecord(fromLine, fromTags), To: lineRecord(toLine, toTags), NotLineWide: []string{}}
	proof.Lines = lines
	for _, f := range fa.inv.CRDs {
		if t := ta.byName[f.Name]; t != nil && f.StorageVersion != t.StorageVersion {
			proof.StorageChanges = append(proof.StorageChanges, StorageChange{CRD: f.Name, Earlier: f.StorageVersion, Later: t.StorageVersion})
		}
	}
	lines.NotLineWide = lineWideProblems(fromTags, toTags)
	laterDefs, laterProblems := laterLineRemovals(toTags)
	lines.NotLineWide = append(lines.NotLineWide, laterProblems...)
	var removals []Removal
	var defsRemoved []DefinitionRemoval
	if len(lines.NotLineWide) == 0 {
		removals, defsRemoved, lines.NotLineWide, err = lineRemovals(fromTags, toTags)
		if err != nil {
			return withhold(err)
		}
	}
	lines.LineWide = len(lines.NotLineWide) == 0
	if !lines.LineWide {
		if removals, defsRemoved, err = anchorRemovals(fa, ta); err != nil {
			return withhold(err)
		}
	}
	all := append(append([]*tagState{}, fromTags...), toTags...)
	history := storageHistory(all)
	for i := range removals {
		removals[i].WasStorage = slicesContains(history[removals[i].CRD], removals[i].Version)
	}
	proof.StorageHistory = storageRecords(history)
	proof.Removals = append([]Removal{}, removals...)
	proof.DefinitionsRemoved = append(append([]DefinitionRemoval{}, defsRemoved...), laterDefs...)
	proof.UnlistedRemovals = unlistedRemovals(fromTags, toTags)
	byCRD := map[string][]Removal{}
	var names []string
	for _, rm := range removals {
		if byCRD[rm.CRD] == nil {
			names = append(names, rm.CRD)
		}
		byCRD[rm.CRD] = append(byCRD[rm.CRD], rm)
	}
	sort.Strings(names)
	states := map[string]*tagState{}
	for _, st := range append(append([]*tagState{}, fromTags...), toTags...) {
		states[st.tag.Name] = st
	}
	var out []extract.Candidate
	for _, name := range names {
		c, err := x.candidate(pair, fromLine, toLine, states, fa, ta, byCRD[name], lines.LineWide)
		if err != nil {
			return withhold(err)
		}
		out = append(out, c)
	}
	if err := uniqueIDs(out); err != nil {
		return withhold(err)
	}
	// A rule must not forbid a version that an unread or templated CRD
	// source at the later anchor may still serve.
	if u := ta.scan.unreadable(); len(out) > 0 && len(u) > 0 {
		return withhold(problemf("at %s: %s is %s (%s): a version the rules forbid may still be served there", ta.tag.Name, u[0].Path, u[0].Class, u[0].Detail))
	}
	proof.Completeness = completeness(fromLine, toLine, fromTags, toTags, lines, proof.DefinitionsRemoved, proof.UnlistedRemovals)
	return extract.Extraction{Candidates: out, Proof: proof}, nil
}

// hopShape names the shape of a pair of lines.
func hopShape(from, to *releaseLine) string {
	switch {
	case from.Major == to.Major && from.Minor+1 == to.Minor:
		return HopPreviousMinor
	case from.Major != to.Major:
		return HopMajor
	}
	return HopSkippedMinor
}

// laterLineRemovals finds the CRDs the later anchor defines that a later
// release of its line does not: a definition gone there (clean scan) is
// recorded as removed; either way the pair's rules do not hold for the
// whole later line.
func laterLineRemovals(to []*tagState) ([]DefinitionRemoval, []string) {
	ta := to[0]
	if !ta.complete() {
		return nil, nil
	}
	var defs []DefinitionRemoval
	var problems []string
	for i := range ta.inv.CRDs {
		c := &ta.inv.CRDs[i]
		var absent []string
		last := ta
		for _, st := range to[1:] {
			if !st.complete() {
				continue
			}
			if st.byName[c.Name] != nil {
				if len(absent) == 0 {
					last = st
				}
				continue
			}
			if !st.gone(c.Name) {
				problems = append(problems, fmt.Sprintf("%s: %s is not under the listed paths and the scan does not establish that it is gone", st.tag.Name, c.Name))
				continue
			}
			absent = append(absent, st.tag.Name)
		}
		if len(absent) == 0 {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s: %s is no longer defined anywhere in the repository", strings.Join(absent, ", "), c.Name))
		lc := last.byName[c.Name]
		var members []string
		for _, v := range lc.Versions {
			if v.Served {
				members = append(members, member(lc.Group, v.Name, lc.Kind))
			}
		}
		sort.Strings(members)
		defs = append(defs, DefinitionRemoval{CRD: c.Name, Members: members, FromTag: last.tag.Name, FromPath: lc.Path, AbsentAt: absent})
	}
	return defs, problems
}

// storageHistory maps each CRD to every storage version it has at the
// releases read, sorted.
func storageHistory(states []*tagState) map[string][]string {
	out := map[string][]string{}
	for _, st := range states {
		if !st.complete() {
			continue
		}
		for i := range st.inv.CRDs {
			c := &st.inv.CRDs[i]
			if !slicesContains(out[c.Name], c.StorageVersion) {
				out[c.Name] = append(out[c.Name], c.StorageVersion)
				sort.Strings(out[c.Name])
			}
		}
	}
	return out
}

func storageRecords(h map[string][]string) []StorageHistory {
	out := []StorageHistory{}
	for name, vs := range h {
		out = append(out, StorageHistory{CRD: name, Versions: vs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CRD < out[j].CRD })
	return out
}

// unlistedRemovals compares the definitions outside the listed paths that
// the inventory does not hold (class extra, anywhere but a reviewed
// exclusion): a version one of them serves in the earlier line that no
// file of the later line serves.
func unlistedRemovals(from, to []*tagState) []UnlistedRemoval {
	later := map[string]bool{}
	for _, st := range to {
		if !st.complete() {
			continue
		}
		for m := range st.served {
			later[m] = true
		}
		for _, f := range st.scan.Findings {
			for _, m := range f.Served {
				later[m] = true
			}
		}
	}
	seen := map[string]bool{}
	out := []UnlistedRemoval{}
	for _, st := range from {
		if !st.complete() {
			continue
		}
		for _, f := range st.scan.Findings {
			if f.Class != ClassExtra {
				continue
			}
			for _, m := range f.Served {
				if later[m] || seen[m] {
					continue
				}
				seen[m] = true
				out = append(out, UnlistedRemoval{Member: m, FromTag: st.tag.Name, Path: f.Path})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Member < out[j].Member })
	return out
}

func problemOf(st *tagState) string {
	if p, ok := asProblem(st.err); ok {
		return p.msg
	}
	if st.inv != nil && st.inv.Problem != "" {
		return st.inv.Problem
	}
	return "the inventory is not complete"
}

// sameIdentity requires a CRD name to define the same group and kind at
// every release read.
func sameIdentity(states []*tagState) error {
	seen := map[string]*CRD{}
	where := map[string]string{}
	for _, st := range states {
		if !st.complete() {
			continue
		}
		for i := range st.inv.CRDs {
			c := &st.inv.CRDs[i]
			if p, ok := seen[c.Name]; ok && (p.Group != c.Group || p.Kind != c.Kind) {
				return problemf("CustomResourceDefinition %s names %s/%s at %s and %s/%s at %s", c.Name, p.Group, p.Kind, where[c.Name], c.Group, c.Kind, st.tag.Name)
			}
			seen[c.Name], where[c.Name] = c, st.tag.Name
		}
	}
	return nil
}

func lineRecord(l *releaseLine, states []*tagState) LineRecord {
	rec := LineRecord{Line: l.key(), Tags: []LineTag{}}
	anchor := states[0]
	for _, st := range states {
		lt := LineTag{Tag: st.tag.Name, Commit: st.tag.Commit, Complete: st.complete(), Added: []string{}, Dropped: []string{}, ScanFindings: []Finding{}}
		if !lt.Complete {
			lt.Problem = problemOf(st)
		} else {
			lt.CRDs = len(st.inv.CRDs)
			lt.ScanClean = st.scan.Clean()
			if !st.scan.Complete {
				lt.ScanFindings = append(lt.ScanFindings, Finding{Class: ClassUnread, Detail: st.scan.Problem})
			}
			lt.ScanFindings = append(lt.ScanFindings, st.scan.Findings...)
			if anchor.complete() {
				for m := range st.served {
					if !anchor.served[m] {
						lt.Added = append(lt.Added, m)
					}
				}
				for m := range anchor.served {
					if !st.served[m] {
						lt.Dropped = append(lt.Dropped, m)
					}
				}
				sort.Strings(lt.Added)
				sort.Strings(lt.Dropped)
			}
		}
		rec.Tags = append(rec.Tags, lt)
	}
	return rec
}

// lineWideProblems lists what keeps the pair's rules from ranging over the
// whole lines before the removals are compared: an incomplete release, a
// conflicting definition, a CRD whose group or kind changes.
func lineWideProblems(from, to []*tagState) []string {
	var out []string
	all := append(append([]*tagState{}, from...), to...)
	for _, st := range all {
		switch {
		case !st.complete():
			out = append(out, fmt.Sprintf("%s: %s", st.tag.Name, problemOf(st)))
		case len(st.scan.conflicts()) > 0:
			c := st.scan.conflicts()[0]
			out = append(out, fmt.Sprintf("%s: %s defines %s differently from the listed paths", st.tag.Name, c.Path, strings.Join(c.CRDs, ", ")))
		}
	}
	// A later-line release with an unread or templated CRD source may
	// serve a version the rules forbid.
	for _, st := range to {
		if !st.complete() {
			continue
		}
		if u := st.scan.unreadable(); len(u) > 0 {
			out = append(out, fmt.Sprintf("%s: %s is %s: a version the rules forbid may still be served there", st.tag.Name, u[0].Path, u[0].Class))
		}
	}
	if err := sameIdentity(all); err != nil {
		out = append(out, err.Error())
	}
	return out
}

// served union and intersection over releases.
func union(states []*tagState) map[string]bool {
	out := map[string]bool{}
	for _, st := range states {
		for m := range st.served {
			out[m] = true
		}
	}
	return out
}

func intersection(states []*tagState) map[string]bool {
	out := map[string]bool{}
	for m := range states[0].served {
		in := true
		for _, st := range states[1:] {
			if !st.served[m] {
				in = false
				break
			}
		}
		if in {
			out[m] = true
		}
	}
	return out
}

// lineRemovals derives the removals of the whole lines: every member some
// earlier-line release serves that no later-line release serves. It also
// returns why the lines do not support a line-wide rule: a member served
// in the earlier line that some later-line releases serve and others do
// not, or a removed definition that is not gone from the whole repository
// at every later-line release that lacks it.
func lineRemovals(from, to []*tagState) ([]Removal, []DefinitionRemoval, []string, error) {
	uf, ut, it := union(from), union(to), intersection(to)
	var notLineWide []string
	var flapping []string
	for m := range uf {
		if ut[m] && !it[m] {
			flapping = append(flapping, m)
		}
	}
	sort.Strings(flapping)
	for _, m := range flapping {
		notLineWide = append(notLineWide, fmt.Sprintf("%s is served by some releases of the later line and not by others", m))
	}
	ta := to[0]
	// Every CRD some earlier-line release defines.
	defined := map[string]bool{}
	var names []string
	for _, st := range from {
		for i := range st.inv.CRDs {
			if n := st.inv.CRDs[i].Name; !defined[n] {
				defined[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	var out []Removal
	var defs []DefinitionRemoval
	for _, name := range names {
		var removed []string
		for _, st := range from {
			c := st.byName[name]
			if c == nil {
				continue
			}
			for _, v := range c.Versions {
				m := member(c.Group, v.Name, c.Kind)
				if v.Served && !ut[m] && !slicesContains(removed, m) {
					removed = append(removed, m)
				}
			}
		}
		if len(removed) == 0 {
			continue
		}
		absentAt := []*tagState{}
		for _, st := range to {
			if st.byName[name] == nil {
				absentAt = append(absentAt, st)
			}
		}
		// A definition missing at the later anchor without a clean scan
		// there is not line-wide (the anchor is in absentAt); the anchor
		// comparison then withholds the pair.
		for _, st := range absentAt {
			if !st.gone(name) {
				notLineWide = append(notLineWide, fmt.Sprintf("%s: %s is not under the listed paths and the scan is not clean", st.tag.Name, name))
			}
		}
		sort.Strings(removed)
		if ta.byName[name] == nil {
			defs = append(defs, definitionRemoval(name, removed, from, absentAt))
			continue
		}
		for _, m := range removed {
			rm, err := removalFor(name, m, from, ta)
			if err != nil {
				return nil, nil, nil, err
			}
			out = append(out, rm)
		}
	}
	return out, defs, notLineWide, nil
}

// definitionRemoval records a CRD the later anchor defines nowhere, citing
// the latest earlier-line release that defines it.
func definitionRemoval(name string, members []string, from, absentAt []*tagState) DefinitionRemoval {
	d := DefinitionRemoval{CRD: name, Members: members, AbsentAt: []string{}}
	for _, st := range absentAt {
		d.AbsentAt = append(d.AbsentAt, st.tag.Name)
	}
	for i := len(from) - 1; i >= 0; i-- {
		if c := from[i].byName[name]; c != nil {
			d.FromTag, d.FromPath = from[i].tag.Name, c.Path
			break
		}
	}
	return d
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// removalFor cites a removed member: the earlier-line anchor when it serves
// the member, otherwise the highest earlier-line release that does; and the
// later anchor's state of the version.
func removalFor(name, m string, from []*tagState, ta *tagState) (Removal, error) {
	var cite *tagState
	var entry CRDVersion
	var crd *CRD
	for i := len(from) - 1; i >= 0; i-- {
		st := from[i]
		c := st.byName[name]
		if c == nil {
			continue
		}
		for _, v := range c.Versions {
			if v.Served && member(c.Group, v.Name, c.Kind) == m && (cite == nil || i == 0) {
				cite, entry, crd = st, v, c
			}
		}
	}
	if cite == nil {
		return Removal{}, fmt.Errorf("internal: no earlier release serves %s", m)
	}
	rm := Removal{CRD: name, Member: m, Version: entry.Name, FromTag: cite.tag.Name, FromPath: crd.Path, FromStartLine: entry.StartLine, FromEndLine: entry.EndLine}
	t := ta.byName[name]
	if t == nil {
		return Removal{}, fmt.Errorf("internal: %s is not defined at %s", name, ta.tag.Name)
	}
	rm.ToPath = t.Path
	lv, present := t.version(entry.Name)
	switch {
	case !present:
		rm.Reason = ReasonAbsent
	case !lv.Served:
		rm.Reason, rm.ToLine = ReasonUnserved, lv.ServedLine
	default:
		return Removal{}, fmt.Errorf("internal: %s is served at %s", m, ta.tag.Name)
	}
	return rm, nil
}

// anchorRemovals compares the two anchors only, as version 1 did, except
// that a definition missing from the later anchor is recorded as removed
// (not withheld) when the whole repository is established at that release
// and holds it nowhere.
func anchorRemovals(fa, ta *tagState) ([]Removal, []DefinitionRemoval, error) {
	var out []Removal
	var defs []DefinitionRemoval
	for i := range fa.inv.CRDs {
		f := &fa.inv.CRDs[i]
		t := ta.byName[f.Name]
		if t == nil && !ta.gone(f.Name) {
			return nil, nil, problemf("CustomResourceDefinition %s at %s is not under the listed paths at %s and the rest of the repository is not established (scan not clean): a removed definition cannot be told from a moved one", f.Name, fa.tag.Name, ta.tag.Name)
		}
		var removed []string
		for _, v := range f.Versions {
			if m := member(f.Group, v.Name, f.Kind); v.Served && !ta.served[m] {
				removed = append(removed, m)
			}
		}
		sort.Strings(removed)
		if t == nil {
			defs = append(defs, definitionRemoval(f.Name, removed, []*tagState{fa}, []*tagState{ta}))
			continue
		}
		for _, m := range removed {
			rm, err := removalFor(f.Name, m, []*tagState{fa}, ta)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, rm)
		}
	}
	return out, defs, nil
}

func completeness(fromLine, toLine *releaseLine, from, to []*tagState, lines *LinesRecord, defs []DefinitionRemoval, unlisted []UnlistedRemoval) *Completeness {
	c := &Completeness{Declared: true, Scan: true, LineWide: lines.LineWide, Hop: hopShape(fromLine, toLine), Reasons: []string{}}
	for _, st := range append(append([]*tagState{}, from...), to...) {
		if !st.complete() {
			c.Declared = false
			c.Scan = false
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s: the listed paths are not complete", st.tag.Name))
			continue
		}
		if !st.scan.Clean() {
			c.Scan = false
			var classes []string
			seen := map[string]bool{}
			for _, f := range st.scan.Findings {
				if !f.blocks() {
					continue
				}
				k := f.Class
				if f.Location != "" {
					k += " (" + f.Location + ")"
				}
				if !seen[k] {
					seen[k] = true
					classes = append(classes, k)
				}
			}
			if !st.scan.Complete {
				classes = append(classes, "incomplete")
			}
			sort.Strings(classes)
			c.Reasons = append(c.Reasons, fmt.Sprintf("%s: the full-tree scan found %s files", st.tag.Name, strings.Join(classes, ", ")))
		}
	}
	if !lines.LineWide {
		c.Reasons = append(c.Reasons, "the rules hold for the anchor pair only")
	}
	if c.Hop != HopPreviousMinor {
		c.Reasons = append(c.Reasons, fmt.Sprintf("the pair is a %s hop: a line attestation covers only the previous minor line", c.Hop))
	}
	for _, d := range defs {
		where := "the later line"
		if len(d.AbsentAt) > 0 {
			where = strings.Join(d.AbsentAt, ", ")
		}
		c.Reasons = append(c.Reasons, fmt.Sprintf("%s no longer defines %s: whether an upgraded cluster keeps the old definition or deletes it with its objects depends on the install method and is not established", where, d.CRD))
	}
	for _, u := range unlisted {
		c.Reasons = append(c.Reasons, fmt.Sprintf("%s is served outside the listed paths (%s at %s) and by no file of the later line", u.Member, u.Path, u.FromTag))
	}
	// An unlisted removal comes from an extra definition, which already
	// keeps the scan from being clean.
	c.Attestable = c.Declared && c.Scan && c.LineWide && c.Hop == HopPreviousMinor && len(defs) == 0
	return c
}

// nameSlug turns a CRD name into a rule id part without collisions: a
// hyphen becomes two hyphens and a dot one. Valid names never hold ".-",
// "-." or "..", so the mapping is injective on them.
func nameSlug(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(s), "-", "--"), ".", "-")
}

func slug(s string) string {
	return strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(s))
}

// uniqueIDs withholds a pair whose rules would share an id: the run would
// otherwise fail as a whole.
func uniqueIDs(cands []extract.Candidate) error {
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.Rule.ID] {
			return problemf("two rules would have the id %s", c.Rule.ID)
		}
		seen[c.Rule.ID] = true
	}
	return nil
}

// versionRank orders Kubernetes version names: GA above beta above alpha,
// then by major and stability number; other names sort lowest.
func versionRank(v string) [3]int {
	m := kubeVersionRE.FindStringSubmatch(v)
	if m == nil {
		return [3]int{-1, 0, 0}
	}
	major, _ := strconv.Atoi(m[1])
	n, _ := strconv.Atoi(m[3])
	stab := 2
	switch m[2] {
	case "alpha":
		stab = 0
	case "beta":
		stab = 1
	}
	return [3]int{stab, major, n}
}

var kubeVersionRE = regexp.MustCompile(`^v([0-9]+)(?:(alpha|beta)([0-9]+))?$`)

func higher(a, b string) bool {
	x, y := versionRank(a), versionRank(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return a > b
}

// replacement is the highest version the later CRD serves, "" when none.
func replacement(t *CRD) string {
	best := ""
	if t == nil {
		return best
	}
	for _, v := range t.Versions {
		if v.Served && (best == "" || higher(v.Name, best)) {
			best = v.Name
		}
	}
	return best
}

// nextAction tells the user what to do before the upgrade. A removed version
// that was ever a storage version may still hold stored objects and stay
// listed in status.storedVersions, and an API server refuses a definition
// that drops a stored version: the objects are migrated first.
func nextAction(f *CRD, repl string, stored []string, to string) string {
	if len(stored) == 0 {
		if repl == "" {
			return fmt.Sprintf("migrate %s objects before upgrading to %s", f.Kind, to)
		}
		return fmt.Sprintf("change apiVersion of %s to %s/%s before upgrading to %s", f.Kind, f.Group, repl, to)
	}
	vs := strings.Join(stored, ", ")
	if repl == "" {
		return fmt.Sprintf("migrate stored %s objects off %s and remove it from status.storedVersions before upgrading to %s", f.Kind, vs, to)
	}
	next := fmt.Sprintf("migrate stored %s objects to %s and remove %s from status.storedVersions, then change apiVersion to %s/%s before upgrading to %s", f.Kind, repl, vs, f.Group, repl, to)
	if len(next) > maxNext {
		next = fmt.Sprintf("migrate stored %s objects to %s and prune status.storedVersions, then change apiVersion to %s/%s before upgrading to %s", f.Kind, repl, f.Group, repl, to)
	}
	return next
}

// lineRange is the range of a line-wide rule. Consecutive minor lines of one
// major take the release-boundary shape (the later line's first release is
// the boundary); any other pair of lines (a new major, skipped minor
// numbers) ranges over each whole line without a boundary.
func lineRange(from, to *releaseLine, fromSource, toSource string) *constraintengine.VersionRange {
	at := func(major, minor int) string { return fmt.Sprintf("%d.%d.0", major, minor) }
	r := &constraintengine.VersionRange{
		From: constraintengine.VersionBound{Gte: at(from.Major, from.Minor), Lt: at(from.Major, from.Minor+1)},
		To:   constraintengine.VersionBound{Gte: at(to.Major, to.Minor), Lt: at(to.Major, to.Minor+1)},
	}
	if from.Major == to.Major && from.Minor+1 == to.Minor {
		r.Bounds = []constraintengine.RangeBound{
			{Bound: "from.gte", Basis: constraintengine.BasisPreviousMinorLine, SourceID: fromSource},
			{Bound: "from.lt", Basis: constraintengine.BasisRemovedInRelease, SourceID: fromSource},
			{Bound: "to.gte", Basis: constraintengine.BasisRemovedInRelease, SourceID: toSource},
			{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: toSource},
		}
		return r
	}
	r.Bounds = []constraintengine.RangeBound{
		{Bound: "from.gte", Basis: constraintengine.BasisUpgradeFromSeries, SourceID: fromSource},
		{Bound: "from.lt", Basis: constraintengine.BasisUpgradeFromSeries, SourceID: fromSource},
		{Bound: "to.gte", Basis: constraintengine.BasisTargetSeries, SourceID: toSource},
		{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: toSource},
	}
	return r
}

func (x *Extractor) candidate(pair extract.VersionPair, fromLine, toLine *releaseLine, states map[string]*tagState, fa, ta *tagState, removed []Removal, lineWide bool) (extract.Candidate, error) {
	tg := x.target
	f := fa.byName[removed[0].CRD]
	if f == nil {
		f = states[removed[0].FromTag].byName[removed[0].CRD]
	}
	t := ta.byName[f.Name]
	members := make([]string, 0, len(removed))
	versions := make([]string, 0, len(removed))
	type span struct{ start, end int }
	fromSpans := map[string]*span{}
	var fromOrder []string
	var toSources []extract.SourceRef
	absent := false
	for _, rm := range removed {
		members = append(members, rm.Member)
		versions = append(versions, rm.Version)
		sp := fromSpans[rm.FromTag]
		if sp == nil {
			sp = &span{1 << 30, 0}
			fromSpans[rm.FromTag] = sp
			fromOrder = append(fromOrder, rm.FromTag)
		}
		sp.start, sp.end = min(sp.start, rm.FromStartLine), max(sp.end, rm.FromEndLine)
		switch rm.Reason {
		case ReasonAbsent:
			absent = true
		default:
			toSources = append(toSources, extract.SourceRef{ID: "served-false-" + rm.Version + "-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: t.Path, StartLine: rm.ToLine, EndLine: rm.ToLine})
		}
	}
	sort.Strings(members)
	sort.Slice(versions, func(i, j int) bool { return higher(versions[j], versions[i]) })
	if absent || len(toSources) > 7 {
		toSources = []extract.SourceRef{{ID: "crd-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: t.Path}}
	}
	// The anchor first, then any later earlier-line release, by tag.
	sort.SliceStable(fromOrder, func(i, j int) bool {
		if fromOrder[i] == fa.tag.Name || fromOrder[j] == fa.tag.Name {
			return fromOrder[i] == fa.tag.Name
		}
		return fromOrder[i] < fromOrder[j]
	})
	var sources []extract.SourceRef
	for _, tagName := range fromOrder {
		st := states[tagName]
		sp := fromSpans[tagName]
		sources = append(sources, extract.SourceRef{ID: "crd-versions-" + slug(st.version), Repo: pair.Repo, Commit: st.tag.Commit, Path: st.byName[f.Name].Path, StartLine: sp.start, EndLine: sp.end})
	}
	fromSource, toSource := sources[0].ID, toSources[0].ID
	sources = append(sources, toSources...)
	id := fmt.Sprintf("%s.crd-version-removal.%s.%s-to-%s", tg.Project, nameSlug(f.Name), slug(pair.From), slug(pair.To))
	if len(id) > maxIDBytes {
		return extract.Candidate{}, problemf("rule id for %s would be %d bytes, over %d", f.Name, len(id), maxIDBytes)
	}
	repl := replacement(t)
	var stored []string
	for _, rm := range removed {
		if rm.WasStorage {
			stored = append(stored, rm.Version)
		}
	}
	sort.Slice(stored, func(i, j int) bool { return higher(stored[j], stored[i]) })
	next := nextAction(f, repl, stored, pair.To)
	var pass []string
	if repl != "" {
		pass = []string{member(f.Group, repl, f.Kind)}
	}
	if len(next) > maxNext {
		return extract.Candidate{}, problemf("next action for %s would be %d bytes, over %d", f.Name, len(next), maxNext)
	}
	vs := "version " + versions[0]
	if len(versions) > 1 {
		vs = "versions " + strings.Join(versions, ", ")
	}
	what := fmt.Sprintf("%s %s no longer serves %s of %s (CustomResourceDefinition %s), which %s served.", tg.Name, pair.To, vs, f.Kind, f.Name, pair.From)
	basis := "Derived from the complete CustomResourceDefinition manifests at both release tags."
	var rng *constraintengine.VersionRange
	if lineWide {
		basis = fmt.Sprintf("Derived from the complete CustomResourceDefinition manifests at every release of %s and %s, with a scan of the whole repository at each; it holds for upgrades from any %s release to any %s release.", fromLine.key(), toLine.key(), fromLine.key(), toLine.key())
		rng = lineRange(fromLine, toLine, fromSource, toSource)
	}
	return extract.Candidate{
		Project:     tg.Project,
		Description: what + " " + basis + " Storage versions, stored objects, conversion and schema changes are not checked.",
		RequiredFacts: []extract.Fact{{
			Side: "proposed", ID: tg.FactID(), Component: tg.Component, Type: string(constraintengine.FactSet),
			Description: fmt.Sprintf("Custom-resource versions (group/version/Kind) of the %s custom resources in the complete target apply set.", tg.Name),
		}},
		Rule: extract.Rule{
			ID:           id,
			Operator:     constraintengine.OperatorForbidSetMember,
			Subject:      extract.Subject{Component: tg.Component, From: pair.From, To: pair.To},
			SetCondition: &extract.SetCondition{Side: "proposed", Component: tg.Component, FactID: tg.FactID(), Members: members},
			Range:        rng,
			ReasonCode:   reasonCode,
			NextAction:   next,
		},
		Sources:     sources,
		PassMembers: pass,
	}, nil
}
