// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// TargetsSchema identifies targets.json.
const TargetsSchema = "prufyx.io/crd-version-targets/v1"

// targetsJSON is the reviewed source table. It is data, not code, but it is
// embedded next to the code and covered by the extractor's code digest, so
// any change to it is a new extractor version and is reviewed as one.
//
//go:embed targets.json
var targetsJSON []byte

// Target is one reviewed source entry: where a catalog project keeps the
// rendered CustomResourceDefinition manifests it ships, which release tags
// form its lines, and which parts of its repository the full-tree scan
// skips (each with the reason a reviewer accepted).
type Target struct {
	// Project is the catalog project slug, also the rule id prefix.
	Project string
	// Name is the public project name used in descriptions.
	Name string
	// Repo is the repository key, github.com/<owner>/<name>.
	Repo string
	// Component is the rule subject component (the catalog identity).
	Component string
	// FactProject is the project part of the set fact id
	// component.<FactProject>.custom_resource_versions_set.
	FactProject string
	// TagPrefixes are the prefixes of final release tags ("v", ""), in
	// order of preference. A version tagged under two prefixes must name
	// one commit.
	TagPrefixes []string
	// MinFrom is the first earlier line (major, minor) a pair may start
	// from.
	MinFrom [2]int
	// Paths are the CRD manifest locations, read at every tag of a line.
	Paths []PathSpec
	// Exclude lists the parts of the repository whose CRD-like files the
	// full-tree scan records without letting them block attestation, each
	// with its reviewed reason. A listed path is never excluded.
	Exclude []Exclusion
	// Attest makes the extractor attest the target's lines for the
	// custom-resource version family. Only a project of the reviewed
	// custom-resource table (its set fact is registered) may attest; a
	// test pins the two to each other, so registering a project is also
	// a new version of this extractor.
	Attest bool

	// voided are the Exclude entries that do not hold at the release being
	// scanned (see guard.go); set on a copy made for one scan.
	voided map[string]bool
}

// PathSpec is a file, or a directory whose files with names matching Match
// are read (with Recursive, also in its subdirectories). A path that is not
// Optional must exist at every tag. A directory file whose name matches
// Guard but not Match makes the inventory incomplete: it may hold a
// definition the extractor would not read.
type PathSpec struct {
	Path      string
	Dir       bool
	Recursive bool
	Optional  bool
	Match     *regexp.Regexp
	Guard     *regexp.Regexp
}

// Exclusion is a reviewed part of the repository. Path is a directory
// prefix (ending in "/"), an exact file path, or a path.Match pattern over
// the whole path (a wildcard never crosses "/"). The scan still reads every
// file under it and records each one that holds CRD-like content (path,
// sha256, the definitions it holds), but such a file does not block
// attestation. With Copies, the reviewer states that the files are
// (possibly templated) copies of the listed definitions: the scan checks
// that claim, and a file that defines a listed CRD with other versions or
// served flags, defines one the inventory does not hold, or cannot be read
// after its template directives are removed blocks attestation.
//
// Every entry names its repository, the reason the files are not installed
// and the evidence a reviewer read (what uses the files and how). The reason
// and the evidence must hold at every tag of the window; the install-surface
// guard (guard.go) checks the part of that claim a program can: at a tag
// where a Helm chart, a kustomization, a Makefile, a document with an
// install command or an embedding Go package refers to the excluded path,
// or the path lies under a chart, the entry is void for that tag and the
// files under it block attestation like any others. An entry that is not a
// declared copy may not lie under a chart, an install, deploy, manifests or
// CRD directory (see installSegments).
type Exclusion struct {
	Path     string
	Repo     string
	Reason   string
	Evidence string
	Copies   bool
}

// DefaultExcludedSegments are the directory names whose content is not
// what a project normally installs: tests, test data, examples and
// vendored code. The scan reads them like the rest of the tree, but a file
// there is never a conflicting copy that withholds a pair; any CRD-like
// file there other than a consistent copy blocks attestation unless a
// reviewed exclusion covers it. (Rook installs from deploy/examples.)
var DefaultExcludedSegments = []string{"_testdata", "e2e", "example", "examples", "test", "testdata", "tests", "third_party", "vendor"}

// Targets is the reviewed source table, ordered by project.
var Targets = mustLoadTargets(targetsJSON)

type targetsFile struct {
	Schema  string       `json:"schema"`
	Targets []targetJSON `json:"targets"`
}

type targetJSON struct {
	Project     string          `json:"project"`
	Name        string          `json:"name"`
	Repo        string          `json:"repo"`
	Component   string          `json:"component"`
	FactProject string          `json:"factProject"`
	TagPrefixes []string        `json:"tagPrefixes"`
	MinFrom     string          `json:"minFrom"`
	Attest      bool            `json:"attest"`
	Paths       []pathJSON      `json:"paths"`
	Exclude     []exclusionJSON `json:"exclude"`
}

type pathJSON struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Recursive bool   `json:"recursive"`
	Optional  bool   `json:"optional"`
	Match     string `json:"match"`
	Guard     string `json:"guard"`
}

type exclusionJSON struct {
	Path     string `json:"path"`
	Repo     string `json:"repo"`
	Reason   string `json:"reason"`
	Evidence string `json:"evidence"`
	Copies   bool   `json:"copies,omitempty"`
}

var (
	projectRE     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	factProjectRE = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	lineRE        = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
	globMeta      = "*?["
)

func mustLoadTargets(raw []byte) []Target {
	ts, err := LoadTargets(raw)
	if err != nil {
		panic("crdversions: targets.json: " + err.Error())
	}
	return ts
}

// LoadTargets decodes and validates a targets document. Unknown fields,
// unsorted or duplicate projects, invalid patterns, paths that are not
// clean repository paths and exclusions without a reason are refused.
func LoadTargets(raw []byte) ([]Target, error) {
	var doc targetsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	if doc.Schema != TargetsSchema {
		return nil, fmt.Errorf("schema %q, want %q", doc.Schema, TargetsSchema)
	}
	if len(doc.Targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	var out []Target
	seen := map[string]string{}
	for i, tj := range doc.Targets {
		t, err := tj.target()
		if err != nil {
			return nil, fmt.Errorf("target %d (%s): %w", i, tj.Project, err)
		}
		if i > 0 && doc.Targets[i-1].Project >= t.Project {
			return nil, fmt.Errorf("targets are not sorted by project at %s", t.Project)
		}
		for _, k := range []string{"project " + t.Project, "fact " + t.FactProject, "repo " + t.Repo, "component " + t.Component} {
			if prev, dup := seen[k]; dup {
				return nil, fmt.Errorf("%s is used by %s and %s", k, prev, t.Project)
			}
			seen[k] = t.Project
		}
		out = append(out, t)
	}
	return out, nil
}

func (tj targetJSON) target() (Target, error) {
	t := Target{Project: tj.Project, Name: tj.Name, Repo: tj.Repo, Component: tj.Component, FactProject: tj.FactProject, TagPrefixes: tj.TagPrefixes, Attest: tj.Attest}
	switch {
	case !projectRE.MatchString(t.Project) || len(t.ExtractorID()) > 128:
		return t, fmt.Errorf("project slug")
	case strings.TrimSpace(t.Name) != t.Name || t.Name == "" || len(t.Name) > 64:
		return t, fmt.Errorf("name")
	case !factProjectRE.MatchString(t.FactProject):
		return t, fmt.Errorf("factProject")
	}
	repo, err := extract.ParseRepo(t.Repo)
	if err != nil || repo.Key != t.Repo {
		return t, fmt.Errorf("repo %q", t.Repo)
	}
	if t.Component != "pkg:github/"+strings.TrimPrefix(t.Repo, "github.com/") {
		return t, fmt.Errorf("component %q does not name repository %s", t.Component, t.Repo)
	}
	if len(t.TagPrefixes) == 0 || len(t.TagPrefixes) > 2 {
		return t, fmt.Errorf("tagPrefixes: one or two of \"v\" and \"\"")
	}
	for i, p := range t.TagPrefixes {
		if (p != "" && p != "v") || (i > 0 && p == t.TagPrefixes[0]) {
			return t, fmt.Errorf("tagPrefixes: one or two of \"v\" and \"\"")
		}
	}
	m := lineRE.FindStringSubmatch(tj.MinFrom)
	if m == nil {
		return t, fmt.Errorf("minFrom %q is not major.minor", tj.MinFrom)
	}
	t.MinFrom[0], _ = strconv.Atoi(m[1])
	t.MinFrom[1], _ = strconv.Atoi(m[2])
	if len(tj.Paths) == 0 {
		return t, fmt.Errorf("no paths")
	}
	seenPath := map[string]bool{}
	required := false
	for _, pj := range tj.Paths {
		ps, err := pj.spec()
		if err != nil {
			return t, fmt.Errorf("path %q: %w", pj.Path, err)
		}
		for other := range seenPath {
			if other == ps.Path || strings.HasPrefix(ps.Path, other+"/") || strings.HasPrefix(other, ps.Path+"/") {
				return t, fmt.Errorf("paths %q and %q overlap", other, ps.Path)
			}
		}
		seenPath[ps.Path] = true
		required = required || !ps.Optional
		t.Paths = append(t.Paths, ps)
	}
	if !required {
		return t, fmt.Errorf("every path is optional")
	}
	for i, ej := range tj.Exclude {
		if err := validExclusion(ej); err != nil {
			return t, fmt.Errorf("exclusion %q: %w", ej.Path, err)
		}
		if i > 0 && tj.Exclude[i-1].Path >= ej.Path {
			return t, fmt.Errorf("exclusions are not sorted at %q", ej.Path)
		}
		for _, ps := range t.Paths {
			if exclusionMatches(ej.Path, ps.Path) || (strings.HasSuffix(ej.Path, "/") && strings.HasPrefix(ej.Path, ps.Path+"/")) {
				return t, fmt.Errorf("exclusion %q covers the listed path %s", ej.Path, ps.Path)
			}
		}
		if ej.Repo != t.Repo {
			return t, fmt.Errorf("exclusion %q names repository %q, not %s", ej.Path, ej.Repo, t.Repo)
		}
		t.Exclude = append(t.Exclude, Exclusion{Path: ej.Path, Repo: ej.Repo, Reason: ej.Reason, Evidence: ej.Evidence, Copies: ej.Copies})
	}
	return t, nil
}

func cleanRepoPath(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\x00\n\\")
}

func (pj pathJSON) spec() (PathSpec, error) {
	ps := PathSpec{Path: pj.Path, Dir: pj.Directory, Recursive: pj.Recursive, Optional: pj.Optional}
	if !cleanRepoPath(pj.Path) {
		return ps, fmt.Errorf("not a clean repository path")
	}
	if !pj.Directory {
		if pj.Recursive || pj.Match != "" || pj.Guard != "" {
			return ps, fmt.Errorf("a file path takes no recursive, match or guard")
		}
		return ps, nil
	}
	if pj.Match == "" || pj.Guard == "" {
		return ps, fmt.Errorf("a directory needs match and guard")
	}
	var err error
	if ps.Match, err = regexp.Compile(pj.Match); err != nil {
		return ps, fmt.Errorf("match: %w", err)
	}
	if ps.Guard, err = regexp.Compile(pj.Guard); err != nil {
		return ps, fmt.Errorf("guard: %w", err)
	}
	return ps, nil
}

func validExclusion(ej exclusionJSON) error {
	p := strings.TrimSuffix(ej.Path, "/")
	if !cleanRepoPath(p) {
		return fmt.Errorf("not a clean repository path")
	}
	if strings.ContainsAny(ej.Path, globMeta) {
		if strings.HasSuffix(ej.Path, "/") {
			return fmt.Errorf("a pattern names files, not a directory")
		}
		// The install-location check reads the directory part literally:
		// a pattern there could match a directory it refuses
		// (de*/examples/x.yaml matches deploy/examples/x.yaml).
		if strings.ContainsAny(path.Dir(ej.Path), globMeta) {
			return fmt.Errorf("a pattern may only be in the last path element")
		}
		if _, err := path.Match(ej.Path, ""); err != nil {
			return fmt.Errorf("pattern: %w", err)
		}
	}
	if r := strings.TrimSpace(ej.Reason); r != ej.Reason || len(r) < 12 || len(r) > 300 {
		return fmt.Errorf("a reason of 12 to 300 characters is required")
	}
	if e := strings.TrimSpace(ej.Evidence); e != ej.Evidence || len(e) < 40 || len(e) > 800 {
		return fmt.Errorf("evidence of 40 to 800 characters is required")
	}
	if !ej.Copies {
		if seg := installSegment(ej.Path); seg != "" {
			return fmt.Errorf("%q lies under a %q directory: definitions there are installed or generated for install and are never excluded", ej.Path, seg)
		}
	}
	return nil
}

// installSegments are the directory names of the places a project installs
// from; an entry that is not a declared, checked copy may not lie under one.
// "chart", "charts", "deploy", "deployment", "deployments", "install" and
// "installation" count at any depth. "manifests" counts only as the first
// directory of the repository (the install directory of the projects that
// have one; test/e2e/manifests holds the manifests of end-to-end tests), and
// "crd" or "crds" only directly below a "config" directory (the kubebuilder
// layout). The install-surface guard decides the rest per tag, and refuses
// every path that lies under a Helm chart.
var installSegments = []string{"chart", "charts", "deploy", "deployment", "deployments", "install", "installation"}

// installSegment returns the install location an exclusion path lies under
// ("" when it lies under none). For a directory prefix every segment is a
// directory; for a file or pattern the directory part is. Case-insensitive,
// while defaultSegment is case-sensitive: both err on the strict side (a
// Deploy/ entry is refused, a Test/ directory is not default-excluded).
func installSegment(entry string) string {
	dir := strings.TrimSuffix(entry, "/")
	if !strings.HasSuffix(entry, "/") {
		dir = path.Dir(entry)
	}
	if dir == "." {
		return ""
	}
	segs := strings.Split(strings.ToLower(dir), "/")
	if segs[0] == "manifests" {
		return "manifests"
	}
	for i, seg := range segs {
		for _, s := range installSegments {
			if seg == s {
				return s
			}
		}
		if seg == "config" && i+1 < len(segs) && (segs[i+1] == "crd" || segs[i+1] == "crds") {
			return "config/" + segs[i+1]
		}
	}
	return ""
}

// exclusionMatches reports whether one exclusion entry covers a file path.
func exclusionMatches(entry, p string) bool {
	switch {
	case strings.HasSuffix(entry, "/"):
		return strings.HasPrefix(p, entry)
	case strings.ContainsAny(entry, globMeta):
		ok, _ := path.Match(entry, p)
		return ok
	default:
		return entry == p
	}
}

// Where a scanned file lies.
const (
	// locTree: anywhere else in the repository.
	locTree = iota
	// locDefault: under a directory named by DefaultExcludedSegments.
	locDefault
	// locReviewed: under a reviewed exclusion of the target.
	locReviewed
)

// place is the location of one scanned path: its kind, the default segment
// ("default: <name>") or reviewed exclusion entry, and whether the entry
// declares checked copies.
type place struct {
	kind   int
	entry  string
	copies bool
	// void: a reviewed exclusion that an install surface refers to at this
	// release. The place is a default-like one ("void: <entry>"): the files
	// are classified, block attestation and never withhold a pair, but a
	// definition may not be taken to be gone while one of them is opaque,
	// and Go sources there are read.
	void bool
}

// placeOf locates a file path. A reviewed exclusion wins over a default
// segment; a default segment matches a whole directory name.
func (t Target) placeOf(p string) place {
	for _, e := range t.Exclude {
		if exclusionMatches(e.Path, p) {
			if t.voided[e.Path] {
				return place{kind: locDefault, entry: voidPrefix + e.Path, void: true}
			}
			return place{kind: locReviewed, entry: e.Path, copies: e.Copies}
		}
	}
	if d := defaultSegment(p); d != "" {
		return place{kind: locDefault, entry: "default: " + d}
	}
	return place{kind: locTree}
}

// defaultSegment returns the first directory segment of a file path that
// names a default-excluded directory ("" when none does).
func defaultSegment(p string) string {
	if dir := path.Dir(p); dir != "." {
		for _, seg := range strings.Split(dir, "/") {
			for _, d := range DefaultExcludedSegments {
				if seg == d {
					return d
				}
			}
		}
	}
	return ""
}

// TargetFor returns the target of a project slug.
func TargetFor(project string) (Target, bool) {
	for _, t := range Targets {
		if t.Project == project {
			return t, true
		}
	}
	return Target{}, false
}

// FactID is the set fact a target's rules read.
func (t Target) FactID() string {
	return "component." + t.FactProject + ".custom_resource_versions_set"
}

// ExtractorID is the extractor id of one target.
func (t Target) ExtractorID() string { return IDPrefix + t.Project }
