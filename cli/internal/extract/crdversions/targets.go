// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// TargetSchema identifies a target file, target-<project>.json.
const TargetSchema = "prufyx.io/crd-version-target/v1"

// The catalogs a target's project may belong to.
const (
	// CatalogCNCF: a project of the embedded CNCF landscape catalog.
	CatalogCNCF = "cncf"
	// CatalogCommunity: a project outside the CNCF catalog, listed in the
	// reviewed custom-resource table with its upstream provenance.
	CatalogCommunity = "community"
)

// The reviewed source table is one file per target, target-<project>.json,
// next to the code (see source in extractor.go). The files are data, not
// code, but each is covered by the code digest of its own extractor id, so
// any change to a target is a new code digest of that id and is reviewed as
// one.
// Target is one reviewed source entry: where a catalog project keeps the
// rendered CustomResourceDefinition manifests it ships, which release tags
// form its lines, and which parts of its repository the full-tree scan
// skips (each with the reason a reviewer accepted).
type Target struct {
	// Project is the catalog project slug, also the rule id prefix.
	Project string
	// Catalog is the catalog the project belongs to: CatalogCNCF (the
	// embedded CNCF landscape catalog) or CatalogCommunity (a project
	// outside the CNCF catalog whose identity, upstream repository and
	// licence the reviewed custom-resource table records; nothing about
	// it says it is a CNCF project). A target file names only the
	// community catalog ("catalog": "community"); an entry without the
	// field is a CNCF catalog project.
	Catalog string
	// Name is the public project name used in descriptions.
	Name string
	// Repo is the repository key, github.com/<owner>/<name>.
	Repo string
	// Component is the rule subject component (the catalog identity).
	Component string
	// FactProject is the project part of the set fact id
	// component.<FactProject>.custom_resource_versions_set.
	FactProject string
	// TagPrefixes are the prefixes of final release tags ("v", "",
	// "knative-v"), in order of preference. A version tagged under two
	// prefixes must name one commit.
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
	// Remote, when set, moves the source of the target's definitions to
	// another repository from one release line on (see Remote).
	Remote *Remote
	// DeclaredChannel names the install channel Paths describe, for a
	// project that ships more than one (Gateway API's standard channel);
	// Channels are the other channels it ships. Both are empty for a
	// project with one install.
	DeclaredChannel string
	Channels        []Channel

	// voided are the Exclude entries that do not hold at the release being
	// scanned (see guard.go); set on a copy made for one scan.
	voided map[string]bool
}

// Remote is a per-line source switch: from release line FromLine on, the
// definitions a release installs are not in its own repository but in the
// kustomize directory its Kustomization file names as a remote resource
//
//	https://github.com/<owner>/<name>/<Directory>?ref=<tag>
//
// of another repository (Repo). Kong Ingress Controller does this from 3.4:
// its CRDs moved to Kong/kubernetes-configuration, and every release pins
// the tag of that repository it installs. The extractor reads the release's
// Kustomization (it must hold exactly that one resource and nothing else),
// takes the tag from it, resolves the tag to the commit this table pins for
// it, and reads that directory's own kustomization.yaml and the CRD files it
// lists, at the pinned commit. A tag the table does not pin withholds the
// release (and so the pairs that read its line): the table is the reviewed
// record of which commit a tag names, checked by a reviewer against the
// repository, and a tag that upstream moves later cannot change what is
// read. Every citation of such a definition names the other repository and
// its full commit. A line before FromLine reads the target's own Paths, as
// any other target.
type Remote struct {
	// FromLine is the first release line (major, minor) that installs from
	// Repo.
	FromLine [2]int
	// Kustomization is the file, in the target's own repository, that
	// names the remote resource.
	Kustomization string
	// Repo is the other repository, github.com/<owner>/<name>.
	Repo string
	// Directory is the directory of Repo the resource names; its own
	// kustomization.yaml lists the files that define the CRDs.
	Directory string
	// Pins maps each tag the Kustomization may name to the full commit it
	// points at, in ascending tag order.
	Pins []Pin
}

// Pin is one reviewed tag of a Remote and the commit it names.
type Pin struct {
	Tag    string
	Commit string
}

// pinFor returns the commit pinned for a tag.
func (r *Remote) pinFor(tag string) (string, bool) {
	for _, p := range r.Pins {
		if p.Tag == tag {
			return p.Commit, true
		}
	}
	return "", false
}

// appliesTo reports whether a release line installs from the remote.
func (r *Remote) appliesTo(major, minor int) bool {
	return r != nil && (major > r.FromLine[0] || (major == r.FromLine[0] && minor >= r.FromLine[1]))
}

// Channel is another install channel of the project: a directory of
// CustomResourceDefinitions that defines the same custom resources as the
// target's declared Paths with other served versions (Gateway API's
// experimental channel beside its standard one). The rules a target derives
// are about the declared channel. A channel is read at every release, in
// full and strictly, to keep a rule from forbidding a version that the
// channel still serves: such a version is recorded as retained by the
// channel and no rule is derived for it. A channel's files are declared
// files, so the scan does not take them for conflicting copies.
type Channel struct {
	Name  string
	Paths []PathSpec
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
// With PrePatch (a directory prefix only), the reviewer states that the
// files are the definitions a kustomization at that path renders into the
// listed paths before its patches apply (the generated sources of a
// rendered bundle). The scan checks that claim at every tag (see
// checkPrePatch): only when the kustomization, its patches and the files
// have the exact shape it reads, and the patched definitions are the listed
// ones, do the files stop blocking attestation. Otherwise every file keeps
// its class, as under a declared copy.
//
// Every entry names its repository, the reason the files are not installed
// and the evidence a reviewer read (what uses the files and how). The reason
// and the evidence must hold at every tag of the window; the install-surface
// guard (guard.go) checks the part of that claim a program can: at a tag
// where a Helm chart, a kustomization, a Makefile, a document with an
// install command or an embedding Go package refers to the excluded path,
// or the path lies under a chart, the entry is void for that tag and the
// files under it block attestation like any others. An entry that is not a
// declared copy or pre-patch copy may not lie under a chart, an install,
// deploy, manifests or CRD directory (see installSegments).
type Exclusion struct {
	Path     string
	Repo     string
	Reason   string
	Evidence string
	Copies   bool
	// PrePatch is the kustomization that renders the files under Path
	// into the listed paths ("" when the entry declares no pre-patch
	// copies).
	PrePatch string
}

// checked reports an entry whose claim the scan checks (declared copies or
// pre-patch copies): the install-surface guard does not void it, and the
// files under it keep their classes.
func (e Exclusion) checked() bool { return e.Copies || e.PrePatch != "" }

// TagPrefixes are the release tag prefixes a target may name: none, "v",
// and "knative-v" (Knative's release tags, knative-v1.15.0). Each ends in a
// character that is not a digit or a dot, so a version is never read with
// part of it taken for the prefix.
var TagPrefixes = []string{"", "v", "knative-v"}

const tagPrefixNames = `"", "v" and "knative-v"`

// DefaultExcludedSegments are the directory names whose content is not
// what a project normally installs: tests, test data, examples and
// vendored code. The scan reads them like the rest of the tree, but a file
// there is never a conflicting copy that withholds a pair; any CRD-like
// file there other than a consistent copy blocks attestation unless a
// reviewed exclusion covers it. (Rook installs from deploy/examples.)
var DefaultExcludedSegments = []string{"_testdata", "e2e", "example", "examples", "test", "testdata", "tests", "third_party", "vendor"}

// Targets is the reviewed source table, ordered by project.
var Targets = mustLoadTargets(source)

// targetFile is the document of one target file.
type targetFile struct {
	Schema string     `json:"schema"`
	Target targetJSON `json:"target"`
}

// targetFilePattern matches the target files at the root of the package.
const targetFilePattern = "target-*.json"

// TargetFileName is the name of a project's target file.
func TargetFileName(project string) string { return "target-" + project + ".json" }

type targetJSON struct {
	Project     string          `json:"project"`
	Catalog     string          `json:"catalog,omitempty"`
	Name        string          `json:"name"`
	Repo        string          `json:"repo"`
	Component   string          `json:"component"`
	FactProject string          `json:"factProject"`
	TagPrefixes []string        `json:"tagPrefixes"`
	MinFrom     string          `json:"minFrom"`
	Attest      bool            `json:"attest"`
	Paths       []pathJSON      `json:"paths"`
	Exclude     []exclusionJSON `json:"exclude"`
	Remote      *remoteJSON     `json:"remote,omitempty"`
	// DeclaredChannel and Channels: see Target.
	DeclaredChannel string        `json:"declaredChannel,omitempty"`
	Channels        []channelJSON `json:"channels,omitempty"`
}

type channelJSON struct {
	Name  string     `json:"name"`
	Paths []pathJSON `json:"paths"`
}

type remoteJSON struct {
	FromLine      string    `json:"fromLine"`
	Kustomization string    `json:"kustomization"`
	Repo          string    `json:"repo"`
	Directory     string    `json:"directory"`
	Pins          []pinJSON `json:"pins"`
}

type pinJSON struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
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
	PrePatch string `json:"prePatch,omitempty"`
}

var (
	projectRE     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	factProjectRE = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	lineRE        = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
	globMeta      = "*?["
)

func mustLoadTargets(fsys fs.FS) []Target {
	ts, err := LoadTargets(fsys)
	if err != nil {
		panic("crdversions: target files: " + err.Error())
	}
	return ts
}

// LoadTargets reads and validates every target file (target-*.json) at the
// root of fsys and returns the targets ordered by project. Each file is
// decoded strictly (LoadTarget); across files no project, fact project,
// repository or component may be used twice. A file is part of the code
// digest of its own extractor id only; this check reads the others, but it
// can only refuse to start, never change what an extractor derives.
func LoadTargets(fsys fs.FS) ([]Target, error) {
	names, err := fs.Glob(fsys, targetFilePattern)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	var out []Target
	seen := map[string]string{}
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		t, err := LoadTarget(name, raw)
		if err != nil {
			return nil, err
		}
		for _, k := range []string{"project " + t.Project, "fact " + t.FactProject, "repo " + t.Repo, "component " + t.Component} {
			if prev, dup := seen[k]; dup {
				return nil, fmt.Errorf("%s is used by %s and %s", k, prev, t.Project)
			}
			seen[k] = t.Project
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Project < out[j].Project })
	return out, nil
}

// LoadTarget decodes and validates one target file. Its name must be
// TargetFileName of the project it holds. Unknown fields, trailing data,
// invalid patterns, paths that are not clean repository paths and
// exclusions without a reason are refused.
func LoadTarget(name string, raw []byte) (Target, error) {
	var doc targetFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Target{}, fmt.Errorf("%s: %w", name, err)
	}
	if dec.More() {
		return Target{}, fmt.Errorf("%s: trailing data", name)
	}
	if doc.Schema != TargetSchema {
		return Target{}, fmt.Errorf("%s: schema %q, want %q", name, doc.Schema, TargetSchema)
	}
	t, err := doc.Target.target()
	if err != nil {
		return Target{}, fmt.Errorf("%s (%s): %w", name, doc.Target.Project, err)
	}
	if name != TargetFileName(t.Project) {
		return Target{}, fmt.Errorf("%s holds the target %s, want the file name %s", name, t.Project, TargetFileName(t.Project))
	}
	return t, nil
}

func (tj targetJSON) target() (Target, error) {
	t := Target{Project: tj.Project, Catalog: CatalogCNCF, Name: tj.Name, Repo: tj.Repo, Component: tj.Component, FactProject: tj.FactProject, TagPrefixes: tj.TagPrefixes, Attest: tj.Attest}
	switch tj.Catalog {
	case "":
	case CatalogCommunity:
		t.Catalog = CatalogCommunity
	default:
		// "cncf" is not spelled out: an entry without the field is a CNCF
		// catalog project, so one target has exactly one spelling.
		return t, fmt.Errorf("catalog %q: omit it for a CNCF catalog project or name %q", tj.Catalog, CatalogCommunity)
	}
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
		return t, fmt.Errorf("tagPrefixes: one or two of %s", tagPrefixNames)
	}
	for i, p := range t.TagPrefixes {
		if !slicesContains(TagPrefixes, p) || (i > 0 && p == t.TagPrefixes[0]) {
			return t, fmt.Errorf("tagPrefixes: one or two of %s", tagPrefixNames)
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
	if err := tj.channels(&t); err != nil {
		return t, fmt.Errorf("channels: %w", err)
	}
	for i, ej := range tj.Exclude {
		if err := validExclusion(ej); err != nil {
			return t, fmt.Errorf("exclusion %q: %w", ej.Path, err)
		}
		if i > 0 && tj.Exclude[i-1].Path >= ej.Path {
			return t, fmt.Errorf("exclusions are not sorted at %q", ej.Path)
		}
		for _, ps := range t.allListedPaths() {
			if exclusionMatches(ej.Path, ps.Path) || (strings.HasSuffix(ej.Path, "/") && strings.HasPrefix(ej.Path, ps.Path+"/")) {
				return t, fmt.Errorf("exclusion %q covers the listed path %s", ej.Path, ps.Path)
			}
		}
		if ej.Repo != t.Repo {
			return t, fmt.Errorf("exclusion %q names repository %q, not %s", ej.Path, ej.Repo, t.Repo)
		}
		if ej.PrePatch != "" {
			// The rendering is compared with the declared definitions of
			// the repository itself: a target with other channels or a
			// remote source has none to compare it with alone.
			if len(t.Channels) > 0 || tj.Remote != nil {
				return t, fmt.Errorf("exclusion %q: prePatch is not read for a target with channels or a remote source", ej.Path)
			}
			for _, ps := range t.allListedPaths() {
				if ej.PrePatch == ps.Path || strings.HasPrefix(ej.PrePatch, ps.Path+"/") {
					return t, fmt.Errorf("exclusion %q: prePatch %s lies under the listed path %s", ej.Path, ej.PrePatch, ps.Path)
				}
			}
		}
		t.Exclude = append(t.Exclude, Exclusion{Path: ej.Path, Repo: ej.Repo, Reason: ej.Reason, Evidence: ej.Evidence, Copies: ej.Copies, PrePatch: ej.PrePatch})
	}
	if tj.Remote != nil {
		remote, err := tj.Remote.remote(t)
		if err != nil {
			return t, fmt.Errorf("remote: %w", err)
		}
		t.Remote = remote
	}
	return t, nil
}

var channelNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// channels validates a target's install channels: a declared channel name
// when there are others, distinct names, clean non-overlapping paths (each
// channel with a path that is required), and not together with a Remote.
func (tj targetJSON) channels(t *Target) error {
	if len(tj.Channels) == 0 {
		if tj.DeclaredChannel != "" {
			return fmt.Errorf("declaredChannel %q without channels", tj.DeclaredChannel)
		}
		return nil
	}
	if !channelNameRE.MatchString(tj.DeclaredChannel) || len(tj.Channels) > 4 {
		return fmt.Errorf("declaredChannel is required with channels (at most four)")
	}
	if tj.Remote != nil {
		return fmt.Errorf("a target with channels does not install from another repository")
	}
	if t.Attest {
		return fmt.Errorf("a target with channels does not attest")
	}
	t.DeclaredChannel = tj.DeclaredChannel
	taken := map[string]bool{tj.DeclaredChannel: true}
	owner := map[string]string{}
	for _, p := range t.Paths {
		owner[p.Path] = tj.DeclaredChannel
	}
	for _, cj := range tj.Channels {
		if !channelNameRE.MatchString(cj.Name) || taken[cj.Name] {
			return fmt.Errorf("channel name %q is not a distinct lower-case name", cj.Name)
		}
		taken[cj.Name] = true
		if len(cj.Paths) == 0 {
			return fmt.Errorf("channel %s has no paths", cj.Name)
		}
		ch := Channel{Name: cj.Name}
		required := false
		for _, pj := range cj.Paths {
			ps, err := pj.spec()
			if err != nil {
				return fmt.Errorf("channel %s path %q: %w", cj.Name, pj.Path, err)
			}
			for other, by := range owner {
				if other == ps.Path || strings.HasPrefix(ps.Path, other+"/") || strings.HasPrefix(other, ps.Path+"/") {
					return fmt.Errorf("channel %s path %q overlaps %q of %s", cj.Name, ps.Path, other, by)
				}
			}
			owner[ps.Path] = cj.Name
			required = required || !ps.Optional
			ch.Paths = append(ch.Paths, ps)
		}
		if !required {
			return fmt.Errorf("every path of channel %s is optional", cj.Name)
		}
		t.Channels = append(t.Channels, ch)
	}
	return nil
}

var (
	pinTagRE    = regexp.MustCompile(`^v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(-[0-9A-Za-z][0-9A-Za-z.-]{0,30})?$`)
	pinCommitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func (rj remoteJSON) remote(t Target) (*Remote, error) {
	r := &Remote{Kustomization: rj.Kustomization, Repo: rj.Repo, Directory: rj.Directory}
	m := lineRE.FindStringSubmatch(rj.FromLine)
	if m == nil {
		return nil, fmt.Errorf("fromLine %q is not major.minor", rj.FromLine)
	}
	r.FromLine[0], _ = strconv.Atoi(m[1])
	r.FromLine[1], _ = strconv.Atoi(m[2])
	repo, err := extract.ParseRepo(rj.Repo)
	if err != nil || repo.Key != rj.Repo || rj.Repo == t.Repo {
		return nil, fmt.Errorf("repo %q is not another canonical repository", rj.Repo)
	}
	if !cleanRepoPath(rj.Kustomization) || !cleanRepoPath(rj.Directory) {
		return nil, fmt.Errorf("kustomization and directory must be clean repository paths")
	}
	if t.Attest {
		return nil, fmt.Errorf("a target that installs from another repository does not attest")
	}
	if len(rj.Pins) == 0 || len(rj.Pins) > 64 {
		return nil, fmt.Errorf("one to 64 pins are required")
	}
	for i, p := range rj.Pins {
		if !pinTagRE.MatchString(p.Tag) || !pinCommitRE.MatchString(p.Commit) {
			return nil, fmt.Errorf("pin %q is not a tag with a full lower-case commit", p.Tag)
		}
		if i > 0 && !pinTagLess(rj.Pins[i-1].Tag, p.Tag) {
			return nil, fmt.Errorf("pins are not in ascending tag order at %q", p.Tag)
		}
		r.Pins = append(r.Pins, Pin{Tag: p.Tag, Commit: p.Commit})
	}
	return r, nil
}

// pinTagLess orders tags by version number, then by the text of the
// pre-release, a release after its pre-releases.
func pinTagLess(a, b string) bool {
	ma, mb := pinTagRE.FindStringSubmatch(a), pinTagRE.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x < y
		}
	}
	switch {
	case ma[4] == mb[4]:
		return false
	case ma[4] == "":
		return false
	case mb[4] == "":
		return true
	}
	return ma[4] < mb[4]
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
	if ej.PrePatch != "" {
		switch {
		case ej.Copies:
			return fmt.Errorf("copies and prePatch exclude each other")
		case !strings.HasSuffix(ej.Path, "/") || strings.ContainsAny(ej.Path, globMeta):
			return fmt.Errorf("prePatch needs a directory prefix")
		case !cleanRepoPath(ej.PrePatch) || !isKustomizationName(path.Base(ej.PrePatch)):
			return fmt.Errorf("prePatch %q is not the clean repository path of a kustomization", ej.PrePatch)
		case strings.HasPrefix(ej.PrePatch, ej.Path):
			return fmt.Errorf("prePatch %s lies under the entry", ej.PrePatch)
		}
	}
	if !ej.Copies && ej.PrePatch == "" {
		if seg := installSegment(ej.Path); seg != "" {
			return fmt.Errorf("%q lies under a %q directory: definitions there are installed or generated for install and are never excluded", ej.Path, seg)
		}
	}
	return nil
}

// installSegments are the directory names of the places a project installs
// from; an entry that is not a declared, checked copy (or pre-patch copy)
// may not lie under one.
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
// ("default: <name>") or reviewed exclusion entry, whether the entry
// declares checked copies, and the kustomization of an entry that declares
// pre-patch copies.
type place struct {
	kind     int
	entry    string
	copies   bool
	prePatch string
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
			return place{kind: locReviewed, entry: e.Path, copies: e.Copies, prePatch: e.PrePatch}
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

// allListedPaths are the declared paths and the paths of every channel.
func (t Target) allListedPaths() []PathSpec {
	out := append([]PathSpec(nil), t.Paths...)
	for _, c := range t.Channels {
		out = append(out, c.Paths...)
	}
	return out
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
