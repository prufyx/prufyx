// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Derived tree exclusions (files outside the install path).
//
// A CRD-like file under a directory named by DefaultExcludedSegments never
// withholds a pair, but unless a reviewed exclusion covers it, it blocks
// attestation. The name of a directory is not evidence that nothing
// installs from it, so the name only NOMINATES a tree. A nominated tree
// (the directory up to and including its first default segment) is cleared
// only with positive proof, computed from the pinned bytes of the tag; any
// doubt leaves the files blocking and records the reason (UNKNOWN):
//
//  1. the tree is a test tree or an example tree by its segment name
//     (vendored code is another component and stays blocking);
//  2. the tree does not overlap a listed path, a file the inventory read,
//     a generation, literal-kustomization or remote path, or a reviewed
//     exclusion of the target;
//  3. every finding under it is of a class a non-install tree may hold
//     (an external source, an exclusion-void or anything else keeps it
//     blocking);
//  4. the install-surface guard finds no referrer (kustomization, chart,
//     Makefile, shell script, document, container build, nix file, kodata,
//     //go:embed in a non-test package);
//  5. no file the guard does not read (NotRead: CI configuration, other
//     scripts and build systems, Go code outside test directories, a
//     container build that copies its context) could name the tree: a path
//     word that overlaps it, a path built from variables only, a
//     context-wide COPY. Only a file proven unrelated by that test is
//     recorded as such (count and digest);
//  6. no symbolic link lies in the tree (links are never followed: the
//     mirror refuses them), and none outside it that overlaps a listed
//     path or is named like an install file.
//
// The proof runs at every tag the scan reads; a pair is attestable only if
// every tag of both lines scans clean, so the tree is proven at every tag
// of both lines. A file whose tree is cleared is recorded as excluded or
// excluded-unread with the location "derived: <class> <root>/" and its
// digest, in the same way as a file under a reviewed exclusion, and the
// proof (verdict, referrers, digest of what was checked) is in
// ScanRecord.TreeVerdicts. Nothing is written to a target file: the claim
// is derived from the pinned bytes by the extractor and is re-derived,
// byte for byte, wherever the extractor runs again.
//
// It runs only when the pipeline asks for it (WithDerivedTrees) and the
// target attests (never in an onboarding batch dry run), and never on an
// incomplete scan.

// Tree classes.
const (
	TreeClassTest    = "test-tree"
	TreeClassExample = "example-tree"
)

// Tree verdicts.
const (
	TreeCleared = "cleared"
	TreeUnknown = "unknown"
)

// The reasons of a tree verdict. Closed list.
const (
	TreeReasonProven           = "proven-non-install"
	TreeReasonOtherComponent   = "other-component"
	TreeReasonInstallPath      = "overlaps-install-path"
	TreeReasonOtherFinding     = "holds-finding-of-other-class"
	TreeReasonSurfaceReference = "install-surface-reference"
	TreeReasonUnreadSurface    = "unread-surface-overlap"
	TreeReasonContextCopy      = "container-build-copies-context"
	TreeReasonSymlink          = "symbolic-link"
	TreeReasonBounds           = "bounds"
)

// Bounds of the proof.
const (
	maxTreeSurfaceFiles = 20000
	maxTreeSurfaceBytes = 2 << 20
	maxTreeSymlinks     = 2000
	maxTreeRoots        = 256
	maxTreeFiles        = 64
)

// TreeFile is one file under a cleared tree: its path and what identifies
// its bytes.
type TreeFile struct {
	Path   string `json:"path"`
	OID    string `json:"oid"`
	SHA256 string `json:"sha256,omitempty"`
}

// TreeVerdict is the decision on one nominated tree at one tag.
type TreeVerdict struct {
	Root    string `json:"root"`
	Verdict string `json:"verdict"`
	// Class is the tree class of a cleared tree.
	Class  string `json:"class,omitempty"`
	Reason string `json:"reason"`
	// By and Ref name the file and the word that made the verdict unknown.
	By  string `json:"by,omitempty"`
	Ref string `json:"ref,omitempty"`
	// Detail is the text of the guard's finding, when it voided the tree.
	Detail string `json:"detail,omitempty"`
	// Files are the files of the tree the scan found (up to maxTreeFiles;
	// Count is all of them).
	Files []TreeFile `json:"files,omitempty"`
	Count int        `json:"count"`
	// Checked is the number of files the guard does not read that were
	// tested against the tree and the digest of their paths and object ids.
	Checked       int    `json:"checked"`
	CheckedDigest string `json:"checkedDigest,omitempty"`
}

// derivedPrefix starts the location of a file under a derived tree.
const derivedPrefix = "derived: "

// WithDerivedTrees lets the extractor clear nominated trees (see above).
// Off by default: it is the pipeline that asks for it.
func (x *Extractor) WithDerivedTrees() *Extractor {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.deriveTrees = true
	return x
}

var (
	testSegs    = map[string]bool{"_testdata": true, "e2e": true, "test": true, "testdata": true, "tests": true}
	exampleSegs = map[string]bool{"example": true, "examples": true}
)

// treeClearable are the classes of finding a non-install tree may hold.
var treeClearable = map[string]bool{
	ClassExtra: true, ClassConflict: true, ClassReference: true,
	ClassUnread: true, ClassUnsupported: true, ClassGoDefined: true,
}

// treeRoot returns the directory of p up to and including its first default
// segment, and that segment.
func treeRoot(p string) (string, string) {
	dir := path.Dir(p)
	if dir == "." {
		return "", ""
	}
	segs := strings.Split(dir, "/")
	for i, s := range segs {
		for _, d := range DefaultExcludedSegments {
			if s == d {
				return strings.Join(segs[:i+1], "/"), d
			}
		}
	}
	return "", ""
}

func under(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }

// pathsOverlap reports whether one path is the other or lies under it.
// A glob counts by its literal directory prefix.
func pathsOverlap(a, b string) bool {
	norm := func(p string) string {
		p = strings.Trim(p, "/")
		if i := strings.IndexAny(p, globMeta); i >= 0 {
			p = path.Dir(p[:i] + "x")
			if p == "." {
				p = ""
			}
		}
		return p
	}
	a, b = norm(a), norm(b)
	if a == "" || b == "" {
		return true
	}
	return under(a, b) || under(b, a)
}

// ownedPaths are the paths of the target and the inventory a tree must not
// overlap: the listed install paths of every channel, the files the
// inventory read, generation, literal-kustomization and remote paths, and
// the reviewed exclusions.
func (x *Extractor) ownedPaths(inv *Inventory) []string {
	var out []string
	for _, p := range x.target.allListedPaths() {
		out = append(out, p.Path)
	}
	if inv != nil {
		for _, f := range inv.Files {
			out = append(out, f.Path)
		}
		for _, c := range inv.CRDs {
			out = append(out, c.Path)
		}
	}
	for _, g := range x.target.Generation {
		out = append(out, g.Kustomization, g.Output)
	}
	if l := x.target.LiteralKustomization; l != nil {
		out = append(out, l.Path, l.Makefile, l.Default)
	}
	if r := x.target.Remote; r != nil {
		out = append(out, r.Kustomization)
	}
	for _, e := range x.target.Exclude {
		out = append(out, e.Path)
	}
	var clean []string
	for _, p := range out {
		if p != "" {
			clean = append(clean, p)
		}
	}
	return clean
}

// ---- words of files the guard does not read ----

// surfaceWords is what is kept of one file the guard does not read.
type surfaceWords struct {
	// words are the path-like words (they contain a slash), and the
	// literals joined by a path join call.
	words []string
	// fsLits are the quoted literals of lines that call a file-system
	// function (Go only).
	fsLits []string
	// context is set when a COPY or ADD takes the whole build context.
	context bool
	// big is set when the file is over the bound.
	big bool
}

var (
	wordSplitRE = regexp.MustCompile("[\\s\"'`=:,;<>|&!#^]+")
	joinCallRE  = regexp.MustCompile(`(?:filepath|path)\.Join\(([^)]*)\)`)
	litRE       = regexp.MustCompile("[\"`]([^\"`\\n]{1,200})[\"`]")
	fsCallRE    = regexp.MustCompile(`(?:Join|ReadFile|ReadDir|WalkDir|Walk|Glob|Open|OpenFile|Stat|Abs|Getwd|Chdir)\(`)
)

// wildSegment reports a path segment that stands for any name: a variable,
// a glob, a parent reference or an empty segment.
func wildSegment(s string) bool {
	return s == "" || s == ".." || strings.ContainsAny(s, "*?[$@{}()%")
}

func wordSegments(w string) []string {
	var out []string
	for _, s := range strings.Split(w, "/") {
		if s == "." {
			continue
		}
		out = append(out, s)
	}
	return out
}

// namesTree reports whether the word could name the tree root (its
// segments rs), a path inside it, or a directory above it. A word counts
// only when it holds a slash. A match needs at least one literal segment
// equal to a segment of the root; a word of two or more segments that are
// all variables builds its path from variables only and counts too.
func namesTree(word string, rs []string) bool {
	if !strings.Contains(word, "/") {
		return false
	}
	ws := wordSegments(word)
	allWild := len(ws) >= 2
	for _, s := range ws {
		if !wildSegment(s) {
			allWild = false
		}
	}
	if allWild {
		return true
	}
	n := len(rs)
	for i := range ws {
		k := min(n, len(ws)-i)
		literal := false
		ok := true
		for j := 0; j < k; j++ {
			switch {
			case wildSegment(ws[i+j]):
			case ws[i+j] == rs[j]:
				literal = true
			default:
				ok = false
			}
			if !ok {
				break
			}
		}
		if ok && literal && (k == n || i+k == len(ws)) {
			return true
		}
	}
	return false
}

func summarizeText(p string, data []byte, goFile, build bool) surfaceWords {
	var sw surfaceWords
	if len(data) > maxTreeSurfaceBytes {
		sw.big = true
		return sw
	}
	text := string(data)
	seen := map[string]bool{}
	add := func(w string) {
		if strings.Contains(w, "/") && !seen[w] {
			seen[w] = true
			sw.words = append(sw.words, w)
		}
	}
	for _, w := range wordSplitRE.Split(text, -1) {
		add(w)
	}
	if goFile {
		for _, m := range joinCallRE.FindAllStringSubmatch(text, -1) {
			var parts []string
			for _, q := range litRE.FindAllStringSubmatch(m[1], -1) {
				parts = append(parts, strings.Trim(q[1], "/"))
			}
			if len(parts) > 0 {
				add(strings.Join(parts, "/") + "/")
			}
		}
		for _, line := range strings.Split(text, "\n") {
			if !fsCallRE.MatchString(line) {
				continue
			}
			for _, q := range litRE.FindAllStringSubmatch(line, -1) {
				sw.fsLits = append(sw.fsLits, q[1])
			}
		}
	}
	if build {
		for _, line := range strings.Split(text, "\n") {
			f := strings.Fields(line)
			if len(f) < 3 || !buildCopyRE.MatchString(f[0]+" ") {
				continue
			}
			var srcs []string
			for _, a := range f[1:] {
				if !buildFlagRE.MatchString(a) {
					srcs = append(srcs, a)
				}
			}
			if len(srcs) < 2 {
				continue
			}
			for _, s := range srcs[:len(srcs)-1] {
				s = strings.Trim(s, "\"'[],")
				if s == "." || s == "./" || s == "*" || s == "./*" || s == ".." {
					sw.context = true
				}
			}
		}
	}
	return sw
}

var (
	// ciNameRE: every file under a directory at the root whose name starts
	// with a dot (CI and tool configuration), and the CI files named by
	// their own name.
	ciNameRE     = regexp.MustCompile(`(?i)^(?:\.[^/]+/.*|\.[a-z-]+\.ya?ml|azure-pipelines.*\.ya?ml|bitbucket-pipelines\.ya?ml|cloudbuild.*\.ya?ml|(?:.*/)?jenkinsfile[^/]*)$`)
	scriptNameRE = regexp.MustCompile(`(?i)\.(?:py|rb|pl|js|mjs|cjs|ts|ps1|bat|cmd|zsh|fish|lua|groovy|gradle|tcl|php)$|^(?:taskfile[^/]*|justfile|tiltfile|procfile|rakefile|gruntfile[^/]*|build|build\.bazel|workspace|module\.bazel|\.ko\.ya?ml|skaffold\.ya?ml|\.goreleaser[^/]*\.ya?ml)$|\.bzl$|\.bazelrc$`)
)

// unreadKind decides what a file the guard does not read (or reads only
// for install tools) is to the tree proof.
func unreadKind(p string) (kind string, ok bool) {
	name := path.Base(p)
	switch {
	case inVendored(p):
		return "", false
	case ciNameRE.MatchString(p):
		return "ci", true
	case scriptNameRE.MatchString(name):
		return "script", true
	case makeNameRE.MatchString(name):
		return "make", true
	case shellNameRE.MatchString(name):
		return "script", true
	case buildNameRE.MatchString(name):
		return "build", true
	case strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") && defaultSegment(p) == "":
		return "go", true
	}
	return "", false
}

type treeFileRef struct {
	e    extract.TreeEntry
	kind string
}

// treeWordsFor reads a surface file (once per object id).
func (x *Extractor) treeWordsFor(r extract.PinnedReader, repo extract.RepoRef, commit string, f treeFileRef) (surfaceWords, error) {
	key := f.kind + ":" + f.e.SHA
	x.mu.Lock()
	sw, ok := x.treeWords[key]
	x.mu.Unlock()
	if ok && f.e.SHA != "" {
		return sw, nil
	}
	data, err := r.Read(repo, commit, f.e.Path)
	if err != nil {
		return surfaceWords{}, fmt.Errorf("tree proof reading %s at %s: %w", f.e.Path, commit, err)
	}
	sw = summarizeText(f.e.Path, data, f.kind == "go", f.kind == "build")
	if f.e.SHA != "" {
		x.mu.Lock()
		x.treeWords[key] = sw
		x.mu.Unlock()
	}
	return sw, nil
}

// unreadOverlap tests the surface words of one file against a root:
// the file, the word and the reason ("" when unrelated).
func unreadOverlap(sw surfaceWords, rs []string) (ref, reason string) {
	if sw.big {
		return "the file is over the bound", TreeReasonBounds
	}
	for _, w := range sw.words {
		if namesTree(w, rs) {
			return clip(w), TreeReasonUnreadSurface
		}
	}
	for _, l := range sw.fsLits {
		for _, s := range rs {
			if l == s {
				return clip(l), TreeReasonUnreadSurface
			}
		}
	}
	if sw.context {
		return "COPY of the whole build context", TreeReasonContextCopy
	}
	return "", ""
}

// sha256Hex is the digest of a path/object list, for the record of what was
// checked.
func checkedDigest(parts []string) string {
	sort.Strings(parts)
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

// clearTrees nominates the trees of the blocking findings under default
// directories, decides each (see the file comment) and rewrites the findings
// of the cleared ones. Reader errors abort, as in the scan.
func (x *Extractor) clearTrees(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string, blobs []extract.TreeEntry, commits []string, inv *Inventory, rec *ScanRecord) error {
	roots := map[string]string{}
	for _, f := range rec.Findings {
		if !f.blocks() || !strings.HasPrefix(f.Location, "default: ") {
			continue
		}
		if root, seg := treeRoot(f.Path); root != "" {
			roots[root] = seg
		}
	}
	if len(roots) == 0 {
		return nil
	}
	names := make([]string, 0, len(roots))
	for root := range roots {
		names = append(names, root)
	}
	sort.Strings(names)
	if len(names) > maxTreeRoots {
		return nil
	}
	verdicts := map[string]*TreeVerdict{}
	unknown := func(root, reason, by, ref, detail string) {
		verdicts[root] = &TreeVerdict{Root: root, Verdict: TreeUnknown, Reason: reason, By: by, Ref: ref, Detail: detail}
	}

	// Files and findings of each root.
	files := map[string][]TreeFile{}
	counts := map[string]int{}
	for _, b := range blobs {
		for _, root := range names {
			if under(b.Path, root) && b.Mode != "120000" {
				counts[root]++
			}
		}
	}
	sha := map[string]string{}
	for _, f := range rec.Findings {
		sha[f.Path] = f.SHA256
	}
	blobOID := map[string]string{}
	for _, b := range blobs {
		blobOID[b.Path] = b.SHA
	}

	owned := x.ownedPaths(inv)
	var cand []string
	for _, root := range names {
		seg := roots[root]
		switch {
		case !testSegs[seg] && !exampleSegs[seg]:
			unknown(root, TreeReasonOtherComponent, "", seg, "")
			continue
		}
		overlap := ""
		for _, p := range owned {
			if pathsOverlap(p, root) {
				overlap = p
				break
			}
		}
		if overlap != "" {
			unknown(root, TreeReasonInstallPath, overlap, "", "")
			continue
		}
		bad := ""
		for _, f := range rec.Findings {
			if under(f.Path, root) && f.blocks() && !treeClearable[f.Class] {
				bad = f.Class
				break
			}
		}
		if bad != "" {
			unknown(root, TreeReasonOtherFinding, "", bad, "")
			continue
		}
		cand = append(cand, root)
	}

	// Symbolic links.
	if len(cand) > 0 {
		var links []string
		for _, b := range blobs {
			if b.Mode == "120000" {
				links = append(links, b.Path)
			}
		}
		if len(links) > maxTreeSymlinks {
			for _, root := range cand {
				unknown(root, TreeReasonBounds, "", "symbolic links", "")
			}
			cand = nil
		}
		var rest []string
		for _, root := range cand {
			hit := ""
			for _, l := range links {
				if under(l, root) {
					hit = l
					break
				}
				if base := path.Base(l); ciInstallName(base) {
					hit = l
					break
				}
				for _, p := range x.target.allListedPaths() {
					if pathsOverlap(p.Path, l) {
						hit = l
						break
					}
				}
				if hit != "" {
					break
				}
			}
			if hit != "" {
				unknown(root, TreeReasonSymlink, hit, "", "")
				continue
			}
			rest = append(rest, root)
		}
		cand = rest
	}

	// The install-surface guard.
	if len(cand) > 0 {
		excl := make([]Exclusion, 0, len(cand))
		for _, root := range cand {
			excl = append(excl, Exclusion{Path: root + "/", Reason: "derived", Evidence: "derived"})
		}
		voids, voided, err := x.guardEntries(ctx, r, repo, commit, blobs, commits, inv, excl)
		if err != nil {
			return err
		}
		detail := map[string]Finding{}
		for _, v := range voids {
			detail[v.Location] = v
		}
		var rest []string
		for _, root := range cand {
			if voided[root+"/"] {
				v := detail[root+"/"]
				unknown(root, TreeReasonSurfaceReference, v.Path, "", clip(v.Detail))
				continue
			}
			rest = append(rest, root)
		}
		cand = rest
	}

	// Files the guard does not read.
	var checked []string
	if len(cand) > 0 {
		var surf []treeFileRef
		for _, b := range blobs {
			if b.Mode == "120000" {
				continue
			}
			if k, ok := unreadKind(b.Path); ok {
				inRoot := false
				for _, root := range cand {
					inRoot = inRoot || under(b.Path, root)
				}
				// A file inside a nominated tree is part of that tree.
				if !inRoot {
					surf = append(surf, treeFileRef{b, k})
				}
			}
		}
		if len(surf) > maxTreeSurfaceFiles {
			for _, root := range cand {
				unknown(root, TreeReasonBounds, "", "files the guard does not read", "")
			}
			cand = nil
		} else {
			sort.Slice(surf, func(i, j int) bool { return surf[i].e.Path < surf[j].e.Path })
			words := make([]surfaceWords, len(surf))
			errs := make([]error, len(surf))
			x.parallel(len(surf), func(i int) {
				words[i], errs[i] = x.treeWordsFor(r, repo, commit, surf[i])
			})
			for i := range surf {
				if err := ctx.Err(); err != nil {
					return err
				}
				if errs[i] != nil {
					return errs[i]
				}
				checked = append(checked, surf[i].e.Path+"\x00"+surf[i].e.SHA)
			}
			var rest []string
			for _, root := range cand {
				rs := strings.Split(root, "/")
				by, ref, reason := "", "", ""
				for i, f := range surf {
					if ref, reason = unreadOverlap(words[i], rs); reason != "" {
						by = f.e.Path
						break
					}
				}
				if reason != "" {
					unknown(root, reason, by, ref, "")
					continue
				}
				rest = append(rest, root)
			}
			cand = rest
		}
	}

	// Cleared trees.
	digest := checkedDigest(checked)
	for _, root := range cand {
		class := TreeClassTest
		if exampleSegs[roots[root]] {
			class = TreeClassExample
		}
		verdicts[root] = &TreeVerdict{Root: root, Verdict: TreeCleared, Class: class, Reason: TreeReasonProven, Checked: len(checked), CheckedDigest: digest}
	}
	for i, f := range rec.Findings {
		root, _ := treeRoot(f.Path)
		v := verdicts[root]
		if v == nil || !f.blocks() || !strings.HasPrefix(f.Location, "default: ") {
			continue
		}
		if len(files[root]) < maxTreeFiles {
			files[root] = append(files[root], TreeFile{Path: f.Path, OID: blobOID[f.Path], SHA256: sha[f.Path]})
		}
		if v.Verdict != TreeCleared {
			continue
		}
		switch f.Class {
		case ClassUnread, ClassUnsupported, ClassGoDefined:
			rec.Findings[i].Class = ClassExcludedUnread
		default:
			rec.Findings[i].Class = ClassExcluded
		}
		rec.Findings[i].Location = derivedPrefix + v.Class + " " + root + "/"
	}
	for _, root := range names {
		v := verdicts[root]
		if v == nil {
			continue
		}
		v.Files, v.Count = files[root], counts[root]
		rec.TreeVerdicts = append(rec.TreeVerdicts, *v)
	}
	sort.Slice(rec.TreeVerdicts, func(i, j int) bool { return rec.TreeVerdicts[i].Root < rec.TreeVerdicts[j].Root })
	return nil
}

// ciInstallName reports a link name an install tool reads.
func ciInstallName(base string) bool {
	switch strings.ToLower(base) {
	case "kustomization.yaml", "kustomization.yml", "kustomization", "chart.yaml", "requirements.yaml", "makefile", "dockerfile":
		return true
	}
	return strings.Contains(strings.ToLower(base), "crd")
}
