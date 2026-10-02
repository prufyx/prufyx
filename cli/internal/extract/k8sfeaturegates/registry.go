// SPDX-License-Identifier: AGPL-3.0-only

package k8sfeaturegates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The registry of one commit is built in two parts.
//
// Declared is what the release declares as component feature gates: the
// keys of every feature-spec map literal (map[featuregate.Feature]FeatureSpec
// or VersionedSpecs, and client-go's own Feature maps) in the declaration
// directories, resolved to their string names. These directories hold every
// gate the Kubernetes components register on their shared feature gate:
//
//	pkg/features
//	staging/src/k8s.io/<repo>/pkg/features
//	staging/src/k8s.io/client-go/features
//	staging/src/k8s.io/component-base/<area>/features
//	staging/src/k8s.io/component-base/logs/api/v1
//
// All is every gate name spelled anywhere in the source the components are
// built from: a full walk of pkg/, staging/, cmd/ and plugin/ (skipping
// vendor, testdata and directories the Go tool ignores) collecting the
// resolved keys of every feature-spec map literal, every constant declared
// with a feature-gate type, and every string literal converted to one. All
// is a superset of Declared, and a gate is removed only when it is absent
// from All, so a gate that merely moved to another package is never
// reported as removed.
//
// A registry is complete only when every file of the walk was read and
// parsed and every static map key resolved. A key that cannot be resolved
// statically makes the registry incomplete; a key that is a function
// parameter or local variable is counted as dynamic and does not (it
// re-registers names another map declares). Where the commit carries the
// upstream generated feature lists (test/featuregates_linter/test_data or
// test/compatibility_lifecycle/reference), every name they list must be in
// All, or be the Go identifier of a resolved key (the lists name gates by
// identifier: CPUCFSQuotaPeriod is the identifier of the gate a component
// accepts as CustomCPUCFSQuotaPeriod).

var (
	declPkgFeatures      = regexp.MustCompile(`^staging/src/k8s\.io/[^/]+/pkg/features$`)
	declComponentBaseDir = regexp.MustCompile(`^staging/src/k8s\.io/component-base/[^/]+/features$`)
)

func isDeclarationDir(dir string) bool {
	switch dir {
	case "pkg/features", "staging/src/k8s.io/client-go/features", "staging/src/k8s.io/component-base/logs/api/v1":
		return true
	}
	return declPkgFeatures.MatchString(dir) || declComponentBaseDir.MatchString(dir)
}

var walkRoots = []string{"pkg", "staging", "cmd", "plugin"}

// requiredRoots must exist at every commit.
var requiredRoots = map[string]bool{"pkg": true, "staging": true}

// featuregateFile holds the shared feature gate implementation.
const featuregateFile = "staging/src/k8s.io/component-base/featuregate/feature_gate.go"

// referenceListDirs hold upstream's generated feature lists, when present.
var referenceListDirs = []string{"test/featuregates_linter/test_data", "test/compatibility_lifecycle/reference"}

func skipDir(name string) bool {
	return name == "vendor" || name == "testdata" || strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")
}

type pos struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type gateDecl struct {
	Name       string `json:"gate"`
	Declared   pos    `json:"declaredAt"`
	Registered []pos  `json:"registeredAt"`
}

type fileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Gates  int    `json:"gates,omitempty"`
}

// registry is the parsed gate registry of one commit.
type registry struct {
	Commit    string
	Declared  map[string]*gateDecl
	DeclFiles []fileRef
	// DeclProblems make Declared unusable.
	DeclProblems []string
	All          map[string]bool
	// KeyIdents are the Go identifiers of resolved map keys; upstream's
	// generated feature lists name a gate by its identifier, which can
	// differ from the name a component accepts.
	KeyIdents map[string]bool
	// Problems make All unusable (absence cannot be proven).
	Problems       []string
	Roots          map[string]string
	GoFiles        int
	DynamicKeys    int
	ReferenceLists []fileRef
	ErrorLine      *pos
	files          map[string]*fileSummary // path -> summary
	sha            map[string]string       // path -> hex sha256 of the bytes read
}

type walkFile struct {
	path string
	oid  string
}

// buildRegistry walks the commit and parses its gate registry. Read
// failures are recorded as problems; only context errors abort.
func (x *Extractor) buildRegistry(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string) (*registry, error) {
	reg := &registry{Commit: commit, Declared: map[string]*gateDecl{}, All: map[string]bool{}, KeyIdents: map[string]bool{}, Roots: map[string]string{}, files: map[string]*fileSummary{}, sha: map[string]string{}}
	var mu sync.Mutex
	problem := func(format string, a ...any) {
		mu.Lock()
		reg.Problems = append(reg.Problems, fmt.Sprintf(format, a...))
		mu.Unlock()
	}

	rootEntries, err := r.List(repo, commit, "")
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem("root listing: %v", err)
		return reg.finish(), nil
	}
	var dirs []string
	for _, e := range rootEntries {
		for _, root := range walkRoots {
			if e.Path == root && e.Type == "tree" {
				reg.Roots[root] = e.SHA
				dirs = append(dirs, root)
			}
		}
	}
	for root := range requiredRoots {
		if reg.Roots[root] == "" {
			problem("required directory %s/ is missing", root)
		}
	}

	// Breadth-first listing, then parallel reads.
	var files []walkFile
	for len(dirs) > 0 {
		next := make([][]string, len(dirs))
		found := make([][]walkFile, len(dirs))
		err := x.parallel(ctx, len(dirs), func(i int) {
			entries, err := r.List(repo, commit, dirs[i])
			if err != nil {
				problem("listing %s: %v", dirs[i], err)
				return
			}
			for _, e := range entries {
				name := path.Base(e.Path)
				switch {
				case e.Type == "tree":
					if !skipDir(name) {
						next[i] = append(next[i], e.Path)
					}
				case e.Type == "blob" && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go"):
					if e.Mode == "120000" {
						problem("%s is a symbolic link", e.Path)
						continue
					}
					found[i] = append(found[i], walkFile{path: e.Path, oid: e.SHA})
				case e.Type == "commit":
					problem("%s is a submodule", e.Path)
				}
			}
		})
		if err != nil {
			return nil, err
		}
		dirs = nil
		for i := range next {
			dirs = append(dirs, next[i]...)
			files = append(files, found[i]...)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	reg.GoFiles = len(files)

	summaries := make([]*fileSummary, len(files))
	digests := make([]string, len(files))
	err = x.parallel(ctx, len(files), func(i int) {
		f := files[i]
		if s := x.cached(f.oid); s != nil {
			if rec, ok := extract.Reuse(r, repo, commit, f.path, f.oid); ok {
				summaries[i], digests[i] = s, rec.SHA256
				return
			}
		}
		data, err := r.Read(repo, commit, f.path)
		if err != nil {
			problem("reading %s: %v", f.path, err)
			return
		}
		sum := sha256.Sum256(data)
		s := summarize(f.path, data)
		x.store(f.oid, s)
		summaries[i], digests[i] = s, hex.EncodeToString(sum[:])
	})
	if err != nil {
		return nil, err
	}
	for i, f := range files {
		if summaries[i] == nil {
			continue
		}
		if summaries[i].ParseError != "" {
			problem("parsing %s: %s", f.path, summaries[i].ParseError)
			continue
		}
		reg.files[f.path] = summaries[i]
		reg.sha[f.path] = digests[i]
	}

	reg.resolve()
	if err := x.checkReferenceLists(ctx, r, repo, commit, reg); err != nil {
		return nil, err
	}
	if s := reg.files[featuregateFile]; s != nil && len(s.ErrorLines) > 0 {
		reg.ErrorLine = &pos{Path: featuregateFile, Line: s.ErrorLines[0]}
	} else {
		reg.Problems = append(reg.Problems, "the feature gate implementation does not reject unrecognised gates in a way this extractor recognises")
	}
	return reg.finish(), nil
}

func (reg *registry) finish() *registry {
	sort.Strings(reg.Problems)
	reg.Problems = compactStrings(reg.Problems)
	sort.Strings(reg.DeclProblems)
	reg.DeclProblems = compactStrings(reg.DeclProblems)
	return reg
}

func compactStrings(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || in[i-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// parallel runs fn(0..n-1) on at most x.concurrency goroutines.
func (x *Extractor) parallel(ctx context.Context, n int, fn func(int)) error {
	workers := x.concurrency
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	var err error
	for i := 0; i < n; i++ {
		if err = ctx.Err(); err != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	if err == nil {
		err = ctx.Err()
	}
	return err
}

// importDir maps a Go import path to its directory in the kubernetes tree.
func importDir(p string) (string, bool) {
	if rest, ok := strings.CutPrefix(p, "k8s.io/kubernetes/"); ok {
		return rest, true
	}
	if rest, ok := strings.CutPrefix(p, "k8s.io/"); ok && rest != "" {
		return "staging/src/k8s.io/" + rest, true
	}
	return "", false
}

type dirInfo struct {
	pkg    string // package name, "" if inconsistent
	consts map[string]constRef
}

type constRef struct {
	decl constDecl
	path string
	dup  bool
}

func (reg *registry) dirs() map[string]*dirInfo {
	out := map[string]*dirInfo{}
	paths := make([]string, 0, len(reg.files))
	for p := range reg.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		s := reg.files[p]
		dir := path.Dir(p)
		d := out[dir]
		if d == nil {
			d = &dirInfo{pkg: s.Package, consts: map[string]constRef{}}
			out[dir] = d
		}
		if d.pkg != s.Package {
			d.pkg = ""
		}
		for name, c := range s.Consts {
			if old, ok := d.consts[name]; ok {
				old.dup = true
				d.consts[name] = old
				continue
			}
			d.consts[name] = constRef{decl: c, path: p}
		}
	}
	return out
}

// resolve computes Declared and All from the parsed files.
func (reg *registry) resolve() {
	dirs := reg.dirs()
	type resolved struct {
		name string
		at   pos // where the name is spelled (constant declaration or literal)
	}
	var lookup func(ref exprRef, file string, depth int) (resolved, string)
	lookup = func(ref exprRef, file string, depth int) (resolved, string) {
		if depth > 8 {
			return resolved{}, "reference chain too deep"
		}
		switch ref.Kind {
		case refLiteral:
			return resolved{name: ref.Value}, ""
		case refLocal:
			if ref.Dynamic {
				return resolved{}, "dynamic"
			}
			d := dirs[path.Dir(file)]
			c, ok := d.consts[ref.Value]
			if !ok || c.dup {
				return resolved{}, fmt.Sprintf("%s is not a unique package-level name", ref.Value)
			}
			got, why := lookup(c.decl.Ref, c.path, depth+1)
			if why == "" && got.at.Path == "" {
				got.at = pos{Path: c.path, Line: c.decl.Line}
			}
			return got, why
		case refSelector:
			s := reg.files[file]
			target := ""
			for _, imp := range s.Imports {
				local := imp.Name
				dir, ok := importDir(imp.Path)
				if local == "" {
					if ok && dirs[dir] != nil && dirs[dir].pkg != "" {
						local = dirs[dir].pkg
					} else {
						local = lastElem(imp.Path)
					}
				}
				if local == ref.Pkg {
					if !ok {
						return resolved{}, fmt.Sprintf("%s.%s: import %s is outside the tree", ref.Pkg, ref.Value, imp.Path)
					}
					target = dir
				}
			}
			d := dirs[target]
			if target == "" || d == nil {
				return resolved{}, fmt.Sprintf("%s.%s: package not found in the tree", ref.Pkg, ref.Value)
			}
			c, ok := d.consts[ref.Value]
			if !ok || c.dup {
				return resolved{}, fmt.Sprintf("%s.%s is not a unique package-level name", ref.Pkg, ref.Value)
			}
			got, why := lookup(c.decl.Ref, c.path, depth+1)
			if why == "" && got.at.Path == "" {
				got.at = pos{Path: c.path, Line: c.decl.Line}
			}
			return got, why
		}
		return resolved{}, "not a static name"
	}

	paths := make([]string, 0, len(reg.files))
	for p := range reg.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	declFileGates := map[string]int{}
	for _, p := range paths {
		s := reg.files[p]
		inDecl := isDeclarationDir(path.Dir(p))
		for _, k := range s.Keys {
			got, why := lookup(k.Ref, p, 0)
			switch {
			case why == "dynamic":
				reg.DynamicKeys++
				if inDecl {
					reg.DeclProblems = append(reg.DeclProblems, fmt.Sprintf("%s:%d: feature-spec map key is not a static name", p, k.Line))
				}
				continue
			case why != "":
				msg := fmt.Sprintf("%s:%d: feature-spec map key cannot be resolved (%s)", p, k.Line, why)
				reg.Problems = append(reg.Problems, msg)
				if inDecl {
					reg.DeclProblems = append(reg.DeclProblems, msg)
				}
				continue
			}
			reg.All[got.name] = true
			if k.Ref.Kind == refLocal || k.Ref.Kind == refSelector {
				reg.KeyIdents[k.Ref.Value] = true
			}
			if !inDecl {
				continue
			}
			at := got.at
			if at.Path == "" {
				at = pos{Path: p, Line: k.Line}
			}
			g := reg.Declared[got.name]
			if g == nil {
				g = &gateDecl{Name: got.name, Declared: at}
				reg.Declared[got.name] = g
			} else if at.Path < g.Declared.Path || (at.Path == g.Declared.Path && at.Line < g.Declared.Line) {
				g.Declared = at
			}
			g.Registered = append(g.Registered, pos{Path: p, Line: k.Line})
		}
		for _, c := range s.Consts {
			if !c.Feature {
				continue
			}
			got, why := lookup(c.Ref, p, 0)
			if why == "" {
				reg.All[got.name] = true
			}
		}
		for _, lit := range s.Literals {
			reg.All[lit] = true
		}
	}
	for _, g := range reg.Declared {
		sort.Slice(g.Registered, func(i, j int) bool {
			if g.Registered[i].Path != g.Registered[j].Path {
				return g.Registered[i].Path < g.Registered[j].Path
			}
			return g.Registered[i].Line < g.Registered[j].Line
		})
		declFileGates[g.Declared.Path]++
	}
	var declPaths []string
	for p := range reg.files {
		if isDeclarationDir(path.Dir(p)) {
			declPaths = append(declPaths, p)
		}
	}
	sort.Strings(declPaths)
	for _, p := range declPaths {
		reg.DeclFiles = append(reg.DeclFiles, fileRef{Path: p, SHA256: reg.sha[p], Gates: declFileGates[p]})
	}
	if len(reg.Declared) == 0 {
		reg.DeclProblems = append(reg.DeclProblems, "no feature gate is declared in the declaration directories")
	}
}

// checkReferenceLists cross-checks upstream's generated feature lists.
func (x *Extractor) checkReferenceLists(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string, reg *registry) error {
	for _, dir := range referenceListDirs {
		entries, err := r.List(repo, commit, dir)
		if errors.Is(err, extract.ErrNotFound) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			reg.Problems = append(reg.Problems, fmt.Sprintf("listing %s: %v", dir, err))
			continue
		}
		for _, e := range entries {
			if e.Type != "blob" || !strings.HasSuffix(e.Path, "feature_list.yaml") {
				continue
			}
			data, err := r.Read(repo, commit, e.Path)
			if err != nil {
				reg.Problems = append(reg.Problems, fmt.Sprintf("reading %s: %v", e.Path, err))
				continue
			}
			var list []map[string]any
			if err := yaml.Unmarshal(data, &list); err != nil {
				reg.Problems = append(reg.Problems, fmt.Sprintf("parsing %s: %v", e.Path, firstLine(err.Error())))
				continue
			}
			sum := sha256.Sum256(data)
			reg.ReferenceLists = append(reg.ReferenceLists, fileRef{Path: e.Path, SHA256: hex.EncodeToString(sum[:]), Gates: len(list)})
			for i, item := range list {
				name, ok := item["name"].(string)
				if !ok {
					reg.Problems = append(reg.Problems, fmt.Sprintf("%s: entry %d has no name", e.Path, i))
					continue
				}
				if !reg.All[name] && !reg.KeyIdents[name] {
					reg.Problems = append(reg.Problems, fmt.Sprintf("%s lists %s, which the parsed registry does not hold", e.Path, name))
				}
			}
		}
	}
	return nil
}
