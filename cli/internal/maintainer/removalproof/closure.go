// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"context"
	"errors"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	maxModFileBytes = 4 << 20
	maxPackages     = 20000
)

type problem struct{ code, detail string }

// sourceFile is one non-test Go file of the tree that the binary imports.
type sourceFile struct {
	path string
	dir  string
	data []byte
}

// importClosure is what the main package of a binary imports, transitively and
// over every build constraint.
type importClosure struct {
	files    []sourceFile
	modules  []moduleRef
	problems []problem
}

// moduleRef is a module to verify. as is the module path imports use, which
// differs from path under a replace directive.
type moduleRef struct{ path, version, sum, as string }

func (m moduleRef) String() string { return m.path + "@" + m.version }

type replacement struct{ oldVersion, target, version string }

type modFile struct {
	module   string
	requires map[string]string
	replaces map[string][]replacement
}

// modVerbs are the directives of a go.mod. Any other is an error, so that no
// spelling of a require or replace is skipped.
var modVerbs = map[string]bool{"module": true, "go": true, "toolchain": true, "require": true, "exclude": true,
	"replace": true, "retract": true, "godebug": true, "tool": true, "ignore": true}

// replacementFor is the replacement the go tool applies to the required
// version of a module: one naming that version, else one naming no version.
func (m modFile) replacementFor(p string) (replacement, bool) {
	for _, want := range []string{m.requires[p], ""} {
		for _, r := range m.replaces[p] {
			if r.oldVersion == want {
				return r, true
			}
		}
	}
	return replacement{}, false
}

// parseModFile reads the module, require and replace directives of a go.mod.
// An unknown directive, a parenthesis other than a block's own, or a require or
// replace it cannot read is an error.
func parseModFile(raw []byte) (modFile, error) {
	m := modFile{requires: map[string]string{}, replaces: map[string][]replacement{}}
	if len(raw) > maxModFileBytes {
		return m, errors.New("go.mod too large")
	}
	block := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		if strings.ContainsAny(line, "\\`") {
			return m, errors.New("escape or raw string")
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		// A quoted token is read only when the quotes are exactly its ends.
		for i, w := range f {
			if n := strings.Count(w, `"`); n != 0 {
				if n != 2 || !strings.HasPrefix(w, `"`) || !strings.HasSuffix(w, `"`) {
					return m, errors.New("unbalanced quote")
				}
				f[i] = w[1 : len(w)-1]
			}
		}
		verb := block
		switch {
		case block != "" && len(f) == 1 && f[0] == ")":
			block = ""
			continue
		case block == "" && len(f) == 2 && f[1] == "(" && modVerbs[f[0]]:
			block = f[0]
			continue
		case block == "":
			verb, f = f[0], f[1:]
		}
		if !modVerbs[verb] || strings.ContainsAny(strings.Join(f, " "), "()") {
			return m, errors.New("unknown directive or misplaced parenthesis")
		}
		switch verb {
		case "module":
			if len(f) != 1 || m.module != "" {
				return m, errors.New("bad module directive")
			}
			m.module = f[0]
		case "require":
			if len(f) != 2 {
				return m, errors.New("bad require directive")
			}
			if old, dup := m.requires[f[0]]; dup && old != f[1] {
				return m, errors.New("module required twice")
			}
			m.requires[f[0]] = f[1]
		case "replace":
			arrow := -1
			for i, w := range f {
				if w == "=>" {
					arrow = i
				}
			}
			if arrow < 1 || arrow > 2 || len(f)-arrow-1 < 1 || len(f)-arrow-1 > 2 {
				return m, errors.New("bad replace directive")
			}
			r := replacement{target: f[arrow+1]}
			if arrow == 2 {
				r.oldVersion = f[1]
			}
			if len(f)-arrow-1 == 2 {
				r.version = f[arrow+2]
			}
			for _, old := range m.replaces[f[0]] {
				if old.oldVersion == r.oldVersion {
					return m, errors.New("module replaced twice")
				}
			}
			m.replaces[f[0]] = append(m.replaces[f[0]], r)
		}
	}
	if block != "" || m.module == "" {
		return m, errors.New("incomplete go.mod")
	}
	return m, nil
}

// parseSumFile maps "path version" to the module zip hash.
func parseSumFile(raw []byte) (map[string]string, error) {
	out := map[string]string{}
	if len(raw) > maxModFileBytes {
		return nil, errors.New("go.sum too large")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			return nil, errors.New("bad go.sum line")
		}
		if strings.HasSuffix(f[1], "/go.mod") {
			continue
		}
		k := f[0] + " " + f[1]
		if old, dup := out[k]; dup && old != f[2] {
			return nil, errors.New("two hashes for one module in go.sum")
		}
		out[k] = f[2]
	}
	return out, nil
}

// goFileName reports a file the go tool may build outside tests.
func goFileName(base string) bool {
	return strings.HasSuffix(base, ".go") && !strings.HasSuffix(base, "_test.go") &&
		!strings.HasPrefix(base, ".") && !strings.HasPrefix(base, "_")
}

// importsOf returns the imports of a file; ignored is true for a file that is
// never built.
func importsOf(name string, data []byte) (imports []string, ignored bool, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, data, parser.ImportsOnly|parser.ParseComments)
	if err != nil {
		return nil, false, err
	}
	for _, cg := range f.Comments {
		if cg.End() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if constraint.IsGoBuild(c.Text) || constraint.IsPlusBuild(c.Text) {
				if x, err := constraint.Parse(c.Text); err == nil && x.String() == "ignore" {
					return nil, true, nil
				}
			}
		}
	}
	for _, im := range f.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			return nil, false, err
		}
		imports = append(imports, p)
	}
	return imports, false, nil
}

func under(p, root string) bool { return p == root || strings.HasPrefix(p, root+"/") }

// closure walks the imports of the binary directory. With verify, each
// external module reached is verified against go.sum and its imports followed;
// without it, only files of the tree are collected.
func (s *sweeper) closure(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, sha, binary string, verify bool) (*importClosure, error) {
	cl := &importClosure{}
	bad := func(code, detail string) { cl.problems = append(cl.problems, problem{code, detail}) }
	read := func(p, code string) ([]byte, bool, error) {
		data, err := r.Read(repo, sha, p)
		if errors.Is(err, extract.ErrNotFound) {
			bad(code, p+" is absent")
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("read %s: %w", p, err)
		}
		return data, true, nil
	}
	raw, ok, err := read("go.mod", CodeGoModInvalid)
	if err != nil || !ok {
		return cl, err
	}
	mod, merr := parseModFile(raw)
	if merr != nil {
		bad(CodeGoModInvalid, merr.Error())
		return cl, nil
	}
	sums := map[string]string{}
	if verify && len(mod.requires) > 0 {
		raw, ok, err := read("go.sum", CodeModuleNoSum)
		if err != nil {
			return cl, err
		}
		if ok {
			if sums, merr = parseSumFile(raw); merr != nil {
				bad(CodeGoModInvalid, merr.Error())
				return cl, nil
			}
		}
	}
	// Every replacement by local path must stay inside the tree, whether or
	// not it applies; local holds those that apply.
	inside := func(target string) (string, bool) {
		c := path.Clean(target)
		return c, strings.HasPrefix(target, "./") && c != ".." && !strings.HasPrefix(c, "../")
	}
	local := map[string]string{}
	for old, rs := range mod.replaces {
		for _, rp := range rs {
			if _, ok := inside(rp.target); rp.version == "" && !ok {
				bad(CodeOutsideReplace, old+" => "+rp.target)
			}
		}
		// The go tool ignores a replacement of a module that is not
		// required: it must not hide the required module holding an import.
		_, required := mod.requires[old]
		if rp, applies := mod.replacementFor(old); required && applies && rp.version == "" {
			if c, ok := inside(rp.target); ok {
				local[old] = c
			}
		}
	}

	type pkgRef struct {
		inTree bool
		dir    string
		mod    moduleRef
	}
	start := binary
	if start == "." {
		start = ""
	}
	queue := []pkgRef{{inTree: true, dir: start}}
	seen := map[string]bool{"tree\x00" + start: true}
	usedModules := map[string]moduleRef{}
	follow := func(ip string) {
		// A path without a dot is the standard library unless go.mod names
		// it: such a module is not verified here, so it refuses.
		if first, _, _ := strings.Cut(ip, "/"); !strings.Contains(first, ".") && !under(ip, mod.module) {
			named := false
			for p := range mod.requires {
				named = named || under(ip, p)
			}
			for p := range mod.replaces {
				named = named || under(ip, p)
			}
			if named {
				bad(CodeImportUnresolved, "module path without a dot: "+ip)
			}
			return
		}
		// The longest module path that holds the import wins.
		best := ""
		for _, cands := range []map[string]string{mod.requires, local, {mod.module: ""}} {
			for p := range cands {
				if under(ip, p) && len(p) > len(best) {
					best = p
				}
			}
		}
		if best == "" {
			bad(CodeImportUnresolved, ip)
			return
		}
		sub := strings.TrimPrefix(strings.TrimPrefix(ip, best), "/")
		next := pkgRef{}
		if dir, ok := local[best]; ok {
			next = pkgRef{inTree: true, dir: rootDir(path.Join(dir, sub))}
		} else if best == mod.module {
			next = pkgRef{inTree: true, dir: sub}
		} else {
			if !verify {
				return
			}
			ref := moduleRef{path: best, version: mod.requires[best]}
			if rp, applies := mod.replacementFor(best); applies && rp.version != "" {
				ref = moduleRef{path: rp.target, version: rp.version}
			}
			sum, ok := sums[ref.path+" "+ref.version]
			if !ok {
				bad(CodeModuleNoSum, ref.String())
				return
			}
			ref.sum, ref.as = sum, best
			usedModules[ref.String()] = ref
			next = pkgRef{dir: sub, mod: ref}
		}
		k := "tree\x00" + next.dir
		if !next.inTree {
			k = next.mod.String() + "\x00" + next.dir
		}
		if !seen[k] {
			seen[k] = true
			queue = append(queue, next)
		}
	}

	for i := 0; i < len(queue); i++ {
		if err := ctx.Err(); err != nil {
			return cl, err
		}
		if i >= maxPackages {
			bad(CodeImportUnresolved, "more packages than the limit")
			break
		}
		p := queue[i]
		if !p.inTree {
			info, prob := s.module(p.mod)
			if prob != nil {
				cl.problems = append(cl.problems, *prob)
				continue
			}
			pk, ok := info.packages[p.dir]
			if !ok || pk.broken {
				bad(CodeImportUnresolved, p.mod.String()+"/"+p.dir)
				continue
			}
			for _, ip := range pk.imports {
				follow(ip)
			}
			continue
		}
		entries, err := r.List(repo, sha, p.dir)
		if errors.Is(err, extract.ErrNotFound) {
			bad(CodeImportUnresolved, "directory "+p.dir)
			continue
		}
		if err != nil {
			return cl, fmt.Errorf("list %q: %w", p.dir, err)
		}
		sort.Slice(entries, func(a, b int) bool { return entries[a].Path < entries[b].Path })
		n := 0
		for _, e := range entries {
			base := path.Base(e.Path)
			if base == "go.mod" && p.dir != "" {
				if _, replaced := localDir(local, p.dir); !replaced {
					bad(CodeNestedModule, p.dir)
				}
			}
			if e.Type == "tree" || !goFileName(base) {
				continue
			}
			if e.Type != "blob" || e.Mode == "120000" {
				bad(CodeImportUnresolved, "not a regular file: "+e.Path)
				continue
			}
			data, ok, err := read(e.Path, CodeImportUnresolved)
			if err != nil {
				return cl, err
			}
			if !ok {
				continue
			}
			imports, ignored, perr := importsOf(e.Path, data)
			if perr != nil {
				bad(CodeImportUnresolved, "unparsable: "+e.Path)
				continue
			}
			if ignored {
				continue
			}
			n++
			cl.files = append(cl.files, sourceFile{path: e.Path, dir: showDir(p.dir), data: data})
			for _, ip := range imports {
				follow(ip)
			}
		}
		if n == 0 {
			bad(CodeImportUnresolved, "no Go file in "+showDir(p.dir))
		}
	}
	for _, m := range usedModules {
		cl.modules = append(cl.modules, m)
	}
	sort.Slice(cl.modules, func(a, b int) bool { return cl.modules[a].String() < cl.modules[b].String() })
	return cl, nil
}

func localDir(local map[string]string, dir string) (string, bool) {
	for old, d := range local {
		if d == dir {
			return old, true
		}
	}
	return "", false
}

// rootDir spells the root directory "" and leaves any other directory as is.
func rootDir(d string) string {
	if d == "." {
		return ""
	}
	return d
}

func showDir(d string) string {
	if d == "" {
		return "."
	}
	return d
}
