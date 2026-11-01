// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// imp is one import of a file.
type imp struct {
	path string
	name string // local name; "" until linked
	kind importKind
	lib  lib
	dot  bool
	dir  string // module-relative directory, for impModule
}

type fileInfo struct {
	path        string
	f           *ast.File
	constrained bool
	imports     []*imp
	aliases     map[string]*imp
	linked      bool
	pkg         *pkg
}

type fnInfo struct {
	decl *ast.FuncDecl // nil for package-level variable initialisers
	fi   *fileInfo
	p    *pkg
	key  string
}

type pkg struct {
	dir     string
	name    string
	files   []*fileInfo
	funcs   map[string][]*fnInfo
	methods map[string][]*fnInfo
	// faults are inventory faults of this package, replayed on every binary
	// whose package set contains it.
	faults  []Omission
	missing bool
	decls   map[*ast.FuncDecl]*fnInfo
	env     map[string]*binding
	envDone bool
}

// moduleDir turns an in-module import path into a repository directory.
func moduleDir(module, p string) string {
	if p == module {
		return ""
	}
	return strings.TrimPrefix(p, module+"/")
}

// loadPkg lists, reads and parses the non-test Go files of a directory.
func (s *scanner) loadPkg(dir string) (*pkg, error) {
	if p, ok := s.pkgs[dir]; ok {
		return p, nil
	}
	p := &pkg{dir: dir, funcs: map[string][]*fnInfo{}, methods: map[string][]*fnInfo{}, decls: map[*ast.FuncDecl]*fnInfo{}}
	s.pkgs[dir] = p
	l, err := s.list(dir)
	if err != nil {
		return nil, err
	}
	if l.missing {
		p.missing = true
		return p, nil
	}
	var files []extract.TreeEntry
	for _, e := range l.entries {
		base := path.Base(e.Path)
		if e.Type == "blob" && base == "go.mod" && dir != "" {
			// A directory with its own go.mod is another module.
			p.faults = append(p.faults, Omission{Reason: ReasonNestedModule, Detail: showDir(dir)})
			p.missing = true
			return p, nil
		}
		if !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") {
			continue
		}
		if e.Type != "blob" || e.Mode == "120000" {
			p.faults = append(p.faults, Omission{Reason: ReasonSourceKind, Detail: e.Path})
			continue
		}
		files = append(files, e)
	}
	if s.g.limits && len(files) > s.g.lim.filesPerDir {
		p.faults = append(p.faults, Omission{Reason: ReasonTooLarge, Detail: "files in " + showDir(dir)})
		return p, nil
	}
	for _, e := range files {
		data, err := s.read(e.Path)
		if errors.Is(err, extract.ErrNotFound) {
			p.faults = append(p.faults, Omission{Reason: ReasonPackageMissing, Detail: e.Path})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cliflags: read %s: %w", e.Path, err)
		}
		s.files++
		s.bytes += len(data)
		if s.g.limits && (len(data) > s.g.lim.fileBytes || s.files > s.g.lim.files || s.bytes > s.g.lim.totalBytes) {
			p.faults = append(p.faults, Omission{Reason: ReasonTooLarge, Detail: e.Path})
			continue
		}
		f, perr := parseSafe(s.fset, e.Path, data, parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil || f == nil {
			if s.g.parse {
				p.faults = append(p.faults, Omission{Reason: ReasonParseError, Detail: e.Path})
			}
			continue
		}
		c := constraintOf(f, e.Path)
		if c.ignored {
			continue
		}
		fi := &fileInfo{path: e.Path, f: f, constrained: c.constrained && s.g.buildTag, pkg: p}
		if p.name == "" {
			p.name = f.Name.Name
		} else if p.name != f.Name.Name {
			p.faults = append(p.faults, Omission{Reason: ReasonParseError, Detail: e.Path})
			continue
		}
		for _, spec := range f.Imports {
			ip, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				p.faults = append(p.faults, Omission{Reason: ReasonParseError, Detail: e.Path})
				continue
			}
			im := &imp{path: ip, kind: classifyImport(ip, s.module), lib: libOf(ip)}
			if spec.Name != nil {
				switch spec.Name.Name {
				case ".":
					im.dot = true
				case "_":
					im.name = "_"
				default:
					im.name = spec.Name.Name
				}
			}
			if im.kind == impModule {
				im.dir = moduleDir(s.module, ip)
			}
			fi.imports = append(fi.imports, im)
		}
		p.files = append(p.files, fi)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			pos := s.fset.Position(fd.Pos())
			fn := &fnInfo{decl: fd, fi: fi, p: p, key: fmt.Sprintf("%s:%d", pos.Filename, pos.Line)}
			p.decls[fd] = fn
			if fd.Recv == nil {
				p.funcs[fd.Name.Name] = append(p.funcs[fd.Name.Name], fn)
			} else {
				p.methods[fd.Name.Name] = append(p.methods[fd.Name.Name], fn)
			}
		}
	}
	sort.Slice(p.files, func(i, j int) bool { return p.files[i].path < p.files[j].path })
	return p, nil
}

// link gives every import of the file its local name and registers the
// alias table. In-module imports are named by the package they load.
func (s *scanner) link(fi *fileInfo) error {
	if fi.linked {
		return nil
	}
	fi.linked = true
	fi.aliases = map[string]*imp{}
	for _, im := range fi.imports {
		if im.dot || im.name == "_" {
			continue
		}
		if im.name == "" {
			im.name = defaultImportName(im.path)
			if im.kind == impModule {
				tp, err := s.loadPkg(im.dir)
				if err != nil {
					return err
				}
				if tp.name != "" {
					im.name = tp.name
				}
			}
		}
		fi.aliases[im.name] = im
	}
	return nil
}

// closure is the package set of one binary: its directory and the
// transitive in-module imports.
type closure struct {
	dirs []string
	pkgs map[string]*pkg
}

func (s *scanner) closureOf(dir string, bin string, om omset) (*closure, error) {
	cl := &closure{pkgs: map[string]*pkg{}}
	queue := []string{dir}
	cl.pkgs[dir] = nil
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if s.g.limits && len(cl.pkgs) > s.g.lim.packages {
			om.add(ReasonTooLarge, bin, "packages")
			break
		}
		p, err := s.loadPkg(d)
		if err != nil {
			return nil, err
		}
		cl.pkgs[d] = p
		if p.missing {
			om.add(ReasonPackageMissing, bin, showDir(d))
		}
		for _, f := range p.faults {
			om.add(f.Reason, bin, f.Detail)
		}
		var next []string
		for _, fi := range p.files {
			if err := s.link(fi); err != nil {
				return nil, err
			}
			for _, im := range fi.imports {
				switch {
				case im.dot && (im.lib != libNone):
					om.add(ReasonIdiomUnsupported, bin, im.path)
				case im.kind == impModule:
					if strings.Contains("/"+im.dir+"/", "/vendor/") || strings.Contains("/"+im.dir+"/", "/testdata/") {
						om.add(ReasonIdiomUnsupported, bin, im.path)
						continue
					}
					if _, seen := cl.pkgs[im.dir]; !seen {
						next = append(next, im.dir)
						cl.pkgs[im.dir] = nil
					}
				case im.kind == impDenied && s.g.imports:
					om.add(ReasonIdiomUnsupported, bin, im.path)
				}
			}
		}
		sort.Strings(next)
		queue = append(queue, next...)
	}
	for d := range cl.pkgs {
		cl.dirs = append(cl.dirs, d)
	}
	sort.Strings(cl.dirs)
	return cl, nil
}
