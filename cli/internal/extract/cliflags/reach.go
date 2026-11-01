// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"go/ast"
	"go/token"
	"sort"
)

// reachable returns the keys of the functions of the package set that main,
// an init function or a package-level initialiser reaches, by name. An
// identifier that names a function of the same package, a selector through an
// in-module import, and a selector whose name is a method of any package of
// the set, are all edges (references count, not only calls: a command's Run
// field names its function). This over-approximates real reachability, so it
// can only keep a registration "reachable"; what it marks unreachable is
// unreachable.
func (a *analysis) reachable() map[string]bool {
	methods := map[string][]*fnInfo{}
	var pkgs []*pkg
	for _, d := range a.cl.dirs {
		p := a.cl.pkgs[d]
		if p == nil || p.missing {
			continue
		}
		pkgs = append(pkgs, p)
		for n, fs := range p.methods {
			methods[n] = append(methods[n], fs...)
		}
	}
	seen := map[string]bool{}
	var queue []*fnInfo
	push := func(fs ...*fnInfo) {
		for _, f := range fs {
			if f != nil && !seen[f.key] {
				seen[f.key] = true
				queue = append(queue, f)
			}
		}
	}
	refs := func(fi *fileInfo, node ast.Node) {
		ast.Inspect(node, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				push(fi.pkg.funcs[n.Name]...)
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok {
					if im := fi.aliases[id.Name]; im != nil && im.kind == impModule {
						if tp := a.cl.pkgs[im.dir]; tp != nil {
							push(tp.funcs[n.Sel.Name]...)
						}
						return true
					}
				}
				push(methods[n.Sel.Name]...)
			}
			return true
		})
	}
	if mp := a.cl.pkgs[a.dir]; mp != nil {
		push(mp.funcs["main"]...)
	}
	for _, p := range pkgs {
		push(p.funcs["init"]...)
		for _, fi := range p.files {
			for _, d := range fi.f.Decls {
				if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					refs(fi, gd)
				}
			}
		}
	}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		refs(f.fi, f.decl.Body)
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]bool{}
	for _, k := range keys {
		out[k] = true
	}
	return out
}
