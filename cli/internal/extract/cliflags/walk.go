// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"
	"unicode/utf8"
)

// callCtx is the lexical context a registration inherits from the calls that
// led to it.
type callCtx struct{ loop, lit, init, goos bool }

type walker struct {
	a          *analysis
	fn         *fnInfo
	fi         *fileInfo
	inh        callCtx
	depth      int
	env        map[string]*binding
	unknown    map[string]bool // parameters whose kind is not known
	paramKinds map[string]rk
	clauses    map[string]*ast.CallExpr
	stack      []ast.Node
}

func (a *analysis) newWalker(fn *fnInfo, cc callCtx, depth int) *walker {
	w := &walker{a: a, fn: fn, fi: fn.fi, inh: cc, depth: depth, unknown: map[string]bool{},
		paramKinds: map[string]rk{}, clauses: map[string]*ast.CallExpr{}}
	w.env = map[string]*binding{}
	for n, b := range a.pkgEnv(fn.p) {
		w.env[n] = b
	}
	return w
}

func (w *walker) g() *guards { return &w.a.s.g }

func (w *walker) omit(reason, detail string) { w.a.omit(reason, detail) }

func (w *walker) alias(name string) *imp { return w.fi.aliases[name] }

// params records what the parameters of the function are: the kind a caller
// bound, else the kind its declared type names, else unknown.
func (w *walker) params(bound map[string]rk) {
	if w.fn.decl == nil || w.fn.decl.Type.Params == nil {
		return
	}
	for _, f := range w.fn.decl.Type.Params.List {
		k := w.classifyType(f.Type)
		for _, n := range f.Names {
			if n.Name == "_" {
				continue
			}
			kk := k
			if b, ok := bound[n.Name]; ok {
				kk = b
			}
			if kk != rkNone {
				w.paramKinds[n.Name] = kk
			} else {
				w.unknown[n.Name] = true
			}
		}
	}
}

func (w *walker) classifyType(t ast.Expr) rk {
	switch t := t.(type) {
	case *ast.StarExpr:
		return w.classifyType(t.X)
	case *ast.ParenExpr:
		return w.classifyType(t.X)
	case *ast.SelectorExpr:
		id, ok := t.X.(*ast.Ident)
		if !ok {
			return rkNone
		}
		im := w.alias(id.Name)
		if im == nil {
			return rkNone
		}
		switch {
		case im.lib == libStd && t.Sel.Name == "FlagSet":
			return rkStd
		case im.lib == libPflag && t.Sel.Name == "FlagSet":
			return rkPflag
		case im.lib == libCobra && t.Sel.Name == "Command":
			return rkCobra
		case im.lib == libKingpin && (t.Sel.Name == "Application" || t.Sel.Name == "CmdClause"):
			return rkKing
		case im.lib == libUrfave && t.Sel.Name == "App":
			return rkUrfave
		}
	}
	return rkNone
}

func (w *walker) classify(e ast.Expr) rk {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return w.classify(e.X)
	case *ast.StarExpr:
		return w.classify(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return w.classify(e.X)
		}
	case *ast.Ident:
		if b := w.env[e.Name]; b != nil && !b.tainted {
			return b.kind
		}
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok && e.Sel.Name == "CommandLine" {
			if im := w.alias(id.Name); im != nil {
				switch im.lib {
				case libStd:
					return rkStd
				case libPflag:
					return rkPflag
				case libKingpin:
					return rkKing
				}
			}
		}
	case *ast.CompositeLit:
		if e.Type != nil {
			return w.classifyType(e.Type)
		}
	case *ast.CallExpr:
		return w.classifyCall(e)
	}
	return rkNone
}

func (w *walker) classifyCall(c *ast.CallExpr) rk {
	if id, ok := c.Fun.(*ast.Ident); ok {
		if id.Name == "new" && len(c.Args) == 1 {
			return w.classifyType(c.Args[0])
		}
		return rkNone
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return rkNone
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if im := w.alias(id.Name); im != nil {
			switch {
			case im.lib == libStd && sel.Sel.Name == "NewFlagSet":
				return rkStd
			case im.lib == libPflag && sel.Sel.Name == "NewFlagSet":
				return rkPflag
			case im.lib == libKingpin && (sel.Sel.Name == "New" || sel.Sel.Name == "NewApplication"):
				return rkKing
			case im.lib == libUrfave && sel.Sel.Name == "NewApp":
				return rkUrfave
			}
			return rkNone
		}
	}
	switch sel.Sel.Name {
	case "Flags", "PersistentFlags":
		if len(c.Args) == 0 {
			return rkPflag
		}
	case "Command":
		if len(c.Args) == 2 && w.classify(sel.X) == rkKing {
			return rkKing
		}
	}
	return rkNone
}

// isKing reports whether x is the kingpin package or a kingpin application or
// command.
func (w *walker) isKing(x ast.Expr) bool {
	if id, ok := x.(*ast.Ident); ok {
		if im := w.alias(id.Name); im != nil && im.lib == libKingpin {
			return true
		}
	}
	return w.classify(x) == rkKing
}

// flagRoot finds the kingpin Flag(name, help) call a method chain or clause
// variable stems from.
func (w *walker) flagRoot(e ast.Expr) *ast.CallExpr {
	for i := 0; i < 64; i++ {
		switch v := e.(type) {
		case *ast.ParenExpr:
			e = v.X
		case *ast.Ident:
			return w.clauses[v.Name]
		case *ast.CallExpr:
			s, ok := v.Fun.(*ast.SelectorExpr)
			if !ok {
				return nil
			}
			if s.Sel.Name == "Flag" && len(v.Args) == 2 && w.isKing(s.X) {
				return v
			}
			e = s.X
		default:
			return nil
		}
	}
	return nil
}

func (w *walker) noteAssign(t obsTable, lhs, rhs []ast.Expr) {
	if len(lhs) != len(rhs) {
		for _, l := range lhs {
			if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
				t.note(id.Name, rkNone, false)
			}
		}
		return
	}
	for i, l := range lhs {
		id, ok := l.(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		k := w.classify(rhs[i])
		t.note(id.Name, k, k != rkNone)
		root := w.flagRoot(rhs[i])
		c, isCall := rhs[i].(*ast.CallExpr)
		if root == nil || !isCall {
			continue
		}
		if c == root {
			w.clauses[id.Name] = root
		} else if s, ok := c.Fun.(*ast.SelectorExpr); ok && clauseMethods[s.Sel.Name] {
			w.clauses[id.Name] = root
		}
	}
}

func (w *walker) noteValueSpec(t obsTable, vs *ast.ValueSpec) {
	switch {
	case len(vs.Values) == 0:
		var k rk
		if vs.Type != nil {
			k = w.classifyType(vs.Type)
		}
		for _, n := range vs.Names {
			if n.Name != "_" {
				t.note(n.Name, k, k != rkNone)
			}
		}
	case len(vs.Values) == len(vs.Names):
		lhs := make([]ast.Expr, len(vs.Names))
		for i, n := range vs.Names {
			lhs[i] = n
		}
		w.noteAssign(t, lhs, vs.Values)
	default:
		for _, n := range vs.Names {
			if n.Name != "_" {
				t.note(n.Name, rkNone, false)
			}
		}
	}
}

// gather computes which local names are provably flag sets. It is flow
// insensitive: a name assigned both a flag set and anything else is tainted
// and never trusted.
func (w *walker) gather(root ast.Node) {
	base := map[string]*binding{}
	for n, b := range w.env {
		base[n] = b
	}
	for round := 0; round < 3; round++ {
		t := obsTable{}
		for n, k := range w.paramKinds {
			t.note(n, k, true)
		}
		for n := range w.unknown {
			t.note(n, rkNone, false)
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				w.noteAssign(t, n.Lhs, n.Rhs)
			case *ast.ValueSpec:
				w.noteValueSpec(t, n)
			case *ast.RangeStmt:
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if id, ok := e.(*ast.Ident); ok && id.Name != "_" {
						t.note(id.Name, rkNone, false)
					}
				}
			}
			return true
		})
		next := t.bindings(base)
		if sameEnv(next, w.env) {
			return
		}
		w.env = next
	}
}

// curCtx is the context of the node being visited.
func (w *walker) curCtx() callCtx {
	cc := w.inh
	for _, n := range w.stack {
		switch n := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			cc.loop = true
		case *ast.FuncLit:
			cc.lit = true
		case *ast.IfStmt:
			if w.mentionsGOOS(n.Cond) {
				cc.goos = true
			}
		case *ast.SwitchStmt:
			if w.mentionsGOOS(n.Tag) {
				cc.goos = true
			}
			for _, cl := range n.Body.List {
				if c, ok := cl.(*ast.CaseClause); ok {
					for _, e := range c.List {
						if w.mentionsGOOS(e) {
							cc.goos = true
						}
					}
				}
			}
		}
	}
	if d := w.fn.decl; d != nil && d.Recv == nil && d.Name.Name == "init" {
		cc.init = true
	}
	return cc
}

func (w *walker) mentionsGOOS(e ast.Expr) bool {
	if e == nil {
		return false
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && (s.Sel.Name == "GOOS" || s.Sel.Name == "GOARCH") {
			if id, ok := s.X.(*ast.Ident); ok {
				if im := w.alias(id.Name); im != nil && im.path == "runtime" {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// ctxOmits records the withholds the context of a registration implies.
func (w *walker) ctxOmits() {
	cc := w.curCtx()
	g := w.g()
	if cc.loop && g.loop {
		w.omit(ReasonRegistrationInLoop, "")
	}
	if (cc.lit || cc.init) && g.initReg {
		w.omit(ReasonInitRegistration, "")
	}
	if (cc.goos && g.goos) || w.fi.constrained {
		w.omit(ReasonBuildConstrained, "")
	}
}

func (w *walker) visit(n ast.Node) bool {
	if n == nil {
		w.stack = w.stack[:len(w.stack)-1]
		return true
	}
	w.stack = append(w.stack, n)
	switch n := n.(type) {
	case *ast.CallExpr:
		w.call(n)
		w.urfaveAppend(n)
		w.escape(n)
	case *ast.AssignStmt:
		w.urfaveAssign(n)
	case *ast.ReturnStmt:
		w.urfaveReturn(n)
	case *ast.CompositeLit:
		w.urfave(n)
	case *ast.SelectorExpr:
		w.selector(n)
	case *ast.Ident:
		w.escape(n)
	}
	return true
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// exprText renders a receiver expression for identity purposes only.
func exprText(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.ParenExpr:
		return exprText(e.X)
	case *ast.StarExpr:
		return exprText(e.X)
	case *ast.UnaryExpr:
		return exprText(e.X)
	case *ast.SelectorExpr:
		return exprText(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return exprText(e.Fun) + "()"
	}
	return "?"
}

func (w *walker) call(c *ast.CallExpr) {
	sel, isSel := c.Fun.(*ast.SelectorExpr)
	if isSel {
		switch sel.Sel.Name {
		case "SetNormalizeFunc":
			if w.g().normalize {
				w.omit(ReasonNormalizeFunc, "")
			}
		case "AddGoFlagSet", "InitFlags":
			if w.g().global {
				w.omit(ReasonGlobalFlagsetShared, "")
			}
		case "SetArgs":
			if w.g().argsRewrite && !(len(c.Args) == 1 && w.verbatimArgs(c.Args[0])) {
				w.omit(ReasonArgsRewritten, "")
			}
		case "MarkHidden":
			w.mark(c, w.a.hidden)
		case "MarkDeprecated":
			w.mark(c, w.a.deprecated)
		case "Short", "Hidden":
			w.kingModifier(sel)
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if im := w.alias(id.Name); im != nil {
				w.pkgCall(c, sel, im)
				return
			}
		}
		if k := w.classify(sel.X); k != rkNone {
			w.methodCall(c, sel, k)
			return
		}
		w.tripwire(c, sel)
	}
	w.followArgs(c)
}

func (w *walker) mark(c *ast.CallExpr, into map[string]bool) {
	if len(c.Args) == 0 {
		return
	}
	if name, ok := litString(c.Args[0]); ok {
		into[name] = true
	}
}

func (w *walker) kingModifier(sel *ast.SelectorExpr) {
	root := w.flagRoot(sel.X)
	if root == nil {
		return
	}
	m := w.a.modOf(w.a.posKey(root.Pos()))
	if sel.Sel.Name == "Short" {
		m.short = true
	} else {
		m.hidden = true
	}
}

func (w *walker) pkgCall(c *ast.CallExpr, sel *ast.SelectorExpr, im *imp) {
	verb := sel.Sel.Name
	switch im.lib {
	case libStd, libPflag:
		if info, ok := w.g().verb(verb); ok {
			k := rkStd
			if im.lib == libPflag {
				k = rkPflag
			}
			w.registerCall(c, k, info, "pkg:"+libDefaultName[im.lib]+".CommandLine")
		} else if !listedNonRegistering(verb) {
			w.unlisted(verb)
		}
	case libKingpin:
		if verb == "Flag" {
			w.registerCall(c, rkKing, kingFlagInfo, "pkg:kingpin.CommandLine")
		}
	case libNone:
		if im.kind == impModule {
			w.followArgs(c)
		}
	}
}

func (w *walker) methodCall(c *ast.CallExpr, sel *ast.SelectorExpr, k rk) {
	verb := sel.Sel.Name
	identity := w.fn.key + "|" + exprText(sel.X)
	if s, ok := unparen(sel.X).(*ast.SelectorExpr); ok && s.Sel.Name == "CommandLine" {
		// A package-level flag set is shared by every function.
		identity = "pkg:" + exprText(s)
	}
	switch k {
	case rkStd, rkPflag:
		if info, ok := w.g().verb(verb); ok {
			w.registerCall(c, k, info, identity)
			return
		}
		if !listedNonRegistering(verb) {
			w.unlisted(verb)
		}
	case rkKing:
		if verb == "Flag" {
			w.registerCall(c, k, kingFlagInfo, identity)
		}
	}
}

// unlisted withholds a method or package function of a flag library that is
// neither a known registration nor on the non-registering list.
func (w *walker) unlisted(verb string) {
	if w.g().unlisted {
		w.omit(ReasonDelegatedUnresolved, "method "+verb)
	}
}

func (w *walker) unresolved(detail string) {
	if w.g().delegated {
		w.omit(ReasonDelegatedUnresolved, detail)
	}
}

// registerCall records a registration call, or withholds when its shape is
// not the one the library has.
func (w *walker) registerCall(c *ast.CallExpr, k rk, info verbInfo, identity string) {
	if len(c.Args) != info.arity || c.Ellipsis.IsValid() {
		w.unresolved("shape")
		return
	}
	w.ctxOmits()
	key := w.a.posKey(c.Pos())
	name, ok := litString(c.Args[info.name])
	if !ok {
		if w.g().dynamic {
			w.omit(ReasonDynamicRegistration, "")
		}
		return
	}
	ev := w.a.events[key]
	if ev == nil {
		ev = &event{key: key, name: name, idiom: k.idiom(), identity: identity, fnKey: w.fn.key, root: w.fn.decl == nil}
		w.a.events[key] = ev
	}
	if info.short >= 0 {
		if sh, lit := litString(c.Args[info.short]); !lit || sh != "" {
			ev.shorthand = true
		}
	}
}

// tripwire withholds a registration-shaped call whose receiver is not a
// proven flag set. A receiver that is a parameter of unknown kind is parked:
// a followed call may bind it later.
func (w *walker) tripwire(c *ast.CallExpr, sel *ast.SelectorExpr) {
	if !w.g().tripwire {
		return
	}
	verb := sel.Sel.Name
	shaped := false
	if info, ok := w.g().verb(verb); ok && len(c.Args) == info.arity {
		shaped = true
	}
	if verb == "Flag" && len(c.Args) == 2 {
		shaped = true
	}
	if verb == "AddFlag" || verb == "AddFlagSet" || verb == "AddGoFlag" {
		shaped = true
	}
	if !shaped {
		return
	}
	if id, ok := unparen(sel.X).(*ast.Ident); ok && w.unknown[id.Name] && w.fn.decl != nil {
		w.a.pending[w.fn.key+"|"+id.Name] = true
		return
	}
	w.omit(ReasonDelegatedUnresolved, "receiver")
}

type paramInfo struct {
	name     string
	variadic bool
	typ      ast.Expr
}

func paramsOf(fd *ast.FuncDecl) []paramInfo {
	var out []paramInfo
	if fd.Type.Params == nil {
		return nil
	}
	for _, f := range fd.Type.Params.List {
		_, variadic := f.Type.(*ast.Ellipsis)
		if len(f.Names) == 0 {
			out = append(out, paramInfo{variadic: variadic, typ: f.Type})
			continue
		}
		for _, n := range f.Names {
			out = append(out, paramInfo{name: n.Name, variadic: variadic, typ: f.Type})
		}
	}
	return out
}

// resolve finds the in-module function a call goes to. benign is true for a
// call into the standard library, the flag libraries or the reviewed
// allowlist, which are not followed.
func (w *walker) resolve(c *ast.CallExpr, nargs int) (fn *fnInfo, benign bool) {
	switch f := unparen(c.Fun).(type) {
	case *ast.Ident:
		if cands := w.fn.p.funcs[f.Name]; len(cands) == 1 {
			return cands[0], false
		}
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			if im := w.alias(id.Name); im != nil {
				if im.kind != impModule {
					return nil, true
				}
				p := w.a.cl.pkgs[im.dir]
				if p != nil && len(p.funcs[f.Sel.Name]) == 1 {
					return p.funcs[f.Sel.Name][0], false
				}
				return nil, false
			}
		}
		if cands := w.fn.p.methods[f.Sel.Name]; len(cands) > 0 {
			if m := filterArity(cands, nargs); len(m) == 1 {
				return m[0], false
			}
			return nil, false
		}
		var all []*fnInfo
		for _, d := range w.a.cl.dirs {
			if p := w.a.cl.pkgs[d]; p != nil {
				all = append(all, filterArity(p.methods[f.Sel.Name], nargs)...)
			}
		}
		if len(all) == 1 {
			return all[0], false
		}
	}
	return nil, false
}

func filterArity(c []*fnInfo, n int) []*fnInfo {
	var out []*fnInfo
	for _, f := range c {
		if ps := paramsOf(f.decl); len(ps) == n && (n == 0 || !ps[n-1].variadic) {
			out = append(out, f)
		}
	}
	return out
}

// followArgs follows a flag set passed to an in-module function, up to
// MaxFollowDepth calls from the function that knew it.
func (w *walker) followArgs(c *ast.CallExpr) {
	binds := map[int]rk{}
	for i, a := range c.Args {
		if k := w.classify(a); k != rkNone && k != rkUrfave {
			binds[i] = k
		}
	}
	if len(binds) == 0 {
		return
	}
	callee, benign := w.resolve(c, len(c.Args))
	if benign {
		return
	}
	if callee == nil || c.Ellipsis.IsValid() {
		w.unresolved("callee")
		return
	}
	ps := paramsOf(callee.decl)
	if len(ps) != len(c.Args) {
		w.unresolved("callee")
		return
	}
	bound := map[string]rk{}
	typed := true
	idx := make([]int, 0, len(binds))
	for i := range binds {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		p := ps[i]
		if p.variadic || p.name == "" {
			w.unresolved("callee")
			return
		}
		if (&walker{a: w.a, fi: callee.fi}).classifyType(p.typ) == rkNone {
			typed = false
		}
		bound[p.name] = binds[i]
	}
	if typed {
		// The callee declares the library type itself: its own pass sees the
		// registrations.
		return
	}
	if w.g().depthLimit && w.depth+1 > MaxFollowDepth {
		w.unresolved("depth")
		return
	}
	w.a.follows++
	if w.g().limits && w.a.follows > w.g().lim.follows {
		w.omit(ReasonTooLarge, "follow")
		return
	}
	for n := range bound {
		w.a.bound[callee.key+"|"+n] = true
	}
	w.a.analyzeFunc(callee, bound, w.curCtx(), w.depth+1)
}

// methodValue withholds a registration method used as a value (reg :=
// fs.String; reg("x", ...)): the call that registers is no longer one the
// walker can attribute.
func (w *walker) methodValue(n *ast.SelectorExpr) {
	if !w.g().escape {
		return
	}
	verb := n.Sel.Name
	_, isVerb := w.g().verb(verb)
	k := w.classify(n.X)
	if !isVerb && verb != "Flag" && verb != "AddFlag" && verb != "AddFlagSet" && verb != "AddGoFlag" {
		// An unlisted method of a proven flag set, taken as a value.
		if (k == rkStd || k == rkPflag) && !listedNonRegistering(verb) && !w.calledDirectly(n) {
			w.unlisted(verb)
		}
		return
	}
	if len(w.stack) >= 2 {
		if c, ok := w.stack[len(w.stack)-2].(*ast.CallExpr); ok && c.Fun == ast.Expr(n) {
			return
		}
	}
	registrar := w.classify(n.X) != rkNone
	if id, ok := n.X.(*ast.Ident); ok {
		if im := w.alias(id.Name); im != nil {
			registrar = im.lib == libStd || im.lib == libPflag || im.lib == libKingpin
		}
	}
	if registrar {
		w.unresolved("method value")
	}
}

func (w *walker) calledDirectly(n *ast.SelectorExpr) bool {
	if len(w.stack) >= 2 {
		if c, ok := w.stack[len(w.stack)-2].(*ast.CallExpr); ok && c.Fun == ast.Expr(n) {
			return true
		}
	}
	return false
}

// selector checks method values and the uses of os.Args.
func (w *walker) selector(n *ast.SelectorExpr) {
	w.methodValue(n)
	id, ok := n.X.(*ast.Ident)
	if !ok || n.Sel.Name != "Args" || !w.g().argsRewrite {
		return
	}
	im := w.alias(id.Name)
	if im == nil || im.path != "os" {
		return
	}
	if !w.argsUseOK() {
		w.omit(ReasonArgsRewritten, "")
	}
}

var parserMethods = map[string]bool{"Parse": true, "ParseArgs": true, "Run": true, "SetArgs": true}

// verbatimArgs reports whether e is exactly os.Args or os.Args[1:].
func (w *walker) verbatimArgs(e ast.Expr) bool {
	e = unparen(e)
	if s, ok := e.(*ast.SliceExpr); ok {
		lo, isLit := s.Low.(*ast.BasicLit)
		if s.High != nil || s.Max != nil || s.Slice3 || !isLit || lo.Kind != token.INT || lo.Value != "1" {
			return false
		}
		e = unparen(s.X)
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Args" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	im := w.alias(id.Name)
	return im != nil && im.path == "os"
}

// argsUseOK: the node on top of the stack (os.Args) is used as os.Args[0], or
// as os.Args / os.Args[1:] passed to a parser call.
func (w *walker) argsUseOK() bool {
	i := len(w.stack) - 2
	for i >= 0 {
		if _, ok := w.stack[i].(*ast.ParenExpr); !ok {
			break
		}
		i--
	}
	if i < 0 {
		return false
	}
	child := w.stack[i+1]
	switch p := w.stack[i].(type) {
	case *ast.IndexExpr:
		if bl, ok := p.Index.(*ast.BasicLit); ok && p.X == child && bl.Kind == token.INT && bl.Value == "0" {
			return true
		}
	case *ast.SliceExpr:
		if p.X == child && w.verbatimArgs(p) {
			j := i - 1
			for j >= 0 {
				if _, ok := w.stack[j].(*ast.ParenExpr); !ok {
					break
				}
				j--
			}
			if j >= 0 {
				if call, ok := w.stack[j].(*ast.CallExpr); ok {
					return w.parserCall(call)
				}
			}
		}
	case *ast.CallExpr:
		return w.parserCall(p)
	}
	return false
}

// parserCall reports whether c hands its arguments to a flag parser the
// walker can account for: a method of the flag libraries, of a proven flag
// set, command or application, or a method whose name no function or
// interface of the package set declares (so it can only be a library's). A
// hand-written Parse in the package set is not one: it can accept a name that
// is never registered.
func (w *walker) parserCall(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || !parserMethods[sel.Sel.Name] {
		return false
	}
	if !w.g().argsParser {
		return true
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if im := w.alias(id.Name); im != nil {
			return im.lib != libNone
		}
	}
	if w.classify(sel.X) != rkNone {
		return true
	}
	return !w.a.declared(sel.Sel.Name)
}

// escape withholds a flag set that leaves the places the walker can follow:
// returned, stored in a field or composite, or used anywhere else.
func (w *walker) escape(n ast.Expr) {
	if !w.g().escape {
		return
	}
	if id, ok := n.(*ast.Ident); ok {
		if w.env[id.Name] == nil && w.clauses[id.Name] == nil {
			return
		}
		if root := w.clauses[id.Name]; root != nil && !w.keepsFlagSet() {
			// A kingpin clause that leaves: it may get a shorthand elsewhere.
			w.a.modOf(w.a.posKey(root.Pos())).short = true
		}
	}
	if w.classify(n).isSet() && !w.keepsFlagSet() {
		w.unresolved("escape")
	}
}

// keepsFlagSet reports whether the node on top of the stack is used in a way
// that keeps the flag set where the walker sees it.
func (w *walker) keepsFlagSet() bool {
	i := len(w.stack) - 2
	for i >= 0 {
		switch w.stack[i].(type) {
		case *ast.ParenExpr, *ast.StarExpr, *ast.UnaryExpr:
			i--
			continue
		}
		break
	}
	if i < 0 {
		return true
	}
	child := w.stack[i+1]
	switch p := w.stack[i].(type) {
	case *ast.SelectorExpr, *ast.CallExpr:
		return true
	case *ast.AssignStmt:
		for _, l := range p.Lhs {
			if l == child {
				return true
			}
		}
		for _, l := range p.Lhs {
			if _, ok := l.(*ast.Ident); !ok {
				return false
			}
		}
		return true
	case *ast.ValueSpec, *ast.Field, *ast.ExprStmt, *ast.BinaryExpr, *ast.IfStmt:
		return true
	case *ast.KeyValueExpr:
		return p.Key == child
	}
	return false
}

// urfaveFlagType reports whether t names a urfave/cli flag struct: cli.XFlag
// or the v3 generic cli.FlagBase[...].
func (w *walker) urfaveFlagType(t ast.Expr) bool {
	if w.g().urfaveGen {
		switch x := t.(type) {
		case *ast.IndexExpr:
			t = x.X
		case *ast.IndexListExpr:
			t = x.X
		}
	}
	typ, ok := t.(*ast.SelectorExpr)
	if !ok || !(strings.HasSuffix(typ.Sel.Name, "Flag") || typ.Sel.Name == "FlagBase") {
		return false
	}
	id, ok := typ.X.(*ast.Ident)
	if !ok {
		return false
	}
	im := w.alias(id.Name)
	return im != nil && im.lib == libUrfave
}

// urfaveOwner reports whether t is a urfave type that is not a flag (App,
// Command): the types whose Flags field holds a flag list.
func (w *walker) urfaveOwner(t ast.Expr) bool {
	sel, ok := t.(*ast.SelectorExpr)
	if !ok || w.urfaveFlagType(t) {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	im := w.alias(id.Name)
	return im != nil && im.lib == libUrfave
}

// urfaveFlagSlice reports whether t is []cli.Flag.
func (w *walker) urfaveFlagSlice(t ast.Expr) bool {
	arr, ok := t.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	sel, ok := arr.Elt.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Flag" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	im := w.alias(id.Name)
	return im != nil && im.lib == libUrfave
}

// urfaveImport reports whether the import is urfave/cli or one of its
// sub-packages (altsrc), the only wrappers that keep a flag's name.
func urfaveImport(im *imp) bool {
	for _, root := range []string{"github.com/urfave/cli", "gopkg.in/urfave/cli.v1", "gopkg.in/urfave/cli.v2"} {
		if underRoot(im.path, root) {
			return true
		}
	}
	return false
}

// urfaveElemOK reports whether an element of a flag list is one the walker
// reads: a flag literal, a package-level variable initialised with one, or a
// call into a urfave package (altsrc.NewStringFlag) wrapping one. Anything
// else (a custom type with its own Names method, a function result, a wrapper
// of the module's own) is a flag with an unknown name.
func (w *walker) urfaveElemOK(e ast.Expr) bool {
	e = unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = unparen(u.X)
	}
	switch x := e.(type) {
	case *ast.CompositeLit:
		return x.Type != nil && w.urfaveFlagType(x.Type)
	case *ast.Ident:
		return w.a.urfaveVar(x.Name)
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		if im := w.alias(id.Name); w.g().urfaveWrap && (im == nil || !urfaveImport(im)) {
			return false
		}
		for _, a := range x.Args {
			if w.urfaveElemOK(a) {
				return true
			}
		}
	}
	return false
}

// urfaveListOK reports whether e is a whole flag list the walker reads: a
// []cli.Flag literal (its elements are checked where it is visited), or a
// package-level variable initialised with one.
func (w *walker) urfaveListOK(e ast.Expr) bool {
	e = unparen(e)
	switch x := e.(type) {
	case *ast.CompositeLit:
		return x.Type != nil && w.urfaveFlagSlice(x.Type)
	case *ast.Ident:
		return w.a.urfaveList(x.Name)
	}
	return false
}

func (w *walker) importsUrfave() bool {
	for _, im := range w.fi.imports {
		if im.lib == libUrfave {
			return true
		}
	}
	return false
}

func (w *walker) listDynamic() {
	if w.g().urfaveElems {
		w.omit(ReasonDynamicRegistration, "flag list")
	}
}

// urfaveAppend: in a file that uses urfave/cli, append(list, x...) must add
// flags the walker reads.
func (w *walker) urfaveAppend(c *ast.CallExpr) {
	if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != "append" || len(c.Args) < 2 || !w.importsUrfave() {
		return
	}
	if c.Ellipsis.IsValid() {
		if !w.urfaveListOK(c.Args[len(c.Args)-1]) {
			w.listDynamic()
		}
		return
	}
	for _, a := range c.Args[1:] {
		if !w.urfaveElemOK(a) {
			w.listDynamic()
		}
	}
}

// urfaveAssign: x.Flags = v must assign a list the walker reads.
func (w *walker) urfaveAssign(n *ast.AssignStmt) {
	if !w.importsUrfave() {
		return
	}
	for i, l := range n.Lhs {
		sel, ok := l.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Flags" || len(n.Lhs) != len(n.Rhs) {
			continue
		}
		if !w.urfaveListOK(n.Rhs[i]) {
			w.listDynamic()
		}
	}
}

// urfaveReturn: a function returning []cli.Flag must return lists the walker
// reads.
func (w *walker) urfaveReturn(n *ast.ReturnStmt) {
	d := w.fn.decl
	if d == nil || d.Type.Results == nil || !w.importsUrfave() {
		return
	}
	for _, s := range w.stack {
		if _, ok := s.(*ast.FuncLit); ok {
			return
		}
	}
	for i, f := range d.Type.Results.List {
		if !w.urfaveFlagSlice(f.Type) || i >= len(n.Results) {
			continue
		}
		if !w.urfaveListOK(n.Results[i]) {
			w.listDynamic()
		}
	}
}

// urfave reads flag literals of urfave/cli: &cli.StringFlag{Name: "lit"}.
func (w *walker) urfave(n *ast.CompositeLit) {
	if arr, ok := n.Type.(*ast.ArrayType); ok {
		// []cli.Flag{...}: every element must be a flag the walker reads.
		if sel, ok := arr.Elt.(*ast.SelectorExpr); ok && sel.Sel.Name == "Flag" {
			if id, ok := sel.X.(*ast.Ident); ok {
				if im := w.alias(id.Name); im != nil && im.lib == libUrfave && w.g().urfaveElems {
					for _, e := range n.Elts {
						if !w.urfaveElemOK(e) {
							w.omit(ReasonDynamicRegistration, "flag element")
						}
					}
				}
			}
		}
		return
	}
	if n.Type != nil && w.urfaveOwner(n.Type) {
		for _, e := range n.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Flags" && !w.urfaveListOK(kv.Value) {
					w.listDynamic()
				}
			}
		}
		return
	}
	if n.Type == nil || !w.urfaveFlagType(n.Type) {
		return
	}
	w.ctxOmits()
	var nameExpr, aliasExpr ast.Expr
	hidden, dynamic := false, false
	for _, e := range n.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			dynamic = true
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Name":
			nameExpr = kv.Value
		case "Aliases":
			aliasExpr = kv.Value
		case "Hidden":
			if v, ok := kv.Value.(*ast.Ident); ok && v.Name == "true" {
				hidden = true
			}
		}
	}
	var names []string
	if nameExpr == nil {
		dynamic = true
	} else if s, ok := litString(nameExpr); ok {
		for _, part := range strings.Split(s, ",") {
			names = append(names, strings.TrimSpace(part))
		}
	} else {
		dynamic = true
	}
	if aliasExpr != nil {
		cl, ok := aliasExpr.(*ast.CompositeLit)
		if !ok {
			dynamic = true
		} else {
			for _, e := range cl.Elts {
				if s, ok := litString(e); ok {
					names = append(names, strings.TrimSpace(s))
				} else {
					dynamic = true
				}
			}
		}
	}
	if dynamic {
		if w.g().dynamic {
			w.omit(ReasonDynamicRegistration, "")
		}
		return
	}
	var longs, shorts []string
	for _, nm := range names {
		if utf8.RuneCountInString(nm) == 1 {
			shorts = append(shorts, nm)
		} else {
			longs = append(longs, nm)
		}
	}
	register := longs
	if len(longs) == 0 {
		register = shorts
	}
	if !w.g().aliases && len(register) > 1 {
		// Mutation only: the first spelling is the name, the rest are lost.
		register = register[:1]
	}
	base := w.a.posKey(n.Pos())
	identity := w.listIdentity(n)
	sort.Strings(register)
	for _, nm := range register {
		key := fmt.Sprintf("%s#%s", base, nm)
		ev := w.a.events[key]
		if ev == nil {
			ev = &event{key: key, name: nm, idiom: IdiomUrfave, identity: identity, fnKey: w.fn.key, root: w.fn.decl == nil}
			w.a.events[key] = ev
		}
		ev.hidden = ev.hidden || hidden
		if len(longs) > 0 && len(shorts) > 0 {
			ev.shorthand = true
		}
	}
}

// listIdentity is the identity of the flag list a urfave literal sits in.
func (w *walker) listIdentity(n *ast.CompositeLit) string {
	for i := len(w.stack) - 2; i >= 0; i-- {
		if cl, ok := w.stack[i].(*ast.CompositeLit); ok {
			if _, ok := cl.Type.(*ast.ArrayType); ok {
				return "urfave:" + w.a.posKey(cl.Pos())
			}
		}
	}
	return "urfave:" + w.a.posKey(n.Pos())
}
