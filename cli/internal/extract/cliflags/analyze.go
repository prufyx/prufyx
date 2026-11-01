// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// rk is what a receiver expression is proven to be.
type rk uint8

const (
	rkNone   rk = iota
	rkStd       // standard library *flag.FlagSet
	rkPflag     // *pflag.FlagSet, including cobra's Flags() and PersistentFlags()
	rkCobra     // *cobra.Command
	rkKing      // kingpin application or command clause
	rkUrfave    // urfave/cli application: a parser, not a registrar
)

func (k rk) idiom() string {
	switch k {
	case rkStd:
		return IdiomFlag
	case rkPflag, rkCobra:
		return IdiomPflag
	case rkKing:
		return IdiomKingpin
	}
	return ""
}

// isSet reports the kinds whose registration surface is the value itself.
// A cobra command is not one: its flags are only reached through Flags()
// and PersistentFlags(), which are recognised by name wherever they occur.
func (k rk) isSet() bool { return k == rkStd || k == rkPflag || k == rkKing }

type binding struct {
	kind    rk
	tainted bool
}

// verbInfo describes a registration method: which argument is the name, which
// the shorthand (-1: none) and how many arguments the call has.
type verbInfo struct{ name, short, arity int }

// regVerbs are the registration methods of the standard flag package and of
// pflag, by method name. The same table serves both: a method that only one
// of them has is simply never called on the other.
var regVerbs = buildVerbs()

func buildVerbs() map[string]verbInfo {
	types := []string{
		"Bool", "BoolSlice", "BytesBase64", "BytesHex", "Duration", "DurationSlice", "Float32", "Float32Slice",
		"Float64", "Float64Slice", "Int", "Int8", "Int16", "Int32", "Int64", "IntSlice", "Int32Slice", "Int64Slice",
		"IP", "IPNet", "IPMask", "IPSlice", "String", "StringArray", "StringSlice", "StringToInt", "StringToInt64",
		"StringToString", "Uint", "Uint8", "Uint16", "Uint32", "Uint64", "UintSlice",
	}
	m := map[string]verbInfo{}
	for _, t := range types {
		m[t] = verbInfo{0, -1, 3}
		m[t+"Var"] = verbInfo{1, -1, 4}
		m[t+"P"] = verbInfo{0, 1, 4}
		m[t+"VarP"] = verbInfo{1, 2, 5}
	}
	// pflag Count has no default value argument.
	m["Count"] = verbInfo{0, -1, 2}
	m["CountVar"] = verbInfo{1, -1, 3}
	m["CountP"] = verbInfo{0, 1, 3}
	m["CountVarP"] = verbInfo{1, 2, 4}
	m["Var"] = verbInfo{1, -1, 3}
	m["VarP"] = verbInfo{1, 2, 4}
	m["VarPF"] = verbInfo{1, 2, 4}
	for _, f := range []string{"Func", "BoolFunc"} {
		m[f] = verbInfo{0, -1, 3}
		m[f+"P"] = verbInfo{0, 1, 4}
	}
	m["TextVar"] = verbInfo{1, -1, 4}
	m["TextVarP"] = verbInfo{1, 2, 5}
	return m
}

// nonRegistering are the methods and package functions of the standard flag
// package and of pflag that are known not to register a name. On a proven
// flag set every other method, and every other package function of those two
// libraries, is withheld: an unlisted method could register a name the scanner
// does not see.
var nonRegistering = map[string]bool{
	"Parse": true, "Parsed": true, "ParseAll": true, "Args": true, "Arg": true, "NArg": true, "NFlag": true,
	"Lookup": true, "ShorthandLookup": true, "Set": true, "Changed": true, "Visit": true, "VisitAll": true,
	"PrintDefaults": true, "FlagUsages": true, "FlagUsagesWrapped": true, "SetOutput": true, "Output": true,
	"Name": true, "Init": true, "HasFlags": true, "HasAvailableFlags": true, "SetInterspersed": true,
	"SetAnnotation": true, "ErrorHandling": true, "NewFlagSet": true, "UnquoteUsage": true,
	"NormalizedName": true, "GetNormalizeFunc": true, "SetNormalizeFunc": true, "MarkHidden": true,
	"MarkDeprecated": true, "MarkShorthandDeprecated": true, "AddGoFlagSet": true, "CopyToGoFlagSet": true,
	"Usage": true, "SetUsage": true, "ParseErrorsAllowlist": true, "ParseErrorsWhitelist": true, "SortFlags": true,
}

func listedNonRegistering(verb string) bool {
	return nonRegistering[verb] || strings.HasPrefix(verb, "Get") || strings.HasPrefix(verb, "Mark")
}

var kingFlagInfo = verbInfo{0, -1, 2}

// clauseMethods are the kingpin flag clause methods that return the clause
// again, so that a variable holding the result is still a flag clause.
var clauseMethods = map[string]bool{
	"Default": true, "Envar": true, "NoEnvar": true, "Required": true, "Short": true, "Hidden": true,
	"Help": true, "PlaceHolder": true, "Action": true, "PreAction": true, "HintOptions": true, "HintAction": true,
}

type event struct {
	key       string
	name      string
	idiom     string
	identity  string
	shorthand bool
	hidden    bool
	fnKey     string // the function holding the registration
	root      bool   // in a package-level initialiser, which always runs
}

type mod struct{ short, hidden bool }

type analysis struct {
	s           *scanner
	bin         string
	cl          *closure
	om          omset
	events      map[string]*event
	mods        map[string]*mod
	hidden      map[string]bool
	deprecated  map[string]bool
	pending     map[string]bool
	bound       map[string]bool
	follows     int
	declNames   map[string]bool
	dir         string
	err         error
	urfaveVars  map[string]bool
	urfaveLists map[string]bool
}

func newAnalysis(s *scanner, bin, dir string, cl *closure, om omset) *analysis {
	return &analysis{s: s, bin: bin, dir: dir, cl: cl, om: om, events: map[string]*event{}, mods: map[string]*mod{},
		hidden: map[string]bool{}, deprecated: map[string]bool{}, pending: map[string]bool{}, bound: map[string]bool{}}
}

// declared reports whether name is used as an identifier anywhere in the
// package set other than as the selected name of a selector expression
// (x.name). That covers functions, methods, interface methods, struct fields
// (also embedded and keyed in literals), parameters, variables and constants:
// a parser held in a field or a func-typed variable is declared here, so a
// call named like it is not taken for a library's.
func (a *analysis) declared(name string) bool {
	if !a.s.g.declAll {
		return a.declaredFuncs(name)
	}
	if a.declNames == nil {
		a.declNames = map[string]bool{}
		for _, d := range a.cl.dirs {
			p := a.cl.pkgs[d]
			if p == nil {
				continue
			}
			for _, fi := range p.files {
				sels := map[*ast.Ident]bool{}
				ast.Inspect(fi.f, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.SelectorExpr:
						sels[n.Sel] = true
					case *ast.Ident:
						if !sels[n] {
							a.declNames[n.Name] = true
						}
					}
					return true
				})
			}
		}
	}
	return a.declNames[name]
}

// urfaveVar reports whether name is a package-level variable of the package
// set initialised with a urfave flag literal; urfaveList the same for a
// []cli.Flag literal.
func (a *analysis) urfaveVar(name string) bool {
	a.indexUrfaveVars()
	return a.urfaveVars[name]
}

func (a *analysis) urfaveList(name string) bool {
	a.indexUrfaveVars()
	return a.urfaveLists[name]
}

func (a *analysis) indexUrfaveVars() {
	if a.urfaveVars != nil {
		return
	}
	a.urfaveVars, a.urfaveLists = map[string]bool{}, map[string]bool{}
	for _, d := range a.cl.dirs {
		p := a.cl.pkgs[d]
		if p == nil {
			continue
		}
		for _, fi := range p.files {
			w := &walker{a: a, fi: fi}
			for _, decl := range fi.f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Values) != len(vs.Names) {
						continue
					}
					for i, v := range vs.Values {
						e := unparen(v)
						if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
							e = unparen(u.X)
						}
						cl, ok := e.(*ast.CompositeLit)
						if !ok || cl.Type == nil {
							continue
						}
						if w.urfaveFlagType(cl.Type) {
							a.urfaveVars[vs.Names[i].Name] = true
						} else if w.urfaveFlagSlice(cl.Type) {
							a.urfaveLists[vs.Names[i].Name] = true
						}
					}
				}
			}
		}
	}
}

func (a *analysis) omit(reason, detail string) { a.om.add(reason, a.bin, detail) }

func (a *analysis) posKey(p token.Pos) string {
	pos := a.s.fset.Position(p)
	return fmt.Sprintf("%s:%d:%d", pos.Filename, pos.Line, pos.Column)
}

func (a *analysis) modOf(key string) *mod {
	m := a.mods[key]
	if m == nil {
		m = &mod{}
		a.mods[key] = m
	}
	return m
}

// run analyses every package of the set: every function and every
// package-level variable initialiser, without regard to reachability. The
// registrations of the set are the registrations of the binary.
func (a *analysis) run() {
	for _, d := range a.cl.dirs {
		p := a.cl.pkgs[d]
		if p == nil || p.missing {
			continue
		}
		for _, fi := range p.files {
			for _, decl := range fi.f.Decls {
				if err := a.s.ctx.Err(); err != nil {
					a.err = err
					return
				}
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if d.Body != nil {
						a.analyzeFunc(p.decls[d], nil, callCtx{}, 0)
					}
				case *ast.GenDecl:
					if d.Tok == token.VAR {
						a.analyzeVars(fi, d)
					}
				}
			}
		}
	}
	keys := make([]string, 0, len(a.pending))
	for k := range a.pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !a.bound[k] && a.s.g.tripwire {
			a.omit(ReasonDelegatedUnresolved, "receiver")
		}
	}
}

func (a *analysis) analyzeVars(fi *fileInfo, d *ast.GenDecl) {
	fn := &fnInfo{fi: fi, p: fi.pkg, key: fi.path + ":var"}
	w := a.newWalker(fn, callCtx{}, 0)
	for _, spec := range d.Specs {
		ast.Inspect(spec, w.visit)
	}
}

func (a *analysis) analyzeFunc(fn *fnInfo, bound map[string]rk, cc callCtx, depth int) {
	if err := a.s.ctx.Err(); err != nil {
		a.err = err
		return
	}
	w := a.newWalker(fn, cc, depth)
	w.params(bound)
	w.gather(fn.decl.Body)
	ast.Inspect(fn.decl.Body, w.visit)
}

// pkgEnv holds the package-level variables that are provably flag sets.
func (a *analysis) pkgEnv(p *pkg) map[string]*binding {
	if p.envDone {
		return p.env
	}
	p.envDone = true
	p.env = map[string]*binding{}
	for round := 0; round < 3; round++ {
		t := obsTable{}
		for _, fi := range p.files {
			w := &walker{a: a, fi: fi, env: p.env, clauses: map[string]*ast.CallExpr{}}
			for _, decl := range fi.f.Decls {
				if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					for _, spec := range gd.Specs {
						if vs, ok := spec.(*ast.ValueSpec); ok {
							w.noteValueSpec(t, vs)
						}
					}
				}
			}
		}
		next := t.bindings(nil)
		if sameEnv(next, p.env) {
			break
		}
		p.env = next
	}
	return p.env
}

type obs struct {
	kinds   map[rk]bool
	unknown bool
}

type obsTable map[string]*obs

func (t obsTable) note(name string, k rk, known bool) {
	o := t[name]
	if o == nil {
		o = &obs{kinds: map[rk]bool{}}
		t[name] = o
	}
	if known {
		o.kinds[k] = true
	} else {
		o.unknown = true
	}
}

// bindings turns the observations into bindings: tracked when every
// assignment is a recognised flag set of one kind, tainted when it is mixed
// with anything else, absent when none is recognised.
func (t obsTable) bindings(base map[string]*binding) map[string]*binding {
	out := map[string]*binding{}
	for n, b := range base {
		if _, shadowed := t[n]; !shadowed {
			out[n] = b
		}
	}
	for n, o := range t {
		switch {
		case len(o.kinds) == 0:
		case len(o.kinds) == 1 && !o.unknown:
			for k := range o.kinds {
				out[n] = &binding{kind: k}
			}
		default:
			out[n] = &binding{tainted: true}
		}
	}
	return out
}

func sameEnv(a, b map[string]*binding) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w := b[k]; w == nil || *w != *v {
			return false
		}
	}
	return true
}

// litString returns the value of a plain string literal.
func litString(e ast.Expr) (string, bool) {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

var memberRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// memberCharsetRE is the member pattern with upper case admitted, used to
// tell an upper-case name from a name outside the charset.
var memberCharsetRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// MemberCode classifies a registered flag name against the member contract
// and returns "" when it can be a set member. The contract is the exact
// pattern
//
//	^[a-z0-9][a-z0-9._-]{0,127}$
//
// that is: a long name (two or more bytes), at most MaxMemberBytes bytes,
// lower case, from [a-z0-9._-], starting with a letter or digit. It is the
// set-member pattern of the constraint engine
// (^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$) without upper case, which the member
// guard refuses, and without "/", which is the separator of structured
// members and never part of a flag name. A name that fails gives the reason:
//
//	one byte                          FLAG_NAME_NOT_LONG
//	more than 128 bytes               MEMBER_TOO_LONG
//	upper case, otherwise valid       FLAG_NAME_UPPERCASE
//	anything else (including "/")     MEMBER_CHARSET
func MemberCode(name string) string {
	switch {
	case len(name) == 1:
		return ReasonNameNotLong
	case len(name) > MaxMemberBytes:
		return ReasonMemberTooLong
	case memberRE.MatchString(name):
		if !constraintengine.ValidSetMember(name) {
			return ReasonMemberCharset
		}
		return ""
	case memberCharsetRE.MatchString(name):
		return ReasonNameUppercase
	}
	return ReasonMemberCharset
}

func clip(name string) string {
	if len(name) <= maxNameBytes {
		return name
	}
	cut := maxNameBytes
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return name[:cut]
}

// fill turns the collected events into the binary's flags and set.
func (a *analysis) fill(b *Binary) {
	g := a.s.g
	type agg struct {
		idioms        map[string]bool
		hidden, short bool
		reached       bool
		identityCount map[string]int
	}
	var reach map[string]bool
	if g.reach {
		reach = a.reachable()
	}
	byName := map[string]*agg{}
	keys := make([]string, 0, len(a.events))
	for k := range a.events {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ev := a.events[k]
		ag := byName[ev.name]
		if ag == nil {
			ag = &agg{idioms: map[string]bool{}, identityCount: map[string]int{}}
			byName[ev.name] = ag
		}
		ag.idioms[ev.idiom] = true
		m := a.mods[k]
		if ev.hidden || (m != nil && m.hidden) {
			ag.hidden = true
		}
		if ev.shorthand || (m != nil && m.short) {
			ag.short = true
		}
		ag.identityCount[ev.identity]++
		if ev.root || reach[ev.fnKey] {
			ag.reached = true
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	var members []string
	for _, n := range names {
		ag := byName[n]
		f := Flag{Name: clip(n), Hidden: ag.hidden || a.hidden[n], Deprecated: a.deprecated[n], Withheld: []string{}}
		if ag.short && g.shorthand {
			f.Withheld = append(f.Withheld, ReasonHasShorthand)
		}
		if g.negation && ag.idioms[IdiomKingpin] && strings.HasPrefix(n, "no-") {
			f.Withheld = append(f.Withheld, ReasonKingpinNegation)
		}
		if g.reach && !ag.reached {
			f.Withheld = append(f.Withheld, ReasonReachabilityUnproven)
		}
		if g.builtin && (n == "help" || n == "version") {
			f.Withheld = append(f.Withheld, ReasonBuiltinName)
		}
		code := ""
		if g.nameClass {
			code = MemberCode(n)
			if code != "" {
				f.Withheld = append(f.Withheld, code)
			}
		}
		if code == "" {
			members = append(members, n)
		}
		if g.duplicate {
			for _, c := range ag.identityCount {
				if c > 1 {
					a.omit(ReasonDuplicateRegistration, "")
					break
				}
			}
		}
		sort.Strings(f.Withheld)
		b.Flags = append(b.Flags, f)
	}
	if len(members) > constraintengine.MaxSetMembers {
		a.omit(ReasonSetTooLarge, "")
		members = nil
	}
	if members == nil {
		members = []string{}
	}
	b.Set.Members = members
	idioms := map[string]bool{}
	for _, d := range a.cl.dirs {
		p := a.cl.pkgs[d]
		if p == nil {
			continue
		}
		for _, fi := range p.files {
			for _, im := range fi.imports {
				switch im.lib {
				case libStd:
					idioms[IdiomFlag] = true
				case libPflag, libCobra:
					idioms[IdiomPflag] = true
				case libKingpin:
					idioms[IdiomKingpin] = true
				case libUrfave:
					idioms[IdiomUrfave] = true
				}
			}
		}
	}
	for _, ag := range byName {
		for i := range ag.idioms {
			idioms[i] = true
		}
	}
	for i := range idioms {
		b.Idioms = append(b.Idioms, i)
	}
	sort.Strings(b.Idioms)
	switch {
	case idioms[IdiomFlag] || idioms[IdiomUrfave]:
		b.Class = ClassSingleDashLong
	case len(idioms) > 0:
		b.Class = ClassDoubleDash
	}
}

// declaredFuncs is the narrow form (functions, methods, interface methods
// only), kept as the switched-off behaviour of the declAll guard.
func (a *analysis) declaredFuncs(name string) bool {
	for _, d := range a.cl.dirs {
		p := a.cl.pkgs[d]
		if p == nil {
			continue
		}
		if len(p.funcs[name]) > 0 || len(p.methods[name]) > 0 {
			return true
		}
		for _, fi := range p.files {
			found := false
			ast.Inspect(fi.f, func(n ast.Node) bool {
				if it, ok := n.(*ast.InterfaceType); ok {
					for _, m := range it.Methods.List {
						for _, nm := range m.Names {
							found = found || nm.Name == name
						}
					}
				}
				return !found
			})
			if found {
				return true
			}
		}
	}
	return false
}
