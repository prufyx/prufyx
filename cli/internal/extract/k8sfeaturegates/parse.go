// SPDX-License-Identifier: AGPL-3.0-only

package k8sfeaturegates

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// Import paths whose Feature type names a feature gate.
const (
	featuregatePath     = "k8s.io/component-base/featuregate"
	clientFeaturesPath  = "k8s.io/client-go/features"
	unrecognizedGateMsg = "unrecognized feature gate"
)

// Reference kinds of an expression that should evaluate to a gate name.
const (
	refLiteral  = "literal"  // a string literal
	refLocal    = "local"    // an identifier: a package-level name, or a local variable
	refSelector = "selector" // pkg.Name
	refOther    = "other"    // anything else: not resolvable statically
)

// exprRef is a gate-name expression reduced to what resolution needs.
// Conversions such as featuregate.Feature(x) or string(x) are unwrapped.
type exprRef struct {
	Kind  string
	Value string // literal value, identifier, or selected name
	Pkg   string // local import name for a selector
	// Dynamic marks an identifier that names a function parameter or a
	// variable declared inside a function body: its value flows in at run
	// time and is not a declaration.
	Dynamic bool
}

type constDecl struct {
	Ref  exprRef
	Line int
	// Feature marks a constant declared with a feature-gate type.
	Feature bool
}

type mapKey struct {
	Ref  exprRef
	Line int
}

type importSpec struct {
	Name string // explicit alias, "" when none
	Path string
}

// fileSummary is everything the registry needs from one Go file. It
// depends only on the file's bytes, so it is cached by blob id.
type fileSummary struct {
	Package string
	Imports []importSpec
	// Consts holds package-level constants and variables by name.
	Consts map[string]constDecl
	// Keys are the keys of every feature-spec map literal in the file.
	Keys []mapKey
	// Literals are gate names spelled as conversions of a string literal to
	// a feature-gate type anywhere in the file.
	Literals []string
	// ErrorLines are the lines of string literals that contain the
	// unrecognised-gate error text.
	ErrorLines []int
	// ParseError is set when the file does not parse.
	ParseError string
}

// summarize parses one Go file.
func summarize(name string, src []byte) *fileSummary {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return &fileSummary{ParseError: firstLine(err.Error())}
	}
	s := &fileSummary{Package: file.Name.Name, Consts: map[string]constDecl{}}
	featureImports := map[string]bool{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return &fileSummary{ParseError: "import path"}
		}
		spec := importSpec{Path: p}
		if imp.Name != nil {
			spec.Name = imp.Name.Name
		}
		s.Imports = append(s.Imports, spec)
		if p == featuregatePath || p == clientFeaturesPath {
			local := spec.Name
			if local == "" {
				local = lastElem(p)
			}
			featureImports[local] = true
		}
	}
	isFeatureType := func(e ast.Expr) bool {
		switch t := e.(type) {
		case *ast.Ident:
			return t.Name == "Feature"
		case *ast.SelectorExpr:
			x, ok := t.X.(*ast.Ident)
			return ok && t.Sel.Name == "Feature" && featureImports[x.Name]
		}
		return false
	}
	isSpecType := func(e ast.Expr) bool {
		var name string
		switch t := e.(type) {
		case *ast.Ident:
			name = t.Name
		case *ast.SelectorExpr:
			name = t.Sel.Name
		}
		return name == "FeatureSpec" || name == "VersionedSpecs"
	}
	// Package-level declarations.
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			typed := vs.Type != nil && isFeatureType(vs.Type)
			for i, n := range vs.Names {
				d := constDecl{Line: fset.Position(n.Pos()).Line, Feature: typed}
				if i < len(vs.Values) {
					d.Ref = refOf(vs.Values[i], nil)
					if call, ok := vs.Values[i].(*ast.CallExpr); ok && len(call.Args) == 1 && isFeatureType(call.Fun) {
						d.Feature = true
					}
				} else {
					// Implicit repetition (iota style) or a declaration
					// without a value: never a resolvable gate name.
					d.Ref = exprRef{Kind: refOther}
				}
				if _, dup := s.Consts[n.Name]; dup {
					d.Ref = exprRef{Kind: refOther}
				}
				s.Consts[n.Name] = d
			}
		}
	}
	// Feature-spec map literals, conversions and error strings anywhere.
	var scopes []map[string]bool
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			// Leaving the node on top of the stack.
			switch stack[len(stack)-1].(type) {
			case *ast.FuncDecl, *ast.FuncLit:
				scopes = scopes[:len(scopes)-1]
			}
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.FuncDecl:
			scopes = append(scopes, localNames(x.Recv, x.Type, x.Body))
		case *ast.FuncLit:
			scopes = append(scopes, localNames(nil, x.Type, x.Body))
		case *ast.CompositeLit:
			mt, ok := x.Type.(*ast.MapType)
			if !ok || !isFeatureType(mt.Key) || !isSpecType(mt.Value) {
				return true
			}
			for _, elt := range x.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					s.Keys = append(s.Keys, mapKey{Ref: exprRef{Kind: refOther}, Line: fset.Position(elt.Pos()).Line})
					continue
				}
				s.Keys = append(s.Keys, mapKey{Ref: refOf(kv.Key, scopes), Line: fset.Position(kv.Key.Pos()).Line})
			}
		case *ast.CallExpr:
			if len(x.Args) == 1 && isFeatureType(x.Fun) {
				if lit, ok := x.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						s.Literals = append(s.Literals, v)
					}
				}
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if v, err := strconv.Unquote(x.Value); err == nil && strings.Contains(v, unrecognizedGateMsg) {
					s.ErrorLines = append(s.ErrorLines, fset.Position(x.Pos()).Line)
				}
			}
		}
		return true
	})
	return s
}

// localNames collects the parameter, receiver, result and body-declared
// variable names of a function. Shadowing is resolved conservatively: a
// name declared anywhere in the function counts as local throughout it.
func localNames(recv *ast.FieldList, typ *ast.FuncType, body *ast.BlockStmt) map[string]bool {
	names := map[string]bool{}
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				names[n.Name] = true
			}
		}
	}
	addFields(recv)
	if typ != nil {
		addFields(typ.Params)
		addFields(typ.Results)
	}
	if body != nil {
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if x.Tok == token.DEFINE {
					for _, l := range x.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							names[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for _, id := range x.Names {
					names[id.Name] = true
				}
			case *ast.RangeStmt:
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if id, ok := e.(*ast.Ident); ok {
						names[id.Name] = true
					}
				}
			}
			return true
		})
	}
	return names
}

// refOf reduces a gate-name expression. scopes are the enclosing
// functions' local names (innermost last).
func refOf(e ast.Expr, scopes []map[string]bool) exprRef {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.CallExpr:
			// A conversion T(x): one argument, a type-like function.
			if len(x.Args) == 1 && x.Ellipsis == token.NoPos {
				switch f := x.Fun.(type) {
				case *ast.Ident:
					if f.Name == "Feature" || f.Name == "string" {
						e = x.Args[0]
						continue
					}
				case *ast.SelectorExpr:
					if f.Sel.Name == "Feature" {
						e = x.Args[0]
						continue
					}
				}
			}
			return exprRef{Kind: refOther}
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return exprRef{Kind: refOther}
			}
			v, err := strconv.Unquote(x.Value)
			if err != nil {
				return exprRef{Kind: refOther}
			}
			return exprRef{Kind: refLiteral, Value: v}
		case *ast.Ident:
			dynamic := false
			for _, s := range scopes {
				if s[x.Name] {
					dynamic = true
				}
			}
			return exprRef{Kind: refLocal, Value: x.Name, Dynamic: dynamic}
		case *ast.SelectorExpr:
			pkg, ok := x.X.(*ast.Ident)
			if !ok {
				return exprRef{Kind: refOther}
			}
			for _, s := range scopes {
				if s[pkg.Name] {
					// A field of a local value, not a package selector.
					return exprRef{Kind: refOther, Dynamic: true}
				}
			}
			return exprRef{Kind: refSelector, Pkg: pkg.Name, Value: x.Sel.Name}
		default:
			return exprRef{Kind: refOther}
		}
	}
}

func lastElem(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
