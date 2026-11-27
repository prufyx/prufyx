// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// registerVerbRE matches the method names that register a flag in the standard
// library and pflag.
var registerVerbRE = regexp.MustCompile(`^(Var|VarP|VarPF|Func|BoolFunc|TextVar|(Bool|BoolSlice|BytesBase64|BytesHex|Count|Duration|DurationSlice|Float32|Float32Slice|Float64|Float64Slice|IP|IPMask|IPNet|IPSlice|Int|Int16|Int32|Int32Slice|Int64|Int64Slice|Int8|IntSlice|String|StringArray|StringSlice|StringToInt|StringToInt64|StringToString|Uint|Uint16|Uint32|Uint64|Uint8|UintSlice)(Var)?P?)$`)

// registrations finds, per name, the calls in the files that register it with a
// string literal.
func registrations(files []sourceFile, names []string) map[string][]Site {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string][]Site{}
	for _, sf := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, sf.path, sf.data, 0)
		if err != nil {
			continue // no site: the name is then refused as not found
		}
		digest := sha256.Sum256(sf.data)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !registerVerbRE.MatchString(sel.Sel.Name) {
				return true
			}
			// The name is the first or second argument.
			for i := 0; i < len(call.Args) && i < 2; i++ {
				lit, ok := call.Args[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(lit.Value)
				if err == nil && want[v] {
					out[v] = append(out[v], Site{Path: sf.path, Line: fset.Position(lit.Pos()).Line, SHA256: hex.EncodeToString(digest[:])})
				}
				break
			}
			return true
		})
	}
	return out
}

// tolerantMarkers are identifiers that let a parser accept an unknown flag.
var tolerantMarkers = map[string]bool{
	"UnknownFlags": true, "ParseErrorsWhitelist": true, "ParseErrorsAllowlist": true,
	"FParseErrWhitelist": true, "DisableFlagParsing": true, "IgnoreUnknownFlags": true,
	"IgnoreUnknown": true, "SkipFlagParsing": true,
}

// unresolvedParsers are libraries whose parse sites this check cannot resolve.
var unresolvedParsers = []string{
	"github.com/spf13/cobra", "github.com/alecthomas/kingpin", "gopkg.in/alecthomas/kingpin",
	"github.com/urfave/cli", "gopkg.in/urfave/cli", "github.com/alecthomas/kong",
	"github.com/jessevdk/go-flags", "github.com/peterbourgon/ff",
}

// checkParser requires, over the files of the tree the binary imports, that the
// only parser is the standard library or pflag command line, parsed in the
// binary directory, with no marker of a tolerant parser. A flag set can be made
// to continue after an unknown flag by Init, or be built so that it does (the
// zero value), so both are refused, as is any use of CommandLine other than a
// direct method call on it: an alias hides the later calls. Anything it cannot
// resolve is a refusal.
func checkParser(files []sourceFile, binary string) []problem {
	var out []problem
	resolved := false
	for _, sf := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, sf.path, sf.data, 0)
		if err != nil {
			out = append(out, problem{CodeParserUnresolved, "unparsable: " + sf.path})
			continue
		}
		at := func(p token.Pos) string { return sf.path + ":" + strconv.Itoa(fset.Position(p).Line) }
		unresolved := func(p token.Pos, why string) {
			out = append(out, problem{CodeParserUnresolved, at(p) + " " + why})
		}
		libs := map[string]bool{} // local names of flag and pflag
		for _, im := range f.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				unresolved(im.Pos(), "import")
				continue
			}
			for _, root := range unresolvedParsers {
				if p == root || strings.HasPrefix(p, root+"/") || strings.HasPrefix(p, root+".") {
					unresolved(im.Pos(), "imports "+p)
				}
			}
			if p != "flag" && p != "github.com/spf13/pflag" {
				continue
			}
			name := path.Base(p)
			if im.Name != nil {
				name = im.Name.Name
			}
			if name == "." {
				unresolved(im.Pos(), "dot import of a flag library")
				continue
			}
			libs[name] = true
		}
		isLib := func(e ast.Expr) bool {
			id, ok := e.(*ast.Ident)
			return ok && libs[id.Name]
		}
		commandLine := func(e ast.Expr) bool {
			s, ok := e.(*ast.SelectorExpr)
			return ok && s.Sel.Name == "CommandLine" && isLib(s.X)
		}
		flagSetType := func(e ast.Expr) bool {
			s, ok := e.(*ast.SelectorExpr)
			return ok && s.Sel.Name == "FlagSet" && isLib(s.X)
		}
		// calls are the selectors that are called directly; allowed are the
		// CommandLine and FlagSet selectors in a permitted position. A parent
		// is visited before its children.
		calls := map[*ast.SelectorExpr]bool{}
		allowed := map[ast.Expr]bool{}
		// pointer permits a *FlagSet that is the whole type of a parameter,
		// result, field or variable. Anywhere else (a slice or map element, a
		// type argument, an alias) an elided literal could build a zero value.
		pointer := func(t ast.Expr) {
			if star, ok := t.(*ast.StarExpr); ok && flagSetType(star.X) {
				allowed[star.X] = true
			}
		}
		fields := func(lists ...*ast.FieldList) {
			for _, l := range lists {
				if l == nil {
					continue
				}
				for _, fd := range l.List {
					pointer(fd.Type)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if tolerantMarkers[x.Name] {
					out = append(out, problem{CodeParserTolerant, at(x.Pos()) + " " + x.Name})
				}
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if commandLine(l) {
						unresolved(l.Pos(), "CommandLine is replaced")
					}
				}
			case *ast.FuncType:
				fields(x.Params, x.Results)
			case *ast.StructType:
				fields(x.Fields)
			case *ast.ValueSpec:
				pointer(x.Type)
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				calls[sel] = true
				if commandLine(sel.X) {
					allowed[sel.X] = true
				}
				switch sel.Sel.Name {
				case "NewFlagSet":
					strict := false
					if len(x.Args) == 2 {
						if mode, ok := x.Args[1].(*ast.SelectorExpr); ok && isLib(mode.X) && (mode.Sel.Name == "ExitOnError" || mode.Sel.Name == "PanicOnError") {
							strict = true
						}
					}
					if !strict {
						unresolved(x.Pos(), "flag set that does not exit on a parse error")
					}
				case "ParseFlags", "ParseAll", "ParseKnownFlags":
					unresolved(x.Pos(), sel.Sel.Name)
				case "Init":
					// Without types any Init with arguments may be a flag
					// set's: two, three as a method expression, or one call
					// returning both.
					if len(x.Args) > 0 {
						unresolved(x.Pos(), "Init may re-initialise a flag set")
					}
				case "Parse":
					if (isLib(sel.X) && len(x.Args) == 0) || commandLine(sel.X) {
						if sf.dir == binary {
							resolved = true
						}
					}
				}
			case *ast.SelectorExpr:
				if (x.Sel.Name == "NewFlagSet" || x.Sel.Name == "Init") && !calls[x] {
					unresolved(x.Pos(), x.Sel.Name+" used as a value")
				}
				if commandLine(x) && !allowed[x] {
					unresolved(x.Pos(), "CommandLine used as a value")
				}
				if flagSetType(x) && !allowed[x] {
					unresolved(x.Pos(), "FlagSet used other than as a plain pointer type")
				}
				// (*flag.FlagSet).Init and the like.
				if star, ok := ast.Unparen(x.X).(*ast.StarExpr); ok && flagSetType(star.X) {
					unresolved(x.Pos(), "method expression of a flag set")
				}
			}
			return true
		})
	}
	if !resolved {
		out = append(out, problem{CodeParserUnresolved, "no command line parse resolved in " + binary})
	}
	return out
}
