// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The structs that carry the seam's members. A literal of one of them with
// positional elements writes every member without naming one.
var seamHolders = map[string]bool{"Options": true, "OnboardingAdmissionInput": true}

// seamFields are the members only the seam (or the command line, by name) may
// write.
var seamFields = map[string]bool{"VerifyPr": true, "AdmissionRunner": true, "AdmissionVerifier": true, "SeamRefusals": true,
	"OnboardingAdmissionInProcess": true, "AdmissionEvent": true}

func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return typeName(x.X)
	}
	return ""
}

func importsPath(f *ast.File, suffix string) bool {
	for _, imp := range f.Imports {
		if strings.HasSuffix(strings.Trim(imp.Path.Value, "\""), suffix) {
			return true
		}
	}
	return false
}

// indirectWrites lists the ways, other than a plain keyed literal, an
// assignment, ++/-- or an address-of, in which a file can write a seam member:
// a positional literal of a holder struct, a range target, a dot-import of the
// gate (bare names), a type alias or definition built on a holder, and reflection
// by member name (a literal name of a member, or any non-literal name in a file
// that imports reflect).
func indirectWrites(f *ast.File, gatePath string, fields, holders map[string]bool) []string {
	var out []string
	for _, imp := range f.Imports {
		if imp.Name != nil && imp.Name.Name == "." && strings.HasSuffix(strings.Trim(imp.Path.Value, "\""), gatePath) {
			out = append(out, "dot-import of the gate")
		}
	}
	hasReflect := importsPath(f, "reflect") || importsPath(f, "unsafe")
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if holders[typeName(x.Type)] {
				for _, e := range x.Elts {
					if _, kv := e.(*ast.KeyValueExpr); !kv {
						out = append(out, "positional literal of "+typeName(x.Type))
						break
					}
				}
			}
		case *ast.TypeSpec:
			if holders[typeName(x.Type)] {
				out = append(out, "type "+x.Name.Name+" built on "+typeName(x.Type))
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if sel, ok := e.(*ast.SelectorExpr); ok && fields[sel.Sel.Name] {
					out = append(out, "range target ."+sel.Sel.Name)
				}
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "FieldByName" && sel.Sel.Name != "FieldByNameFunc") || len(x.Args) != 1 {
				return true
			}
			if lit, ok := x.Args[0].(*ast.BasicLit); ok {
				if fields[strings.Trim(lit.Value, "`\"")] {
					out = append(out, "reflection on "+lit.Value)
				}
			} else if hasReflect {
				out = append(out, "reflection by a computed name")
			}
		}
		return true
	})
	return out
}

func parseSrc(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The detector itself: each pattern is found, and a plain read is not.
func TestIndirectWriteDetector(t *testing.T) {
	t.Parallel()
	const gate = "maintainer/knowledgegate"
	cases := []struct {
		name, src, want string
	}{
		{"unkeyed literal", "package p\nvar _ = kg.Options{a, b}\n", "positional literal of Options"},
		{"unkeyed bare literal", "package p\nvar _ = Options{a}\n", "positional literal of Options"},
		{"unkeyed input", "package p\nvar _ = kg.OnboardingAdmissionInput{a}\n", "positional literal of OnboardingAdmissionInput"},
		{"range assign key", "package p\nfunc f() { for o.VerifyPr = range xs {} }\n", "range target .VerifyPr"},
		{"range assign value", "package p\nfunc f() { for _, o.SeamRefusals = range xs {} }\n", "range target .SeamRefusals"},
		{"dot import", "package p\nimport . \"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate\"\n", "dot-import of the gate"},
		{"reflect literal", "package p\nimport \"reflect\"\nfunc f() { reflect.ValueOf(&o).Elem().FieldByName(\"AdmissionRunner\").Set(v) }\n", "reflection on \"AdmissionRunner\""},
		{"reflect raw string", "package p\nfunc f() { v.FieldByName(`VerifyPr`) }\n", "reflection on `VerifyPr`"},
		{"reflect computed", "package p\nimport \"reflect\"\nfunc f() { reflect.ValueOf(&o).Elem().FieldByName(name) }\n", "reflection by a computed name"},
		{"alias of holder", "package p\ntype O = kg.Options\n", "type O built on Options"},
		{"defined type of holder", "package p\ntype O kg.OnboardingAdmissionInput\n", "type O built on OnboardingAdmissionInput"},
	}
	for _, c := range cases {
		got := indirectWrites(parseSrc(t, c.src), gate, seamFields, seamHolders)
		found := false
		for _, g := range got {
			found = found || g == c.want
		}
		if !found {
			t.Errorf("%s: got %v, want %q", c.name, got, c.want)
		}
	}
	for name, src := range map[string]string{
		"keyed literal":       "package p\nvar _ = kg.Options{Base: b}\n",
		"empty literal":       "package p\nvar _ = kg.Options{}\n",
		"plain read":          "package p\nfunc f() { _ = o.VerifyPr }\n",
		"other field reflect": "package p\nfunc f() { v.FieldByName(\"Base\") }\n",
		"named import":        "package p\nimport kg \"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate\"\n",
	} {
		if got := indirectWrites(parseSrc(t, src), gate, seamFields, seamHolders); len(got) != 0 {
			t.Errorf("%s: flagged %v", name, got)
		}
	}
}

// No non-test file of the package writes a seam member in one of those ways.
func TestSeamMembersNotWrittenIndirectlyInPackage(t *testing.T) {
	t.Parallel()
	n := 0
	for name, f := range seamSources(t) {
		n++
		for _, w := range indirectWrites(f, "maintainer/knowledgegate", seamFields, seamHolders) {
			t.Errorf("%s: %s", name, w)
		}
	}
	if n == 0 {
		t.Fatal("no sources scanned")
	}
}
