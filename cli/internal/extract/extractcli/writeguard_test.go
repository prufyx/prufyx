// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// SEC-B B-m2: extract.Output.Write follows symlinks, depends on the umask and
// writes in place. Its source is part of every extractor's code digest, so it
// stays until the next digest bump, but nothing outside tests may call it:
// output goes through Output.Files() and safefs.WriteTree.

// outputWriteCalls returns the positions of `v.Write(...)` calls where v is a
// variable assigned from a call to Run (extract.Run, or Run inside package
// extract), i.e. holds an *extract.Output.
func outputWriteCalls(fset *token.FileSet, f *ast.File) []token.Pos {
	isRun := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch fn := c.Fun.(type) {
		case *ast.Ident:
			return f.Name.Name == "extract" && fn.Name == "Run"
		case *ast.SelectorExpr:
			x, ok := fn.X.(*ast.Ident)
			return ok && x.Name == "extract" && fn.Sel.Name == "Run"
		}
		return false
	}
	holders := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch a := n.(type) {
		case *ast.AssignStmt:
			if len(a.Rhs) == 1 && isRun(a.Rhs[0]) {
				if id, ok := a.Lhs[0].(*ast.Ident); ok {
					holders[id.Name] = true
				}
			}
		case *ast.ValueSpec:
			if len(a.Values) == 1 && isRun(a.Values[0]) {
				holders[a.Names[0].Name] = true
			}
		}
		return true
	})
	var out []token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Write" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && holders[id.Name] {
			out = append(out, c.Pos())
		}
		// extract.Run(...).Write(...)
		if isRun(sel.X) {
			out = append(out, c.Pos())
		}
		return true
	})
	return out
}

func TestOutputWriteNotCalledOutsideTests(t *testing.T) {
	root := filepath.Join("..", "..", "..") // the cli module
	fset := token.NewFileSet()
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") && d.Name() != "." && d.Name() != ".." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		scanned++
		for _, pos := range outputWriteCalls(fset, f) {
			t.Errorf("%s calls the unsafe extract.Output.Write; use Output.Files() with safefs.WriteTree", fset.Position(pos))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("only %d files scanned; the module root is wrong", scanned)
	}
}

// The scanner must actually see the call shapes it guards against.
func TestOutputWriteScannerDetects(t *testing.T) {
	src := `package x
import "example/extract"
func f() {
	out, _ := extract.Run(nil, nil, nil, nil, extract.Options{})
	_ = out.Write("d")
	extract.Run(nil, nil, nil, nil, extract.Options{}).Write("d")
	var w interface{ Write(string) error }
	_ = w.Write("d")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(outputWriteCalls(fset, f)); got != 2 {
		t.Fatalf("found %d calls, want 2", got)
	}
}
