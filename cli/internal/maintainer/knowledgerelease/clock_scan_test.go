// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExpiredPackageIsRefusedAtTheWallClockDefault is date independent: a
// correctly signed package built at a clock far in the past is expired for the
// real clock now and forever, so the zero (default) verify clock must refuse it
// while a clock inside its validity accepts it.
func TestExpiredPackageIsRefusedAtTheWallClockDefault(t *testing.T) {
	o := projectsFixture(t)
	o.Now = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(o.OutputDir, "cncf-projects-91.tar")
	if _, err := InspectLiveAt(pkg, o.Root, o.RootDigest, ProfileCNCFProjects, r.PackageDigest, o.Now.Add(time.Hour)); err != nil {
		t.Fatalf("control: the package must verify inside its validity: %v", err)
	}
	if _, err := InspectLive(pkg, o.Root, o.RootDigest, ProfileCNCFProjects, r.PackageDigest); err == nil {
		t.Fatal("an expired package must be refused by the default (wall clock) verify")
	}
	if _, err := InspectLiveAt(pkg, o.Root, o.RootDigest, ProfileCNCFProjects, r.PackageDigest, time.Time{}); err == nil {
		t.Fatal("a zero clock must be the wall clock and refuse the expired package")
	}
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b strings.Builder
	_ = printer.Fprint(&b, fset, e)
	return b.String()
}

const wallDefault = "time.Now().UTC()"

var clockedTypes = map[string]bool{"Options": true, "RefreshOptions": true, "VerifyRequest": true, "FinalizePackageOptions": true}
var seamPackages = map[string]bool{"knowledgerelease": true, "knowledgepublish": true, "knowledge": true}

// clockViolations scans every non-test Go file under root (a cli directory)
// for a Now key in a composite literal of a clocked type, or an assignment to a
// .Now field in a file that imports a seam package. Only the CLI may set the
// wall clock; the seam packages and communityapp/knowledge.go may forward.
func clockViolations(t *testing.T, root string) (violations []string, seen map[string]int) {
	t.Helper()
	forwarded := map[string]bool{"now": true, "o.Now": true, "opts.Now": true, "req.Now": true}
	seen = map[string]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		inCmd := strings.HasPrefix(rel, "cmd/prufyx-maintainer/")
		inRelease := strings.HasPrefix(rel, "internal/maintainer/knowledgerelease/")
		inSeam := inRelease || strings.HasPrefix(rel, "internal/maintainer/knowledgepublish/") || strings.HasPrefix(rel, "internal/knowledge/")
		forwarder := inSeam || rel == "internal/communityapp/knowledge.go"
		importsSeam := inSeam
		for _, imp := range file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if i := strings.LastIndex(p, "/"); i >= 0 && seamPackages[p[i+1:]] {
				importsSeam = true
			}
		}
		bad := func(format string, a ...any) { violations = append(violations, rel+": "+fmt.Sprintf(format, a...)) }
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				name, qualified := "", false
				switch tt := x.Type.(type) {
				case *ast.Ident:
					name = tt.Name
				case *ast.SelectorExpr:
					if pkg, ok := tt.X.(*ast.Ident); ok && seamPackages[pkg.Name] {
						name, qualified = tt.Sel.Name, true
					}
				}
				if !clockedTypes[name] || !qualified && !inSeam {
					return true
				}
				for _, el := range x.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Now" {
						v := exprString(fset, kv.Value)
						if inCmd && v == wallDefault || forwarder && forwarded[v] {
							seen[rel+" literal"]++
						} else {
							bad("%s literal sets Now: %s", name, v)
						}
					}
				}
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					sel, ok := l.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Now" || !importsSeam {
						continue
					}
					v := ""
					if i < len(x.Rhs) {
						v = exprString(fset, x.Rhs[i])
					}
					if inCmd && v == wallDefault {
						seen[rel+" assign"]++
					} else {
						bad("assignment .Now = %s", v)
					}
				}
			case *ast.CallExpr:
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Now" && exprString(fset, sel.X) == "time" &&
					(inRelease || rel == "internal/knowledge/verify.go") {
					bad("reads the wall clock directly (time.Now)")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return violations, seen
}

// TestOnlyTheProductionDefaultSetsTheClock pins the seam over the whole cli
// tree: only the CLI default (the wall clock) and forwarding inside the seam
// packages set a clock; the release package never reads the wall clock.
func TestOnlyTheProductionDefaultSetsTheClock(t *testing.T) {
	violations, seen := clockViolations(t, filepath.Join("..", "..", ".."))
	for _, v := range violations {
		t.Error(v)
	}
	if seen["cmd/prufyx-maintainer/knowledge_publish.go assign"] < 2 {
		t.Fatalf("CLI default wiring not found: %v", seen)
	}
	if seen["internal/maintainer/knowledgerelease/live.go literal"] != 1 || seen["internal/maintainer/knowledgerelease/knowledgerelease.go literal"] != 1 {
		t.Fatalf("clock forwarding not found: %v", seen)
	}
}

// TestClockScanDetectsPlantedViolations proves the scan is not vacuous.
func TestClockScanDetectsPlantedViolations(t *testing.T) {
	const mod = "github.com/prufyx/prufyx/cli/internal/"
	cases := map[string]string{
		"internal/other/a.go":                       "package other\nimport \"time\"\nimport \"" + mod + "knowledge\"\nvar _ = knowledge.VerifyRequest{Now: time.Unix(1, 0)}\n",
		"internal/other/b.go":                       "package other\nimport \"" + mod + "maintainer/knowledgerelease\"\nfunc f() { var o knowledgerelease.Options; o.Now = fixed() }\n",
		"internal/other/c.go":                       "package other\nimport \"" + mod + "maintainer/knowledgepublish\"\nvar _ = knowledgepublish.FinalizePackageOptions{Now: x}\n",
		"cmd/prufyx-maintainer/d.go":                "package main\nimport \"" + mod + "maintainer/knowledgerelease\"\nvar _ = knowledgerelease.RefreshOptions{Now: fixed}\n",
		"internal/knowledge/e.go":                   "package knowledge\nvar _ = VerifyRequest{Now: fixed}\n",
		"internal/maintainer/knowledgerelease/f.go": "package knowledgerelease\nimport \"time\"\nvar _ = time.Now()\n",
	}
	for rel, src := range cases {
		dir := t.TempDir()
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if v, _ := clockViolations(t, dir); len(v) == 0 {
			t.Errorf("planted violation in %s was not detected", rel)
		}
	}
}
