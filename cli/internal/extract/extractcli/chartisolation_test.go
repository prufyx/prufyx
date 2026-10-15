// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

const modulePath = "github.com/prufyx/prufyx/cli"

// moduleImports returns the module packages the non-test files of the
// package at importPath import, under every build tag the repository's
// gates build with.
func moduleImports(t *testing.T, importPath string) []string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", filepath.FromSlash(strings.TrimPrefix(importPath, modulePath+"/")))
	seen := map[string]bool{}
	var out []string
	for _, tags := range [][]string{nil, {"parityreview"}} {
		ctx := build.Default
		ctx.BuildTags = tags
		p, err := ctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("%s: %v", importPath, err)
		}
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, modulePath+"/") && !seen[imp] {
				seen[imp] = true
				out = append(out, imp)
			}
		}
	}
	return out
}

// reaches reports whether the package at from depends on target, directly
// or through other module packages (standard and vendored packages cannot
// import this module's internal packages).
func reaches(t *testing.T, from, target string) bool {
	t.Helper()
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if p == target {
			return true
		}
		for _, imp := range moduleImports(t, p) {
			if !seen[imp] {
				seen[imp] = true
				queue = append(queue, imp)
			}
		}
	}
	return false
}

// A code digest covers the framework and the extractor's own package. The
// chart run code (extract/chartrun) is in neither for any extractor that is
// not a chart extractor, so no such extractor, and not the framework, may
// depend on it: otherwise a change there could change what the extractor
// derives without moving its digest. A chart extractor's digest covers the
// framework, chartrun and its own package.
func TestChartRunIsOutsideEveryOtherExtractorsInputs(t *testing.T) {
	chartPkg := modulePath + "/internal/" + chartrun.SourceDir
	if !reaches(t, modulePath+"/internal/extract/extractcli", chartPkg) {
		t.Fatal("the import walk does not see extractcli's use of chartrun")
	}
	if reaches(t, modulePath+"/internal/extract", chartPkg) {
		t.Fatal("the extract framework depends on chartrun")
	}
	fw, err := extract.CodeFiles(extract.FrameworkSource())
	if err != nil {
		t.Fatal(err)
	}
	cr, err := extract.CodeFiles(chartrun.Source())
	if err != nil {
		t.Fatal(err)
	}
	for id, spec := range Catalog() {
		ex := spec.New(1)
		dir, _ := ex.(extract.CodeSource).SourceFiles()
		pkg := modulePath + "/internal/" + dir
		cx, chart := chartrun.Unwrap(ex)
		if !chart {
			if reaches(t, pkg, chartPkg) {
				t.Errorf("%s: %s depends on chartrun, which its code digest does not cover", id, pkg)
			}
			continue
		}
		files, err := chartrun.CodeFiles(cx)
		if err != nil {
			t.Fatal(err)
		}
		covered := map[string]string{}
		for _, f := range files {
			covered[f.Path] = f.SHA256
		}
		for _, f := range append(append([]extract.CodeFile(nil), fw...), cr...) {
			if covered[f.Path] != f.SHA256 {
				t.Errorf("%s: the code digest does not cover %s", id, f.Path)
			}
		}
	}
}
