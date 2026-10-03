// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
)

var versionDirRE = regexp.MustCompile(`^v[0-9]{1,3}((alpha|beta)[0-9]{1,3})?$`)

// removedDecl is one APILifecycleRemoved method: the kind it belongs to, the
// release it returns, and the lines of the method declaration.
type removedDecl struct {
	Kind      string `json:"kind"`
	Major     int    `json:"major"`
	Minor     int    `json:"minor"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

// lifecycleFile is one parsed zz_generated.prerelease-lifecycle.go.
type lifecycleFile struct {
	Path    string        `json:"path"`
	Group   string        `json:"group"`
	Version string        `json:"version"`
	Removed []removedDecl `json:"removed"`
}

const (
	removedFunc  = "APILifecycleRemoved"
	lifecyclePkg = "zz_generated.prerelease-lifecycle.go"
)

// parseLifecycle parses one generated lifecycle file with go/parser; nothing
// is compiled or executed. Every APILifecycleRemoved method must be the
// generated shape, a method on a pointer receiver returning two integer
// literals; anything else is an error, so a file is either understood
// completely or not at all.
func parseLifecycle(path, version string, src []byte) ([]removedDecl, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Name.Name != version {
		return nil, fmt.Errorf("%s: package %s is not the version directory %s", path, f.Name.Name, version)
	}
	var out []removedDecl
	seen := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name.Name != removedFunc {
			continue
		}
		bad := func(why string) error {
			return fmt.Errorf("%s:%d: %s is not the generated form: %s", path, fset.Position(fd.Pos()).Line, removedFunc, why)
		}
		if len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
			return nil, bad("receiver")
		}
		star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			return nil, bad("receiver is not a pointer")
		}
		kind, ok := star.X.(*ast.Ident)
		if !ok {
			return nil, bad("receiver type")
		}
		if fd.Type.Params.NumFields() != 0 || fd.Type.Results.NumFields() != 2 {
			return nil, bad("signature")
		}
		if fd.Body == nil || len(fd.Body.List) != 1 {
			return nil, bad("body")
		}
		ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 2 {
			return nil, bad("body is not a two-value return")
		}
		var nums [2]int
		for i, e := range ret.Results {
			lit, ok := e.(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				return nil, bad("returned values are not integer literals")
			}
			n, err := strconv.Atoi(lit.Value)
			if err != nil || n < 0 {
				return nil, bad("returned value")
			}
			nums[i] = n
		}
		if seen[kind.Name] {
			return nil, bad("duplicate method for " + kind.Name)
		}
		seen[kind.Name] = true
		out = append(out, removedDecl{Kind: kind.Name, Major: nums[0], Minor: nums[1], StartLine: fset.Position(fd.Pos()).Line, EndLine: fset.Position(fd.End()).Line})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out, nil
}

// parseGroupName returns the string literal assigned to the package-level
// constant GroupName in a register.go.
func parseGroupName(path string, src []byte) (string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if n.Name != "GroupName" {
					continue
				}
				if i >= len(vs.Values) {
					return "", fmt.Errorf("%s: GroupName has no value", path)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", fmt.Errorf("%s: GroupName is not a string literal", path)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					return "", fmt.Errorf("%s: GroupName: %w", path, err)
				}
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("%s: no GroupName constant", path)
}

// gvk is a group/version/kind as the OpenAPI specification names it.
type gvk struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

func (g gvk) String() string {
	if g.Group == "" {
		return g.Version + "/" + g.Kind
	}
	return g.Group + "/" + g.Version + "/" + g.Kind
}

func gvkLess(a, b gvk) bool {
	if a.Group != b.Group {
		return a.Group < b.Group
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Kind < b.Kind
}

// parseSpec returns the set of group/version/kinds the swagger document
// declares through x-kubernetes-group-version-kind. An empty set is an
// error: a specification that declares nothing proves no absence.
func parseSpec(path string, src []byte) (map[gvk]bool, error) {
	var doc struct {
		Swagger     string `json:"swagger"`
		Definitions map[string]struct {
			GVK []gvk `json:"x-kubernetes-group-version-kind"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[gvk]bool{}
	for _, d := range doc.Definitions {
		for _, g := range d.GVK {
			if g.Version == "" || g.Kind == "" {
				return nil, fmt.Errorf("%s: incomplete group-version-kind %+v", path, g)
			}
			out[g] = true
		}
	}
	if doc.Swagger == "" || len(out) == 0 {
		return nil, fmt.Errorf("%s: not a Kubernetes OpenAPI specification declaring kinds (%d)", path, len(out))
	}
	return out, nil
}
