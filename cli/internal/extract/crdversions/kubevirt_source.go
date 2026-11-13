// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const kubevirtProfile = "kubevirt-v1"
const kvComponents = "pkg/virt-operator/resource/generate/components"
const kvInstall = "pkg/virt-operator/resource/generate/install"
const kvAPI = "staging/src/kubevirt.io/api"
const kvClient = "staging/src/kubevirt.io/client-go"
const kvConstructors = kvComponents + "/crds.go"

// SourceGrant binds reviewed constructor semantics and dependency routing to
// exact source trees. A release with different inputs cannot use the grant.
type SourceGrant struct {
	Files         []SourceFilePin `json:"files"`
	Trees         []SourceTreePin `json:"trees"`
	AbsentForeign []string        `json:"absentForeign,omitempty"`
}
type SourceFilePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type SourceTreePin struct {
	Path string `json:"path"`
	SHA1 string `json:"sha1"`
}

var kvTrees = []string{kvComponents, kvInstall, "pkg", "tools", "cmd", kvAPI, kvClient, "vendor", "kubevirtci"}
var kvRouting = []string{"go.mod", "go.sum", "go.work", "go.work.sum", kvAPI + "/go.mod", kvAPI + "/go.sum", kvClient + "/go.mod", kvClient + "/go.sum", "vendor/modules.txt"}
var kvPinnedFiles = append(append([]string{}, kvRouting...), kvConstructors, kvComponents+"/virttemplate.go", kvInstall+"/strategy.go")

func validateConstructorProfile(t Target) error {
	if t.ConstructorProfile == "" {
		if len(t.SourceGrants) != 0 {
			return fmt.Errorf("source grants need a constructor profile")
		}
		return nil
	}
	if t.ConstructorProfile != kubevirtProfile || t.Project != "kubevirt" || t.Repo != "github.com/kubevirt/kubevirt" || t.Catalog != CatalogCNCF || t.Component != "pkg:github/kubevirt/kubevirt" || t.FactProject != "kubevirt" || len(t.SourceGrants) == 0 || len(t.SourceGrants) > 64 {
		return fmt.Errorf("unsupported constructor profile or identity")
	}
	for _, g := range t.SourceGrants {
		if len(g.AbsentForeign) > 64 {
			return fmt.Errorf("too many absent foreign paths")
		}
		for i, p := range g.AbsentForeign {
			if !cleanRepoPath(p) || strings.ContainsAny(p, globMeta) || (!strings.HasPrefix(p, "kubevirtci/") && !strings.HasPrefix(p, "vendor/")) || (i > 0 && g.AbsentForeign[i-1] >= p) {
				return fmt.Errorf("invalid absent foreign path %s", p)
			}
		}
		if len(g.Trees) != len(kvTrees) || len(g.Files) != len(kvPinnedFiles) {
			return fmt.Errorf("constructor grant must bind every fixed tree and routing input")
		}
		seen := map[string]bool{}
		for _, p := range g.Trees {
			if !slicesContains(kvTrees, p.Path) || seen[p.Path] || !extract.IsCommitSHA(p.SHA1) {
				return fmt.Errorf("invalid constructor tree pin %s", p.Path)
			}
			seen[p.Path] = true
		}
		seen = map[string]bool{}
		for _, p := range g.Files {
			if !slicesContains(kvPinnedFiles, p.Path) || seen[p.Path] || (p.SHA256 != "absent" && !sha256DigRE.MatchString(p.SHA256)) {
				return fmt.Errorf("invalid routing pin %s", p.Path)
			}
			if p.SHA256 == "absent" && !slicesContains(kvRouting, p.Path) {
				return fmt.Errorf("mandatory constructor source %s absent", p.Path)
			}
			seen[p.Path] = true
		}
	}
	return nil
}

func validateProfileJSON(raw []byte) error {
	_, values, err := decodeStrict(raw)
	if err != nil || len(values) != 1 {
		return fmt.Errorf("constructor target has duplicate or malformed fields")
	}
	root, ok := values[0].(map[string]any)
	if !ok {
		return fmt.Errorf("constructor target is not an object")
	}
	target, ok := root["target"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing exact target member")
	}
	for key := range target {
		if (strings.EqualFold(key, "constructorProfile") && key != "constructorProfile") || (strings.EqualFold(key, "sourceGrants") && key != "sourceGrants") {
			return fmt.Errorf("constructor members require exact spelling")
		}
	}
	grants, ok := target["sourceGrants"].([]any)
	if !ok {
		return fmt.Errorf("missing exact sourceGrants array")
	}
	for _, g := range grants {
		m, ok := g.(map[string]any)
		if !ok || (len(m) != 2 && len(m) != 3) || (len(m) == 3 && m["absentForeign"] == nil) {
			return fmt.Errorf("invalid source grant fields")
		}
		for _, kind := range []string{"files", "trees"} {
			rows, ok := m[kind].([]any)
			if !ok {
				return fmt.Errorf("invalid source grant %s", kind)
			}
			for _, row := range rows {
				p, ok := row.(map[string]any)
				digest := "sha256"
				if kind == "trees" {
					digest = "sha1"
				}
				if !ok || len(p) != 2 || p["path"] == nil || p[digest] == nil {
					return fmt.Errorf("invalid source pin fields")
				}
			}
		}
	}
	return nil
}

func kvEntry(r extract.PinnedReader, repo extract.RepoRef, c, p string) (extract.TreeEntry, error) {
	dir := path.Dir(p)
	if dir == "." {
		dir = ""
	}
	es, err := r.List(repo, c, dir)
	if err != nil {
		return extract.TreeEntry{}, err
	}
	for _, e := range es {
		if e.Path == p {
			return e, nil
		}
	}
	return extract.TreeEntry{}, extract.ErrNotFound
}

// kvGrant checks every routing input, including nonexistence. It never consults
// the process's workspace, module cache, environment or filesystem.
func kvGrant(r extract.PinnedReader, repo extract.RepoRef, c string, t Target) error {
	return kvCheckGrant(r, repo, c, t, nil)
}

func kvCheckGrant(r extract.PinnedReader, repo extract.RepoRef, c string, t Target, selected **SourceGrant) error {
	treeIDs := map[string]string{}
	for _, p := range kvTrees {
		e, err := kvEntry(r, repo, c, p)
		if err != nil {
			return problemf("constructor tree %s unavailable: %v", p, err)
		}
		if e.Type != "tree" || e.Mode != "040000" {
			return problemf("constructor tree %s is not regular", p)
		}
		treeIDs[p] = e.SHA
	}
	routing := map[string][]byte{}
	digests := map[string]string{}
	for _, p := range kvPinnedFiles {
		e, err := kvEntry(r, repo, c, p)
		if isNotFound(err) {
			if !slicesContains(kvRouting, p) {
				return problemf("mandatory constructor source %s is missing", p)
			}
			digests[p] = "absent"
			continue
		}
		if err != nil {
			return err
		}
		if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
			return problemf("routing input %s is not a regular file", p)
		}
		b, err := r.Read(repo, c, p)
		if err != nil {
			return err
		}
		if len(b) > MaxFileBytes {
			return problemf("oversized routing input %s", p)
		}
		sum := sha256.Sum256(b)
		digests[p] = "sha256:" + hex.EncodeToString(sum[:])
		routing[p] = b
	}
	matched := false
	var absent []string
	for i, g := range t.SourceGrants {
		ok := true
		for _, p := range g.Trees {
			ok = ok && treeIDs[p.Path] == p.SHA1
		}
		for _, p := range g.Files {
			ok = ok && digests[p.Path] == p.SHA256
		}
		if ok {
			matched = true
			absent = g.AbsentForeign
			if selected != nil {
				*selected = &t.SourceGrants[i]
			}
			break
		}
	}
	if !matched {
		return problemf("no reviewed constructor/routing source grant for %s", c)
	}
	for _, p := range absent {
		_, err := kvEntry(r, repo, c, p)
		if err == nil {
			return problemf("foreign absence grant names an existing path %s", p)
		}
		if !isNotFound(err) {
			return err
		}
	}
	// Every local module route must resolve inside the two granted staged modules.
	for _, base := range []string{"", kvAPI, kvClient} {
		p := path.Join(base, "go.mod")
		b := routing[p]
		if len(b) == 0 {
			return problemf("missing module routing %s", p)
		}
		m, err := kvParseRouting(b)
		if err != nil || m.module == "" {
			return problemf("invalid module routing %s", p)
		}
		expected := "kubevirt.io/kubevirt"
		if base == kvAPI {
			expected = "kubevirt.io/api"
		}
		if base == kvClient {
			expected = "kubevirt.io/client-go"
		}
		if m.module != expected {
			return problemf("wrong module identity %s", p)
		}
		foundAPI := base != ""
		for _, repl := range m.replaces {
			if repl.version != "" {
				if repl.old == "kubevirt.io/api" {
					return problemf("API route is not the granted staged tree")
				}
				continue
			}
			resolved := path.Clean(path.Join(base, repl.newPath))
			if (repl.old != "kubevirt.io/api" || resolved != kvAPI) && (repl.old != "kubevirt.io/client-go" || resolved != kvClient) {
				return problemf("unsupported local module route %s", repl.newPath)
			}
			foundAPI = foundAPI || repl.old == "kubevirt.io/api"
		}
		if !foundAPI {
			return problemf("module %s does not resolve the granted API tree", p)
		}
	}
	if b := routing["go.work"]; len(b) > 0 {
		w, err := kvParseRouting(b)
		if err != nil {
			return problemf("invalid workspace")
		}
		seen := map[string]bool{}
		for _, u := range w.use {
			p := path.Clean(u)
			if p != "." && p != kvAPI && p != kvClient {
				return problemf("unsupported workspace module %s", p)
			}
			seen[p] = true
		}
		if len(w.use) != 3 || !seen["."] || !seen[kvAPI] || !seen[kvClient] {
			return problemf("workspace does not bind exactly the granted modules")
		}
		for _, repl := range w.replaces {
			if repl.version == "" || repl.old == "kubevirt.io/api" {
				return problemf("unsupported workspace replacement")
			}
		}
	} else {
		return problemf("constructor profile requires explicit workspace routing")
	}
	apiRoute := false
	for _, ln := range strings.Split(string(routing["vendor/modules.txt"]), "\n") {
		if strings.HasPrefix(ln, "# kubevirt.io/api ") {
			if !strings.HasSuffix(ln, " => ./"+kvAPI) {
				return problemf("vendored API route differs from granted staged tree")
			}
			apiRoute = true
		}
	}
	if !apiRoute {
		return problemf("missing vendored API route")
	}
	return nil
}

type kvRoute struct{ old, newPath, version string }
type kvRoutes struct {
	module   string
	use      []string
	replaces []kvRoute
}

// Only the unquoted line-oriented routing syntax in the reviewed source
// grants is supported. Comments, requirements and tool directives cannot
// introduce routing; all other syntax fails closed.
func kvParseRouting(data []byte) (kvRoutes, error) {
	var out kvRoutes
	block := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line, _, _ := strings.Cut(raw, "//")
		if strings.ContainsAny(line, "\"`") || strings.Contains(line, "/*") {
			return out, problemf("unsupported quoted module routing")
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == ")" {
			if len(f) != 1 || block == "" {
				return out, problemf("unbalanced routing block")
			}
			block = ""
			continue
		}
		directive := block
		if directive == "" {
			directive = f[0]
			f = f[1:]
		}
		if len(f) == 1 && f[0] == "(" {
			if block != "" {
				return out, problemf("nested routing block")
			}
			switch directive {
			case "use", "replace", "require", "tool":
				block = directive
				continue
			default:
				return out, problemf("unsupported routing block")
			}
		}
		switch directive {
		case "module":
			if len(f) != 1 || out.module != "" {
				return out, problemf("ambiguous module")
			}
			out.module = f[0]
		case "go", "toolchain":
			if len(f) != 1 {
				return out, problemf("invalid routing version")
			}
		case "use":
			if len(f) != 1 {
				return out, problemf("invalid workspace use")
			}
			out.use = append(out.use, f[0])
		case "replace":
			arrow := -1
			for i, s := range f {
				if s == "=>" {
					if arrow != -1 {
						return out, problemf("ambiguous replacement")
					}
					arrow = i
				}
			}
			if arrow < 1 || arrow > 2 || len(f) < arrow+2 || len(f) > arrow+3 {
				return out, problemf("unsupported replacement")
			}
			r := kvRoute{old: f[0], newPath: f[arrow+1]}
			if len(f) == arrow+3 {
				r.version = f[arrow+2]
			}
			out.replaces = append(out.replaces, r)
		case "require":
			if len(f) != 2 {
				return out, problemf("invalid requirement")
			}
		case "tool":
			if len(f) != 1 {
				return out, problemf("invalid tool directive")
			}
		default:
			return out, problemf("unsupported routing directive %s", directive)
		}
	}
	if block != "" {
		return out, problemf("unfinished routing block")
	}
	return out, nil
}

type kvPackage struct {
	bindings map[string]kvExpr
	files    map[string]*ast.File
	imports  map[string]map[string]string
}
type kvExpr struct {
	expr ast.Expr
	file string
}
type kvValue struct {
	text      string
	boolean   bool
	isBool    bool
	fields    map[string]kvValue
	items     []kvValue
	file      string
	line, end int
}
type kvReader struct {
	r        extract.PinnedReader
	repo     extract.RepoRef
	commit   string
	fset     *token.FileSet
	packages map[string]*kvPackage
	records  map[string]FileRecord
}

func (k *kvReader) load(dir string) (*kvPackage, error) {
	if p := k.packages[dir]; p != nil {
		return p, nil
	}
	es, err := k.r.List(k.repo, k.commit, dir)
	if err != nil {
		return nil, err
	}
	p := &kvPackage{bindings: map[string]kvExpr{}, files: map[string]*ast.File{}, imports: map[string]map[string]string{}}
	k.packages[dir] = p
	for _, e := range es {
		if !strings.HasSuffix(e.Path, ".go") || strings.HasSuffix(e.Path, "_test.go") {
			continue
		}
		if e.Type != "blob" || e.Mode != "100644" {
			return nil, problemf("nonregular Go source %s", e.Path)
		}
		b, err := k.r.Read(k.repo, k.commit, e.Path)
		if err != nil {
			return nil, err
		}
		if len(b) > MaxFileBytes {
			return nil, problemf("oversized Go source %s", e.Path)
		}
		f, err := parser.ParseFile(k.fset, e.Path, b, parser.ParseComments)
		if err != nil {
			return nil, problemf("invalid Go source %s", e.Path)
		}
		sum := sha256.Sum256(b)
		k.records[e.Path] = FileRecord{Path: e.Path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: len(b), Lines: extract.CountLines(b)}
		p.files[e.Path] = f
		p.imports[e.Path] = map[string]string{}
		for _, im := range f.Imports {
			s, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				return nil, err
			}
			name := path.Base(s)
			if im.Name != nil {
				name = im.Name.Name
			}
			p.imports[e.Path][name] = s
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				v, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range v.Names {
					if i >= len(v.Values) {
						continue
					}
					if _, dup := p.bindings[n.Name]; dup {
						return nil, problemf("duplicate Go declaration %s", n.Name)
					}
					p.bindings[n.Name] = kvExpr{v.Values[i], e.Path}
				}
			}
		}
	}
	return p, nil
}

func (k *kvReader) expr(dir, file string, e ast.Expr, depth int) (kvValue, error) {
	fail := func() (kvValue, error) {
		return kvValue{}, problemf("unsupported constructor expression at %s:%d", file, k.fset.Position(e.Pos()).Line)
	}
	if depth > 64 {
		return fail()
	}
	value := kvValue{file: file, line: k.fset.Position(e.Pos()).Line, end: k.fset.Position(e.End()).Line}
	p, err := k.load(dir)
	if err != nil {
		return value, err
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return fail()
		}
		value.text, err = strconv.Unquote(e.Value)
		return value, err
	case *ast.Ident:
		if e.Name == "true" || e.Name == "false" {
			value.boolean = e.Name == "true"
			value.isBool = true
			return value, nil
		}
		b, ok := p.bindings[e.Name]
		if !ok {
			return fail()
		}
		if f := p.files[b.file]; f != nil {
			for _, cg := range f.Comments {
				for _, c := range cg.List {
					if strings.HasPrefix(c.Text, "//go:build") || strings.HasPrefix(c.Text, "// +build") {
						return fail()
					}
				}
			}
		}
		return k.expr(dir, b.file, b.expr, depth+1)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return fail()
		}
		a, err := k.expr(dir, file, e.X, depth+1)
		if err != nil {
			return value, err
		}
		b, err := k.expr(dir, file, e.Y, depth+1)
		if err != nil {
			return value, err
		}
		if a.fields != nil || b.fields != nil || a.isBool || b.isBool {
			return fail()
		}
		value.text = a.text + b.text
		return value, nil
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			if im, ok := p.imports[file][id.Name]; ok {
				if im == "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1" && (e.Sel.Name == "NamespaceScoped" || e.Sel.Name == "ClusterScoped") {
					value.text = "Namespaced"
					if e.Sel.Name == "ClusterScoped" {
						value.text = "Cluster"
					}
					return value, nil
				}
				if !strings.HasPrefix(im, "kubevirt.io/api/") || strings.Contains(im, "..") {
					return fail()
				}
				d := path.Join(kvAPI, strings.TrimPrefix(im, "kubevirt.io/api/"))
				return k.expr(d, file, &ast.Ident{Name: e.Sel.Name, NamePos: e.Sel.Pos()}, depth+1)
			}
		}
		a, err := k.expr(dir, file, e.X, depth+1)
		if err != nil {
			return value, err
		}
		v, ok := a.fields[e.Sel.Name]
		if !ok {
			return fail()
		}
		return v, nil
	case *ast.CompositeLit:
		if _, ok := e.Type.(*ast.ArrayType); ok || e.Type == nil {
			// An elided composite with keyed fields is a struct, not a slice.
			structValue := len(e.Elts) > 0
			for _, el := range e.Elts {
				if _, ok := el.(*ast.KeyValueExpr); !ok {
					structValue = false
					break
				}
			}
			if _, slice := e.Type.(*ast.ArrayType); slice {
				structValue = false
			}
			if !structValue {
				value.items = []kvValue{}
				for _, el := range e.Elts {
					v, err := k.expr(dir, file, el, depth+1)
					if err != nil {
						return value, err
					}
					value.items = append(value.items, v)
				}
				return value, nil
			}
		}
		value.fields = map[string]kvValue{}
		for _, el := range e.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				return fail()
			}
			id, ok := kv.Key.(*ast.Ident)
			if !ok {
				return fail()
			}
			if _, dup := value.fields[id.Name]; dup {
				return fail()
			}
			switch id.Name {
			case "Name", "Served", "Storage", "Group", "Version", "Kind":
			default:
				continue
			}
			v, err := k.expr(dir, file, kv.Value, depth+1)
			if err != nil {
				return value, err
			}
			value.fields[id.Name] = v
		}
		return value, nil
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "newCRDVersions" && dir == kvComponents && len(e.Args) == 0 {
			return k.expr(kvAPI+"/core/v1", file, &ast.Ident{Name: "ApiSupportedVersions", NamePos: e.Pos()}, depth+1)
		}
	}
	return fail()
}

func kvField(l *ast.CompositeLit, name string) (ast.Expr, error) {
	var out ast.Expr
	for _, el := range l.Elts {
		v, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return nil, problemf("unkeyed constructor literal")
		}
		id, ok := v.Key.(*ast.Ident)
		if !ok {
			return nil, problemf("unsupported constructor key")
		}
		if id.Name == name {
			if out != nil {
				return nil, problemf("duplicate constructor field %s", name)
			}
			out = v.Value
		}
	}
	if out == nil {
		return nil, problemf("missing constructor field %s", name)
	}
	return out, nil
}

func (k *kvReader) constructor(fn *ast.FuncDecl) (CRD, error) {
	c := CRD{Path: kvConstructors, StartLine: k.fset.Position(fn.Pos()).Line}
	p, err := k.load(kvComponents)
	if err != nil {
		return c, err
	}
	if p.imports[kvConstructors]["extv1"] != "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1" {
		return c, problemf("constructor CRD type import is not canonical")
	}
	for alias, im := range p.imports[kvConstructors] {
		if alias == "_" || alias == "." {
			return c, problemf("unsupported constructor import")
		}
		switch im {
		case "fmt", "strings", "kubevirt.io/kubevirt/pkg/pointer", "k8s.io/api/scheduling/v1", "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1", "k8s.io/apimachinery/pkg/apis/meta/v1", "k8s.io/apimachinery/pkg/util/yaml":
		default:
			if !strings.HasPrefix(im, "kubevirt.io/api/") {
				return c, problemf("unsupported constructor import %s", im)
			}
		}
	}
	var spec *ast.CompositeLit
	var name ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return true
		}
		s, ok := a.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if s.Sel.Name == "Spec" {
			if id, ok := s.X.(*ast.Ident); ok && id.Name == "crd" {
				if spec != nil {
					spec = nil
					return false
				}
				spec, _ = a.Rhs[0].(*ast.CompositeLit)
			}
		}
		if s.Sel.Name == "Name" {
			if id, ok := s.X.(*ast.Ident); ok && id.Name == "crd" {
				name = a.Rhs[0]
			}
			if obj, ok := s.X.(*ast.SelectorExpr); ok && obj.Sel.Name == "ObjectMeta" {
				if id, ok := obj.X.(*ast.Ident); ok && id.Name == "crd" {
					name = a.Rhs[0]
				}
			}
		}
		return true
	})
	if spec == nil || name == nil {
		return c, problemf("constructor %s has no closed spec/name", fn.Name.Name)
	}
	text := func(e ast.Expr) (string, error) {
		v, err := k.expr(kvComponents, kvConstructors, e, 0)
		if err != nil {
			return "", err
		}
		if v.text == "" {
			return "", problemf("nonstring constructor identity")
		}
		return v.text, nil
	}
	c.Name, err = text(name)
	if err != nil {
		return c, err
	}
	for _, field := range []string{"Group", "Scope"} {
		e, err := kvField(spec, field)
		if err != nil {
			return c, err
		}
		s, err := text(e)
		if err != nil {
			return c, err
		}
		if field == "Group" {
			c.Group = s
		} else {
			c.Scope = s
		}
	}
	e, err := kvField(spec, "Names")
	if err != nil {
		return c, err
	}
	names, ok := e.(*ast.CompositeLit)
	if !ok {
		return c, problemf("nonliteral CRD names")
	}
	for _, field := range []string{"Kind", "Plural"} {
		e, err := kvField(names, field)
		if err != nil {
			return c, err
		}
		s, err := text(e)
		if err != nil {
			return c, err
		}
		if field == "Kind" {
			c.Kind = s
		} else {
			c.Plural = s
		}
	}
	e, err = kvField(spec, "Versions")
	if err != nil {
		return c, err
	}
	vs, err := k.expr(kvComponents, kvConstructors, e, 0)
	if err != nil {
		return c, err
	}
	c.VersionsLine = k.fset.Position(e.Pos()).Line
	if vs.file != c.Path {
		c.VersionsPath = vs.file
	}
	if len(vs.items) == 0 || len(vs.items) > MaxVersionsPerCRD {
		return c, problemf("invalid constructor version slice")
	}
	seen := map[string]bool{}
	for _, v := range vs.items {
		n, s, st := v.fields["Name"], v.fields["Served"], v.fields["Storage"]
		if !versionRE.MatchString(n.text) || seen[n.text] || !s.isBool || !st.isBool || s.file != v.file || st.file != v.file {
			return c, problemf("incomplete constructor version")
		}
		seen[n.text] = true
		cv := CRDVersion{Name: n.text, Served: s.boolean, Storage: st.boolean, StartLine: v.line, EndLine: v.end, ServedLine: s.line, StorageLine: st.line}
		if v.file != c.Path {
			cv.SourcePath = v.file
		}
		c.Versions = append(c.Versions, cv)
		if st.boolean {
			if c.StorageVersion != "" || !s.boolean {
				return c, problemf("invalid constructor storage")
			}
			c.StorageVersion = n.text
		}
	}
	if !groupRE.MatchString(c.Group) || !pluralRE.MatchString(c.Plural) || !kindRE.MatchString(c.Kind) || c.Name != c.Plural+"."+c.Group || (c.Scope != "Cluster" && c.Scope != "Namespaced") || c.StorageVersion == "" {
		return c, problemf("invalid constructor identity %s", c.Name)
	}
	return c, nil
}

func readKubeVirtConstructors(r extract.PinnedReader, repo extract.RepoRef, commit string, t Target, inv *Inventory) error {
	if err := validateConstructorProfile(t); err != nil {
		return err
	}
	if err := kvCheckGrant(r, repo, commit, t, &inv.ConstructorGrant); err != nil {
		return err
	}
	k := &kvReader{r: r, repo: repo, commit: commit, fset: token.NewFileSet(), packages: map[string]*kvPackage{}, records: map[string]FileRecord{}}
	p, err := k.load(kvComponents)
	if err != nil {
		return err
	}
	f := p.files[kvConstructors]
	if f == nil {
		return problemf("missing CRD constructor source")
	}
	seen := map[string]bool{}
	var projected []CRD
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
			continue
		}
		star, ok := fn.Type.Results.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		s, ok := star.X.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != "CustomResourceDefinition" {
			continue
		}
		if fn.Recv != nil || fn.Type.Params.NumFields() != 0 {
			return problemf("unsupported parameterized CRD constructor")
		}
		c, err := k.constructor(fn)
		if err != nil {
			return err
		}
		projected = append(projected, c)
		seen[fn.Name.Name] = true
	}
	if len(projected) == 0 || !seen["NewKubeVirtCrd"] {
		return problemf("incomplete constructor universe")
	}
	// The pinned caller must list every workload constructor exactly once.
	b, err := r.Read(repo, commit, kvInstall+"/strategy.go")
	if err != nil {
		return err
	}
	caller, err := parser.ParseFile(token.NewFileSet(), "strategy.go", b, 0)
	if err != nil {
		return err
	}
	calls := map[string]int{}
	ast.Inspect(caller, func(n ast.Node) bool {
		l, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		a, ok := l.Type.(*ast.ArrayType)
		if !ok {
			return true
		}
		if _, ok := a.Elt.(*ast.FuncType); !ok {
			return true
		}
		for _, el := range l.Elts {
			if s, ok := el.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "components" {
					calls[s.Sel.Name]++
				}
			}
		}
		return true
	})
	for name := range seen {
		if name != "NewKubeVirtCrd" && calls[name] != 1 {
			return problemf("constructor %s is not exactly once in runtime install list", name)
		}
	}
	for name := range calls {
		if !seen[name] {
			return problemf("unresolved runtime constructor %s", name)
		}
	}
	existing := map[string]*CRD{}
	existingKinds := map[string]string{}
	for i := range inv.CRDs {
		existing[inv.CRDs[i].Name] = &inv.CRDs[i]
		existingKinds[inv.CRDs[i].Group+"/"+inv.CRDs[i].Kind] = inv.CRDs[i].Name
	}
	projectedNames := map[string]bool{}
	for _, c := range projected {
		if projectedNames[c.Name] {
			return problemf("duplicate projected CRD %s", c.Name)
		}
		projectedNames[c.Name] = true
		if other := existingKinds[c.Group+"/"+c.Kind]; other != "" && other != c.Name {
			return problemf("constructor kind conflicts with %s", other)
		}
		if old := existing[c.Name]; old != nil {
			if c.Name != "kubevirts.kubevirt.io" || old.Group != c.Group || old.Kind != c.Kind || old.Scope != c.Scope || len(old.Versions) != len(c.Versions) {
				return problemf("constructor overlaps declared CRD %s", c.Name)
			}
			for _, v := range c.Versions {
				ov, ok := old.version(v.Name)
				if !ok || ov.Served != v.Served || ov.Storage != v.Storage {
					return problemf("operator manifest differs from constructor")
				}
			}
			continue
		}
		inv.CRDs = append(inv.CRDs, c)
		existing[c.Name] = &c
		existingKinds[c.Group+"/"+c.Kind] = c.Name
	}
	if len(inv.CRDs) > MaxCRDsPerTag {
		return problemf("too many projected CRDs")
	}
	sort.Slice(inv.CRDs, func(i, j int) bool { return inv.CRDs[i].Name < inv.CRDs[j].Name })
	var files []string
	for p := range k.records {
		files = append(files, p)
	}
	sort.Strings(files)
	for _, p := range files {
		inv.Files = append(inv.Files, k.records[p])
	}
	inv.ConstructorProfile = kubevirtProfile
	return nil
}

// VerifyKubeVirtConstructorGroups checks a constructor citation against freshly
// read, granted source. Requested groups are queries, never proof inputs.
func VerifyKubeVirtConstructorGroups(r extract.PinnedReader, t Target, commit, sourcePath string, groups []string) error {
	if r == nil || t.ConstructorProfile != kubevirtProfile || sourcePath != kvConstructors || !extract.IsCommitSHA(commit) || len(groups) == 0 || len(groups) > MaxCRDsPerTag {
		return problemf("unsupported KubeVirt constructor citation")
	}
	repo, err := extract.ParseRepo(t.Repo)
	if err != nil {
		return err
	}
	inv := &Inventory{Commit: commit}
	if err := readKubeVirtConstructors(r, repo, commit, t, inv); err != nil {
		return err
	}
	defined := map[string]bool{}
	for _, crd := range inv.CRDs {
		if crd.Path == sourcePath {
			defined[crd.Group] = true
		}
	}
	for _, group := range groups {
		if !defined[group] {
			return problemf("constructor source does not define group %s", group)
		}
	}
	return nil
}
