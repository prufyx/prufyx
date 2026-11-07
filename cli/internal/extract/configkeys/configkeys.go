// SPDX-License-Identifier: AGPL-3.0-only

// Package configkeys walks the Go configuration struct tags of one package
// directory of a pinned source tree and lists the key paths a configuration
// document may hold, from a reviewed root type. It is inert: nothing in the
// registry, the data or the factory calls it yet, and no collector or
// preparer exists for the config_keys_set fact.
//
// The walker reads only through an extract.PinnedReader, parses with go/parser
// and never type-checks or executes anything. It is default-deny: a field type
// it cannot resolve inside the directory (another package, a generic type, a
// function, a type outside a small reviewed allowlist), a custom unmarshaller,
// a free-form map or interface, an implicit key name where case folding makes
// the key ambiguous, a key collision, a member the shared encoder refuses and
// any parse problem each add a ledger entry, and a result with any ledger
// entry is never attestable.
//
// Not covered by this slice (listed in the change description): the generated
// configuration documentation parser, per-project targets, cross-package
// types, build-constraint evaluation, protobuf-defined configuration.
package configkeys

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// ResultSchema names the result layout.
const ResultSchema = "configkeys.v1"

// Evidence bases. Only a complete, ledger-free struct-tag walk is mechanical;
// everything else is withheld. A documentation-only source would be a draft
// for review; this slice has no documentation parser.
const (
	BasisMechanical = "mechanical"
	BasisWithheld   = "withheld"
)

// Tags the walker understands.
const (
	TagYAML         = "yaml"
	TagJSON         = "json"
	TagMapstructure = "mapstructure"
)

// Walk bounds.
const (
	maxDepth    = 24
	maxKeys     = 20000
	maxFiles    = 400
	maxFileSize = 2 << 20
)

// Target names the root of one walk: a package directory of the repository, a
// type declared in it and the tag family that decodes it.
type Target struct {
	Repo extract.RepoRef
	Dir  string
	Root string
	Tag  string
}

func (t Target) validate() error {
	if t.Repo.Key == "" || strings.HasPrefix(t.Dir, "/") || strings.Contains(t.Dir, "..") || strings.Contains(t.Dir, "\\") {
		return errors.New("configkeys: bad target directory or repository")
	}
	if !ast.IsExported(t.Root) && t.Root == "" {
		return errors.New("configkeys: empty root type")
	}
	for _, r := range t.Root {
		if !(r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return errors.New("configkeys: bad root type name")
		}
	}
	switch t.Tag {
	case TagYAML, TagJSON, TagMapstructure:
		return nil
	}
	return errors.New("configkeys: unknown tag family")
}

// Result is the canonical outcome of one walk.
type Result struct {
	Schema   string        `json:"schema"`
	Commit   string        `json:"commit"`
	Dir      string        `json:"dir"`
	Root     string        `json:"root"`
	Tag      string        `json:"tag"`
	Basis    string        `json:"basis"`
	Complete bool          `json:"complete"`
	Keys     []string      `json:"keys"`
	Ledger   []LedgerEntry `json:"ledger"`
}

// Attestable reports whether the result may back an attestation: only when
// nothing was withheld, at least one key was found and the basis is
// mechanical. A non-empty ledger never yields one, whatever other fields say.
func (r *Result) Attestable() bool {
	return r != nil && len(r.Ledger) == 0 && r.Complete && r.Basis == BasisMechanical && len(r.Keys) > 0
}

// Has reports whether member is a key of the walked document.
func (r *Result) Has(member string) bool {
	i := sort.SearchStrings(r.Keys, member)
	return i < len(r.Keys) && r.Keys[i] == member
}

// RemovalCandidates returns the keys in old and not in next, sorted. It
// answers only when both results are attestable and walk the same root with
// the same tag family; otherwise ok is false and nothing may be derived.
func RemovalCandidates(old, next *Result) (removed []string, ok bool) {
	if !old.Attestable() || !next.Attestable() || old.Root != next.Root || old.Tag != next.Tag {
		return nil, false
	}
	removed = []string{}
	for _, k := range old.Keys {
		if !next.Has(k) {
			removed = append(removed, k)
		}
	}
	return removed, true
}

// guards are switched off only by tests.
type guards struct {
	ledger                                          ledgerGuards
	custom, collision, implicit, dynamic, allowlist bool
	hook                                            func(string)
}

func defaultGuards() guards {
	return guards{ledger: defaultLedgerGuards(), custom: true, collision: true, implicit: true, dynamic: true, allowlist: true}
}

// Scan walks the target at the pinned commit.
func Scan(ctx context.Context, r extract.PinnedReader, t Target, sha string) (*Result, error) {
	return scan(ctx, r, t, sha, defaultGuards())
}

func scan(ctx context.Context, r extract.PinnedReader, t Target, sha string, g guards) (*Result, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if !extract.IsCommitSHA(sha) {
		return nil, errors.New("configkeys: sha must be a full 40-character commit SHA")
	}
	w := &walker{g: g, tag: t.Tag, keys: map[string]bool{}, types: map[string]*typeDecl{}, custom: map[string]bool{}}
	if err := w.load(ctx, r, t, sha); err != nil {
		return nil, err
	}
	w.safeWalk(t.Root)
	res := &Result{Schema: ResultSchema, Commit: sha, Dir: t.Dir, Root: t.Root, Tag: t.Tag, Keys: []string{}}
	for k := range w.keys {
		res.Keys = append(res.Keys, k)
	}
	sort.Strings(res.Keys)
	res.Ledger = ledgerOf(w.led, g.ledger)
	res.Complete = len(res.Ledger) == 0
	if !g.ledger.veto {
		res.Complete = true
	}
	if res.Complete && len(res.Keys) > 0 {
		res.Basis = BasisMechanical
	} else {
		res.Basis = BasisWithheld
	}
	return res, nil
}

type typeDecl struct {
	spec *ast.TypeSpec
	file *fileInfo
	dup  bool
}

type fileInfo struct {
	name    string
	imports map[string]string // local name -> import path
}

type walker struct {
	g      guards
	tag    string
	keys   map[string]bool
	types  map[string]*typeDecl
	custom map[string]bool // receiver type names with a custom unmarshaller
	led    []LedgerEntry
	over   bool
}

func (w *walker) add(code, item string) { w.led = append(w.led, LedgerEntry{Code: code, Item: item}) }

func (w *walker) load(ctx context.Context, r extract.PinnedReader, t Target, sha string) error {
	entries, err := r.List(t.Repo, sha, t.Dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		b := path.Base(e.Path)
		if e.Type == "blob" && strings.HasSuffix(b, ".go") && !strings.HasSuffix(b, "_test.go") {
			names = append(names, e.Path)
		}
	}
	sort.Strings(names)
	if len(names) > maxFiles {
		return errors.New("configkeys: too many source files")
	}
	fset := token.NewFileSet()
	pkgName := ""
	for _, p := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, err := r.Read(t.Repo, sha, p)
		if err != nil {
			return err
		}
		base := path.Base(p)
		if len(data) > maxFileSize {
			w.add(ReasonParse, base)
			continue
		}
		f, perr := parseSafe(fset, base, data)
		if perr != nil {
			w.add(ReasonParse, base)
			continue
		}
		if pkgName != "" && f.Name.Name != pkgName {
			w.add(ReasonPackages, base)
		}
		pkgName = f.Name.Name
		if hasConstraint(f) {
			w.add(ReasonBuildConstr, base)
		}
		fi := &fileInfo{name: base, imports: map[string]string{}}
		for _, im := range f.Imports {
			ip, uerr := strconv.Unquote(im.Path.Value)
			if uerr != nil {
				w.add(ReasonParse, base)
				continue
			}
			local := path.Base(ip)
			if im.Name != nil {
				local = im.Name.Name
			}
			fi.imports[local] = ip
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if ts, ok := s.(*ast.TypeSpec); ok {
						if old, dup := w.types[ts.Name.Name]; dup {
							old.dup = true
						} else {
							w.types[ts.Name.Name] = &typeDecl{spec: ts, file: fi}
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					switch d.Name.Name {
					case "UnmarshalYAML", "UnmarshalJSON", "UnmarshalText", "UnmarshalTOML":
						if n := recvName(d.Recv.List[0].Type); n != "" {
							w.custom[n] = true
						} else {
							w.add(ReasonUnresolvable, d.Name.Name)
						}
					}
				}
			}
		}
	}
	return nil
}

func recvName(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

func parseSafe(fset *token.FileSet, name string, data []byte) (f *ast.File, err error) {
	defer func() {
		if r := recover(); r != nil {
			f, err = nil, errors.New("parser panic")
		}
	}()
	return parser.ParseFile(fset, name, data, parser.ParseComments|parser.SkipObjectResolution)
}

// hasConstraint reports a //go:build or // +build line before the package
// clause. Constraints are not evaluated: the file is withheld.
func hasConstraint(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() >= f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:build") || strings.HasPrefix(c.Text, "// +build") {
				return true
			}
		}
	}
	return false
}

func (w *walker) safeWalk(root string) {
	defer func() {
		if r := recover(); r != nil {
			w.add(ReasonPanic, "walk")
		}
	}()
	if w.g.hook != nil {
		w.g.hook("walk")
	}
	td, ok := w.types[root]
	if !ok {
		w.add(ReasonRootNotFound, root)
		return
	}
	st := &state{stack: map[string]bool{}}
	w.named(root, td, nil, root, st, 0)
}

type state struct{ stack map[string]bool }

// level holds the key names already used at one document level, across
// flattened (inline) structs.
type level map[string]string

func (w *walker) emit(path []membercode.Seg, goPath string) bool {
	m, err := membercode.ConfigKey(path)
	if err != nil {
		switch {
		case errors.Is(err, membercode.ErrCharset):
			w.add(ReasonCharset, goPath)
		case errors.Is(err, membercode.ErrAmbiguous):
			w.add(ReasonAmbiguous, goPath)
		case errors.Is(err, membercode.ErrTooLong):
			w.add(ReasonTooLong, goPath)
		default:
			w.add(ReasonInvalidMember, goPath)
		}
		return false
	}
	if len(w.keys) >= maxKeys {
		if !w.over {
			w.over = true
			w.add(ReasonKeyLimit, "walk")
		}
		return false
	}
	w.keys[m] = true
	return true
}

var builtinLeaf = map[string]bool{
	"bool": true, "string": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"float32": true, "float64": true, "byte": true, "rune": true,
}

// stdLeaf are the reviewed non-local types that decode as a scalar.
var stdLeaf = map[string]bool{"time.Duration": true, "time.Time": true}

// named resolves a local type name and walks its declaration.
func (w *walker) named(name string, td *typeDecl, path []membercode.Seg, goPath string, st *state, depth int) {
	w.namedFlat(name, td, path, goPath, st, depth, nil)
}

func (w *walker) namedFlat(name string, td *typeDecl, path []membercode.Seg, goPath string, st *state, depth int, lv level) {
	if td.dup {
		w.add(ReasonAmbiguousType, name)
		return
	}
	if td.spec.TypeParams != nil {
		w.add(ReasonUnresolvable, goPath)
		return
	}
	if w.g.custom && w.custom[name] {
		w.add(ReasonCustomUnmarsh, name)
		return
	}
	if st.stack[name] {
		w.add(ReasonUnresolvable, goPath)
		return
	}
	st.stack[name] = true
	defer delete(st.stack, name)
	w.expr(td.spec.Type, td.file, path, goPath, st, depth, lv)
}

// expr walks the type expression of one field value (or the root). path is
// the document path of the value itself; lv is non-nil only for a flattened
// struct whose fields join the parent level.
func (w *walker) expr(e ast.Expr, fi *fileInfo, path []membercode.Seg, goPath string, st *state, depth int, lv level) {
	if depth > maxDepth {
		w.add(ReasonDepth, goPath)
		return
	}
	switch x := e.(type) {
	case *ast.ParenExpr:
		w.expr(x.X, fi, path, goPath, st, depth, lv)
	case *ast.StarExpr:
		w.expr(x.X, fi, path, goPath, st, depth, lv)
	case *ast.Ident:
		if builtinLeaf[x.Name] && w.types[x.Name] == nil {
			w.flatLeaf(lv, goPath)
			return
		}
		if (x.Name == "any") && w.types[x.Name] == nil {
			w.dynamic(ReasonDynamicAny, goPath, lv)
			return
		}
		if td, ok := w.types[x.Name]; ok {
			w.namedFlat(x.Name, td, path, goPath, st, depth+1, lv)
			return
		}
		w.add(ReasonUnresolvable, goPath)
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if ok {
			if ip, found := fi.imports[id.Name]; found && stdLeaf[ip+"."+x.Sel.Name] || !w.g.allowlist {
				w.flatLeaf(lv, goPath)
				return
			}
		}
		w.add(ReasonImportDenied, goPath)
	case *ast.ArrayType:
		w.expr(x.Elt, fi, append(clone(path), membercode.Seg{Kind: membercode.Item}), goPath+"[]", st, depth+1, nil)
	case *ast.MapType:
		w.dynamic(ReasonDynamicMap, goPath, lv)
	case *ast.InterfaceType:
		w.dynamic(ReasonDynamicAny, goPath, lv)
	case *ast.StructType:
		w.structType(x, fi, path, goPath, st, depth+1, lv)
	default:
		w.add(ReasonUnresolvable, goPath)
	}
}

// flatLeaf rejects a scalar where a flattened struct was required.
func (w *walker) flatLeaf(lv level, goPath string) {
	if lv != nil {
		w.add(ReasonUnresolvable, goPath)
	}
}

// dynamic records a free-form value: the key of the parent is the leaf and
// the children cannot be known, so the result is withheld.
func (w *walker) dynamic(code, goPath string, lv level) {
	if !w.g.dynamic {
		return
	}
	w.add(code, goPath)
}

func clone(p []membercode.Seg) []membercode.Seg {
	return append(make([]membercode.Seg, 0, len(p)+1), p...)
}

func (w *walker) structType(s *ast.StructType, fi *fileInfo, path []membercode.Seg, goPath string, st *state, depth int, lv level) {
	if lv == nil {
		lv = level{}
	}
	for _, f := range s.Fields.List {
		w.field(f, fi, path, goPath, st, depth, lv)
	}
}

type tagInfo struct {
	name   string
	has    bool
	skip   bool
	inline bool
}

func (w *walker) parseTag(f *ast.Field, goPath string) (tagInfo, bool) {
	var ti tagInfo
	if f.Tag == nil {
		return ti, true
	}
	raw, err := strconv.Unquote(f.Tag.Value)
	if err != nil {
		w.add(ReasonBadTag, goPath)
		return ti, false
	}
	v, ok := reflect.StructTag(raw).Lookup(w.tag)
	if !ok {
		if strings.Contains(raw, w.tag+":") {
			w.add(ReasonBadTag, goPath)
			return ti, false
		}
		return ti, true
	}
	if v == "-" {
		ti.skip = true
		return ti, true
	}
	parts := strings.Split(v, ",")
	ti.name, ti.has = parts[0], true
	for _, o := range parts[1:] {
		if o == "inline" || o == "squash" {
			ti.inline = true
		}
	}
	return ti, true
}

func (w *walker) field(f *ast.Field, fi *fileInfo, path []membercode.Seg, goPath string, st *state, depth int, lv level) {
	embedded := len(f.Names) == 0
	var names []string
	if embedded {
		n := recvName(f.Type)
		if n == "" {
			if se, ok := stripPtr(f.Type).(*ast.SelectorExpr); ok {
				n = se.Sel.Name
			}
		}
		if n == "" {
			w.add(ReasonUnresolvable, goPath+".embedded")
			return
		}
		names = []string{n}
	} else {
		for _, id := range f.Names {
			names = append(names, id.Name)
		}
	}
	for _, n := range names {
		fp := goPath + "." + n
		if !ast.IsExported(n) && !embedded {
			continue
		}
		ti, ok := w.parseTag(f, fp)
		if !ok {
			continue
		}
		if ti.skip {
			continue
		}
		// json flattens an embedded struct without a name; yaml and
		// mapstructure need an explicit inline or squash option.
		inline := embedded && (ti.inline || (w.tag == TagJSON && ti.name == ""))
		if !embedded && ti.inline {
			inline = true
		}
		if inline {
			w.expr(f.Type, fi, path, fp, st, depth, lv)
			continue
		}
		if embedded && !ast.IsExported(n) && !ti.has {
			continue
		}
		key := ti.name
		if key == "" {
			if w.tag == TagYAML || !w.g.implicit {
				key = strings.ToLower(n)
			} else {
				w.add(ReasonImplicitName, fp)
				continue
			}
		}
		if w.g.collision {
			if prev, dup := lv[key]; dup {
				w.add(ReasonKeyCollision, fp)
				_ = prev
				continue
			}
		}
		lv[key] = fp
		child := append(clone(path), membercode.Seg{Kind: membercode.Prop, Name: key})
		if !w.emit(child, fp) {
			continue
		}
		w.expr(f.Type, fi, child, fp, st, depth, nil)
	}
}

func stripPtr(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return e
		}
	}
}
