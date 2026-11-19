// SPDX-License-Identifier: AGPL-3.0-only

package chartapisurface

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template/parse"
)

var (
	keyRE        = regexp.MustCompile(`(?m)^---[ \t]*$|^(apiVersion|kind):[ \t]*([^\n]*)(\n|$)`)
	apiVersionRE = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?/)?v[0-9]{1,4}(?:(?:alpha|beta)[0-9]{1,4})?$`)
	kindRE       = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
)

// builders are functions that make a string from parts.
var builders = map[string]bool{
	"printf": true, "print": true, "println": true, "cat": true, "join": true,
	"replace": true, "trimPrefix": true, "trimSuffix": true, "upper": true,
	"lower": true, "title": true, "ternary": true, "regexReplaceAll": true,
	"list": true, "dict": true,
}

// passFilters leave a finite value unchanged apart from whitespace/quotes.
var passFilters = map[string]bool{"trim": true, "quote": true, "squote": true}

type tmplDef struct {
	file string
	tree *parse.Tree
	sub  bool // defined in a subchart
}

type parsedFile struct {
	file    string
	text    string
	trees   map[string]*parse.Tree
	root    string // name of the file's own tree; "" for helper files and plain files
	plain   bool   // not a template: a plain manifest file (crds/)
	cond    bool   // the file belongs to a conditional subchart
	subchrt bool
}

type event struct {
	kind  string // "api", "kind", "sep"
	vals  []string
	line  int
	cond  bool
	tags  map[string]bool
	codes []Withheld
}

type scanner struct {
	led       *Ledger
	defs      map[string][]tmplDef
	usesFiles bool
	hadDocs   int // templated files that are not pure helpers
	cache     map[string]vres
	fileText  map[string]string

	// per file
	file     string
	text     string
	lookupV  map[string]bool
	inDefine bool
	fileCond bool
	events   []event
	nest     int
	stack    []string
}

type vres struct {
	vals  []string
	tags  map[string]bool
	codes []Withheld
}

func (s *scanner) withhold(code, detail string, line int) {
	s.led.Withheld = append(s.led.Withheld, Withheld{Code: code, File: s.file, Line: line, Detail: detail})
}

func (s *scanner) lineOf(off int) int {
	if off > len(s.text) {
		off = len(s.text)
	}
	return 1 + strings.Count(s.text[:off], "\n")
}

// Read reads one archive and returns its ledger without a served-API check.
func Read(raw []byte) (*Ledger, error) {
	if len(raw) == 0 || len(raw) > MaxArchiveBytes {
		return nil, refuse("archive size %d outside 1..%d", len(raw), MaxArchiveBytes)
	}
	sum := sha256.Sum256(raw)
	root, err := readArchive(raw, "", 0, &budget{})
	if err != nil {
		return nil, err
	}
	led := &Ledger{
		Schema: Schema, Mode: Mode,
		Chart: ChartID{Name: root.meta.Name, Version: root.meta.Version, ArchiveSHA256: "sha256:" + hex.EncodeToString(sum[:])},
	}
	s := &scanner{led: led, defs: map[string][]tmplDef{}, cache: map[string]vres{}, fileText: map[string]string{}}
	s.run(root)
	led.Finish()
	return led, nil
}

func (s *scanner) run(root *chart) {
	var files []*parsedFile
	// dependencies must be present in the archive
	walkCharts(root, func(c *chart) {
		for _, d := range c.meta.Dependencies {
			found := false
			for _, sc := range c.subs {
				if sc.meta.Name == d.Name {
					found = true
				}
			}
			if !found {
				s.file = c.dir + "Chart.yaml"
				s.withhold(CodeDependencyMissing, d.Name, 0)
			}
		}
	})
	walkCharts(root, func(c *chart) {
		names := make([]string, 0, len(c.files))
		for rel := range c.files {
			names = append(names, rel)
		}
		sort.Strings(names)
		for _, rel := range names {
			data := c.files[rel]
			disp := c.dir + rel
			switch {
			case strings.HasPrefix(rel, "crds/"):
				files = append(files, &parsedFile{file: disp, text: string(data), plain: true, subchrt: c.dir != "", cond: c.conditional})
			case strings.HasPrefix(rel, "templates/"):
				base := rel[strings.LastIndex(rel, "/")+1:]
				if base == "NOTES.txt" {
					continue
				}
				pf := &parsedFile{file: disp, text: string(data), subchrt: c.dir != "", cond: c.conditional}
				s.fileText[disp] = pf.text
				trees := map[string]*parse.Tree{}
				t := parse.New(disp)
				t.Mode = parse.SkipFuncCheck
				if _, err := t.Parse(pf.text, "", "", trees); err != nil {
					s.file = disp
					s.withhold(CodeTemplateParse, "", 0)
					continue
				}
				pf.trees = trees
				if !strings.HasPrefix(base, "_") {
					pf.root = disp
				}
				for n, tr := range trees {
					if n == disp {
						continue
					}
					s.defs[n] = append(s.defs[n], tmplDef{file: disp, tree: tr, sub: c.dir != ""})
				}
				files = append(files, pf)
			}
		}
	})
	for _, pf := range files {
		s.scanFile(pf)
	}
	if len(s.led.APIs) > MaxEntries {
		s.led.APIs = s.led.APIs[:MaxEntries]
		s.file = ""
		s.withhold(CodeTooManyEntries, "", 0)
	}
	if len(s.led.APIs) == 0 && s.hadDocs > 0 {
		s.file = ""
		s.withhold(CodeEmptyScan, "templates exist but no object was listed", 0)
	}
	if len(s.led.APIs) == 0 && s.usesFiles {
		s.file = ""
		s.withhold(CodeFilesOrTpl, "no object listed and the chart reads files or renders strings", 0)
	}
}

func (s *scanner) scanFile(pf *parsedFile) {
	s.file, s.text = pf.file, pf.text
	s.fileCond = pf.cond
	if pf.plain {
		s.hadDocs++
		s.events = nil
		s.nest = 0
		s.walkList([]parse.Node{&parse.TextNode{NodeType: parse.NodeText, Text: []byte(pf.text)}}, false)
		s.flush(false)
		return
	}
	names := make([]string, 0, len(pf.trees))
	for n := range pf.trees {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		tr := pf.trees[n]
		if tr == nil || tr.Root == nil {
			continue
		}
		isRoot := n == pf.file
		if isRoot && pf.root == "" {
			continue // helper file: text outside defines is not output
		}
		if isRoot && strings.TrimSpace(tr.Root.String()) != "" {
			s.hadDocs++
		}
		s.lookupV = map[string]bool{}
		visitAll(tr.Root, func(nd parse.Node) {
			if p, ok := nd.(*parse.PipeNode); ok {
				for _, d := range p.Decl {
					if pipeHasIdent(p, "lookup") && len(d.Ident) > 0 {
						s.lookupV[d.Ident[0]] = true
					}
				}
			}
			if pipeNodeUsesFiles(nd) {
				s.usesFiles = true
			}
		})
		s.events, s.nest, s.inDefine = nil, 0, !isRoot
		s.walkList(tr.Root.Nodes, false)
		s.flush(s.inDefine)
	}
}

// ---- tree helpers

func visitAll(n parse.Node, f func(parse.Node)) {
	if n == nil {
		return
	}
	f(n)
	switch x := n.(type) {
	case *parse.ListNode:
		if x == nil {
			return
		}
		for _, c := range x.Nodes {
			visitAll(c, f)
		}
	case *parse.ActionNode:
		visitAll(x.Pipe, f)
	case *parse.PipeNode:
		if x == nil {
			return
		}
		for _, d := range x.Decl {
			visitAll(d, f)
		}
		for _, c := range x.Cmds {
			visitAll(c, f)
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			visitAll(a, f)
		}
	case *parse.IfNode:
		visitAll(x.Pipe, f)
		visitAll(x.List, f)
		visitAll(x.ElseList, f)
	case *parse.WithNode:
		visitAll(x.Pipe, f)
		visitAll(x.List, f)
		visitAll(x.ElseList, f)
	case *parse.RangeNode:
		visitAll(x.Pipe, f)
		visitAll(x.List, f)
		visitAll(x.ElseList, f)
	case *parse.TemplateNode:
		visitAll(x.Pipe, f)
	case *parse.ChainNode:
		visitAll(x.Node, f)
	}
}

func pipeHasIdent(n parse.Node, name string) bool {
	found := false
	visitAll(n, func(x parse.Node) {
		if id, ok := x.(*parse.IdentifierNode); ok && id.Ident == name {
			found = true
		}
	})
	return found
}

func pipeNodeUsesFiles(n parse.Node) bool {
	switch x := n.(type) {
	case *parse.IdentifierNode:
		return x.Ident == "tpl"
	case *parse.FieldNode:
		return len(x.Ident) > 0 && x.Ident[0] == "Files"
	case *parse.VariableNode:
		return len(x.Ident) > 1 && x.Ident[0] == "$" && x.Ident[1] == "Files"
	case *parse.ChainNode:
		return false
	}
	return false
}

func usesFilesIn(n parse.Node) bool {
	found := false
	visitAll(n, func(x parse.Node) {
		if pipeNodeUsesFiles(x) {
			found = true
		}
	})
	return found
}

func mentionsCapabilities(n parse.Node) bool {
	found := false
	visitAll(n, func(x parse.Node) {
		switch v := x.(type) {
		case *parse.FieldNode:
			if len(v.Ident) > 0 && v.Ident[0] == "Capabilities" {
				found = true
			}
		case *parse.VariableNode:
			if len(v.Ident) > 1 && v.Ident[0] == "$" && v.Ident[1] == "Capabilities" {
				found = true
			}
		}
	})
	return found
}

// ---- event walk

func (s *scanner) walkList(nodes []parse.Node, cond bool) {
	s.nest++
	defer func() { s.nest-- }()
	if s.nest > MaxNestDepth {
		s.withhold(CodeTemplateDepth, "control nesting", 0)
		return
	}
	skip := map[int]bool{}
	off := map[int]int{}
	for i := 0; i < len(nodes); i++ {
		if skip[i] {
			continue
		}
		switch n := nodes[i].(type) {
		case *parse.TextNode:
			start := off[i]
			text := string(n.Text)
			base := int(n.Pos) + start
			rest := text[start:]
			for _, m := range keyRE.FindAllStringSubmatchIndex(rest, -1) {
				line := s.lineOf(base + m[0])
				if m[2] < 0 {
					s.events = append(s.events, event{kind: "sep", line: line})
					continue
				}
				key := rest[m[2]:m[3]]
				parts := []parse.Node{textNode(rest[m[4]:m[5]])}
				endsNL := m[1] > m[5]
				if !endsNL && i+1 < len(nodes) {
					for j := i + 1; j < len(nodes); j++ {
						if t, ok := nodes[j].(*parse.TextNode); ok {
							if idx := bytes.IndexByte(t.Text, '\n'); idx >= 0 {
								parts = append(parts, textNode(string(t.Text[:idx])))
								off[j] = idx
								break
							}
							parts = append(parts, t)
							skip[j] = true
							continue
						}
						parts = append(parts, nodes[j])
						skip[j] = true
					}
				}
				r := s.evalSeq(parts, 0)
				ev := event{kind: "api", line: line, cond: cond || s.inDefine || s.fileCond, tags: r.tags, codes: r.codes}
				if key == "kind" {
					ev.kind = "kind"
				}
				ev.vals = r.vals
				s.events = append(s.events, ev)
			}
		case *parse.ActionNode:
			if usesFilesIn(n.Pipe) {
				prevNL := i == 0
				if t, ok := nodes[i-boolToInt(i > 0)].(*parse.TextNode); ok && i > 0 {
					prevNL = bytes.HasSuffix(t.Text, []byte("\n"))
				}
				if prevNL {
					s.withhold(CodeFilesOrTpl, "document-level file or string rendering", s.lineOf(int(n.Pos)))
				}
			}
		case *parse.IfNode:
			s.walkList(listNodes(n.List), true)
			s.walkList(listNodes(n.ElseList), true)
		case *parse.WithNode:
			s.walkList(listNodes(n.List), true)
			s.walkList(listNodes(n.ElseList), true)
		case *parse.RangeNode:
			s.walkList(listNodes(n.List), true)
			s.walkList(listNodes(n.ElseList), true)
		}
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func listNodes(l *parse.ListNode) []parse.Node {
	if l == nil {
		return nil
	}
	return l.Nodes
}

func textNode(t string) *parse.TextNode {
	return &parse.TextNode{NodeType: parse.NodeText, Text: []byte(t)}
}

// flush pairs the events of one tree into entries.
func (s *scanner) flush(define bool) {
	var group []event
	emit := func() {
		defer func() { group = nil }()
		var apis, kinds []event
		for _, e := range group {
			if e.kind == "api" {
				apis = append(apis, e)
			} else {
				kinds = append(kinds, e)
			}
		}
		if len(apis) == 0 && len(kinds) == 0 {
			return
		}
		line := 0
		if len(group) > 0 {
			line = group[0].line
		}
		for _, e := range group {
			for _, c := range e.codes {
				s.led.Withheld = append(s.led.Withheld, c)
			}
		}
		if len(apis) != len(kinds) {
			s.withhold(CodeDocumentPairing, fmt.Sprintf("%d apiVersion and %d kind lines in one document", len(apis), len(kinds)), line)
			return
		}
		for i := range apis {
			a, k := apis[i], kinds[i]
			if len(a.codes)+len(k.codes) > 0 {
				continue
			}
			for _, av := range a.vals {
				for _, kv := range k.vals {
					if !apiVersionRE.MatchString(av) || !kindRE.MatchString(kv) {
						s.withhold(CodeInvalidValue, av+" "+kv, a.line)
						continue
					}
					if kv == "List" || strings.HasSuffix(kv, "List") {
						s.withhold(CodeListKind, kv, k.line)
					}
					choice := a.tags[GroupCapabilitySwitch] || a.tags[GroupInlineChoice] || k.tags[GroupCapabilitySwitch] || k.tags[GroupInlineChoice]
					s.led.APIs = append(s.led.APIs, Entry{
						APIVersion: av, Kind: kv, File: s.file, Line: a.line,
						Conditional:  a.cond || k.cond || choice,
						VersionGroup: versionGroup(a.tags), KindGroup: kindGroup(k.tags),
					})
				}
			}
		}
	}
	for _, e := range s.events {
		if e.kind == "sep" {
			emit()
			continue
		}
		group = append(group, e)
	}
	emit()
	s.events = nil
}

func versionGroup(t map[string]bool) string {
	switch {
	case t[GroupCapabilitySwitch]:
		return GroupCapabilitySwitch
	case t[GroupLibraryHelper]:
		return GroupLibraryHelper
	case t[GroupInlineChoice]:
		return GroupInlineChoice
	}
	return GroupLiteral
}

func kindGroup(t map[string]bool) string {
	switch {
	case t[GroupLibraryHelper]:
		return GroupLibraryHelper
	case t[GroupCapabilitySwitch], t[GroupInlineChoice]:
		return GroupTemplatedKindSet
	}
	return GroupLiteral
}

// ---- value evaluation

func (s *scanner) fail(code, detail string, n parse.Node) vres {
	line := 0
	if n != nil {
		line = s.lineOf(int(n.Position()))
	}
	return vres{tags: map[string]bool{}, codes: []Withheld{{Code: code, File: s.file, Line: line, Detail: detail}}}
}

func merge(a, b vres) vres {
	t := map[string]bool{}
	for k := range a.tags {
		t[k] = true
	}
	for k := range b.tags {
		t[k] = true
	}
	return vres{tags: t, codes: append(append([]Withheld(nil), a.codes...), b.codes...)}
}

func (s *scanner) concat(a, b vres) vres {
	out := merge(a, b)
	if len(out.codes) > 0 {
		return out
	}
	if len(a.vals)*len(b.vals) > MaxValueSetSize {
		return vres{tags: out.tags, codes: []Withheld{{Code: CodeValueSetTooLarge, File: s.file}}}
	}
	set := map[string]bool{}
	for _, x := range a.vals {
		for _, y := range b.vals {
			set[x+y] = true
		}
	}
	for v := range set {
		out.vals = append(out.vals, v)
	}
	sort.Strings(out.vals)
	return out
}

func union(a, b vres) vres {
	out := merge(a, b)
	set := map[string]bool{}
	for _, v := range a.vals {
		set[v] = true
	}
	for _, v := range b.vals {
		set[v] = true
	}
	for v := range set {
		out.vals = append(out.vals, v)
	}
	sort.Strings(out.vals)
	return out
}

// evalSeq evaluates the concatenation of nodes to a finite set of strings
// or to typed codes.
func (s *scanner) evalSeq(nodes []parse.Node, depth int) vres {
	acc := vres{vals: []string{""}, tags: map[string]bool{}}
	for _, n := range nodes {
		acc = s.concat(acc, s.evalNode(n, depth))
		if len(acc.codes) > 0 {
			return acc
		}
	}
	if len(acc.codes) == 0 {
		set := map[string]bool{}
		for _, v := range acc.vals {
			v = normalize(v)
			if strings.Contains(v, "\n") {
				return merge(acc, s.fail(CodeExpression, "multi-line value", nil))
			}
			if v != "" {
				set[v] = true
			}
		}
		acc.vals = acc.vals[:0]
		for v := range set {
			acc.vals = append(acc.vals, v)
		}
		sort.Strings(acc.vals)
		if len(acc.vals) == 0 {
			return merge(acc, s.fail(CodeInvalidValue, "empty value", nil))
		}
	}
	return acc
}

func normalize(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	return v
}

func (s *scanner) evalNode(n parse.Node, depth int) vres {
	one := func(v string) vres { return vres{vals: []string{v}, tags: map[string]bool{}} }
	switch x := n.(type) {
	case *parse.TextNode:
		return one(string(x.Text))
	case *parse.CommentNode:
		return one("")
	case *parse.ActionNode:
		return s.evalPipe(x.Pipe, depth)
	case *parse.IfNode:
		return s.evalBranch(&x.BranchNode, depth)
	case *parse.WithNode:
		return s.evalBranch(&x.BranchNode, depth)
	case *parse.TemplateNode:
		return s.evalHelper(x.Name, x, depth)
	}
	return s.fail(CodeExpression, "control structure in a value", n)
}

func (s *scanner) evalBranch(b *parse.BranchNode, depth int) vres {
	tag := GroupInlineChoice
	if mentionsCapabilities(b.Pipe) {
		tag = GroupCapabilitySwitch
	}
	body := s.evalSeq(listNodes(b.List), depth)
	var els vres
	if b.ElseList != nil {
		els = s.evalSeq(listNodes(b.ElseList), depth)
	} else {
		els = vres{vals: []string{""}, tags: map[string]bool{}}
	}
	// an empty alternative is not a value; evalSeq refuses it, so treat the
	// pieces separately here
	out := union(body, els)
	out.tags[tag] = true
	return out
}

// evalPipe classifies one action inside a value.
func (s *scanner) evalPipe(p *parse.PipeNode, depth int) vres {
	if p == nil {
		return s.fail(CodeExpression, "empty action", nil)
	}
	if len(p.Decl) > 0 {
		return vres{vals: []string{""}, tags: map[string]bool{}}
	}
	if len(p.Cmds) == 0 || len(p.Cmds[0].Args) == 0 {
		return s.fail(CodeExpression, "empty pipeline", p)
	}
	prod := p.Cmds[0]
	// helper call: only the name matters; filters must be pass-through
	if id, ok := prod.Args[0].(*parse.IdentifierNode); ok && id.Ident == "include" && len(prod.Args) >= 2 {
		if name, ok := prod.Args[1].(*parse.StringNode); ok {
			for _, f := range p.Cmds[1:] {
				if fid, ok := f.Args[0].(*parse.IdentifierNode); !ok || !passFilters[fid.Ident] {
					return s.fail(CodeExpression, "filter on helper output", p)
				}
			}
			return s.evalHelper(name.Text, p, depth)
		}
	}
	var lookup, built, values, variable bool
	visitAll(p, func(x parse.Node) {
		switch v := x.(type) {
		case *parse.IdentifierNode:
			if v.Ident == "lookup" {
				lookup = true
			}
			if builders[v.Ident] {
				built = true
			}
		case *parse.FieldNode:
			if len(v.Ident) > 0 && v.Ident[0] == "Values" {
				values = true
			}
		case *parse.VariableNode:
			if len(v.Ident) > 1 && v.Ident[0] == "$" && v.Ident[1] == "Values" {
				values = true
			} else if v.Ident[0] != "$" {
				variable = true
				if s.lookupV[v.Ident[0]] {
					lookup = true
				}
			}
		}
	})
	if lookup {
		return s.fail(CodeLookup, "", p)
	}
	// print/printf of string constants only is a literal
	if id, ok := prod.Args[0].(*parse.IdentifierNode); ok && (id.Ident == "print" || id.Ident == "printf" || id.Ident == "println") && len(p.Cmds) == 1 {
		lit, ok := "", true
		for _, a := range prod.Args[1:] {
			sn, isS := a.(*parse.StringNode)
			if !isS || strings.Contains(sn.Text, "%") {
				ok = false
				break
			}
			lit += sn.Text
		}
		if ok && id.Ident != "println" {
			return vres{vals: []string{lit}, tags: map[string]bool{}}
		}
	}
	if built {
		return s.fail(CodeVersionKindBuilt, "", p)
	}
	if values {
		return s.fail(CodeUserValue, "", p)
	}
	if variable {
		return s.fail(CodeVariable, "", p)
	}
	if sn, ok := prod.Args[0].(*parse.StringNode); ok && len(prod.Args) == 1 {
		for _, f := range p.Cmds[1:] {
			if fid, ok := f.Args[0].(*parse.IdentifierNode); !ok || !passFilters[fid.Ident] {
				return s.fail(CodeExpression, "filter on a constant", p)
			}
		}
		return vres{vals: []string{sn.Text}, tags: map[string]bool{}}
	}
	return s.fail(CodeExpression, "", p)
}

func (s *scanner) evalHelper(name string, at parse.Node, depth int) vres {
	if depth >= MaxTemplateDepth {
		return s.fail(CodeTemplateDepth, name, at)
	}
	for _, on := range s.stack {
		if on == name {
			return s.fail(CodeTemplateDepth, "helper cycle "+name, at)
		}
	}
	defs := s.defs[name]
	if len(defs) == 0 {
		return s.fail(CodeHelperNotFound, name, at)
	}
	for _, d := range defs[1:] {
		if d.tree.Root.String() != defs[0].tree.Root.String() {
			return s.fail(CodeHelperAmbiguous, name, at)
		}
	}
	s.stack = append(s.stack, name)
	// positions inside a helper belong to the helper's file
	savedFile, savedText := s.file, s.text
	s.file = defs[0].file
	s.text = s.textOf(defs[0].file, savedFile, savedText)
	r := s.evalSeq(defs[0].tree.Root.Nodes, depth+1)
	s.file, s.text = savedFile, savedText
	s.stack = s.stack[:len(s.stack)-1]
	if defs[0].sub {
		r.tags[GroupLibraryHelper] = true
	}
	return r
}

// textOf returns the source text of a file for line numbers; helpers live in
// files the scanner has parsed, and their text is kept in fileText.
func (s *scanner) textOf(file, cur, curText string) string {
	if file == cur {
		return curText
	}
	return s.fileText[file]
}
