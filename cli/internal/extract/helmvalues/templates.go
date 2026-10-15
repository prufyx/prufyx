// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"sort"
	"strings"
	"text/template/parse"
)

// TemplateRefs is what a syntactic scan of the chart's templates found:
// the values key paths written as .Values.a.b or $.Values.a.b, and the
// files the template parser refused. A value read through with, range,
// index, include, tpl or a variable is not resolved, so a path missing here
// may still be read. The counters record every construct through which a
// template can read values the scan does not resolve; a "no longer read"
// notice is derived only when all of them are zero (see unreadProblem).
type TemplateRefs struct {
	Files   int      `json:"files"`
	Paths   []string `json:"paths"`
	Refused []string `json:"refused"`
	// Dynamic counts index calls in function position.
	Dynamic int `json:"dynamic"`
	// WholeValues counts .Values or $.Values used whole (passed, ranged
	// over or rendered).
	WholeValues int `json:"wholeValues"`
	// Tpl counts uses of tpl, which renders a string as a template.
	Tpl int `json:"tpl"`
	// Indirect counts the other unresolved routes to values: a field or
	// variable chain naming Values after its first element, a chained
	// field naming Values, the string "Values", index outside function
	// position, and the root context ("." or "$") used other than as the
	// data of include or template or the pipeline of if or with.
	Indirect int `json:"indirect"`
	pathsSet map[string]bool
	// files maps a path to the template files that name it.
	files map[string][]string
	file  string
}

// refuse lists an entry the scan does not read as a template.
func (r *TemplateRefs) refuse(name string) {
	r.Refused = append(r.Refused, name)
}

// maxTemplateBytes bounds one template file.
const maxTemplateBytes = 4 << 20

// scanTemplate adds the values references of one template file.
func (r *TemplateRefs) scanTemplate(name string, text []byte) {
	r.Files++
	if r.pathsSet == nil {
		r.pathsSet, r.files = map[string]bool{}, map[string][]string{}
	}
	r.file = name
	if len(text) > maxTemplateBytes {
		r.Refused = append(r.Refused, name)
		return
	}
	trees := map[string]*parse.Tree{}
	t := parse.New(name)
	t.Mode = parse.SkipFuncCheck | parse.ParseComments
	if _, err := t.Parse(string(text), "", "", trees); err != nil {
		r.Refused = append(r.Refused, name)
		return
	}
	names := make([]string, 0, len(trees))
	for n := range trees {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if tr := trees[n]; tr != nil && tr.Root != nil {
			r.walk(tr.Root, true)
		}
	}
}

// add records a root field chain (.Values... or $.Values...): a path, or
// the whole values when the chain is .Values alone. A chain that names
// Values anywhere else is an unresolved route.
func (r *TemplateRefs) add(ident []string) {
	if len(ident) > 0 && ident[0] == "Values" {
		if len(ident) == 1 {
			r.WholeValues++
			return
		}
		p := strings.Join(ident[1:], ".")
		r.pathsSet[p] = true
		if fs := r.files[p]; len(fs) == 0 || fs[len(fs)-1] != r.file {
			r.files[p] = append(fs, r.file)
		}
		return
	}
	if namesValues(ident) {
		r.Indirect++
	}
}

func namesValues(ident []string) bool {
	for _, s := range ident {
		if s == "Values" {
			return true
		}
	}
	return false
}

// rootContext reports an argument that may be the whole root context,
// which holds the values: "$" always, "." where dot may still be the root
// (dotRoot).
func rootContext(node parse.Node, dotRoot bool) bool {
	switch n := node.(type) {
	case *parse.DotNode:
		return dotRoot
	case *parse.VariableNode:
		return len(n.Ident) == 1 && n.Ident[0] == "$"
	}
	return false
}

// rootPipe reports a pipeline that is "." or "$" alone.
func rootPipe(p *parse.PipeNode) bool {
	if p == nil || len(p.Decl) != 0 || len(p.Cmds) != 1 || len(p.Cmds[0].Args) != 1 {
		return false
	}
	return rootContext(p.Cmds[0].Args[0], true)
}

// walk scans one node. dotRoot is false only inside the body of a with or
// range whose pipeline is not the root context alone: dot is then a value
// that pipeline produced, and every way that pipeline could reach the
// values is itself recorded or counted.
func (r *TemplateRefs) walk(node parse.Node, dotRoot bool) {
	switch n := node.(type) {
	case nil:
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, c := range n.Nodes {
			r.walk(c, dotRoot)
		}
	case *parse.ActionNode:
		r.walk(n.Pipe, dotRoot)
	case *parse.PipeNode:
		if n == nil {
			return
		}
		for _, c := range n.Cmds {
			r.walk(c, dotRoot)
		}
	case *parse.CommandNode:
		include := false
		if len(n.Args) > 0 {
			if id, ok := n.Args[0].(*parse.IdentifierNode); ok && id.Ident == "include" {
				include = true
			}
		}
		for i, a := range n.Args {
			if id, ok := a.(*parse.IdentifierNode); ok {
				switch {
				case id.Ident == "index" && i == 0:
					r.Dynamic++
				case id.Ident == "index":
					r.Indirect++
				case id.Ident == "tpl":
					r.Tpl++
				}
			}
			if rootContext(a, dotRoot) {
				// include "name" . hands the root to a named template,
				// whose body this scan reads like any other.
				if !(include && i == 2 && len(n.Args) == 3) {
					r.Indirect++
				}
				continue
			}
			r.walk(a, dotRoot)
		}
	case *parse.FieldNode:
		r.add(n.Ident)
	case *parse.VariableNode:
		if len(n.Ident) > 0 && n.Ident[0] == "$" {
			r.add(n.Ident[1:])
		} else if namesValues(n.Ident) {
			r.Indirect++
		}
	case *parse.ChainNode:
		if namesValues(n.Field) {
			r.Indirect++
		}
		r.walk(n.Node, dotRoot)
	case *parse.StringNode:
		if n.Text == "Values" {
			r.Indirect++
		}
	case *parse.IfNode:
		r.walkBranch(&n.BranchNode, dotRoot, false)
	case *parse.RangeNode:
		r.walkBranch(&n.BranchNode, dotRoot, true)
	case *parse.WithNode:
		r.walkBranch(&n.BranchNode, dotRoot, true)
	case *parse.TemplateNode:
		// template "name" . hands the root to a named template.
		if !rootPipe(n.Pipe) {
			r.walk(n.Pipe, dotRoot)
		}
	}
}

// walkBranch walks an if, with or range. The pipeline of an if or with
// may be the root context alone: it only tests it or makes it dot. A range
// over the root context is counted like any other use of it. rebinds is
// set for with and range, whose body has the pipeline's value as dot; the
// else branch keeps the outer dot.
func (r *TemplateRefs) walkBranch(b *parse.BranchNode, dotRoot, rebinds bool) {
	root := rootPipe(b.Pipe)
	isRange := b.NodeType == parse.NodeRange
	if !root || isRange {
		r.walk(b.Pipe, dotRoot)
	}
	body := dotRoot
	if rebinds {
		body = root && !isRange
	}
	r.walk(b.List, body)
	r.walk(b.ElseList, dotRoot)
}

// finish sorts the record.
func (r *TemplateRefs) finish() {
	r.Paths = r.Paths[:0]
	for p := range r.pathsSet {
		r.Paths = append(r.Paths, p)
	}
	sort.Strings(r.Paths)
	sort.Strings(r.Refused)
	if r.Paths == nil {
		r.Paths = []string{}
	}
	if r.Refused == nil {
		r.Refused = []string{}
	}
}
