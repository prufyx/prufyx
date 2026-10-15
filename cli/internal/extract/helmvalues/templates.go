// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"sort"
	"strings"
	"text/template/parse"
)

// TemplateRefs is what a syntactic scan of the chart's templates found:
// the values key paths written as .Values.a.b or $.Values.a.b, and the
// files the template parser refused. It is a soft fact, recorded in the
// proof and never a rule: a value read through with, range, index,
// include, tpl or a variable is not resolved, so a path missing here may
// still be read.
type TemplateRefs struct {
	Files    int      `json:"files"`
	Paths    []string `json:"paths"`
	Refused  []string `json:"refused"`
	Dynamic  int      `json:"dynamic"`
	pathsSet map[string]bool
}

// maxTemplateBytes bounds one template file.
const maxTemplateBytes = 4 << 20

// scanTemplate adds the values references of one template file.
func (r *TemplateRefs) scanTemplate(name string, text []byte) {
	r.Files++
	if r.pathsSet == nil {
		r.pathsSet = map[string]bool{}
	}
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
			r.walk(tr.Root)
		}
	}
}

func (r *TemplateRefs) add(ident []string) {
	if len(ident) < 2 || ident[0] != "Values" {
		return
	}
	r.pathsSet[strings.Join(ident[1:], ".")] = true
}

func (r *TemplateRefs) walk(node parse.Node) {
	switch n := node.(type) {
	case nil:
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, c := range n.Nodes {
			r.walk(c)
		}
	case *parse.ActionNode:
		r.walk(n.Pipe)
	case *parse.PipeNode:
		if n == nil {
			return
		}
		for _, c := range n.Cmds {
			r.walk(c)
		}
	case *parse.CommandNode:
		for i, a := range n.Args {
			if id, ok := a.(*parse.IdentifierNode); ok && id.Ident == "index" && i == 0 {
				r.Dynamic++
			}
			r.walk(a)
		}
	case *parse.FieldNode:
		r.add(n.Ident)
	case *parse.VariableNode:
		if len(n.Ident) > 0 && n.Ident[0] == "$" {
			r.add(n.Ident[1:])
		}
	case *parse.ChainNode:
		r.walk(n.Node)
	case *parse.IfNode:
		r.walkBranch(&n.BranchNode)
	case *parse.RangeNode:
		r.walkBranch(&n.BranchNode)
	case *parse.WithNode:
		r.walkBranch(&n.BranchNode)
	case *parse.TemplateNode:
		r.walk(n.Pipe)
	}
}

func (r *TemplateRefs) walkBranch(b *parse.BranchNode) {
	r.walk(b.Pipe)
	r.walk(b.List)
	r.walk(b.ElseList)
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
