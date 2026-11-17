// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"fmt"
	"sort"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

// The hand scanner is the reader; a CommonMark parser is the oracle. The whole
// file is parsed a second time with a CommonMark-compliant parser (no
// extensions) and the two views of its structure are compared. Any
// disagreement withholds the file with ENTRY_PARSE_RESIDUE ("commonmark-
// disagreement"): the page a reader sees and the entry this package returns
// must be the same document.

// cmUnit is one top-level block (a paragraph, a quote, a code or HTML block, or
// one list item with everything under it), as a line span.
type cmUnit struct {
	lo, hi   int
	hasFence bool
	// code marks a top-level code block (indented or fenced). The scanner
	// does not make one an item (inside a section it is residue and withholds
	// the entry), so it takes part in the boundary check but not in the item
	// comparison.
	code bool
}

type cmView struct {
	headings  map[int]int // start line -> level
	nested    int         // line of the first heading that is not a child of the document, 0 if none
	fenceBody map[int]bool
	htmlStart map[int]bool
	htmlMulti bool
	units     []cmUnit
	unknown   bool // a block whose span could not be placed
}

func cmParse(lines []string) (v *cmView, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("parser panic: %v", r)
		}
	}()
	src := []byte(strings.Join(lines, "\n") + "\n")
	starts := make([]int, len(lines))
	off := 0
	for i, l := range lines {
		starts[i] = off
		off += len(l) + 1
	}
	lineOf := func(o int) int {
		i := sort.Search(len(starts), func(i int) bool { return starts[i] > o })
		if i < 1 {
			return 1
		}
		return i
	}
	doc := goldmark.New().Parser().Parse(text.NewReader(src))
	v = &cmView{headings: map[int]int{}, fenceBody: map[int]bool{}, htmlStart: map[int]bool{}}

	// Lines of one leaf block.
	leafLines := func(n ast.Node) []int {
		var out []int
		ls := n.Lines()
		for i := 0; i < ls.Len(); i++ {
			out = append(out, lineOf(ls.At(i).Start))
		}
		return out
	}
	// Span of a subtree.
	span := func(root ast.Node) (cmUnit, bool) {
		u := cmUnit{lo: 1 << 30, hi: -1}
		ok := true
		_ = ast.Walk(root, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
			if !entering || n.Type() != ast.TypeBlock {
				return ast.WalkContinue, nil
			}
			if _, isDef := n.(*ast.LinkReferenceDefinition); isDef {
				return ast.WalkSkipChildren, nil
			}
			ls := leafLines(n)
			switch n.(type) {
			case *ast.FencedCodeBlock:
				u.hasFence = true
				if len(ls) == 0 {
					return ast.WalkContinue, nil // an empty fence has no placed line
				}
				if ls[0]-1 < u.lo {
					u.lo = ls[0] - 1
				}
				if ls[len(ls)-1] > u.hi {
					u.hi = ls[len(ls)-1]
				}
			default:
				for _, l := range ls {
					if l < u.lo {
						u.lo = l
					}
					if l > u.hi {
						u.hi = l
					}
				}
			}
			return ast.WalkContinue, nil
		})
		if u.hi < 0 {
			ok = false
		}
		return u, ok
	}

	_ = ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch b := n.(type) {
		case *ast.Heading:
			ls := leafLines(b)
			if len(ls) == 0 {
				v.unknown = true
				return ast.WalkContinue, nil
			}
			v.headings[ls[0]] = b.Level
			if _, top := b.Parent().(*ast.Document); !top && v.nested == 0 {
				v.nested = ls[0]
			}
		case *ast.FencedCodeBlock:
			for _, l := range leafLines(b) {
				v.fenceBody[l] = true
			}
		case *ast.HTMLBlock:
			ls := leafLines(b)
			if len(ls) == 0 {
				v.unknown = true
				return ast.WalkContinue, nil
			}
			v.htmlStart[ls[0]] = true
			if len(ls) > 1 || b.HasClosure() && lineOf(b.ClosureLine.Start) > ls[0] {
				v.htmlMulti = true
			}
		}
		return ast.WalkContinue, nil
	})

	for c := doc.FirstChild(); c != nil; c = c.NextSibling() {
		switch c.(type) {
		case *ast.Heading, *ast.ThematicBreak, *ast.LinkReferenceDefinition:
			continue
		case *ast.List:
			for it := c.FirstChild(); it != nil; it = it.NextSibling() {
				u, ok := span(it)
				if !ok {
					continue // an item holding only definitions or empty fences
				}
				v.units = append(v.units, u)
			}
		default:
			u, ok := span(c)
			if !ok {
				continue
			}
			switch c.(type) {
			case *ast.CodeBlock, *ast.FencedCodeBlock:
				u.code = true
			}
			v.units = append(v.units, u)
		}
	}
	sort.Slice(v.units, func(i, j int) bool { return v.units[i].lo < v.units[j].lo })
	return v, nil
}

// cmFileDisagreement compares the whole-file structure: headings, the lines
// inside fenced code, and HTML blocks. It returns "" when the views agree.
func cmFileDisagreement(sc scanned, v *cmView) string {
	if v.unknown {
		return "a block of the oracle could not be placed"
	}
	if v.nested != 0 {
		return fmt.Sprintf("heading at line %d is inside a list item, quote or other container", v.nested)
	}
	if len(v.headings) != len(sc.headings) {
		return fmt.Sprintf("%d headings against %d", len(sc.headings), len(v.headings))
	}
	for _, h := range sc.headings {
		if lv, ok := v.headings[h.Line]; !ok || lv != h.Level {
			return fmt.Sprintf("heading at line %d", h.Line)
		}
	}
	body := 0
	for i := range sc.lines {
		if sc.fenceBody[i] != v.fenceBody[i+1] {
			return fmt.Sprintf("fenced code at line %d", i+1)
		}
		if sc.fenceBody[i] {
			body++
		}
	}
	if body != len(v.fenceBody) {
		return "fenced code lines differ"
	}
	hand := map[int]bool{}
	for _, n := range sc.html {
		hand[n] = true
	}
	for l := range v.htmlStart {
		if !hand[l] {
			return fmt.Sprintf("HTML block at line %d", l)
		}
	}
	if v.htmlMulti && sc.containerFence == 0 {
		return "a multi-line HTML block"
	}
	return cmItemDisagreement(sc, v)
}

// cmItemDisagreement compares the item structure of the whole file: the
// oracle units and the scanner items must pair off in order with the same
// span. A top-level code block the scanner did not make an item is skipped (it
// is residue to the scanner); every other unit and every scanner item must
// pair.
func cmItemDisagreement(sc scanned, v *cmView) string {
	same := func(h rawItem, u cmUnit) bool {
		return h.Start == u.lo && (h.End == u.hi || u.hasFence && h.End == u.hi+1)
	}
	j := 0
	for _, u := range v.units {
		if j < len(sc.items) && same(sc.items[j], u) {
			j++
			continue
		}
		if u.code {
			continue
		}
		if j < len(sc.items) {
			return fmt.Sprintf("item at line %d", sc.items[j].Start)
		}
		return fmt.Sprintf("a block at line %d the scanner did not read", u.lo)
	}
	if j < len(sc.items) {
		return fmt.Sprintf("item at line %d", sc.items[j].Start)
	}
	return ""
}

// cmSectionDisagreement refuses an oracle unit that crosses a boundary of the
// section [start,end]: one that begins before it and reaches into it, or begins
// inside it and ends after it.
func cmSectionDisagreement(v *cmView, start, end int) string {
	for _, u := range v.units {
		if u.lo < start && u.hi >= start {
			return fmt.Sprintf("a block from line %d crosses the section start", u.lo)
		}
		if u.lo <= end && u.hi > end {
			return fmt.Sprintf("a block from line %d crosses the section end", u.lo)
		}
	}
	return ""
}

// cmDisagreement reports the first disagreement between the scanner and the
// CommonMark oracle for the whole file and for the block spans around [start,end]; ""
// means they agree. A parser failure is a disagreement.
func cmDisagreement(lines []string, sc scanned, start, end int) string {
	v, err := cmParse(lines)
	if err != nil {
		return err.Error()
	}
	if d := cmFileDisagreement(sc, v); d != "" {
		return d
	}
	if start > 0 {
		return cmSectionDisagreement(v, start, end)
	}
	return ""
}
