// SPDX-License-Identifier: AGPL-3.0-only

// Package htmltable is a small strict table reader for vendor pages. It is
// not a general HTML parser: it understands comments, script/style (skipped),
// table, tr, th, td and the inline tags i, em, sup, b, strong, a, span, br,
// code and p. Anything else inside a table, nested tables, unclosed tags or
// a table with no rows is an error, never a guess. Input is untrusted: it is
// size capped, never executed, and nothing is fetched.
package htmltable

import (
	"errors"
	"fmt"
	"html"
	"strconv"
	"strings"
)

// MaxBytes caps the page size read.
const MaxBytes = 4 << 20

// ErrMarkup is wrapped by every rejection.
var ErrMarkup = errors.New("unsupported or malformed table markup")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMarkup, fmt.Sprintf(format, a...))
}

// Cell is one th or td. Text excludes sup content; Markers holds the trimmed
// sup texts in order.
type Cell struct {
	Header  bool
	Text    string
	Italic  bool
	Markers []string
	RowSpan int
	ColSpan int
}

// Table is one table's rows.
type Table struct{ Rows [][]Cell }

// Parse returns every table of the page in document order.
func Parse(page []byte) ([]Table, error) {
	if len(page) > MaxBytes {
		return nil, bad("page over %d bytes", MaxBytes)
	}
	s := string(page)
	var (
		tables  []Table
		inTable bool
		row     []Cell
		inRow   bool
		cur     *Cell
		buf     strings.Builder
		sup     strings.Builder
		italic  int
		supD    int
		anyIt   bool
	)
	flushCell := func() {
		cur.Text = strings.Join(strings.Fields(buf.String()), " ")
		cur.Italic = anyIt
		row = append(row, *cur)
		cur = nil
		buf.Reset()
		sup.Reset()
		italic, supD, anyIt = 0, 0, false
	}
	text := func(t string) {
		if cur == nil {
			return
		}
		t = html.UnescapeString(t)
		if supD > 0 {
			sup.WriteString(t)
			return
		}
		buf.WriteString(t)
		if strings.TrimSpace(t) != "" {
			if italic > 0 {
				anyIt = true
			}
		}
	}
	for i := 0; i < len(s); {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				j = len(s) - i
			}
			text(s[i : i+j])
			i += j
			continue
		}
		if strings.HasPrefix(s[i:], "<!--") {
			j := strings.Index(s[i+4:], "-->")
			if j < 0 {
				return nil, bad("unterminated comment")
			}
			i += 4 + j + 3
			continue
		}
		if i+1 < len(s) && (s[i+1] == '!' || s[i+1] == '?') {
			j := strings.IndexByte(s[i:], '>')
			if j < 0 {
				return nil, bad("unterminated declaration")
			}
			i += j + 1
			continue
		}
		end := tagEnd(s, i)
		if end < 0 {
			return nil, bad("unterminated tag")
		}
		raw := s[i+1 : end]
		i = end + 1
		closing := strings.HasPrefix(raw, "/")
		raw = strings.TrimPrefix(raw, "/")
		raw = strings.TrimSuffix(raw, "/")
		name, attrs := splitTag(raw)
		if name == "" {
			// A lone "<" in text: markup that is not a tag.
			return nil, bad("stray less-than")
		}
		if !closing && (name == "script" || name == "style") {
			k := indexCloseTag(s, i, name)
			if k < 0 {
				return nil, bad("unterminated %s", name)
			}
			e2 := strings.IndexByte(s[i+k:], '>')
			if e2 < 0 {
				return nil, bad("unterminated %s", name)
			}
			i += k + e2 + 1
			continue
		}
		if !inTable {
			if name == "table" && !closing {
				inTable = true
				tables = append(tables, Table{})
			}
			continue
		}
		switch name {
		case "table":
			if !closing {
				return nil, bad("nested table")
			}
			if cur != nil || inRow {
				return nil, bad("table closed inside a row")
			}
			if len(tables[len(tables)-1].Rows) == 0 {
				return nil, bad("table without rows")
			}
			inTable = false
		case "thead", "tbody", "tfoot", "colgroup", "col", "caption":
			if cur != nil || inRow {
				return nil, bad("%s inside a row", name)
			}
		case "tr":
			if closing {
				if !inRow || cur != nil {
					return nil, bad("misplaced </tr>")
				}
				t := &tables[len(tables)-1]
				t.Rows = append(t.Rows, row)
				row, inRow = nil, false
			} else {
				if inRow || cur != nil {
					return nil, bad("nested <tr>")
				}
				inRow = true
			}
		case "th", "td":
			if closing {
				if cur == nil {
					return nil, bad("misplaced </%s>", name)
				}
				flushCell()
				continue
			}
			if !inRow || cur != nil {
				return nil, bad("misplaced <%s>", name)
			}
			rs, err1 := span(attrs, "rowspan")
			cs, err2 := span(attrs, "colspan")
			if err1 != nil || err2 != nil {
				return nil, bad("span attribute")
			}
			cur = &Cell{Header: name == "th", RowSpan: rs, ColSpan: cs}
		case "i", "em":
			if cur != nil {
				if closing {
					italic--
					if italic < 0 {
						return nil, bad("unbalanced <%s>", name)
					}
				} else {
					italic++
				}
			}
		case "sup":
			if cur == nil {
				return nil, bad("sup outside a cell")
			}
			if closing {
				supD--
				if supD < 0 {
					return nil, bad("unbalanced <sup>")
				}
				if supD == 0 {
					if m := strings.TrimSpace(sup.String()); m != "" {
						cur.Markers = append(cur.Markers, m)
					}
					sup.Reset()
				}
			} else {
				supD++
			}
		case "b", "strong", "a", "span", "code", "p", "br", "div", "small", "abbr":
			if name == "br" && cur != nil {
				text(" ")
			}
		default:
			return nil, bad("tag <%s> not supported inside a table", name)
		}
	}
	if inTable || cur != nil || inRow || italic != 0 {
		return nil, bad("document ends inside a table")
	}
	return tables, nil
}

// tagEnd finds the closing '>' of the tag at s[i], honouring quotes.
func tagEnd(s string, i int) int {
	var q byte
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '>':
			return j
		}
	}
	return -1
}

func splitTag(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	k := strings.IndexAny(raw, " \t\r\n")
	name, attrs := raw, ""
	if k >= 0 {
		name, attrs = raw[:k], raw[k+1:]
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", ""
		}
	}
	return strings.ToLower(name), attrs
}

// span reads a rowspan/colspan attribute: absent is 1, otherwise 1..16.
func span(attrs, name string) (int, error) {
	low := strings.ToLower(attrs)
	n := strings.Count(low, name)
	if n == 0 {
		return 1, nil
	}
	if n > 1 {
		return 0, errors.New("duplicate")
	}
	k := strings.Index(low, name)
	if k > 0 && low[k-1] != ' ' && low[k-1] != '\t' && low[k-1] != '\n' {
		return 0, errors.New("attr")
	}
	rest := strings.TrimLeft(attrs[k+len(name):], " ")
	if !strings.HasPrefix(rest, "=") {
		return 0, errors.New("attr")
	}
	rest = strings.TrimLeft(rest[1:], " ")
	if rest == "" {
		return 0, errors.New("attr")
	}
	var v string
	if rest[0] == '"' || rest[0] == '\'' {
		e := strings.IndexByte(rest[1:], rest[0])
		if e < 0 {
			return 0, errors.New("attr")
		}
		v = rest[1 : 1+e]
	} else {
		v = rest
		if e := strings.IndexAny(v, " \t\r\n"); e >= 0 {
			v = v[:e]
		}
	}
	x, err := strconv.Atoi(v)
	if err != nil || x < 1 || x > 16 {
		return 0, errors.New("range")
	}
	return x, nil
}

// Grid expands the spans of the rows into a rectangular grid of
// cell texts, one string per column slot; it errors on overlapping spans or
// ragged rows.
func Grid(rows [][]Cell) ([][]string, error) {
	var grid [][]string
	width := 0
	for r, cells := range rows {
		for len(grid) <= r {
			grid = append(grid, nil)
		}
		c := 0
		for _, cell := range cells {
			for c < len(grid[r]) && grid[r][c] != "" {
				c++
			}
			for dr := 0; dr < cell.RowSpan; dr++ {
				for len(grid) <= r+dr {
					grid = append(grid, nil)
				}
				for dc := 0; dc < cell.ColSpan; dc++ {
					for len(grid[r+dr]) <= c+dc {
						grid[r+dr] = append(grid[r+dr], "")
					}
					if grid[r+dr][c+dc] != "" {
						return nil, bad("overlapping spans")
					}
					grid[r+dr][c+dc] = cell.Text + "\x01"
				}
			}
			c += cell.ColSpan
		}
		if len(grid[r]) > width {
			width = len(grid[r])
		}
	}
	if len(grid) > len(rows) {
		return nil, bad("rowspan reaches past the header rows")
	}
	for r := range grid {
		if len(grid[r]) != width {
			return nil, bad("ragged header row %d", r)
		}
		for c := range grid[r] {
			if grid[r][c] == "" {
				return nil, bad("gap in header row %d", r)
			}
			grid[r][c] = strings.TrimSuffix(grid[r][c], "\x01")
		}
	}
	return grid, nil
}

// indexCloseTag returns the offset from start of the first "</name" in s at or
// after start, compared ASCII case-insensitively without copying or
// lowercasing (a Unicode lowercase can change byte length), or -1.
func indexCloseTag(s string, start int, name string) int {
	n := len(name) + 2
	for i := start; i+n <= len(s); i++ {
		if s[i] != '<' || s[i+1] != '/' {
			continue
		}
		ok := true
		for j := 0; j < len(name); j++ {
			c := s[i+2+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != name[j] {
				ok = false
				break
			}
		}
		if ok {
			return i - start
		}
	}
	return -1
}
