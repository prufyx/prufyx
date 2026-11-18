// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

type lineKind uint8

const (
	kBlank lineKind = iota
	kHeading
	kLinkDef
	kItem
	kResidue
	kComment // a C2 single-line HTML comment: counted in the tiling, never an item
)

type heading struct {
	Line, EndLine int // EndLine > Line for a setext heading (its underline)
	Level         int
	Text          string
}

type rawItem struct {
	Start, End int
	Marker     string
	Block      bool // a paragraph or fenced block outside a list
	// para marks a plain-text paragraph block (not a fenced block); indent is
	// the marker column of a list item that started on an indented line (1 to
	// 3), 0 for any other item.
	para   bool
	indent int
}

type scanned struct {
	lines    []string
	kind     []lineKind // index = line-1
	headings []heading
	items    []rawItem
	// openFence is the line of a fence still open at end of file, 0 if none.
	openFence int
	// containerFence is the first line that proves a fence cannot be read
	// without its container: one opened inside a list item or block quote, or
	// an indented-opener fence whose inner lines or closer are indented
	// differently from its opener. 0 if none.
	containerFence int
	// html lists the lines that start an HTML block (up to 3 spaces, then "<"
	// and a tag name, "<!--", "<?", "<!X" or "<![CDATA["), outside fences.
	html []int
	// fenceBody marks (index = line-1) the lines read as the inside of a
	// fence: after its opener, up to but not including its closer.
	fenceBody []bool
	// comment holds the lines read as a C2 comment: one line, `<!-- text -->`
	// and nothing else, at column zero, between blank lines or the file
	// edges. Such a line is not content and is not an item.
	comment map[int]bool
}

var (
	htmlStartRE = regexp.MustCompile(`^ {0,3}(<!--|<\?|<!\[CDATA\[|<![A-Za-z]|</?[A-Za-z])`)
	htmlRawRE   = regexp.MustCompile(`(?i)^ {0,3}<(pre|script|style|textarea)(?:[ \t>]|$)`)
)

// htmlBlock reports whether l starts an HTML block and whether that block
// reaches past this line (a multi-line comment, or a pre, script, style or
// textarea block): hidden headings or fences can then follow.
func htmlBlock(l string) (starts, multiLine bool) {
	m := htmlStartRE.FindStringSubmatch(l)
	if m == nil {
		return false, false
	}
	t := strings.TrimLeft(l, " ")
	switch {
	case m[1] == "<!--":
		return true, !strings.Contains(t[4:], "-->")
	case m[1] == "<?":
		return true, !strings.Contains(t[2:], "?>")
	case m[1] == "<![CDATA[":
		return true, !strings.Contains(t[9:], "]]>")
	case strings.HasPrefix(m[1], "<!"):
		return true, !strings.Contains(t[2:], ">")
	}
	if r := htmlRawRE.FindStringSubmatch(l); r != nil {
		return true, !strings.Contains(strings.ToLower(l), "</"+strings.ToLower(r[1])+">")
	}
	return true, false
}

// commentMax bounds the text of a C2 comment.
const commentMax = 200

// isCommentLine reports whether l is exactly one HTML comment, `<!--`, text,
// `-->`, starting at column zero with nothing after the closer. The text is
// printable, at most commentMax bytes, and holds no `--` (so no second
// closer and no nested opener), no `<` and no `>`; it does not start with
// `>` or `->` (the abrupt-closing forms).
func isCommentLine(l string) bool {
	if !strings.HasPrefix(l, "<!--") || !strings.HasSuffix(l, "-->") || len(l) < 7 {
		return false
	}
	in := l[4 : len(l)-3]
	if len(in) > commentMax || strings.Contains(in, "--") || strings.ContainsAny(in, "<>") || strings.HasPrefix(in, "->") {
		return false
	}
	for i := 0; i < len(in); i++ {
		if in[i] < 0x20 && in[i] != ' ' {
			return false
		}
	}
	return true
}

var (
	atxRE      = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$`)
	atxCloseRE = regexp.MustCompile(`(?:^|[ \t]+)#+[ \t]*$`)
	hrRE       = regexp.MustCompile(`^ {0,3}([-*_])(?:[ \t]*[-*_]){2,}[ \t]*$`)
	listRE     = regexp.MustCompile(`^([*+-]|[0-9]{1,9}[.)])(?:[ \t]|$)`)
	// A link reference definition: a label, a colon, ONE destination and an
	// optional quoted title, nothing else on the line. The destination must
	// look like a link (absolute http(s) URL, or a path or fragment), so a
	// prose line such as "[BREAKING]: removed" is never taken for one. The
	// label starts with a non-blank character other than ^ (a footnote is not
	// a definition) and a bare destination holds no parenthesis or angle bracket.
	linkDefRE   = regexp.MustCompile(`^ {0,3}\[[^\s^\[\]\\][^\[\]\\]*\]:[ \t]*(?:<(?:https?://|/|\./|\.\./|#)[^<>\s]*>|(?:https?://|/|\./|\.\./|#)[^\s()<>]*)(?:[ \t]+(?:"[^"]*"|'[^']*'|\([^()]*\)))?[ \t]*$`)
	underlineRE = regexp.MustCompile(`^ {0,3}(={2,}|-{2,})[ \t]*$`)
	fenceRE     = regexp.MustCompile("^[ \t]*(`{3,}|~{3,})(.*)$")
	markerRE    = regexp.MustCompile(`^(?:[*+-]|[0-9]{1,9}[.)])[ \t]+\[([A-Z][A-Z0-9 _-]{0,30})\](?:[^(\[]|$)`)
)

// splitLines normalises line breaks and splits. A file whose every line break
// is CRLF is read as LF; any other carriage return, a byte order mark, a NUL
// or invalid UTF-8 is refused.
func splitLines(raw []byte) ([]string, error) {
	if !utf8.Valid(raw) {
		return nil, fail(EntryParseResidue, "file is not valid UTF-8")
	}
	s := string(raw)
	if strings.HasPrefix(s, "\xef\xbb\xbf") {
		return nil, fail(EntryParseResidue, "file starts with a byte order mark")
	}
	if strings.ContainsRune(s, 0) {
		return nil, fail(EntryParseResidue, "file contains a NUL byte")
	}
	if strings.Contains(s, "\r") {
		if strings.Count(s, "\r\n") != strings.Count(s, "\n") || strings.Count(s, "\r") != strings.Count(s, "\r\n") {
			return nil, fail(EntryParseResidue, "file mixes CRLF with other line breaks or carries a bare carriage return")
		}
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' && c != '\n' {
			return nil, fail(EntryParseResidue, "file contains a control byte")
		}
	}
	if s == "" {
		return nil, nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n"), nil
}

// isBlank is CommonMark blank: only ASCII spaces and tabs. A line of other
// Unicode white space (a no-break space, say) is text.
func isBlank(l string) bool { return strings.Trim(l, " \t") == "" }

var containerPrefixRE = regexp.MustCompile(`^(?:(?:[*+-]|[0-9]{1,9}[.)])(?:[ \t]+|$)|>[ \t]*)`)

// containerFence reports whether l opens a fence inside a list item or a
// block quote ("* ~~~", "1. ```", "> ~~~", "- * ~~~"). Such a fence is not
// tracked, so the shape is refused instead of read.
func containerFence(l string) bool {
	t := strings.TrimLeft(l, " \t")
	stripped := false
	for {
		m := containerPrefixRE.FindString(t)
		if m == "" {
			break
		}
		stripped = true
		t = t[len(m):]
	}
	if !stripped {
		return false
	}
	_, _, ok := fenceOpen(t)
	return ok
}

func atxHeading(l string) (level int, text string, ok bool) {
	m := atxRE.FindStringSubmatch(l)
	if m == nil {
		return 0, "", false
	}
	text = strings.TrimSpace(m[2])
	text = strings.TrimSpace(atxCloseRE.ReplaceAllString(text, ""))
	return len(m[1]), text, true
}

func fenceOpen(l string) (ch byte, n int, ok bool) {
	m := fenceRE.FindStringSubmatch(l)
	if m == nil {
		return 0, 0, false
	}
	if m[1][0] == '`' && strings.Contains(m[2], "`") {
		return 0, 0, false // inline code, not a fence
	}
	return m[1][0], len(m[1]), true
}

// indentWidth is the width of the leading white space, a tab counting as 4.
func indentWidth(l string) int {
	w := 0
	for i := 0; i < len(l); i++ {
		switch l[i] {
		case ' ':
			w++
		case '\t':
			w += 4
		default:
			return w
		}
	}
	return w
}

// fenceCloses reports whether l closes a fence opened with n characters of ch
// at indentation openIndent. A closing fence is indented at most 3 columns
// more than its opener; a line indented further is code inside the fence.
func leadingWS(l string) string {
	return l[:len(l)-len(strings.TrimLeft(l, " \t"))]
}

// fenceChars reports whether l, ignoring indentation, is a line of at least n
// fence characters ch (and nothing else but ASCII white space).
func fenceChars(l string, ch byte, n int) bool {
	t := strings.Trim(l, " \t")
	if len(t) < n {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] != ch {
			return false
		}
	}
	return true
}

func fenceCloses(l string, ch byte, n, openIndent int) bool {
	if indentWidth(l) > openIndent+3 {
		return false
	}
	t := strings.Trim(l, " \t") // only ASCII space and tab, never other Unicode white space
	if len(t) < n {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] != ch {
			return false
		}
	}
	return true
}

// commentRunEndsClean reports whether the run of one-line comments that holds
// line i (index) ends at a blank line or the end of the file. Each comment of
// the run is an HTML block of its own for a CommonMark parser (the type 2
// block ends on the line that holds the closer), which the oracle checks.
func commentRunEndsClean(lines []string, i int) bool {
	j := i
	for j+1 < len(lines) && isCommentLine(lines[j+1]) {
		j++
	}
	return j+1 == len(lines) || isBlank(lines[j+1])
}

// indentedListStart reports whether the indented line l (1 to 3 spaces, no
// tab) starts a list item in CommonMark terms while item cur (nil: none) is open, and the
// item's marker text. Four shapes, all closed:
//   - no item is open: any list marker with content starts a list;
//   - cur is a paragraph and a blank line came before: any list marker with
//     content starts a list;
//   - cur is a paragraph and no blank came before: a bullet marker with
//     content, or "1." / "1)" with content, interrupts the paragraph;
//   - cur is a list item that began on an indented line at exactly the same
//     column: the line is its next sibling.
//
// Anything else stays a continuation, as before; the CommonMark oracle still
// compares the result and refuses any disagreement.
func indentedListStart(l string, cur *rawItem, wasBlank bool) (string, bool) {
	ws := leadingWS(l)
	w := indentWidth(l)
	if w < 1 || w > 3 || strings.Contains(ws, "\t") {
		return "", false
	}
	t := l[len(ws):]
	if !listRE.MatchString(t) || isBlank(strings.TrimLeft(t, "*+-0123456789.) \t")) {
		return "", false // not a marker with content
	}
	bullet := t[0] == '*' || t[0] == '+' || t[0] == '-'
	switch {
	case cur == nil:
		// Nothing open (after a heading, a blank, a comment): a list starts.
	case cur.para && wasBlank:
	case cur.para && !wasBlank && (bullet || strings.HasPrefix(t, "1. ") || strings.HasPrefix(t, "1) ")):
	case !cur.para && !cur.Block && cur.indent == w:
	default:
		return "", false
	}
	marker := ""
	if m := markerRE.FindStringSubmatch(t); m != nil {
		marker = m[1]
	}
	return marker, true
}

// scan classifies every line of a file with one pass of a closed grammar.
// Fences are tracked from the first line, so a "#" inside fenced code is never
// a heading, wherever the fence opened.
func scan(lines []string) scanned {
	sc := scanned{lines: lines, kind: make([]lineKind, len(lines)), fenceBody: make([]bool, len(lines)), comment: map[int]bool{}}
	var cur *rawItem // open item, index into sc.items via pointer refreshed below
	curIdx := -1
	sawBlank := false
	inFence := false
	var fch byte
	fenceAt := 0
	fenceIndent := 0
	fenceResidue := false
	fenceIndented := false
	fenceIndentStr := ""
	var flen int
	closeItem := func() { cur = nil; curIdx = -1 }
	extend := func(n int) {
		sc.items[curIdx].End = n
		cur = &sc.items[curIdx]
	}
	open := func(n int, marker string, block bool) {
		sc.items = append(sc.items, rawItem{Start: n, End: n, Marker: marker, Block: block})
		curIdx = len(sc.items) - 1
		cur = &sc.items[curIdx]
	}
	prevAllowsLinkDef := true
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		n := i + 1
		if inFence {
			// A fence opened on an indented line is tracked without its
			// container, so only a closer at exactly the opener's indentation
			// is read; any other shape makes the file unreadable (file-wide stop).
			if fenceIndented && sc.containerFence == 0 && !isBlank(l) {
				// Exact leading white space, never a width: a line must carry the
				// opener's own white space as a prefix, and a tab anywhere in it
				// (tab stops differ from widths) is not read.
				ws := leadingWS(l)
				if !strings.HasPrefix(ws, fenceIndentStr) || strings.Contains(ws, "\t") ||
					(fenceChars(l, fch, flen) && ws != fenceIndentStr) {
					sc.containerFence = n
				}
			}
			if fenceResidue {
				sc.kind[i] = kResidue
			} else {
				sc.kind[i] = kItem
				if isBlank(l) {
					sc.kind[i] = kBlank // a blank inside a fence is still a blank line
				}
				extend(n)
			}
			if fenceCloses(l, fch, flen, fenceIndent) {
				inFence = false
			} else {
				sc.fenceBody[i] = true
			}
			prevAllowsLinkDef = false
			continue
		}
		if isBlank(l) {
			sc.kind[i] = kBlank
			sawBlank = true
			prevAllowsLinkDef = true
			continue
		}
		wasBlank := sawBlank
		sawBlank = false
		if lv, text, ok := atxHeading(l); ok {
			sc.kind[i] = kHeading
			sc.headings = append(sc.headings, heading{Line: n, EndLine: n, Level: lv, Text: text})
			closeItem()
			prevAllowsLinkDef = true
			continue
		}
		indented := l[0] == ' ' || l[0] == '\t'
		if sc.containerFence == 0 && containerFence(l) {
			sc.containerFence = n
		}
		if st, multi := htmlBlock(l); st {
			sc.html = append(sc.html, n)
			if multi && sc.containerFence == 0 {
				sc.containerFence = n
			}
		}
		if isCommentLine(l) && (n == 1 || wasBlank || sc.kind[i-1] == kComment) && commentRunEndsClean(lines, i) {
			sc.kind[i] = kComment
			sc.comment[n] = true
			closeItem()
			prevAllowsLinkDef = false
			continue
		}
		if hrRE.MatchString(l) {
			sc.kind[i] = kResidue
			closeItem()
			prevAllowsLinkDef = false
			continue
		}
		if ch, ln, ok := fenceOpen(l); ok {
			prevAllowsLinkDef = false
			switch {
			case indented && cur != nil:
				sc.kind[i] = kItem
				extend(n)
			case indented:
				// A fence with no item to own it: every line of it is residue,
				// so its contents are never read as headings or items.
				sc.kind[i] = kResidue
			default:
				closeItem()
				open(n, "", true)
				sc.kind[i] = kItem
			}
			fenceResidue = sc.kind[i] == kResidue
			inFence, fch, flen = true, ch, ln
			fenceIndent = indentWidth(l)
			fenceIndented = indented
			fenceIndentStr = leadingWS(l)
			if indented && strings.Contains(fenceIndentStr, "\t") && sc.containerFence == 0 {
				sc.containerFence = n
			}
			fenceAt = n
			continue
		}
		if !indented && listRE.MatchString(l) {
			closeItem()
			marker := ""
			if m := markerRE.FindStringSubmatch(l); m != nil {
				marker = m[1]
			}
			open(n, marker, false)
			sc.kind[i] = kItem
			prevAllowsLinkDef = false
			continue
		}
		if indented {
			if marker, ok := indentedListStart(l, cur, wasBlank); ok {
				w := indentWidth(l)
				closeItem()
				open(n, marker, false)
				sc.items[curIdx].indent = w
				sc.kind[i] = kItem
				prevAllowsLinkDef = false
				continue
			}
			if cur != nil {
				if cur.para && wasBlank && indentWidth(l) <= 3 && !strings.Contains(leadingWS(l), "\t") {
					// A blank line ended the paragraph: text indented by up to
					// three spaces opens the next one.
					closeItem()
					open(n, "", true)
					sc.items[curIdx].para = true
					sc.kind[i] = kItem
					prevAllowsLinkDef = false
					continue
				}
				sc.kind[i] = kItem
				extend(n)
			} else {
				sc.kind[i] = kResidue
			}
			prevAllowsLinkDef = false
			continue
		}
		// Column-zero text.
		if cur != nil && !wasBlank {
			sc.kind[i] = kItem // lazy continuation
			extend(n)
			prevAllowsLinkDef = false
			continue
		}
		if linkDefRE.MatchString(l) && prevAllowsLinkDef {
			sc.kind[i] = kLinkDef
			closeItem()
			continue
		}
		if i+1 < len(lines) && underlineRE.MatchString(lines[i+1]) {
			lv := 2
			if strings.TrimSpace(lines[i+1])[0] == '=' {
				lv = 1
			}
			sc.kind[i], sc.kind[i+1] = kHeading, kHeading
			sc.headings = append(sc.headings, heading{Line: n, EndLine: n + 1, Level: lv, Text: strings.TrimSpace(l)})
			closeItem()
			i++
			prevAllowsLinkDef = true
			continue
		}
		closeItem()
		open(n, "", true)
		sc.items[curIdx].para = true
		sc.kind[i] = kItem
		prevAllowsLinkDef = false
	}
	_ = cur
	if inFence {
		sc.openFence = fenceAt
	}
	return sc
}
