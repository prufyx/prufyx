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
}

type scanned struct {
	lines    []string
	kind     []lineKind // index = line-1
	headings []heading
	items    []rawItem
	// openFence is the line of a fence still open at end of file, 0 if none.
	openFence int
}

var (
	atxRE       = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$`)
	atxCloseRE  = regexp.MustCompile(`(?:^|[ \t]+)#+[ \t]*$`)
	hrRE        = regexp.MustCompile(`^ {0,3}([-*_])(?:[ \t]*[-*_]){2,}[ \t]*$`)
	listRE      = regexp.MustCompile(`^([*+-]|[0-9]{1,9}[.)])(?:[ \t]|$)`)
	linkDefRE   = regexp.MustCompile(`^ {0,3}\[[^\]\n]+\]:[ \t]*\S.*$`)
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
	if s == "" {
		return nil, nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n"), nil
}

func isBlank(l string) bool { return strings.TrimSpace(l) == "" }

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

func fenceCloses(l string, ch byte, n int) bool {
	t := strings.TrimSpace(l)
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

// scan classifies every line of a file with one pass of a closed grammar.
// Fences are tracked from the first line, so a "#" inside fenced code is never
// a heading, wherever the fence opened.
func scan(lines []string) scanned {
	sc := scanned{lines: lines, kind: make([]lineKind, len(lines))}
	var cur *rawItem // open item, index into sc.items via pointer refreshed below
	curIdx := -1
	sawBlank := false
	inFence := false
	var fch byte
	fenceAt := 0
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
			sc.kind[i] = kItem
			extend(n)
			if fenceCloses(l, fch, flen) {
				inFence = false
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
				sc.kind[i] = kResidue
			default:
				closeItem()
				open(n, "", true)
				sc.kind[i] = kItem
			}
			inFence, fch, flen = true, ch, ln
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
			if cur != nil {
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
		sc.kind[i] = kItem
		prevAllowsLinkDef = false
	}
	_ = cur
	if inFence {
		sc.openFence = fenceAt
	}
	return sc
}
