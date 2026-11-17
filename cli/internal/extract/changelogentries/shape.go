// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	placeholderLine    = "{line}"
	placeholderVersion = "{version}"
)

// checkTemplate validates a path template. It must be a clean relative path
// that holds the form's one placeholder exactly once, no other brace, and the
// placeholder must share its path element with literal text. The values a
// placeholder takes (digits and dots) can then never form an element of their
// own, so a resolved path cannot leave the template's directory tree.
func checkTemplate(tpl, placeholder string) error {
	if tpl == "" || strings.ContainsAny(tpl, "\\$") || hasControl(tpl) || strings.HasPrefix(tpl, "/") ||
		strings.HasSuffix(tpl, "/") || path.Clean(tpl) != tpl {
		return fmt.Errorf("path template %q must be a clean repository-relative path", tpl)
	}
	if strings.Count(tpl, placeholder) != 1 {
		return fmt.Errorf("path template %q must hold %s exactly once", tpl, placeholder)
	}
	// A digit next to the placeholder would let two versions or lines name
	// the same file ("1{line}": 1 + 3.5 and 13.5 read as 13.5 and 1 + 3.5).
	if i := strings.Index(tpl, placeholder); i > 0 && isDigit(tpl[i-1]) ||
		i+len(placeholder) < len(tpl) && isDigit(tpl[i+len(placeholder)]) {
		return fmt.Errorf("path template %q has a digit next to %s", tpl, placeholder)
	}
	rest := strings.Replace(tpl, placeholder, "", 1)
	if strings.ContainsAny(rest, "{}") {
		return fmt.Errorf("path template %q holds a placeholder other than %s", tpl, placeholder)
	}
	for _, el := range strings.Split(tpl, "/") {
		if el == "." || el == ".." || strings.Contains(el, "..") {
			return fmt.Errorf("path template %q holds a dot element", tpl)
		}
		if el == placeholder {
			return fmt.Errorf("path template %q: %s must share its path element with literal text", tpl, placeholder)
		}
	}
	return nil
}

// hasControl reports any byte that is not printable ASCII (control, DEL,
// and every byte of a multi-byte character, so no Unicode or bidi text).
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e { // printable ASCII only
			return true
		}
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// notFinalRE is the word list of non-final wording, matched case-insensitively
// as whole words.
var notFinalRE = regexp.MustCompile(`(?i)\b(?:rc|alpha|beta|preview|pre[ -]?release|release candidate|candidate|draft|canary|next|nightly|snapshot|dev|unreleased|tbd|in progress|wip)\b`)

// tokenBoundary reports whether the byte c may sit next to a version token:
// whitespace or ASCII punctuation other than . - _ + (never a letter, digit
// or non-ASCII byte). Start and end of text are checked by the caller.
func tokenBoundary(c byte) bool {
	switch {
	case c == ' ' || c == '\t':
		return true
	case c == '.' || c == '-' || c == '_' || c == '+':
		return false
	case c >= 0x80, c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return false
	}
	return c > 0x20 && c < 0x7f
}

// headingProblem applies the strict rule to one heading of a per-version
// file. A heading may hold a digit only inside exactly one occurrence of the
// file's own version token ("x.y.z" or "vx.y.z"), bounded on both sides by the
// start or end of the text, whitespace or punctuation other than . - _ +.
// Any other digit, or a second occurrence, is EntryDuplicate; non-final
// wording is EntryNotFinal. The rule over-withholds on purpose: a heading
// such as "Upgrading from 2.4" or "2.5.1 / 2024-01-02" is refused, because a
// wrong pass is worse than a withheld entry. It is a known conservative limit.
func headingProblem(text, version string) (Code, string, bool) {
	if notFinalRE.MatchString(text) {
		return EntryNotFinal, "non-final wording", true
	}
	valid := 0
	masked := []byte(text)
	for from := 0; ; {
		i := strings.Index(text[from:], version)
		if i < 0 {
			break
		}
		i += from
		from = i + 1
		s, e := i, i+len(version)
		if s > 0 && text[s-1] == 'v' {
			s--
		}
		if (s > 0 && !tokenBoundary(text[s-1])) || (e < len(text) && !tokenBoundary(text[e])) {
			continue
		}
		valid++
		for k := s; k < e; k++ {
			masked[k] = ' '
		}
	}
	if valid > 1 {
		return EntryDuplicate, "the version token occurs more than once", true
	}
	for _, c := range masked {
		if c >= '0' && c <= '9' {
			return EntryDuplicate, "a digit outside the file's own version token", true
		}
	}
	return "", "", false
}

// resolveTemplate substitutes the placeholder and re-checks the result.
func resolveTemplate(tpl, placeholder, value string) (string, error) {
	p := strings.Replace(tpl, placeholder, value, 1)
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") ||
		strings.ContainsAny(p, "\x00\\{}") {
		return "", fmt.Errorf("resolved path %q is not a clean repository-relative path", p)
	}
	return p, nil
}

// lineOf is major.minor of a canonical final version.
func lineOf(version string) string {
	i := strings.LastIndexByte(version, '.')
	return version[:i]
}

// locateShape reads the two file shapes whose path depends on the tag.
func locateShape(r extract.PinnedReader, t Target, tag extract.Tag) (*Entry, error) {
	placeholder := placeholderLine
	if t.Form == FormPerVersionFile {
		placeholder = placeholderVersion
	}
	if err := checkTemplate(t.Path, placeholder); err != nil {
		return nil, fail(NoChangelogTarget, err.Error())
	}
	if t.Form == FormPerLineFile {
		return locatePerLine(r, t, tag)
	}
	return locatePerVersion(r, t, tag)
}

// locatePerLine resolves {line} and reads the file with the single-file rules,
// unchanged.
func locatePerLine(r extract.PinnedReader, t Target, tag extract.Tag) (*Entry, error) {
	version, ok := tagVersion(tag.Name)
	if !ok {
		// Same refusal as FormFile; the template is valid, the tag is not final.
		return nil, fail(EntryNotFinal, fmt.Sprintf("tag %q is not a final release", tag.Name))
	}
	p, err := resolveTemplate(t.Path, placeholderLine, lineOf(version))
	if err != nil {
		return nil, fail(NoChangelogTarget, err.Error())
	}
	inner := t
	inner.Form, inner.Path = FormFile, p
	e, err := Locate(r, inner, tag)
	if err != nil {
		return nil, err
	}
	e.Source.Form = FormPerLineFile
	return e, nil
}

// locatePerVersion reads the file named for the tag's exact version; the whole
// file is the entry. The tiling, residue, item, bound, empty and referral
// rules are those of a section.
func locatePerVersion(r extract.PinnedReader, t Target, tag extract.Tag) (*Entry, error) {
	if t.Component == "" || strings.ContainsRune(t.Component, 0) {
		return nil, fail(NoChangelogTarget, "component is empty")
	}
	if rr, err := extract.ParseRepo(t.Repo.Key); err != nil || rr.Key != t.Repo.Key {
		return nil, fail(NoChangelogTarget, fmt.Sprintf("repo %q is not a canonical repository key", t.Repo.Key))
	}
	if t.HeadingPattern != "" || len(t.BoundaryPatterns) > 0 {
		return nil, fail(NoChangelogTarget, "a per-version file has no heading patterns")
	}
	maxBytes := MaxFileBytes
	if t.MaxBytes < 0 || t.MaxBytes > MaxFileBytes {
		return nil, fail(NoChangelogTarget, fmt.Sprintf("MaxBytes %d outside 0..%d", t.MaxBytes, MaxFileBytes))
	}
	if t.MaxBytes > 0 {
		maxBytes = t.MaxBytes
	}
	version, ok := tagVersion(tag.Name)
	if !ok {
		return nil, fail(EntryNotFinal, fmt.Sprintf("tag %q is not a final release", tag.Name))
	}
	if !extract.IsCommitSHA(tag.Commit) {
		return nil, fail(SourceNotPinnedGit, "tag has no full commit")
	}
	p, err := resolveTemplate(t.Path, placeholderVersion, version)
	if err != nil {
		return nil, fail(NoChangelogTarget, err.Error())
	}
	raw, err := r.Read(t.Repo, tag.Commit, p)
	if err != nil {
		if errors.Is(err, extract.ErrNotFound) {
			return nil, fail(PathMissingAtTag, p)
		}
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, fail(EntryOverBound, fmt.Sprintf("file is %d bytes, bound %d", len(raw), maxBytes))
	}
	lines, err := splitLines(raw)
	if err != nil {
		return nil, err
	}
	start, end := 1, len(lines)
	for start <= end && isBlank(lines[start-1]) {
		start++
	}
	for end >= start && isBlank(lines[end-1]) {
		end--
	}
	if start > end {
		return nil, fail(EntryEmpty, "the file has no content")
	}
	if end-start+1 > MaxSectionLines {
		return nil, fail(EntryOverBound, fmt.Sprintf("file is %d lines, bound %d", end-start+1, MaxSectionLines))
	}
	sc := scan(lines)
	// The same whole-file refusals as a section in a single file.
	if sc.containerFence != 0 {
		return nil, fail(EntryParseResidue, fmt.Sprintf("line %d cannot be read: a fence without its container, or a multi-line HTML block", sc.containerFence))
	}
	if d := cmDisagreement(lines, sc, start, end); d != "" {
		return nil, fail(EntryParseResidue, "commonmark-disagreement: "+d)
	}
	for _, n := range sc.html {
		if n >= start && n <= end {
			return nil, fail(EntryParseResidue, fmt.Sprintf("line %d starts an HTML block inside the entry, which is not read", n))
		}
	}
	e := &Entry{
		Component: t.Component, Tag: tag.Name, Version: version, TagCommit: tag.Commit,
		Source: Source{
			Repo: t.Repo.Key, Commit: tag.Commit, Path: p,
			FileDigest: hexSum(raw), Form: t.Form,
		},
		// The file has no version heading of its own: HeadingLine is 0.
		Section:   Section{HeadingLine: 0, StartLine: start, EndLine: end},
		Structure: []Heading{},
		Items:     []Item{},
	}
	residue := 0
	for n := start; n <= end; n++ {
		e.Tiling.Lines++
		switch sc.kind[n-1] {
		case kHeading:
			e.Tiling.Headings++
		case kBlank:
			e.Tiling.Blanks++
		case kLinkDef:
			e.Tiling.LinkDefs++
		case kItem:
			e.Tiling.ItemLines++
		default:
			residue++
		}
	}
	if sc.openFence >= start && sc.openFence <= end {
		residue++
	}
	if residue > 0 {
		return nil, fail(EntryParseResidue, fmt.Sprintf("%d line(s) of the file are not a heading, blank, link definition or item", residue))
	}
	for _, h := range sc.headings {
		if h.Line >= start && h.Line <= end {
			// The file name carries the version; the heading may name only it.
			if code, why, bad := headingProblem(h.Text, version); bad {
				return nil, fail(code, fmt.Sprintf("line %d: heading %q: %s", h.Line, h.Text, why))
			}
			// A heading cannot straddle the end: trailing blanks are trimmed,
			// so the last line is content; checked for parity with a section.
			if h.EndLine > end {
				return nil, fail(EntryParseResidue, "a heading straddles the end of the file")
			}
			e.Structure = append(e.Structure, Heading{Level: h.Level, Text: h.Text, Kind: "sub", Line: h.Line, EndLine: h.EndLine})
		}
	}
	var stack []Heading
	seen := map[string]int{}
	hi := 0
	for _, it := range sc.items {
		if it.Start < start || it.Start > end {
			continue
		}
		if it.End > end {
			return nil, fail(EntryParseResidue, "an item reaches past the end of the file")
		}
		for hi < len(e.Structure) && e.Structure[hi].Line < it.Start {
			h := e.Structure[hi]
			hi++
			for len(stack) > 0 && stack[len(stack)-1].Level >= h.Level {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, h)
		}
		hp := make([]string, len(stack))
		for i, s := range stack {
			hp[i] = s.Text
		}
		kind := "list"
		if it.Block {
			kind = "block"
		}
		body := strings.Join(lines[it.Start-1:it.End], "\n")
		d := sha256.New()
		for pi, part := range []string{t.Component, version, strings.Join(hp, "\x1f"), it.Marker, body} {
			if pi > 0 {
				d.Write([]byte{0})
			}
			d.Write([]byte(part))
		}
		item := Item{
			Digest: hex.EncodeToString(d.Sum(nil)), StartLine: it.Start, EndLine: it.End,
			HeadingPath: hp, Marker: it.Marker, Kind: kind,
		}
		seen[item.Digest]++
		item.Occurrence = seen[item.Digest]
		e.Items = append(e.Items, item)
	}
	if len(e.Items) == 0 {
		return nil, fail(EntryEmpty, "the file has no item")
	}
	referral := 0
	for _, it := range e.Items {
		if isReferral(strings.Join(lines[it.StartLine-1:it.EndLine], "\n")) {
			referral++
		}
	}
	if referral == len(e.Items) {
		return nil, fail(EntryRefersElsewhere, "every item only refers to another source")
	}
	e.Section.Digest = hexSum([]byte(strings.Join(lines[start-1:end], "\n") + "\n"))
	return e, nil
}
