// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Locate reads the target's changelog file at the tag's own commit and
// returns the proof that the tag's entry was read in full. It returns a
// *Failure (see CodeOf) for every reason an entry is withheld; any other
// error is a read failure and is not a reason. It reads at most one file,
// only through r, and never falls back to another path, tag or version.
func Locate(r extract.PinnedReader, t Target, tag extract.Tag) (*Entry, error) {
	switch t.Form {
	case FormPerLineFile, FormPerVersionFile:
		return locateShape(r, t, tag)
	}
	c, version, err := prepare(t, tag)
	if err != nil {
		return nil, err
	}
	raw, err := r.Read(t.Repo, tag.Commit, t.Path)
	if err != nil {
		if errors.Is(err, extract.ErrNotFound) {
			return nil, fail(PathMissingAtTag, t.Path)
		}
		return nil, err
	}
	return entryFromBytes(t, c, tag, version, raw)
}

// LocateBytes is Locate over file bytes the caller already holds. It runs the
// same checks and the same parser as Locate, so a caller that must verify an
// entry re-derives it from the bytes instead of trusting a supplied Entry.
func LocateBytes(t Target, tag extract.Tag, raw []byte) (*Entry, error) {
	c, version, err := prepare(t, tag)
	if err != nil {
		return nil, err
	}
	return entryFromBytes(t, c, tag, version, raw)
}

// prepare checks the target and the tag before any byte is read.
func prepare(t Target, tag extract.Tag) (compiled, string, error) {
	var zero compiled
	switch t.Form {
	case "":
		return zero, "", fail(NoChangelogTarget, "target has no form")
	case FormGithubRelease:
		return zero, "", fail(SourceNotPinnedGit, "a release body is mutable and has no commit")
	case FormPostTag:
		return zero, "", fail(EntryNotAtTag, "the entry lands after the tag")
	case FormDocsPage:
		return zero, "", fail(ShapeNotPerTag, "an upgrade guide or docs page is not a per-tag changelog")
	case FormMonorepo:
		return zero, "", fail(MonorepoEntryAmbiguous, "monorepo entries are not read in this version")
	case FormFile:
	default:
		return zero, "", fail(ShapeNotPerTag, fmt.Sprintf("form %q is not read", t.Form))
	}
	c, err := t.compile()
	if err != nil {
		return zero, "", fail(NoChangelogTarget, err.Error())
	}
	version, ok := tagVersion(tag.Name)
	if !ok {
		return zero, "", fail(EntryNotFinal, fmt.Sprintf("tag %q is not a final release", tag.Name))
	}
	if !extract.IsCommitSHA(tag.Commit) {
		return zero, "", fail(SourceNotPinnedGit, "tag has no full commit")
	}
	return c, version, nil
}

// entryFromBytes is the one parser: size bound, line split, scan, section.
func entryFromBytes(t Target, c compiled, tag extract.Tag, version string, raw []byte) (*Entry, error) {
	if len(raw) > c.max {
		return nil, fail(EntryOverBound, fmt.Sprintf("file is %d bytes, bound %d", len(raw), c.max))
	}
	lines, err := splitLines(raw)
	if err != nil {
		return nil, err
	}
	lines, err = maskPreface(lines, c)
	if err != nil {
		return nil, err
	}
	sc := scan(lines)

	// Which headings name which release.
	type rel struct {
		h     heading
		final string // canonical version, "" when not final
		other bool   // a boundary-pattern heading
	}
	rels := make([]rel, 0, len(sc.headings))
	var named []int
	for i, h := range sc.headings {
		x := rel{h: h}
		if m := c.heading.FindStringSubmatch(h.Text); m != nil && finalVersion(m[1]) && linkTargetMatches(c.heading, m, t.Repo.Key) {
			x.final = m[1]
		} else {
			for _, b := range c.boundary {
				if b.MatchString(h.Text) {
					x.other = true
					break
				}
			}
		}
		rels = append(rels, x)
		if x.final == version {
			named = append(named, i)
		}
	}
	// Until the entry is located there is no cut point: a refusal of the
	// location is reported after the checks of the whole file, as before.
	refuse := func(f error) (*Entry, error) {
		if err := fileAgreement(lines, sc); err != nil {
			return nil, err
		}
		cm, cmErr := cmParse(lines)
		if cmErr != nil {
			return nil, fail(EntryParseResidue, "commonmark-disagreement: "+cmErr.Error())
		}
		if d := cmFileDisagreement(sc, cm); d != "" {
			return nil, fail(EntryParseResidue, "commonmark-disagreement: "+d)
		}
		return nil, f
	}
	switch {
	case len(named) > 1:
		return refuse(fail(EntryDuplicate, fmt.Sprintf("%d headings name %s", len(named), version)))
	case len(named) == 0:
		for _, x := range rels {
			if x.final == "" && firstVersionToken(x.h.Text) == version {
				return refuse(fail(EntryNotFinal, fmt.Sprintf("line %d names %s but is not a final release heading", x.h.Line, version)))
			}
		}
		return refuse(fail(EntryMissing, "no heading names "+version))
	}
	// A second heading that names the version in another wording (not a
	// final heading, not a boundary pattern) makes the entry ambiguous.
	// A boundary-pattern heading that names the version exactly is the same
	// kind of second heading (a pre-release suffix, "-rc1", is not exact).
	for _, x := range rels {
		if x.final != "" {
			continue
		}
		if !x.other && firstVersionToken(x.h.Text) == version || x.other && holdsVersionToken(x.h.Text, version) {
			return refuse(fail(EntryDuplicate, fmt.Sprintf("line %d names %s in another wording", x.h.Line, version)))
		}
	}
	vi := named[0]
	vh := sc.headings[vi]

	// Section end: the next heading of the same or a higher level.
	end := len(lines)
	// cut is the number of lines the file-wide agreement checks cover: every
	// line up to and including the heading that follows the entry, or the
	// whole file when nothing follows.
	cut := len(lines)
	for j := vi + 1; j < len(rels); j++ {
		x := rels[j]
		if x.h.Level > vh.Level {
			if x.final != "" || x.other {
				return refuse(fail(EntryBoundaryUnproven, fmt.Sprintf("line %d: a release heading nested inside the entry", x.h.Line)))
			}
			continue
		}
		if x.final == "" && !x.other {
			// A same-level heading of a closed inner style (never a release
			// heading, never a second one for a first-only style) is read as
			// part of the entry; any other one ends it unproven.
			if x.h.Level == vh.Level && innerHeading(c, x.h.Text, j == vi+1 && onlyBlanksBetween(sc, vh.EndLine, x.h.Line)) {
				continue
			}
			return refuse(fail(EntryBoundaryUnproven, fmt.Sprintf("line %d: heading %q ends the entry but names no release", x.h.Line, x.h.Text)))
		}
		end = x.h.Line - 1
		cut = x.h.EndLine
		break
	}

	// Scope of the file-wide checks (C1): the prefix up to the following
	// heading. The prefix is scanned and parsed again on its own, so nothing
	// below the cut can refuse the read, and everything derived below comes
	// from the lines that were checked. The prefix scan must reproduce the
	// whole-file headings up to the cut exactly; any difference is refused.
	lines = lines[:cut]
	whole := sc
	sc = scan(lines)
	if !sameHeadingsUpTo(whole.headings, sc.headings, cut) {
		return nil, fail(EntryParseResidue, "the prefix scan disagrees with the file scan")
	}
	if err := fileAgreement(lines, sc); err != nil {
		return nil, err
	}
	cm, cmErr := cmParse(lines)
	if cmErr != nil {
		return nil, fail(EntryParseResidue, "commonmark-disagreement: "+cmErr.Error())
	}
	if d := cmFileDisagreement(sc, cm); d != "" {
		return nil, fail(EntryParseResidue, "commonmark-disagreement: "+d)
	}
	for end > vh.Line && isBlank(lines[end-1]) {
		end--
	}
	start := vh.Line
	if end-start+1 > MaxSectionLines {
		return nil, fail(EntryOverBound, fmt.Sprintf("section is %d lines, bound %d", end-start+1, MaxSectionLines))
	}

	if d := cmSectionDisagreement(cm, start, end); d != "" {
		return nil, fail(EntryParseResidue, "commonmark-disagreement: "+d)
	}

	checked := prefixBytes(raw, cut)
	e := &Entry{
		Component: t.Component, Tag: tag.Name, Version: version, TagCommit: tag.Commit,
		Source: Source{
			Repo: t.Repo.Key, Commit: tag.Commit, Path: t.Path,
			FileDigest: hexSum(raw), Form: t.Form,
			CheckedBytes: checked, CheckedDigest: hexSum(raw[:checked]),
		},
		Section:   Section{HeadingLine: vh.Line, StartLine: start, EndLine: end},
		Structure: []Heading{},
		Items:     []Item{},
	}

	// Tiling over the section.
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
		case kComment:
			e.Tiling.Comments++
		default:
			residue++
		}
	}
	for _, n := range sc.html {
		if n >= start && n <= end && !sc.comment[n] {
			return nil, fail(EntryParseResidue, fmt.Sprintf("line %d starts an HTML block inside the entry, which is not read", n))
		}
	}
	if sc.openFence >= start && sc.openFence <= end {
		residue++ // a fence that never closes swallows the rest of the file
	}
	if residue > 0 {
		return nil, fail(EntryParseResidue, fmt.Sprintf("%d line(s) of the section are not a heading, blank, link definition or item", residue))
	}
	// A heading must not straddle the end, nor an item reach past it.
	for _, h := range sc.headings {
		if h.Line <= end && h.EndLine > end {
			return nil, fail(EntryParseResidue, "a heading straddles the section end")
		}
	}

	var stack []Heading
	for _, h := range sc.headings {
		if h.Line < start || h.Line > end {
			continue
		}
		hh := Heading{Level: h.Level, Text: h.Text, Kind: "sub", Line: h.Line, EndLine: h.EndLine}
		if h.Line == vh.Line {
			hh.Kind = "version"
		}
		e.Structure = append(e.Structure, hh)
	}
	seen := map[string]int{}
	hi := 0
	for _, it := range sc.items {
		if it.Start < start || it.Start > end {
			continue
		}
		if it.End > end {
			return nil, fail(EntryParseResidue, "an item reaches past the section end")
		}
		// Sub-heading path at the item's start.
		for hi < len(e.Structure) && e.Structure[hi].Line < it.Start {
			h := e.Structure[hi]
			hi++
			if h.Kind == "version" {
				continue
			}
			for len(stack) > 0 && stack[len(stack)-1].Level >= h.Level {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, h)
		}
		path := make([]string, len(stack))
		for i, s := range stack {
			path[i] = s.Text
		}
		kind := "list"
		if it.Block {
			kind = "block"
		}
		body := strings.Join(lines[it.Start-1:it.End], "\n")
		d := sha256.New()
		for pi, part := range []string{t.Component, version, strings.Join(path, "\x1f"), it.Marker, body} {
			if pi > 0 {
				d.Write([]byte{0})
			}
			d.Write([]byte(part))
		}
		item := Item{
			Digest: hex.EncodeToString(d.Sum(nil)), StartLine: it.Start, EndLine: it.End,
			HeadingPath: path, Marker: it.Marker, Kind: kind,
		}
		// An identical item repeated under the same heading has the same
		// digest, and so the same reviewed disposition; Occurrence tells the
		// copies apart.
		seen[item.Digest]++
		item.Occurrence = seen[item.Digest]
		e.Items = append(e.Items, item)
	}
	if len(e.Items) == 0 {
		return nil, fail(EntryEmpty, "the entry has no item")
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

	sec := strings.Join(lines[start-1:end], "\n") + "\n"
	e.Section.Digest = hexSum([]byte(sec))
	return e, nil
}

// onlyBlanksBetween reports whether every line strictly between line a and
// line b is blank.
func onlyBlanksBetween(sc scanned, a, b int) bool {
	for n := a + 1; n < b; n++ {
		if sc.kind[n-1] != kBlank {
			return false
		}
	}
	return true
}

// innerHeading reports whether a same-level heading of the given text is kept
// inside the entry by one of the row's inner heading styles. first says the
// heading is the first heading after the release heading with nothing but
// blank lines between them.
func innerHeading(c compiled, text string, first bool) bool {
	for _, in := range c.inner {
		if in.firstOnly && !first {
			continue
		}
		if in.re.MatchString(text) {
			return true
		}
	}
	return false
}

// linkTargetMatches is the post-match check of a heading style that carries a
// link target: the target must name the row's repository and the heading's own
// version ("v"+version), or, for a target that names a release line
// ("release-x.y"), the line of the version. A style without the groups is not
// affected.
func linkTargetMatches(re *regexp.Regexp, m []string, repoKey string) bool {
	slug, ref, line := "", "", ""
	has := false
	for i, n := range re.SubexpNames() {
		switch n {
		case "slug":
			slug, has = m[i], true
		case "ref":
			ref = m[i]
		case "line":
			line = m[i]
		}
	}
	if !has {
		return true
	}
	if "github.com/"+slug != repoKey {
		return false
	}
	if line != "" {
		// "release-<line>": the target is the release line of the version.
		return finalVersion(m[1]) && line == lineOf(m[1])
	}
	return ref == "v"+m[1]
}

// fileAgreement is the scanner-only part of the file-wide checks: a fence that
// cannot be read without its container, or a multi-line HTML block.
func fileAgreement(lines []string, sc scanned) error {
	if sc.containerFence != 0 {
		return fail(EntryParseResidue, fmt.Sprintf("line %d cannot be read: a fence without its container, or a multi-line HTML block", sc.containerFence))
	}
	return nil
}

// sameHeadingsUpTo reports whether prefix holds exactly the headings of whole
// that end at or before line cut.
func sameHeadingsUpTo(whole, prefix []heading, cut int) bool {
	n := 0
	for _, h := range whole {
		if h.EndLine > cut {
			break
		}
		if n >= len(prefix) || prefix[n] != h {
			return false
		}
		n++
	}
	return n == len(prefix)
}

// prefixBytes is the length in bytes of the first n lines of raw, counting
// their original line breaks.
func prefixBytes(raw []byte, n int) int {
	if n <= 0 {
		return 0
	}
	c := 0
	for i, b := range raw {
		if b == '\n' {
			c++
			if c == n {
				return i + 1
			}
		}
	}
	return len(raw)
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

var tokenRE = regexp.MustCompile(`(?:^|[^0-9A-Za-z.])[vV]?([0-9]+\.[0-9]+\.[0-9]+)`)

// firstVersionToken is the first x.y.z token of a heading text, "" when none.
func firstVersionToken(text string) string {
	m := tokenRE.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

var (
	referralRE = regexp.MustCompile(`(?i)^(?:please\s+)?(?:see|refer(?:\s+to)?|moved\s+to|available\s+(?:at|in)|(?:the\s+)?(?:changes?|notes?|changelog)\s+(?:is|are)\s+(?:listed|documented|described|published|kept|maintained)\s+(?:in|at|on))\b`)
	mdLinkRE   = regexp.MustCompile(`\[[^\]]*\]\([^)]*\)|\[[^\]]*\]\[[^\]]*\]|<https?://[^>]*>|https?://\S+`)
	bulletRE   = regexp.MustCompile(`^(?:[*+-]|[0-9]{1,9}[.)])[ \t]+`)
)

// isReferral reports whether an item only points elsewhere: it starts with
// "see ...", "refer to ..." and the like, or holds nothing but links.
func isReferral(item string) bool {
	text := strings.TrimSpace(bulletRE.ReplaceAllString(item, ""))
	if referralRE.MatchString(text) {
		return true
	}
	rest := strings.TrimSpace(mdLinkRE.ReplaceAllString(text, ""))
	rest = strings.Trim(rest, " \t\n.,;:-*_()[]")
	return rest == ""
}

// prefaceOpen and prefaceClose are the only lines of the C3 block, exactly.
const (
	prefaceOpen  = "<details>"
	prefaceClose = "</details>"
)

// prefaceBanned are substrings that must not occur between the two lines of
// a C3 block (case-insensitive): anything that can open another HTML block
// kind that runs past a blank line or swallows what follows.
var prefaceBanned = []string{"<!", "<?", "<script", "<pre", "<style", "<textarea", "<details", "</details"}

// maskPreface is reader case C3: one balanced `<details>` ... `</details>`
// block wholly above the first release heading of the file may be skipped.
// The block is not part of any entry. Its lines are returned blank, so line
// numbers do not move; every line outside it is still read, scanned and
// compared with the CommonMark oracle exactly as before. The raw bytes, and
// so the checked digest, still cover the block.
//
// When no line is exactly `<details>` above the first release heading,
// lines come back unchanged (and any HTML block anywhere is judged by the
// ordinary checks). When one is, every condition below must hold or the file
// is refused: the closer exists, is the only one, is also above the first
// release heading, both lines are at column zero between blank lines (or the
// file start), nothing between them can open another HTML block, a fence or
// a processing instruction, no heading in the block names a version or
// matches a release or boundary pattern, and the oracle reads both lines as
// HTML blocks of their own (so neither sits inside a fence, a comment or a
// container).
func maskPreface(lines []string, c compiled) ([]string, error) {
	sc := scan(lines)
	open := 0
	for i, l := range lines {
		if l == prefaceOpen && !sc.fenceBody[i] {
			open = i + 1
			break
		}
	}
	if open == 0 {
		return lines, nil
	}
	closeAt := 0
	for i := open; i < len(lines); i++ {
		if lines[i] == prefaceClose && !sc.fenceBody[i] {
			closeAt = i + 1
			break
		}
	}
	isRelease := func(text string) bool {
		if m := c.heading.FindStringSubmatch(text); m != nil && finalVersion(m[1]) {
			return true
		}
		for _, b := range c.boundary {
			if b.MatchString(text) {
				return true
			}
		}
		return false
	}
	first := 0
	for _, h := range sc.headings {
		if h.Line > open && closeAt != 0 && h.Line < closeAt {
			continue
		}
		if isRelease(h.Text) {
			first = h.Line
			break
		}
	}
	if first == 0 || first < open {
		return lines, nil // no release heading below the opener: not the C3 shape
	}
	bad := func(why string) ([]string, error) {
		return nil, fail(EntryParseResidue, "the HTML block above the first entry is not read: "+why)
	}
	if closeAt == 0 {
		return bad("unbalanced <details>")
	}
	if closeAt > first {
		return bad("the block reaches the first entry")
	}
	if (open > 1 && !isBlank(lines[open-2])) || (closeAt < len(lines) && !isBlank(lines[closeAt])) {
		return bad("the block is not set off by blank lines")
	}
	for i := open; i < closeAt-1; i++ {
		low := strings.ToLower(lines[i])
		for _, b := range prefaceBanned {
			if strings.Contains(low, b) {
				return bad("markup that is not read inside the block")
			}
		}
		if sc.fenceBody[i] || fenceBlockLine(lines[i]) {
			return bad("a fence inside the block")
		}
	}
	for _, h := range sc.headings {
		if h.Line > open && h.Line < closeAt && (isRelease(h.Text) || firstVersionToken(h.Text) != "") {
			return bad(fmt.Sprintf("heading at line %d names a version", h.Line))
		}
	}
	v, err := cmParse(lines)
	if err != nil {
		return nil, fail(EntryParseResidue, "commonmark-disagreement: "+err.Error())
	}
	if !v.htmlStart[open] || !v.htmlStart[closeAt] {
		return bad("the oracle does not read the opener and closer as HTML blocks")
	}
	out := make([]string, len(lines))
	copy(out, lines)
	for i := open - 1; i < closeAt; i++ {
		out[i] = ""
	}
	return out, nil
}

// fenceBlockLine reports whether l could open or close a fence.
func fenceBlockLine(l string) bool {
	_, _, ok := fenceOpen(l)
	return ok || fenceChars(l, '`', 3) || fenceChars(l, '~', 3)
}
