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
	case "":
		return nil, fail(NoChangelogTarget, "target has no form")
	case FormGithubRelease:
		return nil, fail(SourceNotPinnedGit, "a release body is mutable and has no commit")
	case FormPostTag:
		return nil, fail(EntryNotAtTag, "the entry lands after the tag")
	case FormDocsPage:
		return nil, fail(ShapeNotPerTag, "an upgrade guide or docs page is not a per-tag changelog")
	case FormMonorepo:
		return nil, fail(MonorepoEntryAmbiguous, "monorepo entries are not read in this version")
	case FormFile:
	case FormPerLineFile, FormPerVersionFile:
		return locateShape(r, t, tag)
	default:
		return nil, fail(ShapeNotPerTag, fmt.Sprintf("form %q is not read", t.Form))
	}
	c, err := t.compile()
	if err != nil {
		return nil, fail(NoChangelogTarget, err.Error())
	}
	version, ok := tagVersion(tag.Name)
	if !ok {
		return nil, fail(EntryNotFinal, fmt.Sprintf("tag %q is not a final release", tag.Name))
	}
	if !extract.IsCommitSHA(tag.Commit) {
		return nil, fail(SourceNotPinnedGit, "tag has no full commit")
	}
	raw, err := r.Read(t.Repo, tag.Commit, t.Path)
	if err != nil {
		if errors.Is(err, extract.ErrNotFound) {
			return nil, fail(PathMissingAtTag, t.Path)
		}
		return nil, err
	}
	if len(raw) > c.max {
		return nil, fail(EntryOverBound, fmt.Sprintf("file is %d bytes, bound %d", len(raw), c.max))
	}
	lines, err := splitLines(raw)
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
		if m := c.heading.FindStringSubmatch(h.Text); m != nil && finalVersion(m[1]) {
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
	switch {
	case len(named) > 1:
		return nil, fail(EntryDuplicate, fmt.Sprintf("%d headings name %s", len(named), version))
	case len(named) == 0:
		for _, x := range rels {
			if x.final == "" && firstVersionToken(x.h.Text) == version {
				return nil, fail(EntryNotFinal, fmt.Sprintf("line %d names %s but is not a final release heading", x.h.Line, version))
			}
		}
		return nil, fail(EntryMissing, "no heading names "+version)
	}
	// A second heading that names the version in another wording (not a
	// final heading, not a boundary pattern) makes the entry ambiguous.
	for _, x := range rels {
		if x.final == "" && !x.other && firstVersionToken(x.h.Text) == version {
			return nil, fail(EntryDuplicate, fmt.Sprintf("line %d names %s in another wording", x.h.Line, version))
		}
	}
	vi := named[0]
	vh := sc.headings[vi]

	// Section end: the next heading of the same or a higher level.
	end := len(lines)
	for j := vi + 1; j < len(rels); j++ {
		x := rels[j]
		if x.h.Level > vh.Level {
			if x.final != "" || x.other {
				return nil, fail(EntryBoundaryUnproven, fmt.Sprintf("line %d: a release heading nested inside the entry", x.h.Line))
			}
			continue
		}
		if x.final == "" && !x.other {
			return nil, fail(EntryBoundaryUnproven, fmt.Sprintf("line %d: heading %q ends the entry but names no release", x.h.Line, x.h.Text))
		}
		end = x.h.Line - 1
		break
	}
	for end > vh.Line && isBlank(lines[end-1]) {
		end--
	}
	start := vh.Line
	if end-start+1 > MaxSectionLines {
		return nil, fail(EntryOverBound, fmt.Sprintf("section is %d lines, bound %d", end-start+1, MaxSectionLines))
	}

	e := &Entry{
		Component: t.Component, Tag: tag.Name, Version: version, TagCommit: tag.Commit,
		Source: Source{
			Repo: t.Repo.Key, Commit: tag.Commit, Path: t.Path,
			FileDigest: hexSum(raw), Form: t.Form,
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
		default:
			residue++
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
