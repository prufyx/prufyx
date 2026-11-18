// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Reasons a proposal is refused (typed; the list is closed).
const (
	// NoRowNoTags: the source records no final release tag to try.
	NoRowNoTags = "NO_FINAL_TAGS"
	// NoRowNoCandidate: no closed candidate row located an entry at any tag.
	NoRowNoCandidate = "NO_CANDIDATE_LOCATES"
	// NoRowNonMarkdown: the changelog is at a known non-markdown path (toml or
	// yaml). Such a file is never read as markdown and no row is proposed.
	NoRowNonMarkdown = "NON_MARKDOWN_SOURCE"
	// NoRowPartialCoverage: the best candidate locates some but not all of the
	// scored tags; the same bar rows-check applies, so no row is emitted.
	NoRowPartialCoverage = "PARTIAL_COVERAGE"
)

// DefaultProposeTags is the number of newest final tags a proposal is scored on.
const DefaultProposeTags = 8

// candidatePaths is the closed, ordered vocabulary of places a changelog is
// tried at: first the single files, then the per-line templates, then the
// per-version templates. Order is the tie-break.
var candidatePaths = []struct{ Form, Path string }{
	{FormFile, "CHANGELOG.md"},
	{FormFile, "docs/CHANGELOG.md"},
	{FormFile, "HISTORY.md"},
	{FormFile, "NEWS.md"},
	{FormFile, "RELEASES.md"},
	{FormFile, "RELEASE_NOTES.md"},
	{FormPerLineFile, "CHANGELOG/CHANGELOG-{line}.md"},
	{FormPerLineFile, "changelogs/CHANGELOG-{line}.md"},
	{FormPerLineFile, "docs/changelog/{line}.md"},
	{FormPerLineFile, "docs/releases/{line}.md"},
	{FormPerVersionFile, "docs/releases/v{version}.md"},
	{FormPerVersionFile, "docs/releases/{version}.md"},
	{FormPerVersionFile, "releases/v{version}.md"},
	{FormPerVersionFile, "releases/{version}.md"},
	{FormPerVersionFile, "changelogs/v{version}.md"},
	{FormPerVersionFile, "changelogs/{version}.md"},
	{FormPerVersionFile, "docs/release-notes/{version}.md"},
	{FormPerVersionFile, "notes/coredns-{version}.md"},
}

// nonMarkdownProbes are known non-markdown changelog places. They are only
// tested for existence, to give the typed refusal; they are never parsed.
var nonMarkdownProbes = []string{
	"releases/v{version}.toml",
	"releases/{version}.toml",
	"changelogs/{version}.yaml",
	"changelogs/{version}.yml",
	"changelogs/v{version}.yaml",
}

// headingOrder and boundaryOrder fix the order the closed styles are tried in.
var headingOrder = []string{
	"version-v-prefixed", "version-plain", "version-bracketed", "version-bracketed-date",
	"version-dash-date", "version-slash-date",
	"version-space-date", "version-v-slash-date", "version-linked-paren-date", "release-v-slash-date",
}

var boundaryOrder = []string{
	"unreleased", "unreleased-bracketed", "prerelease-plain", "prerelease-v-prefixed",
	"main-unreleased", "main-unreleased-parenthesised",
	"master-unreleased", "line-heading-v", "prerelease-linked-paren-date",
}

// Hit is one tag of a proposal's hit table.
type Hit struct {
	Tag     string `json:"tag"`
	Located bool   `json:"located"`
	Code    Code   `json:"code,omitempty"`
}

// Proposal is the chosen row with how it scored.
type Proposal struct {
	Row     rowData
	Hits    []Hit
	Located int
}

// MarshalJSON renders {"row": ..., "located": n, "tags": n, "hits": [...]}.
func (p Proposal) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Row     rowData `json:"row"`
		Located int     `json:"located"`
		Tags    int     `json:"tags"`
		Hits    []Hit   `json:"hits"`
	}{p.Row, p.Located, len(p.Hits), p.Hits})
}

// NoRow is the typed refusal of a proposal.
type NoRow struct{ Reason, Detail string }

func (n *NoRow) Error() string { return "NO-ROW " + n.Reason + ": " + n.Detail }

// versionLess orders final versions numerically.
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

// sortNewestFirst orders final tag names by numeric version, newest first,
// ties by name.
func sortNewestFirst(names []string) {
	sort.Slice(names, func(i, j int) bool {
		vi, _ := tagVersion(names[i])
		vj, _ := tagVersion(names[j])
		if vi != vj {
			return versionLess(vj, vi)
		}
		return names[i] < names[j]
	})
}

// ProposeRow tries the closed candidate rows over the newest final tags (or
// the given tag names) of repo and returns the one with the most located
// entries; ties go to the first candidate in the fixed order. It is read-only
// and deterministic. A *NoRow error is a typed refusal; any other error is an
// input or read failure. The row it returns loads through the same strict
// loader as targets.json.
func ProposeRow(src interface {
	extract.PinnedReader
	extract.TagSource
}, component, repo string, only []string) (*Proposal, error) {
	base := rowData{Component: component, Repo: repo}
	if _, err := (rowData{Component: component, Repo: repo, Form: FormPostTag}).target(); err != nil {
		return nil, fmt.Errorf("component or repo: %w", err)
	}
	rr := extract.RepoRef{Key: repo}
	all, err := src.Tags(rr)
	if err != nil {
		return nil, err
	}
	byName := map[string]extract.Tag{}
	var finals []string
	for _, t := range all {
		if _, dup := byName[t.Name]; dup {
			return nil, fmt.Errorf("tag %q is recorded twice", t.Name)
		}
		byName[t.Name] = t
		if _, ok := tagVersion(t.Name); ok {
			finals = append(finals, t.Name)
		}
	}
	var window []extract.Tag
	if len(only) > 0 {
		seen := map[string]bool{}
		for _, n := range only {
			t, ok := byName[n]
			if _, fin := tagVersion(n); !ok || !fin || seen[n] {
				return nil, fmt.Errorf("tag %q is not a distinct recorded final tag of %s", n, repo)
			}
			seen[n] = true
			window = append(window, t)
		}
	} else {
		sortNewestFirst(finals)
		if len(finals) > DefaultProposeTags {
			finals = finals[:DefaultProposeTags]
		}
		for _, n := range finals {
			window = append(window, byName[n])
		}
	}
	if len(window) == 0 {
		return nil, &NoRow{NoRowNoTags, "no final release tag is recorded for " + repo}
	}
	eval := func(t Target) ([]Hit, int, error) {
		hits := make([]Hit, 0, len(window))
		n := 0
		for _, tag := range window {
			_, err := Locate(src, t, tag)
			if err == nil {
				hits = append(hits, Hit{Tag: tag.Name, Located: true})
				n++
				continue
			}
			c, ok := CodeOf(err)
			if !ok {
				return nil, 0, fmt.Errorf("tag %s: %w", tag.Name, err)
			}
			hits = append(hits, Hit{Tag: tag.Name, Code: c})
		}
		return hits, n, nil
	}
	var best *Proposal
	try := func(r rowData) error {
		t, err := r.target()
		if err != nil {
			return fmt.Errorf("closed candidate %q does not load: %w", r.Path, err)
		}
		hits, n, err := eval(t)
		if err != nil {
			return err
		}
		if n > 0 && (best == nil || n > best.Located) {
			best = &Proposal{Row: r, Hits: hits, Located: n}
		}
		return nil
	}
	for _, c := range candidatePaths {
		r := base
		r.Form, r.Path = c.Form, c.Path
		if c.Form == FormPerVersionFile {
			if err := try(r); err != nil {
				return nil, err
			}
			continue
		}
		for _, h := range headingOrder {
			r.HeadingStyle, r.BoundaryStyles = h, append([]string(nil), boundaryOrder...)
			if err := try(r); err != nil {
				return nil, err
			}
		}
	}
	if best == nil {
		if p := nonMarkdownAt(src, rr, window[0]); p != "" {
			return nil, &NoRow{NoRowNonMarkdown, fmt.Sprintf("the changelog is at %s, which is not markdown and is not read", p)}
		}
		return nil, &NoRow{NoRowNoCandidate, fmt.Sprintf("none of the closed candidates located an entry at any of %d tags", len(window))}
	}
	if best.Located < len(window) {
		tab, _ := json.Marshal(best.Hits)
		return nil, &NoRow{NoRowPartialCoverage, fmt.Sprintf("the best candidate (%s) locates %d of the %d scored tags; hits %s", best.Row.Path, best.Located, len(window), tab)}
	}
	// Drop every boundary style the result does not need, in fixed order.
	for _, b := range boundaryOrder {
		if best.Row.BoundaryStyles == nil {
			break
		}
		var rest []string
		for _, x := range best.Row.BoundaryStyles {
			if x != b {
				rest = append(rest, x)
			}
		}
		if len(rest) == len(best.Row.BoundaryStyles) || len(rest) == 0 {
			continue
		}
		cand := best.Row
		cand.BoundaryStyles = rest
		t, err := cand.target()
		if err != nil {
			return nil, err
		}
		hits, n, err := eval(t)
		if err != nil {
			return nil, err
		}
		if n == best.Located && sameHits(hits, best.Hits) {
			best = &Proposal{Row: cand, Hits: hits, Located: n}
		}
	}
	// The row must survive the strict loader exactly as it will be committed.
	doc, err := json.Marshal(struct {
		Schema string    `json:"schema"`
		Rows   []rowData `json:"rows"`
	}{TargetsSchema, []rowData{best.Row}})
	if err != nil {
		return nil, err
	}
	if _, err := parseTargets(doc); err != nil {
		return nil, errors.New("proposed row is refused by the loader: " + err.Error())
	}
	return best, nil
}

func sameHits(a, b []Hit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nonMarkdownAt returns the probe path that exists at tag, or "". Existence
// only; the bytes are not interpreted.
func nonMarkdownAt(src extract.PinnedReader, repo extract.RepoRef, tag extract.Tag) string {
	v, ok := tagVersion(tag.Name)
	if !ok {
		return ""
	}
	for _, p := range nonMarkdownProbes {
		resolved := strings.Replace(p, "{version}", v, 1)
		if _, err := src.Read(repo, tag.Commit, resolved); err == nil {
			return p
		}
	}
	return ""
}
