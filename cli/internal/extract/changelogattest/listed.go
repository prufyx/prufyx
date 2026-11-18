// SPDX-License-Identifier: AGPL-3.0-only

package changelogattest

import (
	"context"
	"fmt"
	"io/fs"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	ce "github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Identity of the listed-entries extractor.
const (
	// ListedIDPrefix is followed by the project slug of the reviewed row.
	ListedIDPrefix = "changelog.listed."
	// ListedVersion is bumped on any output change.
	ListedVersion = "1.0.0"
)

// ListedProof is the account of one listed-entries derivation.
type ListedProof struct {
	Component string      `json:"component"`
	Line      string      `json:"line"`
	Window    []string    `json:"window"`
	Entries   []*ce.Entry `json:"entries"`
	// Items is the number of items listed over the window.
	Items int `json:"items"`
}

// ListedResult is a derived listed-entries attestation candidate and its
// proof.
type ListedResult struct {
	Candidate extract.AttestationCandidate
	Proof     ListedProof
}

// AttestListed derives the listed-entries attestation of the line the pair
// ends in, for the component of one reviewed target row. The attestation holds
// only when EVERY final release of the to-line (x.y.0 and every patch release
// of the line) has its own entry, read in full by the pinned reader at that
// tag's own commit. No item is judged, no rule is listed, and no entry of the
// previous line is read: its finals are pinned (a root listing of each
// commit) only so that the attestation names the hop it covers. Any failure is a
// *changelogentries.Failure with its typed code, and nothing is attested; a
// partial window never yields an attestation.
func AttestListed(r extract.PinnedReader, t ce.Target, tags []extract.Tag, pair extract.VersionPair) (*ListedResult, error) {
	component, ok := ce.ComponentPURL(t)
	if !ok {
		return nil, failf(ce.NoChangelogTarget, "row %q has no pack component", t.Component)
	}
	if f, known := lineattest.LookupFamily(lineattest.FamilyChangelogListedEntries); !known || !f.Admits(component) {
		return nil, failf(ce.NoChangelogTarget, "component %s is not admitted by the listed-entries family", component)
	}
	if !reviewedRow(t) {
		return nil, failf(ce.NoChangelogTarget, "no reviewed changelog target for %s", t.Component)
	}
	byVersion, all, err := finalTags(tags)
	if err != nil {
		return nil, err
	}
	from, okf := parseRel(extract.Tag{Name: pair.FromTag, Commit: pair.FromCommit})
	to, okt := parseRel(extract.Tag{Name: pair.ToTag, Commit: pair.ToCommit})
	if !okf || !okt || from.maj != to.maj || from.min+1 != to.min {
		return nil, failf(ce.NotPreviousMinor, "%s -> %s is not a hop to the next minor line of one major", pair.From, pair.To)
	}
	for _, p := range []rel{from, to} {
		if got, ok := byVersion[p.version]; !ok || got.tag.Commit != p.tag.Commit {
			return nil, failf(ce.TagMoved, "the pair's tag %s is not in the tag index at that commit", p.tag.Name)
		}
	}
	if l, ok := lineattest.LineOf(pair.To); !ok || l != fmt.Sprintf("%d.%d", to.maj, to.min) {
		return nil, failf(ce.NotPreviousMinor, "%s has no minor line", pair.To)
	}
	line := fmt.Sprintf("%d.%d", to.maj, to.min)
	var lf, lt []rel
	for _, x := range all {
		switch {
		case x.maj == from.maj && x.min == from.min:
			lf = append(lf, x)
		case x.maj == to.maj && x.min == to.min:
			lt = append(lt, x)
		}
	}
	if len(lf) == 0 || len(lt) == 0 || len(lf) > lineattest.MaxReleases || len(lt) > lineattest.MaxReleases {
		return nil, failf(ce.NotPreviousMinor, "a line has no final release or more than %d", lineattest.MaxReleases)
	}
	if lt[0].pat != 0 {
		return nil, failf(ce.EntryMissing, "line %s has no final tag for %d.%d.0", line, to.maj, to.min)
	}

	// The previous line's finals are named by the attestation (it covers the
	// hop between the two lines) and must be commits the extractor read. Their
	// entries are not read and are not required: the root listing of each
	// commit pins that the tag's commit is in the mirror. A commit it cannot
	// list is a read failure, never a partial attestation.
	for _, w := range lf {
		if _, err := r.List(t.Repo, w.tag.Commit, ""); err != nil {
			return nil, err
		}
	}

	proof := ListedProof{Component: component, Line: line, Window: []string{}, Entries: []*ce.Entry{}}
	var sources []extract.SourceRef
	for _, w := range lt {
		e, err := ce.Locate(r, t, w.tag)
		if err != nil {
			return nil, err
		}
		if e.TagCommit != w.tag.Commit || e.Source.Commit != w.tag.Commit {
			return nil, failf(ce.TagMoved, "the entry of %s was not read at the tag commit", w.tag.Name)
		}
		proof.Window = append(proof.Window, w.tag.Name)
		proof.Entries = append(proof.Entries, e)
		proof.Items += len(e.Items)
		sources = append(sources, extract.SourceRef{ID: "changelog-" + w.version, Repo: t.Repo, Commit: w.tag.Commit, Path: e.Source.Path,
			StartLine: e.Section.StartLine, EndLine: e.Section.EndLine})
	}
	rels := func(list []rel) []lineattest.Release {
		out := make([]lineattest.Release, 0, len(list))
		for _, x := range list {
			out = append(out, lineattest.Release{Version: x.version, Commit: x.tag.Commit})
		}
		return out
	}
	return &ListedResult{
		Candidate: extract.AttestationCandidate{
			Basis: extract.BasisMechanical, Component: component, Line: line, FactFamily: lineattest.FamilyChangelogListedEntries,
			RuleIDs: []string{}, Releases: &lineattest.Releases{From: rels(lf), To: rels(lt)}, Sources: sources,
		},
		Proof: proof,
	}, nil
}

// reviewedRow reports whether t is, field for field, a row of the reviewed
// table: a target built in code or altered after loading is not a reviewed
// row and attests nothing.
func reviewedRow(t ce.Target) bool {
	for _, row := range ce.Reviewed {
		if row.Component == t.Component {
			return sameTarget(row, t)
		}
	}
	return false
}

func sameTarget(a, b ce.Target) bool {
	if a.Component != b.Component || a.Repo != b.Repo || a.Form != b.Form || a.Path != b.Path ||
		a.HeadingPattern != b.HeadingPattern || a.MaxBytes != b.MaxBytes || len(a.BoundaryPatterns) != len(b.BoundaryPatterns) {
		return false
	}
	for i := range a.BoundaryPatterns {
		if a.BoundaryPatterns[i] != b.BoundaryPatterns[i] {
			return false
		}
	}
	return true
}

// Listed attests, for the component of one reviewed row, the listed-entries
// family: it implements extract.LineAttester and extract.ComponentAttester.
// It emits no rule and no draft, and judges no item.
type Listed struct {
	slug   string
	target ce.Target

	mu   sync.Mutex
	tags []extract.Tag
}

// NewListed returns the listed-entries extractor of one reviewed row, named by
// the row's own component. A target that is not a row of the reviewed table,
// or whose component has no pack form, is refused.
func NewListed(t ce.Target) (*Listed, error) {
	if !slugRE.MatchString(t.Component) {
		return nil, fmt.Errorf("changelogattest: project slug %q", t.Component)
	}
	if !reviewedRow(t) {
		return nil, fmt.Errorf("changelogattest: %q is not a reviewed changelog target", t.Component)
	}
	component, ok := ce.ComponentPURL(t)
	if !ok {
		return nil, fmt.Errorf("changelogattest: row %q has no pack component", t.Component)
	}
	if f, known := lineattest.LookupFamily(lineattest.FamilyChangelogListedEntries); !known || !f.Admits(component) {
		return nil, fmt.Errorf("changelogattest: component %s is not admitted by the listed-entries family", component)
	}
	return &Listed{slug: t.Component, target: t}, nil
}

// ID implements extract.Extractor.
func (x *Listed) ID() string { return ListedIDPrefix + x.slug }

// Version implements extract.Extractor.
func (x *Listed) Version() string { return ListedVersion }

// Applies implements extract.Extractor.
func (x *Listed) Applies(r extract.RepoRef) bool { return r == x.target.Repo }

// MechanicalFamilies implements extract.MechanicalEmitter: the one family it
// attests. It emits no rule, so no rule fact is declared.
func (x *Listed) MechanicalFamilies() []string {
	return []string{lineattest.FamilyChangelogListedEntries}
}

// AttestedFamilies implements extract.LineAttester.
func (x *Listed) AttestedFamilies() []string {
	return []string{lineattest.FamilyChangelogListedEntries}
}

// AttestedComponent implements extract.ComponentAttester.
func (x *Listed) AttestedComponent() string {
	c, _ := ce.ComponentPURL(x.target)
	return c
}

// SourceFiles implements extract.CodeSource: this package and the entry
// reader (with the reviewed rows) it calls.
func (x *Listed) SourceFiles() (string, fs.FS) {
	s := SourceSet()
	return s.Dir, s.Files
}

// Pairs implements extract.Extractor.
func (x *Listed) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	x.mu.Lock()
	x.tags = append([]extract.Tag(nil), index.Tags...)
	x.mu.Unlock()
	return minorPairs(index)
}

// Extract implements extract.Extractor. A pair whose to-line is not listed
// completely is withheld with its typed reason; nothing is attested.
func (x *Listed) Extract(_ context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	x.mu.Lock()
	tags := append([]extract.Tag(nil), x.tags...)
	x.mu.Unlock()
	if len(tags) == 0 {
		return extract.Extraction{}, fmt.Errorf("changelogattest: Extract before Pairs")
	}
	res, err := AttestListed(r, x.target, tags, pair)
	if err != nil {
		if code, ok := ce.CodeOf(err); ok {
			return extract.Extraction{}, &extract.Withheld{Reason: err.Error(), Proof: map[string]string{"code": string(code)}}
		}
		return extract.Extraction{}, err
	}
	return extract.Extraction{Proof: res.Proof, Attestations: []extract.AttestationCandidate{res.Candidate}}, nil
}
