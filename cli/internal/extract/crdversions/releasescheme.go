// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"regexp"
	"strconv"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// SchemeCalverEdge is the release scheme of a project that ships only edge
// releases named for the calendar month: edge-YY.M.N, later YY.M.N-edge. It
// is a closed set; a new scheme is a reviewed code change, like a new
// attesting component (lineattest.CalverComponent).
const SchemeCalverEdge = "calver-edge"

// ReleaseSchemes are the release schemes a target may name.
var ReleaseSchemes = []string{SchemeCalverEdge}

// The two spellings of a calver-edge release tag, in order of preference.
// The counter is a canonical number without leading zeros. The month may
// carry one (edge-25.03.1, a real tag of the project) and then reads as the
// same release as the canonical spelling.
var calverEdgeRE = [2]*regexp.Regexp{
	regexp.MustCompile(`^edge-(\d{2})\.(0[1-9]|[1-9]|1[0-2])\.([1-9][0-9]{0,2})$`),
	regexp.MustCompile(`^(\d{2})\.(0[1-9]|[1-9]|1[0-2])\.([1-9][0-9]{0,2})-edge$`),
}

// calverEdgeLooseRE is the shape of a tag that looks like a calver-edge
// release; one that has this shape but is not read by calverEdgeRE is a
// release the extractor cannot read (CalverEdgeUnread).
var calverEdgeLooseRE = [2]*regexp.Regexp{
	regexp.MustCompile(`^edge-(\d{2})\.(\d{1,2})\.\d+$`),
	regexp.MustCompile(`^(\d{2})\.(\d{1,2})\.\d+-edge$`),
}

// paddedMonthRank is added to the spelling of a tag with a zero-padded
// month, so the canonical spelling of a version is preferred over it.
const paddedMonthRank = 2

// CalverEdgeRelease reads a calver-edge release tag. version is the engine
// version YY.M.N (26.10.4 for both edge-26.10.4 and 26.10.4-edge, without
// the tag's decoration, and 25.3.1 for edge-25.03.1); spelling is 0 for the
// edge- prefix and 1 for the -edge suffix, plus 2 when the month is
// zero-padded. A tag of any other shape (a release candidate, a foreign
// prefix, a non-canonical number, a year below 10) is not a release.
// This is the one definition of the grammar: the extractor, the release
// completeness check of the knowledge gate and the coverage report all call it.
func CalverEdgeRelease(tag string) (version string, spelling int, ok bool) {
	for i, re := range calverEdgeRE {
		m := re.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		year, _ := strconv.Atoi(m[1])
		if m[1][0] == '0' {
			// A year under 10 is no edge release, and "05" would not be a
			// canonical line number.
			return "", 0, false
		}
		month, _ := strconv.Atoi(m[2])
		if len(m[2]) == 2 && m[2][0] == '0' {
			i += paddedMonthRank
		}
		return strconv.Itoa(year) + "." + strconv.Itoa(month) + "." + m[3], i, true
	}
	return "", 0, false
}

// CalverEdgeUnread reports a tag that has the shape of a calver-edge release
// but that CalverEdgeRelease does not read (edge-26.3.0, 26.3.1000-edge), and
// the calendar line it names (YY.M, as lineattest.LineOf spells it). Such a
// tag may be a release of that line the extractor would silently miss, so a
// consumer must treat the line as having an unread release rather than as
// complete. A tag of a shape that is no release at all (a release candidate)
// is not reported.
func CalverEdgeUnread(tag string) (line string, unread bool) {
	if _, _, ok := CalverEdgeRelease(tag); ok {
		return "", false
	}
	for _, re := range calverEdgeLooseRE {
		if m := re.FindStringSubmatch(tag); m != nil {
			year, _ := strconv.Atoi(m[1])
			month, _ := strconv.Atoi(m[2])
			return strconv.Itoa(year) + "." + strconv.Itoa(month), true
		}
	}
	return "", false
}

// ReleaseTags wraps tags for the framework's check that an attestation names
// recorded release tags (extract.Run). That check accepts a tag that ends in
// the release version after at most a non-numeric prefix, which neither
// "26.3.2-edge" nor "edge-25.03.1" does. For a target with the calver-edge
// scheme, each tag the scheme reads gets one more entry named for the engine
// version at the same commit; the extractor ignores it (it is no release tag
// of the scheme), and it exists only because the tag it stands for is one.
// Any other extractor, and any target without the scheme, gets tags back
// unchanged. Callers of extract.Run pass the extractor's tags through this.
func ReleaseTags(ex extract.Extractor, tags extract.TagSource) extract.TagSource {
	if r, ok := ex.(interface {
		releaseTagSource(extract.TagSource) extract.TagSource
	}); ok {
		return r.releaseTagSource(tags)
	}
	return tags
}

type versionAliasTags struct{ inner extract.TagSource }

// Tags implements extract.TagSource.
func (v versionAliasTags) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	list, err := v.inner.Tags(repo)
	if err != nil {
		return nil, err
	}
	out := append([]extract.Tag{}, list...)
	for _, t := range list {
		if version, _, ok := CalverEdgeRelease(t.Name); ok && version != t.Name {
			out = append(out, extract.Tag{Name: version, Commit: t.Commit})
		}
	}
	return out, nil
}

func (x *Extractor) releaseTagSource(tags extract.TagSource) extract.TagSource {
	if x.target.ReleaseScheme == SchemeCalverEdge {
		return versionAliasTags{inner: tags}
	}
	return tags
}

// releaseOf reads a final release tag of the target: the engine version and
// the rank of the spelling (the index of the tag prefix, or of the calver
// spelling), lower being preferred.
func (t Target) releaseOf(tag string) (version string, rank int, ok bool) {
	if t.ReleaseScheme == SchemeCalverEdge {
		return CalverEdgeRelease(tag)
	}
	for i, prefix := range t.TagPrefixes {
		if m := finalTagRE(prefix).FindStringSubmatch(tag); m != nil {
			return m[1] + "." + m[2] + "." + m[3], i, true
		}
	}
	return "", 0, false
}
