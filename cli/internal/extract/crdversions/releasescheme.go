// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"regexp"
	"strconv"
)

// SchemeCalverEdge is the release scheme of a project that ships only edge
// releases named for the calendar month: edge-YY.M.N, later YY.M.N-edge. It
// is a closed set; a new scheme is a reviewed code change, like a new
// attesting component (lineattest.CalverComponent).
const SchemeCalverEdge = "calver-edge"

// ReleaseSchemes are the release schemes a target may name.
var ReleaseSchemes = []string{SchemeCalverEdge}

// The two spellings of a calver-edge release tag, in order of preference.
// Month and counter are canonical numbers without leading zeros, so
// edge-25.03.1 is not a release.
var calverEdgeRE = [2]*regexp.Regexp{
	regexp.MustCompile(`^edge-(\d{2})\.([1-9]|1[0-2])\.([1-9][0-9]{0,2})$`),
	regexp.MustCompile(`^(\d{2})\.([1-9]|1[0-2])\.([1-9][0-9]{0,2})-edge$`),
}

// CalverEdgeRelease reads a calver-edge release tag. version is the engine
// version YY.M.N (26.10.4 for both edge-26.10.4 and 26.10.4-edge, without
// the tag's decoration); spelling is 0 for the edge- prefix and 1 for the
// -edge suffix. A tag of any other shape (a release candidate, a foreign
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
		return strconv.Itoa(year) + "." + m[2] + "." + m[3], i, true
	}
	return "", 0, false
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
