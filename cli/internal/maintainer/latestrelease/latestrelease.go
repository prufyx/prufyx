// SPDX-License-Identifier: AGPL-3.0-only

// Package latestrelease holds the single rule that decides which release
// (or, for a repository that publishes no releases, which tag) is a
// repository's "latest". The local mirror and the HTTP repin both call it,
// so the two sources cannot pick different baselines from the same data.
//
// The rule (Rule is the same text, recorded in worklists):
//
//   - Drafts and pre-releases are never candidates.
//   - Among the remaining releases, those whose tag is a strict version
//     (an optional prefix, then MAJOR.MINOR.PATCH and nothing after it) are
//     compared by version: the highest MAJOR, then MINOR, then PATCH wins.
//     A tie (the same version under two prefixes) goes to the shorter
//     prefix, then to the lexicographically smaller tag.
//   - When no candidate tag is a strict version, the candidate with the
//     highest release ID wins.
//   - For the tags fallback only strict-version tags are candidates, with
//     the same ordering; a repository with no such tag has no latest.
//
// The order in which a source lists releases plays no part, so a page
// size, a creation-date reordering or a different sort between the two
// sources cannot change the result.
package latestrelease

import (
	"regexp"
	"sort"
	"strconv"
)

// Rule states the selection rule in one sentence for worklists.
const Rule = "latest release: highest strict version (optional prefix, MAJOR.MINOR.PATCH) among non-draft, non-prerelease releases, else the highest release id; latest tag (releases-less repositories): highest strict version among all tags, else none; list order is never used"

// Release is the part of a release the rule looks at.
type Release struct {
	ID         int64
	Tag        string
	Draft      bool
	Prerelease bool
}

// Version is a strictly parsed tag: Prefix + Major.Minor.Patch.
type Version struct {
	Prefix              string
	Major, Minor, Patch int
}

// MaxComponent rejects calendar-style numbers as a MAJOR or MINOR.
const MaxComponent = 999

var (
	strictTagPattern = regexp.MustCompile(`^(.*?)(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	tagPrefixPattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_.]*[-_/])*(?:v|go)?$`)
)

// ParseStrict parses a tag only when it is exactly a conservative prefix
// followed by MAJOR.MINOR.PATCH with nothing after it. The prefix is
// empty, "v", or one or more word segments each ending in "-", "_" or "/"
// optionally followed by a final "v" or "go" (for example "release-", "api/v",
// "go1.22.5"). The line derivation of the repin keeps its own, narrower parser.
func ParseStrict(tag string) (Version, bool) {
	match := strictTagPattern.FindStringSubmatch(tag)
	if match == nil || !tagPrefixPattern.MatchString(match[1]) {
		return Version{}, false
	}
	major, err1 := strconv.Atoi(match[2])
	minor, err2 := strconv.Atoi(match[3])
	patch, err3 := strconv.Atoi(match[4])
	if err1 != nil || err2 != nil || err3 != nil || major > MaxComponent || minor > MaxComponent {
		return Version{}, false
	}
	return Version{Prefix: match[1], Major: major, Minor: minor, Patch: patch}, true
}

// better reports whether a beats b: higher numbers win; for equal numbers
// the shorter prefix wins, then the lexicographically smaller tag.
func better(a, b Version, atag, btag string) bool {
	switch {
	case a.Major != b.Major:
		return a.Major > b.Major
	case a.Minor != b.Minor:
		return a.Minor > b.Minor
	case a.Patch != b.Patch:
		return a.Patch > b.Patch
	case len(a.Prefix) != len(b.Prefix):
		return len(a.Prefix) < len(b.Prefix)
	}
	return atag < btag
}

// Select returns the latest release under the rule. ok is false when there
// is no non-draft, non-prerelease release.
func Select(releases []Release) (Release, bool) {
	var (
		best        Release
		bestV       Version
		haveVersion bool
		fallback    Release
		haveAny     bool
	)
	for _, r := range releases {
		if r.Draft || r.Prerelease || r.Tag == "" {
			continue
		}
		if !haveAny || r.ID > fallback.ID || (r.ID == fallback.ID && r.Tag < fallback.Tag) {
			fallback, haveAny = r, true
		}
		v, ok := ParseStrict(r.Tag)
		if !ok {
			continue
		}
		if !haveVersion || better(v, bestV, r.Tag, best.Tag) {
			best, bestV, haveVersion = r, v, true
		}
	}
	if haveVersion {
		return best, true
	}
	return fallback, haveAny
}

// SelectTag returns the latest tag under the rule, or false when no tag is
// a strict version.
func SelectTag(tags []string) (string, bool) {
	sorted := append([]string(nil), tags...)
	sort.Strings(sorted)
	var (
		best  string
		bestV Version
		have  bool
	)
	for _, t := range sorted {
		v, ok := ParseStrict(t)
		if !ok {
			continue
		}
		if !have || better(v, bestV, t, best) {
			best, bestV, have = t, v, true
		}
	}
	return best, have
}
