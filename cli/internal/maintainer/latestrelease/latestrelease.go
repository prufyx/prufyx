// SPDX-License-Identifier: AGPL-3.0-only

// Package latestrelease holds the single rule that decides which release
// (or, for a repository that publishes no releases, which tag) is a
// repository's "latest". The local mirror and the HTTP repin both call it,
// so the two sources cannot pick different baselines from the same data.
//
// The rule (Rule is the same text, recorded in worklists):
//
//   - Drafts and pre-releases are never candidates.
//   - Only tags with no prefix, "v" or "go" followed by MAJOR.MINOR.PATCH
//     (nothing after it) compete. If any strict-version candidate carries
//     another prefix, or the competing ones carry more than one prefix, the
//     repository is AMBIGUOUS: no release is chosen (see AmbiguousPrefixes,
//     which other code deriving versions from tags shares).
//   - For releases, if any non-strict release (calendar or two-part tags)
//     is newer (higher release id) than the oldest strict release, the
//     repository is AMBIGUOUS: a project that moved on to another tag
//     scheme is never left on its last strict release, even when a later
//     maintenance release on the old scheme exists.
//   - Otherwise the highest MAJOR, then MINOR, then PATCH wins.
//   - When no release tag is a strict version the repository is AMBIGUOUS:
//     the highest id is never taken across unrelated tag families.
//   - For the tags fallback only strict-version tags count, with the same
//     ambiguity rule; a repository with no such tag has no latest.
//
// The order in which a source lists releases plays no part, so a page
// size, a creation-date reordering or a different sort between the two
// sources cannot change the result.
package latestrelease

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Rule states the selection rule in one sentence for worklists.
const Rule = "latest release: highest strict version (tag with no prefix, v or go, then MAJOR.MINOR.PATCH) among non-draft, non-prerelease releases, ambiguous (no baseline) when no release is a strict version, strict tags carry other or mixed prefixes, or a non-strict release is newer than the oldest strict one; latest tag (releases-less repositories): the same over strict-version tags, else none; list order is never used"

// Outcome is the result class of a selection.
type Outcome int

const (
	// None: there is no candidate.
	None Outcome = iota
	// Found: a latest release or tag was chosen.
	Found
	// Ambiguous: candidates exist but the rule refuses to choose.
	Ambiguous
)

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

// DefaultPrefix reports whether a tag prefix competes for "latest" by
// default: none, "v" or "go".
func DefaultPrefix(prefix string) bool { return prefix == "" || prefix == "v" || prefix == "go" }

// AmbiguousPrefixes is the shared prefix rule. Given the prefixes of the
// strict-version tags of one repository it returns "" when they all are the
// same default prefix, and otherwise a reason naming the prefixes. It is
// the one definition of "which prefixes may compete" for every caller that
// derives versions from tags.
func AmbiguousPrefixes(prefixes []string) string {
	set := map[string]bool{}
	other := false
	for _, p := range prefixes {
		set[p] = true
		if !DefaultPrefix(p) {
			other = true
		}
	}
	if len(set) == 0 || (len(set) == 1 && !other) {
		return ""
	}
	names := make([]string, 0, len(set))
	for p := range set {
		names = append(names, strconv.Quote(p))
	}
	sort.Strings(names)
	kind := "mixed prefixes"
	if other {
		kind = "prefixes other than none, v or go"
	}
	return kind + " compete: " + strings.Join(names, ", ")
}

// higher reports whether a is a higher version than b.
func higher(a, b Version) bool {
	switch {
	case a.Major != b.Major:
		return a.Major > b.Major
	case a.Minor != b.Minor:
		return a.Minor > b.Minor
	}
	return a.Patch > b.Patch
}

// Result is the outcome of Select.
type Result struct {
	Outcome Outcome
	Release Release
	// Reason says why the outcome is Ambiguous.
	Reason string
}

// Select returns the latest release under the rule.
func Select(releases []Release) Result {
	var (
		best       Release
		bestV      Version
		have       bool
		prefs      []string
		nonStrict  Release // the highest-id candidate that is not a strict version
		haveNon    bool
		oldest     Release // the lowest-id strict candidate
		candidates int
	)
	for _, r := range releases {
		if r.Draft || r.Prerelease || r.Tag == "" {
			continue
		}
		candidates++
		v, ok := ParseStrict(r.Tag)
		if !ok {
			if !haveNon || r.ID > nonStrict.ID || (r.ID == nonStrict.ID && r.Tag < nonStrict.Tag) {
				nonStrict, haveNon = r, true
			}
			continue
		}
		prefs = append(prefs, v.Prefix)
		if !have || r.ID < oldest.ID {
			oldest = r
		}
		if !have || higher(v, bestV) {
			best, bestV, have = r, v, true
		}
	}
	if candidates == 0 {
		return Result{Outcome: None}
	}
	if !have {
		return Result{Outcome: Ambiguous, Reason: "no release has a strict version tag, so no latest can be ranked"}
	}
	if reason := AmbiguousPrefixes(prefs); reason != "" {
		return Result{Outcome: Ambiguous, Reason: reason}
	}
	if haveNon && nonStrict.ID > oldest.ID {
		return Result{Outcome: Ambiguous, Reason: fmt.Sprintf("release %q is not a strict version and is newer than the strict release %q, so the strict releases may no longer be the latest line", nonStrict.Tag, oldest.Tag)}
	}
	return Result{Outcome: Found, Release: best}
}

// SelectTag returns the latest tag under the rule. Tags carry no recency,
// so only strict-version tags are candidates.
func SelectTag(tags []string) (string, Outcome, string) {
	var (
		best  string
		bestV Version
		have  bool
		prefs []string
	)
	for _, t := range tags {
		v, ok := ParseStrict(t)
		if !ok {
			continue
		}
		prefs = append(prefs, v.Prefix)
		if !have || higher(v, bestV) {
			best, bestV, have = t, v, true
		}
	}
	if !have {
		return "", None, ""
	}
	if reason := AmbiguousPrefixes(prefs); reason != "" {
		return "", Ambiguous, reason
	}
	return best, Found, ""
}
