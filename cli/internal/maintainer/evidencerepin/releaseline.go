// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

// Release-line baselines.
//
// A rule that describes a fixed historical version pair (for example
// "1.24 to 1.25") cites files pinned at a commit of that release line.
// Comparing such a citation with the repository's newest release, which is
// usually on a different line, reports "changed" for changes that are
// irrelevant to the pair. The question that matters for a pinned pair is
// whether the cited content changed in LATER RELEASES OF THE SAME LINE
// (patch releases and errata). This file derives that line and finds its
// newest release.
//
// Safety model. Nothing here is trusted on its own authority:
//
//   - The line is derived from the pinned commit itself. Version-looking
//     tokens in a source id, rule id or rule subject are only HINTS that
//     name candidate release tags; a candidate is accepted only when the
//     tag resolves to exactly the citation's pinned commit. A wrong or
//     misleading hint can therefore only cause a missed derivation (the
//     citation keeps the latest-release baseline), never a wrong line.
//   - A tag name must match a strict MAJOR.MINOR.PATCH grammar behind an
//     explicit, conservative prefix grammar. Pre-release, build-suffixed,
//     four-component, zero-padded and calendar-style tags never derive a
//     line.
//   - The line's newest release is chosen only from a COMPLETE scan of the
//     repository's GitHub Releases (never the tags fallback). Any release
//     on the same numeric line that this code cannot place unambiguously
//     (an unrecognised suffix, or the same numeric line under a different
//     tag prefix) makes the line ambiguous and the citation falls back to
//     the latest-release baseline.
//   - Every fallback is recorded on the citation with its reason; a
//     release-line citation records the line, the pinned tag, and the
//     compared tag.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// BaselineModeLatest compares every citation with the repository's
	// single most recent release (the original behaviour).
	BaselineModeLatest = "latest"
	// BaselineModeReleaseLine compares a citation with the newest release
	// on the release line of its pinned tag when that line can be proven,
	// and with the latest release otherwise.
	BaselineModeReleaseLine = "release-line"

	// BaselineLatest and BaselineReleaseLine are the per-citation record of
	// which baseline was actually used.
	BaselineLatest      = "latest"
	BaselineReleaseLine = "release_line"

	pinFound              = "PINNED"
	pinUnderivable        = "UNDERIVABLE"
	lineResolved          = "RESOLVED"
	lineUnderivable       = "UNDERIVABLE"
	pendingRateLimitedTag = "PENDING_RATE_LIMITED"
	pendingErrorTag       = "PENDING_ERROR"

	// releasePageSize is small because release notes make a page of
	// releases large (a page of 100 can exceed the API response bound);
	// maxReleasePages bound the complete Releases scan
	// used for line resolution. A repository with more releases than this
	// is not scanned completely, so none of its citations get a line.
	releasePageSize = 20
	maxReleasePages = 100
	// maxPinCandidates bounds the tag resolutions spent proving one
	// pinned commit's tag.
	maxPinCandidates = 30
	// maxVersionComponent rejects calendar-style and otherwise
	// non-semantic numbers as a MAJOR or MINOR.
	maxVersionComponent = 999
)

var (
	strictTagPattern  = regexp.MustCompile(`^(.*?)(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	tagPrefixPattern  = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_.]*[-_/])*v?$`)
	hintTriplePattern = regexp.MustCompile(`([0-9]+)[.-]([0-9]+)[.-]([0-9]+)`)
	hintPairPattern   = regexp.MustCompile(`([0-9]+)[.-]([0-9]+)`)
)

// tagVersion is a strictly parsed release tag: Prefix + Major.Minor.Patch.
type tagVersion struct {
	Prefix              string
	Major, Minor, Patch int
}

func (v tagVersion) line() string { return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) }

// parseStrictTag parses a tag name only when it is exactly a conservative
// prefix followed by MAJOR.MINOR.PATCH with nothing after it. The prefix
// is empty, "v", or one or more word segments each ending in "-", "_" or
// "/" optionally followed by a final "v" (for example "release-",
// "release-v", "api/v", "knative-v"). Anything else is not a line.
func parseStrictTag(tag string) (tagVersion, bool) {
	match := strictTagPattern.FindStringSubmatch(tag)
	if match == nil || !tagPrefixPattern.MatchString(match[1]) {
		return tagVersion{}, false
	}
	major, err1 := strconv.Atoi(match[2])
	minor, err2 := strconv.Atoi(match[3])
	patch, err3 := strconv.Atoi(match[4])
	if err1 != nil || err2 != nil || err3 != nil || major > maxVersionComponent || minor > maxVersionComponent {
		return tagVersion{}, false
	}
	return tagVersion{Prefix: match[1], Major: major, Minor: minor, Patch: patch}, true
}

// onLineLoosely reports whether tag names the given prefix and numeric
// line in any form (including forms parseStrictTag rejects, such as
// "v1.2.3-hotfix" or "v1.2.3.4"). It is used only to detect releases that
// make a line ambiguous.
func onLineLoosely(tag string, prefix string, major, minor int) bool {
	head := prefix + strconv.Itoa(major) + "." + strconv.Itoa(minor)
	if !strings.HasPrefix(tag, head) {
		return false
	}
	rest := tag[len(head):]
	return rest == "" || rest[0] < '0' || rest[0] > '9'
}

// versionHints extracts candidate versions from free text. They are only
// hints: the caller must verify every candidate tag against the pinned
// commit. Triples (A.B.C) and pairs (A.B) are returned separately,
// deduplicated and sorted, with out-of-range numbers dropped.
func versionHints(texts ...string) (triples [][3]int, pairs [][2]int) {
	seenTriple := map[[3]int]bool{}
	seenPair := map[[2]int]bool{}
	for _, text := range texts {
		for _, m := range hintTriplePattern.FindAllStringSubmatch(text, -1) {
			a, b, c := atoiSafe(m[1]), atoiSafe(m[2]), atoiSafe(m[3])
			if a < 0 || b < 0 || c < 0 || a > maxVersionComponent || b > maxVersionComponent {
				continue
			}
			key := [3]int{a, b, c}
			if !seenTriple[key] {
				seenTriple[key] = true
				triples = append(triples, key)
			}
		}
		for _, m := range hintPairPattern.FindAllStringSubmatch(text, -1) {
			a, b := atoiSafe(m[1]), atoiSafe(m[2])
			if a < 0 || b < 0 || a > maxVersionComponent || b > maxVersionComponent {
				continue
			}
			key := [2]int{a, b}
			if !seenPair[key] {
				seenPair[key] = true
				pairs = append(pairs, key)
			}
		}
	}
	sort.Slice(triples, func(i, j int) bool { return lessInts(triples[i][:], triples[j][:]) })
	sort.Slice(pairs, func(i, j int) bool { return lessInts(pairs[i][:], pairs[j][:]) })
	return triples, pairs
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

func lessInts(a, b []int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// releaseEntry is one entry of a repository's GitHub Releases list.
type releaseEntry struct {
	Tag        string
	Draft      bool
	Prerelease bool
}

// releaseList is the complete Releases scan of one repository.
type releaseList struct {
	entries []releaseEntry
	// complete is false when the scan hit maxReleasePages.
	complete bool
	// none is true when the repository publishes no Releases at all.
	none bool
}

func fetchAllReleases(ctx context.Context, fetcher APIFetcher, owner, repo string) (releaseList, error) {
	var list releaseList
	for page := 1; page <= maxReleasePages; page++ {
		path := "/repos/" + owner + "/" + repo + "/releases?per_page=" + strconv.Itoa(releasePageSize) + "&page=" + strconv.Itoa(page)
		body, err := apiGet(ctx, fetcher, path)
		if err != nil {
			return releaseList{}, err
		}
		if body == nil {
			if page == 1 {
				return releaseList{complete: true, none: true}, nil
			}
			list.complete = true
			return list, nil
		}
		var raw []struct {
			TagName    string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		if err := json.Unmarshal(body, &raw); err != nil {
			return releaseList{}, fmt.Errorf("%w: decode releases: %v", errRejected, err)
		}
		for _, r := range raw {
			list.entries = append(list.entries, releaseEntry{Tag: r.TagName, Draft: r.Draft, Prerelease: r.Prerelease})
		}
		// Only an empty page ends the scan: a short page proves nothing,
		// because the API may drop entries (drafts) after paginating.
		if len(raw) == 0 {
			list.complete = true
			list.none = len(list.entries) == 0
			return list, nil
		}
	}
	return list, nil
}

// PinResolution records which release tag a citation's pinned commit is,
// when that can be proven. It is kept in the resumable state file.
type PinResolution struct {
	Owner      string `json:"owner"`
	Repo       string `json:"repo"`
	Commit     string `json:"commit"`
	Status     string `json:"status"`
	Tag        string `json:"tag,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	Line       string `json:"line,omitempty"`
	Detail     string `json:"detail,omitempty"`
	ResolvedAt string `json:"resolvedAt,omitempty"`
}

// LineResolution records the newest GitHub Release on one release line of
// one repository. It is the line analogue of RepoResolution and is carried
// in the worklist so downstream tooling can check the freshness and
// provenance of every release-line baseline it relies on.
type LineResolution struct {
	Owner      string `json:"owner"`
	Repo       string `json:"repo"`
	Prefix     string `json:"prefix"`
	Line       string `json:"line"`
	Status     string `json:"status"`
	Tag        string `json:"tag,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Detail     string `json:"detail,omitempty"`
	ResolvedAt string `json:"resolvedAt,omitempty"`
	// Stale is true when this line resolution is older than the run's
	// --max-age bound and was not refreshed this run.
	Stale bool `json:"stale,omitempty"`
}

// pinKey keys a pin by repository, commit and the hint set that was tried,
// so an UNDERIVABLE answer reached with poor hints is never reused for a
// citation with better ones.
func pinKey(owner, repo, commit, hintSignature string) string {
	return owner + "/" + repo + "@" + commit + "#" + hintSignature
}

func hintSignature(triples [][3]int, pairs [][2]int) string {
	var parts []string
	for _, t := range triples {
		parts = append(parts, fmt.Sprintf("%d.%d.%d", t[0], t[1], t[2]))
	}
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%d.%d", p[0], p[1]))
	}
	return sha256Hex(strings.Join(parts, ","))
}
func lineKey(owner, repo, prefix, line string) string {
	return owner + "/" + repo + "|" + prefix + "|" + line
}

// newestOnLine returns the newest non-pre-release GitHub Release on the
// pinned tag's line, or a reason the line is ambiguous. A line is
// ambiguous when any non-pre-release release carries the same numeric
// line under a different prefix, or carries the same prefix and numeric
// line in a form the strict grammar rejects. Drafts and releases GitHub
// flags as pre-releases never count.
func newestOnLine(pinned tagVersion, entries []releaseEntry) (tag string, version tagVersion, reason string) {
	pinnedPresent := false
	for _, entry := range entries {
		if entry.Draft || entry.Prerelease {
			continue
		}
		parsed, strict := parseStrictTag(entry.Tag)
		switch {
		case strict && parsed.Major == pinned.Major && parsed.Minor == pinned.Minor:
			if parsed.Prefix != pinned.Prefix {
				return "", tagVersion{}, "the same numeric line is released under more than one tag prefix"
			}
			if parsed.Patch == pinned.Patch {
				pinnedPresent = true
			}
			if tag == "" || parsed.Patch > version.Patch {
				tag, version = entry.Tag, parsed
			}
		case !strict && onLineLoosely(entry.Tag, pinned.Prefix, pinned.Major, pinned.Minor):
			return "", tagVersion{}, "a release on the line has a tag the strict version grammar does not accept"
		}
	}
	if !pinnedPresent || tag == "" {
		return "", tagVersion{}, "the pinned tag is not a published release"
	}
	return tag, version, ""
}

// tagResolution is one cached tag-to-commit lookup.
type tagResolution struct {
	commit string
	err    error
}

// lineResolver derives pins and lines for BuildWorklist. It is not safe
// for concurrent use.
type lineResolver struct {
	ctx         context.Context
	fetcher     APIFetcher
	state       *State
	now         func() time.Time
	maxAge      time.Duration
	rateLimited *bool

	releases map[string]*releaseResult
	tags     map[string]tagResolution
}

type releaseResult struct {
	list releaseList
	err  error
}

func newLineResolver(ctx context.Context, fetcher APIFetcher, state *State, now func() time.Time, maxAge time.Duration, rateLimited *bool) *lineResolver {
	return &lineResolver{
		ctx: ctx, fetcher: fetcher, state: state, now: now, maxAge: maxAge, rateLimited: rateLimited,
		releases: map[string]*releaseResult{}, tags: map[string]tagResolution{},
	}
}

func (r *lineResolver) stamp() string { return r.now().UTC().Format(time.RFC3339) }

func (r *lineResolver) releaseList(owner, repo string) (releaseList, error) {
	key := owner + "/" + repo
	if cached, ok := r.releases[key]; ok {
		return cached.list, cached.err
	}
	if *r.rateLimited {
		return releaseList{}, errRateLimited
	}
	list, err := fetchAllReleases(r.ctx, r.fetcher, owner, repo)
	if errors.Is(err, errRateLimited) {
		*r.rateLimited = true
	}
	r.releases[key] = &releaseResult{list: list, err: err}
	return list, err
}

func (r *lineResolver) tagCommit(owner, repo, tag string) (string, error) {
	key := owner + "/" + repo + "@" + tag
	if cached, ok := r.tags[key]; ok {
		return cached.commit, cached.err
	}
	if *r.rateLimited {
		return "", errRateLimited
	}
	commit, err := resolveTagCommit(r.ctx, r.fetcher, owner, repo, tag)
	if errors.Is(err, errRateLimited) {
		*r.rateLimited = true
	}
	r.tags[key] = tagResolution{commit: commit, err: err}
	return commit, err
}

func pendingStatus(err error) string {
	if errors.Is(err, errRateLimited) {
		return pendingRateLimitedTag
	}
	return pendingErrorTag
}

func (r *lineResolver) fresh(timestamp string) bool { return isFresh(timestamp, r.now(), r.maxAge) }

// pin proves which release tag the citation's pinned commit is.
func (r *lineResolver) pin(c Citation) PinResolution {
	triples, pairs := versionHints(c.SourceID, c.RuleID, c.SubjectFrom, c.SubjectTo)
	key := pinKey(c.Owner, c.Repo, c.OldCommit, hintSignature(triples, pairs))
	if existing, ok := r.state.Pins[key]; ok && (existing.Status == pinFound || existing.Status == pinUnderivable) && r.fresh(existing.ResolvedAt) {
		return existing
	}
	result := PinResolution{Owner: c.Owner, Repo: c.Repo, Commit: c.OldCommit}
	underivable := func(detail string) PinResolution {
		result.Status, result.Detail, result.ResolvedAt = pinUnderivable, detail, r.stamp()
		r.state.Pins[key] = result
		return result
	}
	pending := func(err error) PinResolution {
		// Pending entries are neither persisted nor reused: they are
		// retried on the next run.
		result.Status = pendingStatus(err)
		result.Detail = "release tag for the pinned commit not yet resolved; re-run with the same --state to resume"
		return result
	}

	list, err := r.releaseList(c.Owner, c.Repo)
	if err != nil {
		return pending(err)
	}
	if list.none {
		return underivable("the repository publishes no GitHub Releases")
	}
	if !list.complete {
		return underivable("the repository has more releases than the line scan covers")
	}

	candidatesFor := func(match func(tagVersion) bool) []string {
		var tags []string
		for _, entry := range list.entries {
			if entry.Draft || entry.Prerelease {
				continue
			}
			if v, ok := parseStrictTag(entry.Tag); ok && match(v) {
				tags = append(tags, entry.Tag)
			}
		}
		sort.Strings(tags)
		return tags
	}
	tripleSet := map[[3]int]bool{}
	for _, t := range triples {
		tripleSet[t] = true
	}
	pairSet := map[[2]int]bool{}
	for _, p := range pairs {
		pairSet[p] = true
	}
	stages := [][]string{
		candidatesFor(func(v tagVersion) bool { return tripleSet[[3]int{v.Major, v.Minor, v.Patch}] }),
		candidatesFor(func(v tagVersion) bool { return pairSet[[2]int{v.Major, v.Minor}] }),
	}

	budget := maxPinCandidates
	for _, stage := range stages {
		var matched []string
		for _, tag := range stage {
			if budget == 0 {
				break
			}
			budget--
			commit, err := r.tagCommit(c.Owner, c.Repo, tag)
			if err != nil {
				return pending(err)
			}
			if commit == c.OldCommit {
				matched = append(matched, tag)
			}
		}
		if len(matched) == 0 {
			continue
		}
		first, _ := parseStrictTag(matched[0])
		for _, tag := range matched[1:] {
			other, _ := parseStrictTag(tag)
			if other.Prefix != first.Prefix || other.Major != first.Major || other.Minor != first.Minor {
				return underivable("the pinned commit is tagged with more than one release line")
			}
		}
		if len(matched) > 1 && !allSameVersion(matched) {
			return underivable("the pinned commit carries more than one release tag")
		}
		result.Status, result.Tag, result.Prefix, result.Line, result.ResolvedAt = pinFound, matched[0], first.Prefix, first.line(), r.stamp()
		r.state.Pins[key] = result
		return result
	}
	return underivable("no release tag named by the source, rule or subject versions points at the pinned commit")
}

func allSameVersion(tags []string) bool {
	first, _ := parseStrictTag(tags[0])
	for _, tag := range tags[1:] {
		other, _ := parseStrictTag(tag)
		if other != first {
			return false
		}
	}
	return true
}

// line finds the newest release on a pinned tag's line.
func (r *lineResolver) line(pin PinResolution) LineResolution {
	pinned, _ := parseStrictTag(pin.Tag)
	key := lineKey(pin.Owner, pin.Repo, pin.Prefix, pin.Line)
	if existing, ok := r.state.Lines[key]; ok && (existing.Status == lineResolved || existing.Status == lineUnderivable) && r.fresh(existing.ResolvedAt) {
		// A cached line is only valid for a pin at or below its newest
		// release; a pin above it means the cache predates that pin.
		if existing.Status == lineUnderivable {
			return existing
		}
		if cachedVersion, ok := parseStrictTag(existing.Tag); ok && cachedVersion.Patch >= pinned.Patch {
			return existing
		}
	}
	result := LineResolution{Owner: pin.Owner, Repo: pin.Repo, Prefix: pin.Prefix, Line: pin.Line}
	pending := func(err error) LineResolution {
		result.Status = pendingStatus(err)
		result.Detail = "release line not yet resolved; re-run with the same --state to resume"
		return result
	}
	list, err := r.releaseList(pin.Owner, pin.Repo)
	if err != nil {
		return pending(err)
	}
	tag, _, reason := newestOnLine(pinned, list.entries)
	if reason != "" {
		result.Status, result.Detail, result.ResolvedAt = lineUnderivable, reason, r.stamp()
		r.state.Lines[key] = result
		return result
	}
	commit, err := r.tagCommit(pin.Owner, pin.Repo, tag)
	if err != nil {
		return pending(err)
	}
	if commit == "" {
		result.Status, result.Detail, result.ResolvedAt = lineUnderivable, "the newest release tag on the line does not resolve to a commit", r.stamp()
		r.state.Lines[key] = result
		return result
	}
	result.Status, result.Tag, result.Commit, result.ResolvedAt = lineResolved, tag, commit, r.stamp()
	r.state.Lines[key] = result
	return result
}

// baselineDecision is the outcome of choosing a citation's baseline.
type baselineDecision struct {
	// pending is non-empty when the baseline cannot be decided this run.
	pending string
	// line is set when the release-line baseline is used.
	line *LineResolution
	pin  PinResolution
	// note explains a fallback to the latest baseline.
	note string
}

func (r *lineResolver) decide(c Citation, repo RepoResolution) baselineDecision {
	if repo.Resolution == resolutionTagFallback {
		return baselineDecision{note: "the repository publishes no GitHub Releases; the tags fallback has no release line"}
	}
	pin := r.pin(c)
	switch pin.Status {
	case pinFound:
	case pinUnderivable:
		return baselineDecision{note: "release line not derived: " + pin.Detail}
	default:
		return baselineDecision{pending: pin.Detail}
	}
	line := r.line(pin)
	switch line.Status {
	case lineResolved:
		return baselineDecision{line: &line, pin: pin}
	case lineUnderivable:
		return baselineDecision{pin: pin, note: "release line not usable: " + line.Detail}
	default:
		return baselineDecision{pending: line.Detail}
	}
}

func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

// LineBaselineConsistent reports whether a release-line citation's
// recorded tags are mutually consistent: both parse under the strict tag
// grammar, share one prefix and the numeric line named by line, and the
// compared tag is not older than the pinned tag. Downstream consumers use
// it to check a worklist they did not produce.
func LineBaselineConsistent(pinnedTag, baselineTag, line string) bool {
	pinned, ok1 := parseStrictTag(pinnedTag)
	baseline, ok2 := parseStrictTag(baselineTag)
	return ok1 && ok2 && pinned.Prefix == baseline.Prefix &&
		pinned.line() == line && baseline.line() == line && baseline.Patch >= pinned.Patch
}
