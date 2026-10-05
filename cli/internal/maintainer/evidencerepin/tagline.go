// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

// Tag-derived release lines.
//
// Some upstream repositories publish their releases only as git tags, with
// no GitHub Releases (golang/go tags go1.N.M; many projects tag vX.Y.Z and
// keep release-X.Y branches). For those, the tags fallback picks one "most
// recent" tag for the whole repository, which is often on a different line
// from a citation's pinned commit, or not a release at all. This file
// derives the citation's own line from the repository's complete list of
// git refs (the same data "git ls-remote" prints) and compares the
// citation with the newest release tag on that line.
//
// Safety model, in addition to releaseline.go's:
//
//   - Only a complete ref listing is used. It is fetched once per
//     repository and run; a listing that is malformed (a peeled entry with
//     no tag, a ref listed twice, a non-hex object id) or too large derives
//     nothing.
//   - The pinned commit must be exactly the commit of a release tag: an
//     annotated tag's peeled commit or a lightweight tag's object. A
//     branch head is never a release, and a branch name never names a
//     line: a pin that is only a branch head, a line that has a branch but
//     no release tag, and a pin with no tag at all are UNKNOWN.
//   - A release tag is MAJOR.MINOR.PATCH behind the conservative prefix
//     grammar of releaseline.go, extended by a single bare lowercase word
//     ("go1.26.6"). Repository-wide, only the prefixes none, "v" and "go"
//     may carry version tags, and only one of them: anything else makes the
//     repository ambiguous (the rule the latest-release selection uses). Every tag on the pinned line is classified: release,
//     pre-release (alpha, beta, rc, pre, preview, dev; never a line head)
//     or unrecognised. One unrecognised tag on the line ("v1.9.0-hotfix-1",
//     "v1.2.3.4", a bare "go1.20") or the same numeric line under a
//     second prefix makes the line UNKNOWN: a release this code cannot
//     order could be newer than the head it would otherwise pick.
//   - A tag naming the line's MAJOR.MINOR under another prefix or with a
//     zero-padded number also makes the line UNKNOWN.
//   - The compared tag is the highest PATCH among the line's release tags,
//     and it must also resolve through the tag API to the same commit (the
//     ref listing cannot tell a commit from a tree or blob).
//     It has the pinned tag's prefix, MAJOR and MINOR and a PATCH not below
//     the pinned one, so the comparison never moves to another line and
//     never to an older release than the pin.
//   - The result is recorded as its own baseline, "tag_line", with a line
//     record whose basis is "git_tags", so every consumer can tell it from
//     a line proven by GitHub Releases.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/latestrelease"
)

const (
	// BaselineTagLine is the per-citation baseline of a citation compared
	// with the newest release tag on its pinned tag's line, derived from
	// git tags because the repository publishes no usable GitHub Releases.
	BaselineTagLine = "tag_line"
	// LineBasisGitTags marks a LineResolution derived from git tags. An
	// empty basis means the line was proven from GitHub Releases.
	LineBasisGitTags = "git_tags"

	// maxRefListingBytes bounds one ref advertisement or ls-remote listing.
	maxRefListingBytes int64 = 32 << 20
	// maxIgnoredOnLine bounds the pre-release tags recorded by name on a
	// line record; the full number is always recorded.
	maxIgnoredOnLine = 20

	ignoredPrerelease = "pre-release"
)

var (
	errRefListingMalformed = errors.New("the ref listing is malformed")
	errRefListingTooLarge  = errors.New("the ref listing is too large")

	tagLinePrefixPattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_.]*[-_/])*(?:v|[a-z]+)?$`)
	prereleasePattern    = regexp.MustCompile(`^(?i)[-.]?(?:alpha|beta|rc|pre|preview|dev)(?:[-.]?[0-9]+)*$`)
	refObjectPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// TagRef is one tag of a ref listing. Commit is the peeled commit for an
// annotated tag and the object itself for a lightweight tag.
type TagRef struct {
	Object    string
	Commit    string
	Annotated bool
}

// RefListing is a repository's complete list of tags and branch heads.
type RefListing struct {
	Tags  map[string]TagRef
	Heads map[string]string
}

// GitRefSource lists a repository's refs. An APIFetcher that also
// implements it enables tag-derived release lines; without it a
// repository without usable GitHub Releases keeps the latest baseline.
type GitRefSource interface {
	GitRefs(ctx context.Context, owner, repo string) (RefListing, error)
}

// ParseLsRemote parses "git ls-remote" output ("<object>\t<ref>" per line).
// Peeled entries ("refs/tags/<name>^{}") give an annotated tag's commit.
// Refs other than tags and branch heads are ignored. Anything malformed
// rejects the whole listing.
func ParseLsRemote(raw []byte) (RefListing, error) {
	if int64(len(raw)) > maxRefListingBytes {
		return RefListing{}, errRefListingTooLarge
	}
	listing := RefListing{Tags: map[string]TagRef{}, Heads: map[string]string{}}
	direct := map[string]string{}
	peeled := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		object, ref, ok := strings.Cut(line, "\t")
		if !ok || !refObjectPattern.MatchString(object) || ref == "" || strings.ContainsAny(ref, "\t\r \x00") {
			return RefListing{}, fmt.Errorf("%w: unexpected line", errRefListingMalformed)
		}
		if seen[ref] {
			return RefListing{}, fmt.Errorf("%w: %s is listed twice", errRefListingMalformed, ref)
		}
		seen[ref] = true
		switch {
		case strings.HasPrefix(ref, "refs/tags/") && strings.HasSuffix(ref, "^{}"):
			peeled[strings.TrimSuffix(strings.TrimPrefix(ref, "refs/tags/"), "^{}")] = object
		case strings.HasPrefix(ref, "refs/tags/"):
			direct[strings.TrimPrefix(ref, "refs/tags/")] = object
		case strings.HasPrefix(ref, "refs/heads/"):
			listing.Heads[strings.TrimPrefix(ref, "refs/heads/")] = object
		}
	}
	for name := range peeled {
		if _, ok := direct[name]; !ok {
			return RefListing{}, fmt.Errorf("%w: peeled entry without its tag", errRefListingMalformed)
		}
	}
	for name, object := range direct {
		if commit, ok := peeled[name]; ok {
			listing.Tags[name] = TagRef{Object: object, Commit: commit, Annotated: true}
		} else {
			listing.Tags[name] = TagRef{Object: object, Commit: object}
		}
	}
	return listing, nil
}

// parseUploadPackAdvertisement turns a smart-HTTP ref advertisement
// (protocol v0, "/info/refs?service=git-upload-pack") into ls-remote form,
// so both share ParseLsRemote.
func parseUploadPackAdvertisement(raw []byte) ([]byte, error) {
	rest := raw
	readPkt := func() (line []byte, flush bool, err error) {
		if len(rest) < 4 {
			return nil, false, fmt.Errorf("%w: truncated advertisement", errRefListingMalformed)
		}
		n, err := strconv.ParseUint(string(rest[:4]), 16, 16)
		if err != nil {
			return nil, false, fmt.Errorf("%w: bad packet length", errRefListingMalformed)
		}
		if n == 0 {
			rest = rest[4:]
			return nil, true, nil
		}
		if n < 4 || int(n) > len(rest) {
			return nil, false, fmt.Errorf("%w: bad packet length", errRefListingMalformed)
		}
		line, rest = rest[4:n], rest[n:]
		return bytes.TrimSuffix(line, []byte("\n")), false, nil
	}
	first, flush, err := readPkt()
	if err != nil || flush || string(first) != "# service=git-upload-pack" {
		return nil, fmt.Errorf("%w: not an upload-pack advertisement", errRefListingMalformed)
	}
	if _, flush, err = readPkt(); err != nil || !flush {
		return nil, fmt.Errorf("%w: missing flush after the service line", errRefListingMalformed)
	}
	var out bytes.Buffer
	for index := 0; ; index++ {
		line, flush, err := readPkt()
		if err != nil {
			return nil, err
		}
		if flush {
			break
		}
		if index == 0 {
			// The first ref carries the capability list after a NUL.
			line, _, _ = bytes.Cut(line, []byte{0})
		}
		object, ref, ok := bytes.Cut(line, []byte(" "))
		if !ok {
			return nil, fmt.Errorf("%w: unexpected ref line", errRefListingMalformed)
		}
		if index == 0 && string(ref) == "capabilities^{}" {
			// An empty repository advertises no refs.
			continue
		}
		out.Write(object)
		out.WriteByte('\t')
		out.Write(ref)
		out.WriteByte('\n')
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: data after the final flush", errRefListingMalformed)
	}
	return out.Bytes(), nil
}

// GitHubRefFetcher lists a repository's refs from github.com's smart-HTTP
// endpoint, the request "git ls-remote" makes. It sends no credentials,
// never follows a redirect and never contacts another host.
type GitHubRefFetcher struct {
	// transport replaces the network transport in tests only.
	transport http.RoundTripper
}

// GitRefs implements GitRefSource.
func (f GitHubRefFetcher) GitRefs(ctx context.Context, owner, repo string) (RefListing, error) {
	if !repoNamePattern.MatchString(owner) || !repoNamePattern.MatchString(repo) || owner == "." || owner == ".." || repo == "." || repo == ".." {
		return RefListing{}, errRejected
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/"+owner+"/"+repo+".git/info/refs?service=git-upload-pack", nil)
	if err != nil {
		return RefListing{}, errRejected
	}
	request.Header.Set("User-Agent", "git/2.0 (prufyx-evidence-repin/1)")
	request.Header.Set("Accept-Encoding", "identity")
	var transport http.RoundTripper = &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig:        &tls.Config{ServerName: "github.com", MinVersion: tls.VersionTLS12},
	}
	if f.transport != nil {
		transport = f.transport
	}
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     transport,
	}
	response, err := client.Do(request)
	if err != nil {
		return RefListing{}, fmt.Errorf("%w: transport: %v", errRejected, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/x-git-upload-pack-advertisement" {
		return RefListing{}, fmt.Errorf("%w: ref listing returned status %d", errRejected, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRefListingBytes+1))
	if err != nil {
		return RefListing{}, fmt.Errorf("%w: read: %v", errRejected, err)
	}
	if int64(len(data)) > maxRefListingBytes {
		return RefListing{}, errRefListingTooLarge
	}
	text, err := parseUploadPackAdvertisement(data)
	if err != nil {
		return RefListing{}, err
	}
	return ParseLsRemote(text)
}

var repoNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// withGitRefs adds a GitRefSource to an APIFetcher that has none.
type withGitRefs struct {
	APIFetcher
	refs GitRefSource
}

func (w withGitRefs) GitRefs(ctx context.Context, owner, repo string) (RefListing, error) {
	return w.refs.GitRefs(ctx, owner, repo)
}

// CompleteReleaseScan forwards an inner releaseScanGate.
func (w withGitRefs) CompleteReleaseScan(owner, repo string) bool {
	if gate, ok := w.APIFetcher.(releaseScanGate); ok {
		return gate.CompleteReleaseScan(owner, repo)
	}
	return true
}

// parseTagLineTag parses a release tag for a tag-derived line: the strict
// grammar of parseStrictTag, whose prefix may also be one bare lowercase
// word ("go1.26.6").
func parseTagLineTag(tag string) (tagVersion, bool) {
	if v, ok := parseStrictTag(tag); ok {
		return v, true
	}
	match := strictTagPattern.FindStringSubmatch(tag)
	if match == nil || !tagLinePrefixPattern.MatchString(match[1]) {
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

// onLineForm classifies a tag that does not parse as a release tag
// relative to one prefix and numeric line.
type onLineForm int

const (
	formNotOnLine onLineForm = iota
	formPrerelease
	formUnrecognised
)

// classifyNonRelease places a tag that is not a strict release tag
// relative to prefix and line MAJOR.MINOR: not on the line at all, a
// recognised pre-release of the line ("v1.2.3-rc.1", "go1.26rc1"), or on
// the line in a form nothing here can order ("v1.2.3-hotfix", "v1.2.3.4",
// "go1.20").
func classifyNonRelease(tag, prefix string, major, minor int) onLineForm {
	head := prefix + strconv.Itoa(major) + "." + strconv.Itoa(minor)
	if !strings.HasPrefix(tag, head) {
		return formNotOnLine
	}
	rest := tag[len(head):]
	if rest == "" {
		return formUnrecognised
	}
	if rest[0] >= '0' && rest[0] <= '9' {
		return formNotOnLine
	}
	suffix := rest
	if rest[0] == '.' {
		digits := 0
		for digits+1 < len(rest) && rest[digits+1] >= '0' && rest[digits+1] <= '9' {
			digits++
		}
		if digits == 0 {
			return formUnrecognised
		}
		suffix = rest[1+digits:]
		if suffix == "" {
			// MAJOR.MINOR.PATCH that the strict grammar refused (a
			// leading zero, an out-of-range number).
			return formUnrecognised
		}
	}
	if prereleasePattern.MatchString(suffix) {
		return formPrerelease
	}
	return formUnrecognised
}

// looseLine reads the first MAJOR.MINOR of a tag, whatever surrounds it:
// the text before the first digit is the prefix, and padded reports a
// leading zero in either number. It finds the line a tag names even when
// the tag is not a release tag, so that such a tag can never be ignored.
func looseLine(tag string) (prefix string, major, minor int, padded, ok bool) {
	i := strings.IndexAny(tag, "0123456789")
	if i < 0 {
		return "", 0, 0, false, false
	}
	digits := func(s string) string {
		n := 0
		for n < len(s) && s[n] >= '0' && s[n] <= '9' {
			n++
		}
		return s[:n]
	}
	a := digits(tag[i:])
	rest := tag[i+len(a):]
	if !strings.HasPrefix(rest, ".") {
		return "", 0, 0, false, false
	}
	b := digits(rest[1:])
	if b == "" || len(a) > 6 || len(b) > 6 {
		return "", 0, 0, false, false
	}
	major, _ = strconv.Atoi(a)
	minor, _ = strconv.Atoi(b)
	padded = (len(a) > 1 && a[0] == '0') || (len(b) > 1 && b[0] == '0')
	return tag[:i], major, minor, padded, true
}

// IgnoredTag is a tag on a line that was deliberately not considered as
// its head, with the reason.
type IgnoredTag struct {
	Tag    string `json:"tag"`
	Reason string `json:"reason"`
}

// tagLine is the outcome of deriving a citation's line from a ref listing.
type tagLine struct {
	pinnedTag string
	pinned    tagVersion
	headTag   string
	head      TagRef
	ignored   []IgnoredTag
	ignoredN  int
	digest    string
	// unknown is non-empty when no line can be used; pinUnknown says
	// whether the pin itself could not be placed (no line record).
	unknown    string
	pinUnknown bool
}

// deriveTagLine places pinnedCommit on a release line of listing and finds
// that line's newest release tag. It is pure and deterministic: the result
// depends only on the listing's content, never on its order.
func deriveTagLine(listing RefListing, pinnedCommit string) tagLine {
	names := make([]string, 0, len(listing.Tags))
	for name := range listing.Tags {
		names = append(names, name)
	}
	sort.Strings(names)
	var versionPrefixes []string
	for _, name := range names {
		if match := strictTagPattern.FindStringSubmatch(name); match != nil {
			versionPrefixes = append(versionPrefixes, match[1])
		}
	}
	// The repository-wide prefix rule is the one the latest-release
	// selection uses: only none, "v" or "go", and only one of them. The
	// input is the prefix of every version-looking tag, so a prefix the
	// strict grammar rejects also makes the repository ambiguous.
	if reason := latestrelease.AmbiguousPrefixes(versionPrefixes); reason != "" {
		return tagLine{pinUnknown: true, unknown: "the repository tags versions under " + reason}
	}

	var atPin []string
	var prereleaseAtPin bool
	for _, name := range names {
		if listing.Tags[name].Commit != pinnedCommit {
			continue
		}
		if _, ok := parseTagLineTag(name); ok {
			atPin = append(atPin, name)
		} else {
			prereleaseAtPin = true
		}
	}
	if len(atPin) == 0 {
		var branches []string
		for branch, commit := range listing.Heads {
			if commit == pinnedCommit {
				branches = append(branches, branch)
			}
		}
		sort.Strings(branches)
		switch {
		case prereleaseAtPin:
			return tagLine{pinUnknown: true, unknown: "the pinned commit carries no release tag, only tags the release grammar does not accept"}
		case len(branches) > 0:
			return tagLine{pinUnknown: true, unknown: "the pinned commit is the head of branch " + branches[0] + ", not a release tag; a branch is never a line head"}
		default:
			return tagLine{pinUnknown: true, unknown: "no tag points at the pinned commit"}
		}
	}
	pinned, _ := parseTagLineTag(atPin[0])
	for _, name := range atPin[1:] {
		other, _ := parseTagLineTag(name)
		if other.Prefix != pinned.Prefix || other.Major != pinned.Major || other.Minor != pinned.Minor {
			return tagLine{pinUnknown: true, unknown: "the pinned commit is tagged with more than one release line"}
		}
		if other != pinned {
			return tagLine{pinUnknown: true, unknown: "the pinned commit carries more than one release tag"}
		}
	}
	result := tagLine{pinnedTag: atPin[0], pinned: pinned}

	var lineTags []string
	headPatch := -1
	for _, name := range names {
		if parsed, ok := parseTagLineTag(name); ok {
			if parsed.Major != pinned.Major || parsed.Minor != pinned.Minor {
				continue
			}
			if parsed.Prefix != pinned.Prefix {
				result.unknown = "the same numeric line is tagged under more than one tag prefix (" + name + ")"
				return result
			}
			lineTags = append(lineTags, name+" "+listing.Tags[name].Commit)
			if parsed.Patch > headPatch {
				headPatch = parsed.Patch
				result.headTag = name
			}
			continue
		}
		if prefix, major, minor, padded, ok := looseLine(name); ok && major == pinned.Major && minor == pinned.Minor && (prefix != pinned.Prefix || padded) {
			// The numeric line under another prefix, or zero-padded: a
			// form nothing here can order against the line's releases.
			result.unknown = "a tag on the line has another prefix or a zero-padded version (" + name + ")"
			return result
		}
		switch classifyNonRelease(name, pinned.Prefix, pinned.Major, pinned.Minor) {
		case formPrerelease:
			result.ignoredN++
			if len(result.ignored) < maxIgnoredOnLine {
				result.ignored = append(result.ignored, IgnoredTag{Tag: name, Reason: ignoredPrerelease})
			}
		case formUnrecognised:
			result.unknown = "a tag on the line has a form the release grammar does not accept (" + name + ")"
			return result
		}
	}
	if result.headTag == "" || headPatch < pinned.Patch {
		result.unknown = "the line has no release tag at or above the pinned one"
		return result
	}
	result.head = listing.Tags[result.headTag]
	sum := sha256.Sum256([]byte(strings.Join(lineTags, "\n")))
	result.digest = "sha256:" + hex.EncodeToString(sum[:])
	return result
}

// tagLineKey keys a tag-derived line apart from a line proven by Releases.
func tagLineKey(owner, repo, prefix, line string) string {
	return lineKey(owner, repo, prefix, line) + "|" + LineBasisGitTags
}

// refListing returns the repository's ref listing, fetched at most once
// per run.
func (r *lineResolver) refListing(source GitRefSource, owner, repo string) (RefListing, error) {
	key := owner + "/" + repo
	if cached, ok := r.refs[key]; ok {
		return cached.listing, cached.err
	}
	listing, err := source.GitRefs(r.ctx, owner, repo)
	r.refs[key] = refResult{listing: listing, err: err}
	return listing, err
}

type refResult struct {
	listing RefListing
	err     error
}

// decideTagLine is decide for a repository whose current release came from
// the tags fallback.
func (r *lineResolver) decideTagLine(c Citation) baselineDecision {
	source, ok := r.fetcher.(GitRefSource)
	if !ok {
		return baselineDecision{note: "the repository publishes no GitHub Releases; the tags fallback has no release line"}
	}
	listing, err := r.refListing(source, c.Owner, c.Repo)
	switch {
	case errors.Is(err, errRefListingMalformed) || errors.Is(err, errRefListingTooLarge):
		return baselineDecision{note: "tag line not derived: " + err.Error()}
	case err != nil:
		return baselineDecision{pending: "git ref listing not available; re-run to retry"}
	}
	derived := deriveTagLine(listing, c.OldCommit)
	if derived.pinUnknown {
		return baselineDecision{note: "tag line not derived: " + derived.unknown}
	}
	pin := PinResolution{Owner: c.Owner, Repo: c.Repo, Commit: c.OldCommit, Status: pinFound, Tag: derived.pinnedTag, Prefix: derived.pinned.Prefix, Line: derived.pinned.line(), ResolvedAt: r.stamp()}
	line := LineResolution{Owner: c.Owner, Repo: c.Repo, Prefix: pin.Prefix, Line: pin.Line, Basis: LineBasisGitTags, ResolvedAt: r.stamp()}
	key := tagLineKey(c.Owner, c.Repo, pin.Prefix, pin.Line)
	if derived.unknown != "" {
		line.Status, line.Detail = lineUnderivable, derived.unknown
		r.state.Lines[key] = line
		return baselineDecision{pin: pin, note: "tag line not usable: " + derived.unknown}
	}
	// The ref listing cannot tell a commit from a tree or blob: resolve the
	// head tag through the tag API too, which peels annotated tags and
	// answers only for a commit, and require the same commit.
	headCommit, err := r.tagCommit(c.Owner, c.Repo, derived.headTag)
	if err != nil {
		return baselineDecision{pending: "tag line head not yet resolved; re-run to retry"}
	}
	if headCommit == "" || headCommit != derived.head.Commit {
		line.Status, line.Detail = lineUnderivable, "the line's newest release tag does not resolve to the commit the ref listing names"
		r.state.Lines[key] = line
		return baselineDecision{pin: pin, note: "tag line not usable: " + line.Detail}
	}
	line.Status, line.Tag, line.Commit = lineResolved, derived.headTag, headCommit
	line.TagsDigest, line.IgnoredTags, line.IgnoredTagCount = derived.digest, derived.ignored, derived.ignoredN
	r.state.Lines[key] = line
	return baselineDecision{line: &line, pin: pin, basis: LineBasisGitTags}
}

// TagLineBaselineConsistent is LineBaselineConsistent for a tag-derived
// line: both tags parse under the tag-line grammar, share one prefix and
// the numeric line, and the compared tag is not older than the pinned one.
func TagLineBaselineConsistent(pinnedTag, baselineTag, line string) bool {
	pinned, ok1 := parseTagLineTag(pinnedTag)
	baseline, ok2 := parseTagLineTag(baselineTag)
	return ok1 && ok2 && pinned.Prefix == baseline.Prefix &&
		pinned.line() == line && baseline.line() == line && baseline.Patch >= pinned.Patch
}
