// SPDX-License-Identifier: AGPL-3.0-only

// Package evidencerepin implements the "evidence repin" maintainer
// subcommand, the maintainer tool that keeps reviewed evidence current as
// upstream projects publish new releases.
//
// It re-resolves the existing rule packs' citations at each project's
// current upstream release commit and classifies what happened to each one:
//
//   - NO_NEW_RELEASE        - no release since the citation's pinned commit
//   - FILE_IDENTICAL        - the whole file at the current release commit is
//     byte-identical to the pinned revision, verified directly against the
//     corpus's recorded contentDigest, which is a WHOLE-FILE digest, not a
//     span digest; when the whole file is unchanged the cited span is
//     necessarily unchanged too
//   - SPAN_IDENTICAL        - the file changed elsewhere, but after fetching
//     the file at the citation's own pinned commit and confirming that
//     fetch matches the recorded contentDigest, the cited span itself is
//     byte-identical at the same line range in the new file
//   - SPAN_MOVED            - same span content found at a different line
//     range in the new file
//   - CONTENT_CHANGED       - path exists, cited span content differs and is
//     not found anywhere else in the new file
//   - PATH_GONE             - path or repository no longer resolvable at the
//     current release commit
//   - CORPUS_DIGEST_MISMATCH - the file fetched at the citation's OWN pinned
//     commit does not hash to the recorded contentDigest (or is not
//     reachable there at all); this means the corpus record itself is
//     wrong or the original capture was not faithful. It is a real
//     integrity finding, reported separately, and is never batch-attestable
//
// It is deterministic and involves no model anywhere. It reads rule packs
// and network bytes and writes a worklist; it never writes to a rule pack
// or a review record, and it never fabricates or alters a compatibility
// claim. Whole-file digesting reuses maintainer/sourcecorpus.SHA directly
// (never reimplemented); span extraction reuses maintainer/sourcecorpus's
// own LF-split/join-with-LF/no-trailing-separator/no-normalization
// convention, applied to actual bytes rather than to a digest, since
// contentDigest is a whole-file digest and cannot be compared to a span.
// Blob retrieval reuses maintainer/sourcecapture's fixed-URL immutable-blob
// fetch discipline (no discovery, no redirects, fixed host, bounded size).
package evidencerepin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/maintainer/latestrelease"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const (
	// Schema identifies the worklist artifact this command produces.
	Schema = "prufyx.io/evidence-repin-worklist/v2"
	// SchemaV1 is the previous worklist schema, whose citations carry no
	// baseline fields and were all compared with the latest release.
	// Consumers may still read it, treating every citation as BaselineLatest.
	SchemaV1 = "prufyx.io/evidence-repin-worklist/v1"
	// Authority states plainly what this output is and is not.
	Authority = "LOCAL_MECHANICAL_CITATION_DRIFT_CLASSIFICATION_NOT_A_CLAIM"
	// StateSchema identifies the resumable progress file.
	StateSchema = "prufyx.io/evidence-repin-state/v2"
	// stateSchemaV1 state files hold repository resolutions that remain
	// valid; their citation results carry no baseline record and are
	// discarded on load.
	stateSchemaV1 = "prufyx.io/evidence-repin-state/v1"

	maxRulesBytes int64 = 16 << 20
	// maxAPIBytes bounds one api.github.com response. A page of releases
	// carries release notes and can be several megabytes.
	maxAPIBytes   int64 = 16 << 20
	maxStateBytes int64 = 64 << 20

	// Drift classes, ordered from cheapest to most expensive to re-review.
	ClassNoNewRelease         = "NO_NEW_RELEASE"
	ClassFileIdentical        = "FILE_IDENTICAL"
	ClassSpanIdentical        = "SPAN_IDENTICAL"
	ClassSpanMoved            = "SPAN_MOVED"
	ClassContentChanged       = "CONTENT_CHANGED"
	ClassPathGone             = "PATH_GONE"
	ClassCorpusDigestMismatch = "CORPUS_DIGEST_MISMATCH"
	// ClassPending is not one of the five reported drift classes. It marks
	// a citation this run could not resolve (rate limit, transport error,
	// or a repo not yet attempted) so a later run can retry it.
	ClassPending = "PENDING"
	// ClassNoReleaseBaseline marks a citation whose repository was
	// definitively determined to publish neither GitHub Releases nor tags,
	// so there is nothing to compare the pinned commit against. It is a
	// terminal class, unlike ClassPending: it does not block a pack's batch (E2), and it is
	// never batch-attestable (E1): the rules citing it need individual
	// review or expire. It is re-derived from the repository's current
	// resolution on every run, never resumed from an earlier one. It is recorded only when both lists were fetched
	// successfully and returned an empty array; a missing repository,
	// an error, a rate limit or an unparseable body stays PENDING.
	ClassNoReleaseBaseline = "NO_RELEASE_BASELINE"

	repoResolved           = "RESOLVED"
	repoPendingRateLimited = "PENDING_RATE_LIMITED"
	repoPendingError       = "PENDING_ERROR"
	repoNoReleasesOrTags   = "NO_RELEASES_OR_TAGS"

	// resolutionTagFallback marks a RepoResolution or ClassResult whose
	// current-commit resolution came from the tags fallback rather than
	// from GitHub Releases (see ResolveCurrentCommit and latestTag). The
	// tags list endpoint carries no documented recency guarantee, so a
	// tag-fallback resolution is weaker evidence than a Releases-based one
	// and must be machine-identifiable so downstream batch re-attestation
	// can refuse it.
	resolutionTagFallback = "tag_fallback"

	// DefaultMaxAge is the freshness bound applied when --max-age is not
	// given: a repo resolution or citation classification older than this
	// is stale and must be recomputed rather than resumed as current.
	DefaultMaxAge = 72 * time.Hour
)

var (
	errRejected    = errors.New("evidence repin rejected")
	blobURLPattern = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/blob/([0-9a-f]{40})/(.+)$`)
	rawURLPattern  = regexp.MustCompile(`^https://raw\.githubusercontent\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/([0-9a-f]{40})/(.+)$`)
)

// parseCitationURL accepts the two immutable-blob URL shapes present in the
// shipped rule packs: the github.com/.../blob/... web form, and the
// raw.githubusercontent.com/.../... form sourcecapture itself fetches from.
// It never accepts a mutable ref (branch/tag name) in place of a commit.
func parseCitationURL(rawURL string) (owner, repo, commit, path string, ok bool) {
	if match := blobURLPattern.FindStringSubmatch(rawURL); match != nil {
		return match[1], match[2], match[3], match[4], true
	}
	if match := rawURLPattern.FindStringSubmatch(rawURL); match != nil {
		return match[1], match[2], match[3], match[4], true
	}
	return "", "", "", "", false
}

// Citation is one immutable evidence source cited by exactly one rule
// source entry in an existing rule pack.
type Citation struct {
	RulePack  string
	RuleID    string
	Project   string
	SourceID  string
	Owner     string
	Repo      string
	Path      string
	OldCommit string
	OldDigest string
	StartLine int
	EndLine   int
	// SubjectFrom and SubjectTo are the rule subject's version strings.
	// They are only hints for naming candidate release tags (see
	// releaseline.go); nothing is concluded from them without a commit match.
	SubjectFrom string
	SubjectTo   string
}

func (c Citation) repoKey() string { return c.Owner + "/" + c.Repo }
func (c Citation) key() string     { return c.RulePack + "\x00" + c.RuleID + "\x00" + c.SourceID }

// LoadCitations reads one rule pack (the shape shared by cncfcheck's and
// projectcheck's data/rules.json) and returns every cited source as a
// Citation. It never mutates the input and never opens a write path to a
// rule pack.
func LoadCitations(rulePackPath string, raw []byte) ([]Citation, error) {
	var document struct {
		Entries []struct {
			Project string `json:"project"`
			Rule    struct {
				ID      string `json:"id"`
				Subject struct {
					From string `json:"from"`
					To   string `json:"to"`
				} `json:"subject"`
				Evidence struct {
					Basis     string                      `json:"basis"`
					Extractor *constraintengine.Extractor `json:"extractor"`
					DerivedAt string                      `json:"derivedAt"`
					Sources   []struct {
						ID            string `json:"id"`
						URL           string `json:"url"`
						Revision      string `json:"revision"`
						ContentDigest string `json:"contentDigest"`
						StartLine     int    `json:"startLine"`
						EndLine       int    `json:"endLine"`
					} `json:"sources"`
				} `json:"evidence"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("%w: decode %s: %v", errRejected, rulePackPath, err)
	}
	var out []Citation
	for _, entry := range document.Entries {
		// The citations of a mechanical rule are classified like any other
		// (drift is information), but a malformed basis is rejected here so a
		// worklist is never built over a rule the engine would not parse.
		evidence := entry.Rule.Evidence
		if err := constraintengine.ValidateReviewedOrMechanicalBasis(evidence.Basis, evidence.Extractor, evidence.DerivedAt); err != nil {
			return nil, fmt.Errorf("%w: invalid evidence basis in %s: rule %s", errRejected, rulePackPath, entry.Rule.ID)
		}
		for _, source := range entry.Rule.Evidence.Sources {
			owner, repo, commit, path, ok := parseCitationURL(source.URL)
			if !ok {
				return nil, fmt.Errorf("%w: unresolvable citation url shape in %s: rule %s source %s", errRejected, rulePackPath, entry.Rule.ID, source.ID)
			}
			if commit != source.Revision {
				return nil, fmt.Errorf("%w: citation url commit does not match revision in %s: rule %s source %s", errRejected, rulePackPath, entry.Rule.ID, source.ID)
			}
			if source.StartLine < 1 || source.EndLine < source.StartLine {
				return nil, fmt.Errorf("%w: invalid span in %s: rule %s source %s", errRejected, rulePackPath, entry.Rule.ID, source.ID)
			}
			out = append(out, Citation{
				RulePack:  rulePackPath,
				RuleID:    entry.Rule.ID,
				Project:   entry.Project,
				SourceID:  source.ID,
				Owner:     owner,
				Repo:      repo,
				Path:      path,
				OldCommit: source.Revision,
				OldDigest: source.ContentDigest,
				StartLine: source.StartLine,
				EndLine:   source.EndLine,

				SubjectFrom: entry.Rule.Subject.From,
				SubjectTo:   entry.Rule.Subject.To,
			})
		}
	}
	for _, entry := range document.Entries {
		if err := CheckPackEntry(entry.Project, entry.Rule.ID); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", errRejected, rulePackPath, err)
		}
	}
	return appendRecordCitations(out, rulePackPath, raw)
}

// appendRecordCitations adds the citations of the pack's line attestation
// and path-policy records (see PackRecords), under their record IDs, so
// source drift is monitored for them exactly as for rules.
func appendRecordCitations(out []Citation, rulePackPath string, raw []byte) ([]Citation, error) {
	records, err := PackRecords(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: pack records in %s: %v", errRejected, rulePackPath, err)
	}
	if len(records) == 0 {
		return out, nil
	}
	for _, record := range records {
		for _, source := range record.Sources {
			owner, repo, commit, path, ok := parseCitationURL(source.URL)
			if !ok {
				return nil, fmt.Errorf("%w: unresolvable citation url shape in %s: %s source %s", errRejected, rulePackPath, record.Scope, source.ID)
			}
			if commit != source.Revision {
				return nil, fmt.Errorf("%w: citation url commit does not match revision in %s: %s source %s", errRejected, rulePackPath, record.Scope, source.ID)
			}
			if source.StartLine < 1 || source.EndLine < source.StartLine {
				return nil, fmt.Errorf("%w: invalid span in %s: %s source %s", errRejected, rulePackPath, record.Scope, source.ID)
			}
			out = append(out, Citation{
				RulePack: rulePackPath, RuleID: record.ID, Project: record.Project, SourceID: source.ID,
				Owner: owner, Repo: repo, Path: path, OldCommit: source.Revision, OldDigest: source.ContentDigest,
				StartLine: source.StartLine, EndLine: source.EndLine,
			})
		}
	}
	return out, nil
}

// APIFetcher performs a bounded, unauthenticated-or-token-bearing GET
// against a fixed api.github.com path. It never follows redirects, never
// contacts another host, and never logs the token.
type APIFetcher interface {
	Fetch(ctx context.Context, path string) (body []byte, status int, err error)
}

// GitHubAPIFetcher is the production APIFetcher. It reads an optional
// bearer token supplied by the caller (never read from disk, never logged,
// never written anywhere) to raise GitHub's unauthenticated 60/hour limit
// to 5000/hour when present.
type GitHubAPIFetcher struct {
	// Token is an optional GitHub token. Empty means unauthenticated.
	Token string
}

func (f GitHubAPIFetcher) Fetch(ctx context.Context, path string) ([]byte, int, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "#\\") {
		return nil, 0, errRejected
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return nil, 0, errRejected
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "prufyx-evidence-repin/1")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.Token != "" {
		request.Header.Set("Authorization", "Bearer "+f.Token)
	}
	client := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
			MaxResponseHeaderBytes: 16 << 10,
			TLSClientConfig:        &tls.Config{ServerName: "api.github.com", MinVersion: tls.VersionTLS12},
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: transport: %v", errRejected, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil || int64(len(data)) > maxAPIBytes {
		return nil, 0, errRejected
	}
	return data, response.StatusCode, nil
}

// RepoResolution records the outcome of resolving one repository's current
// release commit.
type RepoResolution struct {
	Owner         string `json:"owner"`
	Repo          string `json:"repo"`
	Status        string `json:"status"`
	CurrentTag    string `json:"currentTag,omitempty"`
	CurrentCommit string `json:"currentCommit,omitempty"`
	Detail        string `json:"detail,omitempty"`
	ResolvedAt    string `json:"resolvedAt,omitempty"`
	// Resolution is resolutionTagFallback when CurrentCommit came from the
	// tags fallback rather than GitHub Releases, so downstream tooling can
	// treat it as weaker evidence. Empty means Releases resolved it.
	Resolution string `json:"resolution,omitempty"`
	// Determination records how a NO_RELEASES_OR_TAGS status was reached.
	Determination *NoBaselineDetermination `json:"determination,omitempty"`
	// Stale is true when this resolution is older than the run's --max-age
	// bound but could not be refreshed this run (for example because an
	// earlier repository in the same run hit the GitHub API rate limit).
	// A stale resolution is reported as-is, never silently re-stamped with
	// a new ResolvedAt.
	Stale bool `json:"stale,omitempty"`
	// Source, MirrorCheckedAt and MirrorReleasesAt are set when the
	// resolution was read from a local mirror (see mirror.go). ResolvedAt is
	// then the OLDEST of the mirror's own last successful look at the
	// repository and its release metadata, never the time of this run.
	Source           string `json:"source,omitempty"`
	MirrorCheckedAt  string `json:"mirrorCheckedAt,omitempty"`
	MirrorReleasesAt string `json:"mirrorReleasesAt,omitempty"`
}

var errRateLimited = errors.New("github api rate limited")

// NoBaselineDetermination is the evidence that a repository has no release
// or tag to compare against: the releases list and the tags list were each
// fetched with a success status and decoded as a JSON array holding no
// entry. The first page is conclusive because both endpoints page from the
// start of the list, so an empty first page is an empty list.
type NoBaselineDetermination struct {
	ReleasesListEmpty bool `json:"releasesListEmpty"`
	TagsListEmpty     bool `json:"tagsListEmpty"`
}

// noBaselineDetail is the human-readable form recorded on the citation.
const noBaselineDetail = "repository publishes no GitHub Releases and no tags: releases list and tags list were both fetched successfully and are empty"

func (d *NoBaselineDetermination) definitive() bool {
	return d != nil && d.ReleasesListEmpty && d.TagsListEmpty
}

// errNoReleaseBaseline is returned by ResolveCurrentCommit only when both
// lists were fetched and were provably empty.
var errNoReleaseBaseline = errors.New("repository has no releases and no tags")

// ResolveCurrentCommit finds an owner/repo's latest published release
// (falling back to its most recent tag when the project publishes no
// GitHub Releases) and resolves that tag to a commit SHA. It makes at most
// a bounded number of api.github.com requests (the release list or, when
// there are no releases, the tags list, then the tag's ref) and selects the
// latest release or tag with the shared rule of package latestrelease.
// resolution is resolutionTagFallback when the tags fallback was used
// (weaker evidence: see latestTag), or "" when GitHub Releases resolved it.
func ResolveCurrentCommit(ctx context.Context, fetcher APIFetcher, owner, repo string) (tag, commit, resolution string, err error) {
	tag, releasesEmpty, err := latestReleaseTag(ctx, fetcher, owner, repo)
	if err != nil {
		return "", "", "", err
	}
	if tag == "" {
		var tagsEmpty bool
		tag, tagsEmpty, err = latestTag(ctx, fetcher, owner, repo)
		if err != nil {
			return "", "", "", err
		}
		if tag != "" {
			resolution = resolutionTagFallback
		} else if releasesEmpty && tagsEmpty {
			return "", "", "", errNoReleaseBaseline
		}
	}
	if tag == "" {
		return "", "", "", nil
	}
	commit, err = resolveTagCommit(ctx, fetcher, owner, repo, tag)
	if err != nil {
		return "", "", "", err
	}
	return tag, commit, resolution, nil
}

func apiGet(ctx context.Context, fetcher APIFetcher, path string) ([]byte, error) {
	body, status, err := fetcher.Fetch(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRejected, err)
	}
	if status == 403 || status == 429 {
		return nil, errRateLimited
	}
	if status == 404 {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%w: api.github.com returned status %d", errRejected, status)
	}
	return body, nil
}

// latestReleaseTag returns the latest published release tag under the
// shared selection rule (package latestrelease): drafts and pre-releases
// are skipped and the highest strict version wins, whatever order the
// source lists releases in. The whole release list is read (pages of
// releasePageSize, at most maxReleasePages pages; a longer list is judged
// on the pages read, exactly as a truncated mirror list is). empty is true
// only when the endpoint answered successfully with a JSON array that holds
// no release at all; a 404 or a list holding only drafts and prereleases
// is not "empty".
func latestReleaseTag(ctx context.Context, fetcher APIFetcher, owner, repo string) (tag string, empty bool, err error) {
	list, err := fetchAllReleases(ctx, fetcher, owner, repo)
	if err != nil {
		return "", false, err
	}
	if list.notFound {
		return "", false, nil
	}
	candidates := make([]latestrelease.Release, 0, len(list.entries))
	for _, e := range list.entries {
		candidates = append(candidates, latestrelease.Release{ID: e.ID, Tag: e.Tag, Draft: e.Draft, Prerelease: e.Prerelease})
	}
	if best, ok := latestrelease.Select(candidates); ok {
		return best.Tag, false, nil
	}
	return "", len(list.entries) == 0, nil
}

// tagsPageSize and maxTagPages bound the tags-list scan used when a
// project publishes no GitHub Releases. GitHub's tags endpoint has no
// documented sort order, so the highest strict version is chosen over the
// whole list (package latestrelease) rather than from its first page; a
// list longer than the bound is not trusted and the repository stays
// pending. A mirror source serves every recorded tag, so it is subject to
// the same bound.
const (
	tagsPageSize = 100
	maxTagPages  = 50
)

// latestTag is the tags fallback. empty has the same meaning as for
// latestReleaseTag: a successful response holding an empty JSON array.
func latestTag(ctx context.Context, fetcher APIFetcher, owner, repo string) (tag string, empty bool, err error) {
	var names []string
	seen := map[string]bool{}
	for page := 1; ; page++ {
		if page > maxTagPages {
			return "", false, fmt.Errorf("%w: tags list longer than %d pages", errRejected, maxTagPages)
		}
		body, err := apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/tags?per_page="+strconv.Itoa(tagsPageSize)+"&page="+strconv.Itoa(page))
		if err != nil {
			return "", false, err
		}
		if body == nil {
			if page == 1 {
				return "", false, nil
			}
			return "", false, fmt.Errorf("%w: tags page %d not found", errRejected, page)
		}
		var tags []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &tags); err != nil || tags == nil {
			return "", false, fmt.Errorf("%w: tags page %d is not an array", errRejected, page)
		}
		if len(tags) == 0 {
			break
		}
		for _, t := range tags {
			if !seen[t.Name] {
				seen[t.Name] = true
				names = append(names, t.Name)
			}
		}
	}
	if len(names) == 0 {
		return "", true, nil
	}
	best, _ := latestrelease.SelectTag(names)
	return best, false, nil
}

func resolveTagCommit(ctx context.Context, fetcher APIFetcher, owner, repo, tag string) (string, error) {
	body, err := apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/git/ref/tags/"+url.PathEscape(tag))
	if err != nil {
		return "", err
	}
	if body == nil {
		return "", nil
	}
	var ref struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &ref); err != nil || !commitPattern.MatchString(ref.Object.SHA) {
		return "", nil
	}
	if ref.Object.Type == "commit" {
		return ref.Object.SHA, nil
	}
	if ref.Object.Type != "tag" {
		return "", nil
	}
	// Annotated tag: peel one level to the commit it points at.
	body, err = apiGet(ctx, fetcher, "/repos/"+owner+"/"+repo+"/git/tags/"+ref.Object.SHA)
	if err != nil {
		return "", err
	}
	if body == nil {
		return "", nil
	}
	var annotated struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &annotated); err != nil || annotated.Object.Type != "commit" || !commitPattern.MatchString(annotated.Object.SHA) {
		return "", nil
	}
	return annotated.Object.SHA, nil
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// cachingFetcher wraps a sourcecapture.Fetcher and caches results by exact
// request path, so a corpus-wide run fetches each unique (owner, repo,
// revision, path) blob at most once even though many citations across
// different rules commonly share a file (their own new blob, or the old
// blob at a shared pinned revision). It is not safe for concurrent use;
// BuildWorklist classifies citations sequentially.
type cachingFetcher struct {
	fetcher sourcecapture.Fetcher
	cache   map[string]sourcecapture.FetchResult
}

func newCachingFetcher(fetcher sourcecapture.Fetcher) *cachingFetcher {
	return &cachingFetcher{fetcher: fetcher, cache: map[string]sourcecapture.FetchResult{}}
}

func (c *cachingFetcher) Fetch(ctx context.Context, path string) sourcecapture.FetchResult {
	if cached, ok := c.cache[path]; ok {
		return cached
	}
	result := c.fetcher.Fetch(ctx, path)
	c.cache[path] = result
	return result
}

// ClassResult is one citation's drift classification.
type ClassResult struct {
	RulePack  string `json:"rulePack"`
	RuleID    string `json:"ruleId"`
	Project   string `json:"project"`
	SourceID  string `json:"sourceId"`
	Owner     string `json:"owner"`
	Repo      string `json:"repo"`
	Path      string `json:"path"`
	OldCommit string `json:"oldCommit"`
	NewCommit string `json:"newCommit,omitempty"`
	OldStart  int    `json:"oldStartLine"`
	OldEnd    int    `json:"oldEndLine"`
	NewStart  int    `json:"newStartLine,omitempty"`
	NewEnd    int    `json:"newEndLine,omitempty"`
	Class     string `json:"class"`
	Detail    string `json:"detail,omitempty"`
	// ClassifiedAt is when this classification was computed, RFC3339 UTC.
	// It is set once and never silently re-stamped on resume: a reused
	// result keeps its original ClassifiedAt.
	ClassifiedAt string `json:"classifiedAt,omitempty"`
	// Resolution is resolutionTagFallback when the repo's current commit
	// came from the tags fallback rather than GitHub Releases (see
	// RepoResolution.Resolution); this is weaker evidence and must be
	// refusable by downstream batch re-attestation.
	Resolution string `json:"resolution,omitempty"`
	// Stale is true when this result is older than the run's --max-age
	// bound but could not be recomputed this run (its repo's resolution is
	// itself stale and unrefreshed, typically due to a rate limit earlier
	// in the same run). A stale result is reported as-is, with its original
	// ClassifiedAt, never silently re-stamped as current.
	Stale bool `json:"stale,omitempty"`

	// BaselineMode is the requested comparison policy (BaselineModeLatest
	// or BaselineModeReleaseLine) this result was computed under.
	BaselineMode string `json:"baselineMode,omitempty"`
	// Baseline records which baseline NewCommit came from:
	// BaselineReleaseLine (the newest release on the pinned tag's line) or
	// BaselineLatest (the repository's most recent release).
	Baseline string `json:"baseline,omitempty"`
	// BaselineTag is the release tag NewCommit belongs to.
	BaselineTag string `json:"baselineTag,omitempty"`
	// BaselineLine is the release line (MAJOR.MINOR) for a release-line
	// baseline.
	BaselineLine string `json:"baselineLine,omitempty"`
	// PinnedTag is the release tag proven to point at OldCommit, for a
	// release-line baseline.
	PinnedTag string `json:"pinnedTag,omitempty"`
	// LineStatus is set on a release-line baseline only.
	// LineStatusPinnedIsLatest means the pinned tag is itself the newest
	// release of its line, so the line can no longer change and the
	// comparison is trivially unchanged; LineStatusLaterReleases means
	// newer releases exist on the line. Corrections published only on
	// later lines are not seen by a release-line baseline either way.
	LineStatus string `json:"lineStatus,omitempty"`
	// ObservedDigest and ObservedSize describe the file actually served at
	// the citation's own pinned commit when it did not hash to the recorded
	// contentDigest (CORPUS_DIGEST_MISMATCH), to help diagnose transient
	// serving anomalies.
	ObservedDigest string `json:"observedDigest,omitempty"`
	ObservedSize   *int   `json:"observedSize,omitempty"`
	// BaselineNote says why a release-line request used the latest
	// baseline instead.
	BaselineNote string `json:"baselineNote,omitempty"`
}

// costRank orders the worklist cheapest-reviewer-cost first: batch-attestable
// first, full re-review last.
// CORPUS_DIGEST_MISMATCH sorts after PATH_GONE because, although it is a
// corpus integrity finding rather than ordinary drift, it still requires a
// human and is never batch-attestable. PENDING sorts last of all because it
// is not yet actionable.
func costRank(class string) int {
	switch class {
	case ClassNoNewRelease:
		return 0
	case ClassFileIdentical:
		return 1
	case ClassSpanIdentical:
		return 2
	case ClassSpanMoved:
		return 3
	case ClassContentChanged:
		return 4
	case ClassPathGone:
		return 5
	case ClassCorpusDigestMismatch:
		return 6
	case ClassNoReleaseBaseline:
		return 7
	default:
		return 8
	}
}

// spanBytesAt extracts the exact byte span for lines [start,end]
// (1-indexed, inclusive) using the exact same LF-split/join-with-LF/
// no-trailing-separator convention as maintainer/sourcecorpus's VerifySpans.
func spanBytesAt(lines [][]byte, start, end int) ([]byte, bool) {
	if start < 1 || end < start || end > len(lines) {
		return nil, false
	}
	return bytes.Join(lines[start-1:end], []byte{'\n'}), true
}

// classifySpan compares the cited span as it reads in the OLD file bytes
// (already verified by the caller to hash to the corpus's recorded
// contentDigest) against the same line range in the NEW file bytes.
//
// contentDigest in the shipped rule packs is a WHOLE-FILE digest, not a
// span digest (see the package doc comment), so this function never
// compares a digest to a span; it compares the actual cited bytes, which is
// the only reliable way to answer "is the cited span still intact" once the
// containing file has changed. Equal bytes at the same range means the span
// survived untouched (SPAN_IDENTICAL). Otherwise it searches the new file
// for that exact span content at any offset (SPAN_MOVED), and failing that
// concludes the content changed (CONTENT_CHANGED).
func classifySpan(oldData []byte, start, end int, newData []byte) (class string, newStart, newEnd int) {
	oldLines := bytes.Split(oldData, []byte{'\n'})
	oldSpan, ok := spanBytesAt(oldLines, start, end)
	if !ok {
		return ClassContentChanged, 0, 0
	}
	newLines := bytes.Split(newData, []byte{'\n'})
	if sameRange, ok := spanBytesAt(newLines, start, end); ok && bytes.Equal(sameRange, oldSpan) {
		return ClassSpanIdentical, start, end
	}
	spanCount := end - start + 1
	for candidateStart := 1; candidateStart+spanCount-1 <= len(newLines); candidateStart++ {
		candidateEnd := candidateStart + spanCount - 1
		candidate, ok := spanBytesAt(newLines, candidateStart, candidateEnd)
		if ok && bytes.Equal(candidate, oldSpan) {
			return ClassSpanMoved, candidateStart, candidateEnd
		}
	}
	return ClassContentChanged, 0, 0
}

// Classify resolves one citation against its project's current release
// commit and blob fetcher, returning its drift classification. current is
// the repo's resolved current release commit (possibly equal to the
// citation's own OldCommit, in which case no fetch is needed).
//
// blobFetcher is used for both the new blob (at currentCommit) and, when the
// whole file changed, the citation's own old blob (at citation.OldCommit):
// raw.githubusercontent.com is not subject to the GitHub API rate limit, so
// this extra fetch is cheap, and callers that expect many citations to
// share a file should pass a caching Fetcher (see BuildWorklist).
func Classify(ctx context.Context, citation Citation, currentCommit string, blobFetcher sourcecapture.Fetcher) ClassResult {
	result := ClassResult{
		RulePack: citation.RulePack, RuleID: citation.RuleID, Project: citation.Project, SourceID: citation.SourceID,
		Owner: citation.Owner, Repo: citation.Repo, Path: citation.Path,
		OldCommit: citation.OldCommit, OldStart: citation.StartLine, OldEnd: citation.EndLine,
	}
	if currentCommit == "" {
		result.Class = ClassPending
		result.Detail = "current release commit not yet resolved"
		return result
	}
	result.NewCommit = currentCommit
	if currentCommit == citation.OldCommit {
		result.Class = ClassNoNewRelease
		return result
	}
	newPath := "/" + citation.Owner + "/" + citation.Repo + "/" + currentCommit + "/" + citation.Path
	newFetch := blobFetcher.Fetch(ctx, newPath)
	switch newFetch.Kind {
	case "HTTP_200":
		// contentDigest is a whole-file digest (see the package doc
		// comment): when the whole new file still hashes to it, the file
		// did not change at all, so the cited span is necessarily intact
		// too. This is the cheap, batch-attestable case and needs no
		// further fetch.
		if sourcecorpus.SHA(newFetch.Body) == citation.OldDigest {
			result.Class = ClassFileIdentical
			return result
		}
		// The file changed. Fetch it at the citation's OWN pinned
		// revision and verify that fetch actually matches the recorded
		// contentDigest before trusting it as ground truth for the span
		// comparison; if it doesn't, the corpus record itself is wrong
		// and that is a finding in its own right, not a drift class.
		oldPath := "/" + citation.Owner + "/" + citation.Repo + "/" + citation.OldCommit + "/" + citation.Path
		oldFetch := blobFetcher.Fetch(ctx, oldPath)
		switch oldFetch.Kind {
		case "HTTP_200":
			if sourcecorpus.SHA(oldFetch.Body) != citation.OldDigest {
				result.Class = ClassCorpusDigestMismatch
				size := len(oldFetch.Body)
				result.ObservedDigest, result.ObservedSize = sourcecorpus.SHA(oldFetch.Body), &size
				result.Detail = "file fetched at the citation's own pinned commit does not hash to the recorded contentDigest (observed " + result.ObservedDigest + ", " + strconv.Itoa(size) + " bytes; recorded " + citation.OldDigest + ")"
				return result
			}
			class, newStart, newEnd := classifySpan(oldFetch.Body, citation.StartLine, citation.EndLine, newFetch.Body)
			result.Class = class
			if class == ClassSpanMoved {
				result.NewStart, result.NewEnd = newStart, newEnd
			}
		case "HTTP_STATUS":
			if oldFetch.StatusCode == 404 {
				// The citation's own pinned commit is immutable; a 404
				// there means the corpus recorded a URL that does not
				// actually resolve, which is a corpus integrity problem,
				// not ordinary drift.
				result.Class = ClassCorpusDigestMismatch
				result.Detail = "path not found at the citation's own pinned commit " + citation.OldCommit
			} else {
				result.Class = ClassPending
				result.Detail = "old blob fetch returned status " + strconv.Itoa(oldFetch.StatusCode)
			}
		default:
			result.Class = ClassPending
			result.Detail = "old blob fetch " + oldFetch.Kind
		}
	case "HTTP_STATUS":
		if newFetch.StatusCode == 404 {
			result.Class = ClassPathGone
			result.Detail = "path not found at current release commit"
		} else {
			result.Class = ClassPending
			result.Detail = "blob fetch returned status " + strconv.Itoa(newFetch.StatusCode)
		}
	default:
		result.Class = ClassPending
		result.Detail = "blob fetch " + newFetch.Kind
	}
	return result
}

// State is the resumable progress file. Re-running the command with the
// same --state path skips repositories and citations already resolved and
// retries only what is still PENDING, so a corpus-wide pass can proceed
// across several rate-limit windows instead of needing one unbroken run.
type State struct {
	Schema  string                    `json:"schema"`
	Repos   map[string]RepoResolution `json:"repos"`
	Results map[string]ClassResult    `json:"results"`
	Pins    map[string]PinResolution  `json:"pins,omitempty"`
	Lines   map[string]LineResolution `json:"lines,omitempty"`
}

func newState() *State {
	return &State{
		Schema: StateSchema, Repos: map[string]RepoResolution{}, Results: map[string]ClassResult{},
		Pins: map[string]PinResolution{}, Lines: map[string]LineResolution{},
	}
}

// LoadState reads a state file, or returns a fresh empty state if path is
// empty or the file does not yet exist.
func LoadState(path string) (*State, error) {
	if path == "" {
		return newState(), nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read state: %v", errRejected, err)
	}
	if int64(len(raw)) > maxStateBytes {
		return nil, fmt.Errorf("%w: state file too large", errRejected)
	}
	state := newState()
	if err := json.Unmarshal(raw, state); err != nil || (state.Schema != StateSchema && state.Schema != stateSchemaV1) {
		return nil, fmt.Errorf("%w: decode state: %v", errRejected, err)
	}
	if state.Schema == stateSchemaV1 {
		// Repository resolutions carry over; v1 citation results have no
		// baseline record, so they are recomputed rather than resumed.
		state.Schema = StateSchema
		state.Results = nil
	}
	if state.Repos == nil {
		state.Repos = map[string]RepoResolution{}
	}
	if state.Results == nil {
		state.Results = map[string]ClassResult{}
	}
	if state.Pins == nil {
		state.Pins = map[string]PinResolution{}
	}
	if state.Lines == nil {
		state.Lines = map[string]LineResolution{}
	}
	return state, nil
}

// SaveState writes the state file. It is a no-op when path is empty.
func SaveState(path string, state *State) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encode state: %v", errRejected, err)
	}
	return os.WriteFile(path, raw, 0o600)
}

// Summary is the classification distribution over resolved citations,
// and the viability test for batch re-attestation:
// batch re-attestation is viable only if at least half of classified
// citations are batch-attestable, i.e. FILE_IDENTICAL, SPAN_IDENTICAL, or
// NO_NEW_RELEASE. SPAN_MOVED, CONTENT_CHANGED, PATH_GONE, and
// CORPUS_DIGEST_MISMATCH all require a human reviewer and are never counted
// as batch-attestable, even though CORPUS_DIGEST_MISMATCH is a corpus
// integrity finding rather than ordinary citation drift.
type Summary struct {
	TotalCitations int            `json:"totalCitations"`
	Classified     int            `json:"classified"`
	Pending        int            `json:"pending"`
	Distribution   map[string]int `json:"distribution"`
	// BatchAttestableFraction is
	// (FILE_IDENTICAL+SPAN_IDENTICAL+NO_NEW_RELEASE)/Classified.
	BatchAttestableFraction float64 `json:"batchAttestableFraction"`
	FalsificationMet        bool    `json:"falsificationConditionMet"`
	// OldestResolvedAt is the oldest RepoResolution.ResolvedAt among this
	// run's repos, RFC3339 UTC, so a reader can see at a glance how stale
	// the least-fresh repository resolution behind this worklist is,
	// regardless of the run's own GeneratedAt timestamp. Empty when no repo
	// resolution carries a timestamp.
	OldestResolvedAt string `json:"oldestResolvedAt,omitempty"`
	// BaselineDistribution counts classified citations by the baseline
	// they were compared against (BaselineReleaseLine, BaselineLatest).
	BaselineDistribution map[string]int `json:"baselineDistribution,omitempty"`
}

// isFresh reports whether an RFC3339 UTC timestamp is within maxAge of now.
// An empty or unparsable timestamp is never fresh: absence of a recorded
// time must not be treated as "just resolved".
func isFresh(timestamp string, now time.Time, maxAge time.Duration) bool {
	if timestamp == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	return now.Sub(parsed) <= maxAge
}

// oldestResolvedAt returns the earliest ResolvedAt among repos, or "" if
// none carry a parsable timestamp.
func oldestResolvedAt(repos []RepoResolution) string {
	var oldest time.Time
	found := false
	for _, repo := range repos {
		if repo.ResolvedAt == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, repo.ResolvedAt)
		if err != nil {
			continue
		}
		if !found || parsed.Before(oldest) {
			oldest = parsed
			found = true
		}
	}
	if !found {
		return ""
	}
	return oldest.UTC().Format(time.RFC3339)
}

func summarize(results []ClassResult) Summary {
	summary := Summary{Distribution: map[string]int{}, BaselineDistribution: map[string]int{}}
	summary.TotalCitations = len(results)
	for _, result := range results {
		summary.Distribution[result.Class]++
		if result.Class != ClassPending {
			summary.Classified++
			if result.Baseline != "" {
				summary.BaselineDistribution[result.Baseline]++
			}
		} else {
			summary.Pending++
		}
	}
	if summary.Classified > 0 {
		batchable := summary.Distribution[ClassFileIdentical] + summary.Distribution[ClassSpanIdentical] + summary.Distribution[ClassNoNewRelease]
		summary.BatchAttestableFraction = float64(batchable) / float64(summary.Classified)
		summary.FalsificationMet = summary.BatchAttestableFraction < 0.5
	}
	return summary
}

// RuleVerdict rolls citation classifications up to the rule they belong
// to: a rule is batch re-attestable only if every one of
// its citations is FILE_IDENTICAL, SPAN_IDENTICAL or NO_NEW_RELEASE. A
// single citation in any other class makes the whole rule reviewer work,
// because a rule stands on all of its evidence, not its best piece.
type RuleVerdict struct {
	RulePack        string `json:"rulePack"`
	RuleID          string `json:"ruleId"`
	Project         string `json:"project"`
	CitationCount   int    `json:"citationCount"`
	BatchEligible   bool   `json:"batchEligible"`
	WorstClass      string `json:"worstClass"`
	PendingCitation bool   `json:"pendingCitation"`
}

func ruleVerdicts(results []ClassResult) []RuleVerdict {
	order := []string{}
	byRule := map[string]*RuleVerdict{}
	for _, result := range results {
		key := result.RulePack + "\x00" + result.RuleID
		verdict, exists := byRule[key]
		if !exists {
			verdict = &RuleVerdict{RulePack: result.RulePack, RuleID: result.RuleID, Project: result.Project, BatchEligible: true}
			byRule[key] = verdict
			order = append(order, key)
		}
		verdict.CitationCount++
		if result.Class == ClassPending {
			verdict.PendingCitation = true
			verdict.BatchEligible = false
		} else if result.Class != ClassFileIdentical && result.Class != ClassSpanIdentical && result.Class != ClassNoNewRelease {
			verdict.BatchEligible = false
		}
		if costRank(result.Class) > costRank(verdict.WorstClass) || verdict.WorstClass == "" {
			verdict.WorstClass = result.Class
		}
	}
	out := make([]RuleVerdict, 0, len(order))
	for _, key := range order {
		out = append(out, *byRule[key])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// Worklist is the full command output.
type Worklist struct {
	Schema      string           `json:"schema"`
	Authority   string           `json:"authority"`
	GeneratedAt string           `json:"generatedAt"`
	Scope       WorklistScope    `json:"scope"`
	Repos       []RepoResolution `json:"repos"`
	// Lines lists every release-line resolution a citation's baseline
	// relies on.
	Lines       []LineResolution `json:"lines,omitempty"`
	Citations   []ClassResult    `json:"citations"`
	Rules       []RuleVerdict    `json:"rules"`
	Summary     Summary          `json:"summary"`
	Limitations []string         `json:"limitations"`

	// Source is "mirror" when the data came from a local mirror; empty
	// means GitHub over HTTP. Mirror identifies the mirror snapshot used.
	Source string            `json:"source,omitempty"`
	Mirror *MirrorProvenance `json:"mirror,omitempty"`
}

// WorklistScope records what subset of the corpus this run covered.
type WorklistScope struct {
	RulePacks []string `json:"rulePacks"`
	Projects  []string `json:"projects,omitempty"`
	Limit     int      `json:"limit,omitempty"`
	// Baseline is the requested comparison policy; each citation records
	// the baseline it actually used.
	Baseline string `json:"baseline,omitempty"`
	// Source mirrors Worklist.Source.
	Source string `json:"source,omitempty"`
}

var worklistLimitations = []string{
	"this worklist is a mechanical drift classification, not a compatibility claim, a review, or a rule change",
	"it reads existing rule packs and writes only this worklist and an optional state file; it cannot modify a pack or a rule",
	"a repository's \"current release commit\" is its latest release under one shared rule (" + latestrelease.Rule + "), the same rule the local mirror source applies; this is a proxy for \"upstream now\", not a guarantee of the true latest stable line",
	"SPAN_MOVED, CONTENT_CHANGED, PATH_GONE, and CORPUS_DIGEST_MISMATCH all require a human reviewer; this tool only narrows where reviewer time goes",
	"CORPUS_DIGEST_MISMATCH means the file fetched at the citation's own pinned commit does not hash to the recorded contentDigest (or is not reachable there at all); this is a corpus integrity problem, not citation drift, and should be investigated separately",
	"a repo resolution or citation classification resumed from --state is reported as current only if it is within --max-age of this run; an older entry is either recomputed or, when this run could not recompute it, kept and marked \"stale\": true rather than reported as fresh",
	"a citation with \"baseline\": \"release_line\" was compared with the newest GitHub Release on the release line of the release tag proven to point at its pinned commit, not with the repository's most recent release; it answers whether the cited content changed in later releases of that line and says nothing about other release lines",
	"a citation with \"baseline\": \"latest\" under a release-line request fell back because its release line could not be proven unambiguously; the reason is in baselineNote",
	"a repo resolution with \"resolution\": \"tag_fallback\" was resolved from the tags list, not from GitHub Releases; the tags list endpoint carries no documented recency guarantee, so this is weaker evidence and should not be treated as batch-attestable without review",
}

// BuildWorklist filters citations by project/limit, resolves each unique
// repository's current commit (consulting and updating state), classifies
// every citation whose repository resolved, and returns the worklist plus
// the updated state. It stops issuing further api.github.com requests as
// soon as one is rate-limited, so the run degrades to partial, resumable
// results instead of failing outright.
//
// maxAge is the freshness bound: a repo resolution or citation
// classification already in state is resumed as current only when it is
// still PENDING or was resolved/classified within maxAge of now(). An
// entry older than that is recomputed when this run is able to (i.e. no
// earlier rate limit blocked it), or otherwise kept and marked Stale in the
// returned worklist rather than being silently re-stamped as fresh under
// this run's GeneratedAt.
func BuildWorklist(ctx context.Context, citations []Citation, projects []string, limit int, state *State, apiFetcher APIFetcher, blobFetcher sourcecapture.Fetcher, now func() time.Time, maxAge time.Duration, progress io.Writer) (Worklist, error) {
	return BuildWorklistWithBaseline(ctx, citations, projects, limit, state, apiFetcher, blobFetcher, now, maxAge, progress, BaselineModeLatest)
}

// BuildWorklistWithBaseline is BuildWorklist with an explicit baseline
// policy: BaselineModeLatest compares every citation with the repository's
// most recent release; BaselineModeReleaseLine compares a citation with the
// newest release on the release line of its pinned tag whenever that line
// can be proven (see releaseline.go) and with the most recent release
// otherwise. Each result records the baseline it used.
func BuildWorklistWithBaseline(ctx context.Context, citations []Citation, projects []string, limit int, state *State, apiFetcher APIFetcher, blobFetcher sourcecapture.Fetcher, now func() time.Time, maxAge time.Duration, progress io.Writer, baselineMode string) (Worklist, error) {
	if baselineMode != BaselineModeLatest && baselineMode != BaselineModeReleaseLine {
		return Worklist{}, fmt.Errorf("%w: unknown baseline mode", errRejected)
	}
	filtered := filterCitations(citations, projects, limit)
	// Wrap once per run: many citations across a corpus cite the same
	// file (shared old blob, and sometimes shared new blob too), and
	// raw.githubusercontent.com fetches are otherwise repeated verbatim.
	cachedBlobFetcher := newCachingFetcher(blobFetcher)

	repoSet := map[string]struct{ owner, repo string }{}
	repoOrder := []string{}
	for _, citation := range filtered {
		key := citation.repoKey()
		if _, exists := repoSet[key]; !exists {
			repoSet[key] = struct{ owner, repo string }{citation.Owner, citation.Repo}
			repoOrder = append(repoOrder, key)
		}
	}
	sort.Strings(repoOrder)

	rateLimited := false
	resolver := newLineResolver(ctx, apiFetcher, state, now, maxAge, &rateLimited)
	for _, key := range repoOrder {
		if existing, ok := state.Repos[key]; ok && existing.Status == repoResolved && isFresh(existing.ResolvedAt, now(), maxAge) {
			// Still fresh: resume without re-resolving or re-stamping.
			continue
		}
		if rateLimited {
			// Cannot attempt more resolutions this run; leave whatever is
			// already in state untouched (fresh-or-not is settled below,
			// when building the reported repos list).
			continue
		}
		target := repoSet[key]
		tag, commit, tagResolution, err := ResolveCurrentCommit(ctx, apiFetcher, target.owner, target.repo)
		resolution := RepoResolution{Owner: target.owner, Repo: target.repo, ResolvedAt: now().UTC().Format(time.RFC3339)}
		switch {
		case errors.Is(err, errRateLimited):
			resolution.Status = repoPendingRateLimited
			resolution.Detail = "github api rate limit reached; re-run with the same --state to resume"
			rateLimited = true
		case errors.Is(err, errNoReleaseBaseline):
			resolution.Status = repoNoReleasesOrTags
			resolution.Detail = noBaselineDetail
			resolution.Determination = &NoBaselineDetermination{ReleasesListEmpty: true, TagsListEmpty: true}
		case err != nil:
			resolution.Status = repoPendingError
			resolution.Detail = "resolution attempt failed; re-run with the same --state to retry"
		case commit == "":
			// Nothing resolved but emptiness was not proven (404, an
			// undecodable body, only drafts and prereleases, or a tag
			// that did not resolve to a commit): stay PENDING.
			resolution.Status = repoPendingError
			resolution.Detail = "no baseline resolved and absence of releases and tags not proven; re-run to retry"
		default:
			resolution.Status = repoResolved
			resolution.CurrentTag = tag
			resolution.CurrentCommit = commit
			resolution.Resolution = tagResolution
		}
		state.Repos[key] = resolution
		if progress != nil {
			fmt.Fprintf(progress, "evidence repin: resolved %s/%s -> %s (%s)\n", target.owner, target.repo, resolution.CurrentCommit, resolution.Status)
		}
	}
	// Anything left resolved-but-older-than-maxAge at this point is a repo
	// this run could not refresh (rate-limited before reaching it, or
	// already rate-limited when this run started): mark it stale so the
	// worklist never presents it as current, without touching its
	// ResolvedAt.
	for key, resolution := range state.Repos {
		if resolution.Status == repoResolved && !isFresh(resolution.ResolvedAt, now(), maxAge) {
			resolution.Stale = true
			state.Repos[key] = resolution
		}
	}

	results := make([]ClassResult, 0, len(filtered))
	for _, citation := range filtered {
		citationKey := citation.key()
		existing, hadExisting := state.Results[citationKey]
		if hadExisting && existing.Class != ClassPending && existing.Class != ClassNoReleaseBaseline && isFresh(existing.ClassifiedAt, now(), maxAge) && resultMode(existing) == baselineMode && lineStillFresh(state, existing, now(), maxAge) {
			// Still fresh: resume without reclassifying or re-stamping.
			results = append(results, existing)
			continue
		}
		resolution := state.Repos[citation.repoKey()]
		resolutionUsable := resolution.Status == repoResolved && isFresh(resolution.ResolvedAt, now(), maxAge)
		noBaseline := resolution.Status == repoNoReleasesOrTags && resolution.Determination.definitive() && isFresh(resolution.ResolvedAt, now(), maxAge)
		var result ClassResult
		switch {
		case noBaseline:
			result = pendingResult(citation, noBaselineDetail)
			result.Class = ClassNoReleaseBaseline
			result.ClassifiedAt = now().UTC().Format(time.RFC3339)
			result.BaselineMode = baselineMode
		case resolutionUsable:
			baselineCommit, baselineTag := resolution.CurrentCommit, resolution.CurrentTag
			var decision baselineDecision
			if baselineMode == BaselineModeReleaseLine {
				decision = resolver.decide(citation, resolution)
				if decision.line != nil {
					baselineCommit, baselineTag = decision.line.Commit, decision.line.Tag
				}
			}
			if decision.pending != "" {
				result = pendingResult(citation, "baseline unresolved: "+decision.pending)
				result.BaselineMode = baselineMode
				break
			}
			result = Classify(ctx, citation, baselineCommit, cachedBlobFetcher)
			result.ClassifiedAt = now().UTC().Format(time.RFC3339)
			result.Resolution = resolution.Resolution
			result.BaselineMode = baselineMode
			result.BaselineTag = baselineTag
			if decision.line != nil {
				result.Baseline = BaselineReleaseLine
				result.BaselineLine = decision.line.Line
				result.PinnedTag = decision.pin.Tag
				if decision.pin.Tag == decision.line.Tag {
					result.LineStatus = LineStatusPinnedIsLatest
				} else {
					result.LineStatus = LineStatusLaterReleases
				}
			} else {
				result.Baseline = BaselineLatest
				result.BaselineNote = decision.note
			}
		case hadExisting && existing.Class != ClassPending && resultMode(existing) == baselineMode:
			// The prior classification is stale, but this run cannot
			// recompute it (its repo's resolution is itself stale and
			// unrefreshed this run, typically due to an earlier rate
			// limit). Keep it, with its original ClassifiedAt, but mark it
			// Stale so it is never reported as current.
			result = existing
			result.Stale = true
		default:
			result = pendingResult(citation, "repository current commit unresolved: "+resolution.Status)
			result.BaselineMode = baselineMode
		}
		state.Results[citationKey] = result
		results = append(results, result)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if costRank(results[i].Class) != costRank(results[j].Class) {
			return costRank(results[i].Class) < costRank(results[j].Class)
		}
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].SourceID < results[j].SourceID
	})

	repos := make([]RepoResolution, 0, len(repoOrder))
	for _, key := range repoOrder {
		repos = append(repos, state.Repos[key])
	}
	sort.Slice(repos, func(i, j int) bool {
		if repos[i].Owner != repos[j].Owner {
			return repos[i].Owner < repos[j].Owner
		}
		return repos[i].Repo < repos[j].Repo
	})

	rulePackSet := map[string]struct{}{}
	for _, citation := range filtered {
		rulePackSet[citation.RulePack] = struct{}{}
	}
	rulePacks := make([]string, 0, len(rulePackSet))
	for pack := range rulePackSet {
		rulePacks = append(rulePacks, pack)
	}
	sort.Strings(rulePacks)

	summary := summarize(results)
	summary.OldestResolvedAt = oldestResolvedAt(repos)

	// List every release line a reported baseline relies on, marking any
	// that this run could not refresh as stale instead of re-stamping it.
	lineSet := map[string]bool{}
	var lines []LineResolution
	for _, result := range results {
		if result.Baseline != BaselineReleaseLine {
			continue
		}
		key := lineKey(result.Owner, result.Repo, linePrefixOf(result.PinnedTag), result.BaselineLine)
		if lineSet[key] {
			continue
		}
		lineSet[key] = true
		line, ok := state.Lines[key]
		if !ok {
			continue
		}
		if !isFresh(line.ResolvedAt, now(), maxAge) {
			line.Stale = true
		}
		lines = append(lines, line)
	}
	sort.Slice(lines, func(i, j int) bool {
		a, b := lines[i], lines[j]
		if a.Owner != b.Owner {
			return a.Owner < b.Owner
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.Prefix != b.Prefix {
			return a.Prefix < b.Prefix
		}
		return a.Line < b.Line
	})

	worklist := Worklist{
		Schema: Schema, Authority: Authority, GeneratedAt: now().UTC().Format(time.RFC3339),
		Scope:       WorklistScope{RulePacks: rulePacks, Projects: projects, Limit: limit, Baseline: baselineMode},
		Repos:       repos,
		Lines:       lines,
		Citations:   results,
		Rules:       ruleVerdicts(results),
		Summary:     summary,
		Limitations: worklistLimitations,
	}
	return worklist, nil
}

// resultMode is the baseline mode a result was computed under; a result
// that predates the field was compared with the latest release.
func resultMode(result ClassResult) string {
	if result.BaselineMode == "" {
		return BaselineModeLatest
	}
	return result.BaselineMode
}

func pendingResult(citation Citation, detail string) ClassResult {
	return ClassResult{
		RulePack: citation.RulePack, RuleID: citation.RuleID, Project: citation.Project, SourceID: citation.SourceID,
		Owner: citation.Owner, Repo: citation.Repo, Path: citation.Path,
		OldCommit: citation.OldCommit, OldStart: citation.StartLine, OldEnd: citation.EndLine,
		Class: ClassPending, Detail: detail,
	}
}

// linePrefixOf returns the tag prefix of a strictly parsed release tag, or
// "" when the tag does not parse.
func linePrefixOf(tag string) string {
	parsed, _ := parseStrictTag(tag)
	return parsed.Prefix
}

// lineStillFresh reports whether a resumable result's release-line
// resolution is still within maxAge; a latest-baseline result has none.
func lineStillFresh(state *State, result ClassResult, now time.Time, maxAge time.Duration) bool {
	if result.Baseline != BaselineReleaseLine {
		return true
	}
	line, ok := state.Lines[lineKey(result.Owner, result.Repo, linePrefixOf(result.PinnedTag), result.BaselineLine)]
	return ok && line.Status == lineResolved && line.Tag == result.BaselineTag && isFresh(line.ResolvedAt, now, maxAge)
}

func filterCitations(citations []Citation, projects []string, limit int) []Citation {
	sorted := append([]Citation(nil), citations...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].SourceID < sorted[j].SourceID
	})
	if len(projects) == 0 {
		if limit > 0 && limit < len(sorted) {
			return sorted[:limit]
		}
		return sorted
	}
	allow := map[string]struct{}{}
	for _, project := range projects {
		allow[project] = struct{}{}
	}
	filtered := make([]Citation, 0, len(sorted))
	for _, citation := range sorted {
		if _, ok := allow[citation.Project]; ok {
			filtered = append(filtered, citation)
		}
	}
	if limit > 0 && limit < len(filtered) {
		return filtered[:limit]
	}
	return filtered
}

type stringList []string

func (list *stringList) String() string { return strings.Join(*list, ",") }
func (list *stringList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

// Run is the "evidence repin" CLI adapter, wired from prufyx-maintainer's
// "evidence" command.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, apiFetcher APIFetcher, blobFetcher sourcecapture.Fetcher, now func() time.Time, defaultRulePacks []string) int {
	return RunWith(ctx, args, stdout, stderr, Deps{API: apiFetcher, Blobs: blobFetcher, Now: now, DefaultRulePacks: defaultRulePacks})
}

// Deps carries what the "evidence repin" command needs from its caller.
type Deps struct {
	API   APIFetcher
	Blobs sourcecapture.Fetcher
	Now   func() time.Time
	// DefaultRulePacks are used when --rules is not given.
	DefaultRulePacks []string
	// OpenMirror opens the local mirror in a state directory for
	// --source mirror. Nil rejects that source.
	OpenMirror func(stateDir string) (MirrorSource, error)
}

// RunWith is Run with the full set of dependencies.
func RunWith(ctx context.Context, args []string, stdout, stderr io.Writer, deps Deps) int {
	apiFetcher, blobFetcher, now, defaultRulePacks := deps.API, deps.Blobs, deps.Now, deps.DefaultRulePacks
	if len(args) == 0 || args[0] != "repin" {
		fmt.Fprintln(stderr, "evidence: unknown or missing subcommand (expected: repin)")
		return 2
	}
	flags := flag.NewFlagSet("evidence repin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var rulePacks stringList
	var projects stringList
	limit := flags.Int("limit", 0, "cap the number of citations considered (0 = no cap)")
	statePath := flags.String("state", "", "resumable progress file (optional)")
	outputPath := flags.String("output", "", "new worklist output path")
	maxAge := flags.Duration("max-age", DefaultMaxAge, "freshness bound for a resumed repo resolution or citation classification; older entries are recomputed or marked stale, never resumed as current")
	baseline := flags.String("baseline", BaselineModeReleaseLine, "comparison baseline: \"release-line\" compares each citation with the newest release on the release line of its pinned tag when that line can be proven (latest release otherwise); \"latest\" compares every citation with the repository's most recent release")
	source := flags.String("source", SourceHTTP, "where tags, releases and file bytes come from: \"http\" (GitHub, the default) or \"mirror\" (a local factory mirror, strictly offline; needs --mirror-state)")
	mirrorState := flags.String("mirror-state", "", "factory mirror state directory (with --source mirror)")
	wantsOut := flags.String("wants-out", "", "with --source mirror: write the pinned files the mirror is missing as a wants file for \"factory mirror --wants\"")
	flags.Var(&rulePacks, "rules", "rule pack path (repeatable; default: the shipped CNCF and community packs)")
	flags.Var(&projects, "project", "restrict to this project slug (repeatable; default: all)")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *outputPath == "" {
		fmt.Fprintln(stderr, "evidence repin: command rejected")
		return 2
	}
	if *baseline != BaselineModeReleaseLine && *baseline != BaselineModeLatest {
		fmt.Fprintln(stderr, "evidence repin: --baseline must be release-line or latest")
		return 2
	}
	if msg := checkSourceFlags(*source, *mirrorState, *statePath, *wantsOut, deps.OpenMirror != nil); msg != "" {
		fmt.Fprintln(stderr, "evidence repin: "+msg)
		return 2
	}
	if len(rulePacks) == 0 {
		rulePacks = append(stringList(nil), defaultRulePacks...)
	}

	var citations []Citation
	for _, path := range rulePacks {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: cannot read rule pack %s: %v\n", path, err)
			return 2
		}
		if int64(len(raw)) > maxRulesBytes {
			fmt.Fprintf(stderr, "evidence repin: rule pack %s too large\n", path)
			return 2
		}
		parsed, err := LoadCitations(path, raw)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: %v\n", err)
			return 2
		}
		citations = append(citations, parsed...)
	}

	var worklist Worklist
	var missing int
	if *source == SourceMirror {
		src, err := deps.OpenMirror(*mirrorState)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: cannot open the mirror: %v\n", err)
			return 2
		}
		var wants MirrorWants
		worklist, wants, err = BuildMirrorWorklist(ctx, citations, projects, *limit, src, now, *maxAge, stderr, *baseline)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: %v\n", err)
			return 2
		}
		for _, want := range wants.Wants {
			missing += len(want.Paths)
		}
		if *wantsOut != "" {
			if err := writeWants(*wantsOut, wants); err != nil {
				fmt.Fprintf(stderr, "evidence repin: cannot write wants: %v\n", err)
				return 2
			}
		}
	} else {
		state, err := LoadState(*statePath)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: %v\n", err)
			return 2
		}
		worklist, err = BuildWorklistWithBaseline(ctx, citations, projects, *limit, state, apiFetcher, blobFetcher, now, *maxAge, stderr, *baseline)
		if err != nil {
			fmt.Fprintf(stderr, "evidence repin: %v\n", err)
			return 2
		}
		if err := SaveState(*statePath, state); err != nil {
			fmt.Fprintf(stderr, "evidence repin: %v\n", err)
			return 2
		}
	}

	raw, err := json.MarshalIndent(worklist, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "evidence repin: %v\n", err)
		return 2
	}
	if err := os.WriteFile(*outputPath, raw, 0o644); err != nil {
		fmt.Fprintf(stderr, "evidence repin: cannot write worklist: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "evidence repin: %d citations, %d classified, %d pending, %d rules, batch-attestable fraction %.2f\n",
		worklist.Summary.TotalCitations, worklist.Summary.Classified, worklist.Summary.Pending, len(worklist.Rules), worklist.Summary.BatchAttestableFraction)
	if *source == SourceMirror && missing > 0 {
		fmt.Fprintf(stdout, "evidence repin: %d file(s) are not in the mirror; add them with \"factory mirror --wants\" (see --wants-out) and run again\n", missing)
	}
	return 0
}
