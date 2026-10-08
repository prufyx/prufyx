// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// CitationReportSchema identifies the citation-verification report shape.
const CitationReportSchema = "prufyx.io/rule-citation-verification/v1alpha1"

// maxAPIBytes bounds one GitHub REST response read by the revision check.
const maxAPIBytes = 1 << 20

// maxCompareBytes bounds a compare response. The endpoint lists changed
// files whatever per_page says, so for a commit far behind the default
// branch the body is large; only its status is used.
const maxCompareBytes = 32 << 20

// maxTagPages bounds the tag listing used for reachability: 10 requests of
// 100 tags per repository, then the commit is not found.
const maxTagPages = 10

// maxTagPeelDepth bounds how many nested tag objects are followed to reach a
// commit.
const maxTagPeelDepth = 5

// Citation finding checks. Every one is fail-closed: an unresolved or
// unfetchable citation is a failure, never a pass.
const (
	CheckRevisionNotCommit  = "revision-not-commit"
	CheckRevisionUnresolved = "revision-unresolved"
	CheckCitationURL        = "citation-url"
	CheckCitationDigest     = "content-digest-mismatch"
	CheckCitationFetch      = "fetch-failed"
	// CheckRevisionUnreachable: the commit is served for the repository but
	// is neither a tag commit nor in its default branch history (GitHub also
	// answers for commits that exist only in a fork), or this could not be
	// established.
	CheckRevisionUnreachable = "revision-not-in-upstream"
	// CheckCitationNoSources: an item cites no source at all.
	CheckCitationNoSources = "evidence-sources"
	// CheckCitationSpan: strict span check (CitationVerifier.CheckSpans):
	// the cited lines are not inside the file (startLine < 1, endLine <
	// startLine, or endLine past the last line).
	CheckCitationSpan = "line-span-out-of-range"
	// CheckCitationLineRange: the tolerant span check of the default mode
	// (see CitationVerifier.CheckSpans): startLine < 1, startLine > endLine,
	// startLine past the last line, or endLine past the line positions.
	// A different finding than CheckCitationSpan on purpose.
	CheckCitationLineRange = "line-range-fetched"
)

// ObjectKind is what a source revision resolves to on the remote.
type ObjectKind struct {
	// Commit is true when the revision is itself a commit object.
	Commit bool
	// PeeledCommit is the commit a tag-object revision points to, when the
	// revision is an (annotated) tag object. Empty otherwise.
	PeeledCommit string
}

// RevisionResolver reports whether a revision SHA is a commit object and
// whether that commit belongs to the repository's own history.
// Implementations must return an error, never Commit=true or reachable=true,
// when the fact cannot be established.
type RevisionResolver interface {
	ResolveRevision(ctx context.Context, owner, repo, sha string) (ObjectKind, error)
	// RevisionReachable reports whether the commit is a tag commit of
	// owner/repo or in the history of its default branch. GitHub serves the objects of a fork
	// network through the parent repository's URLs, so a commit object that
	// resolves does not prove the upstream project ever contained it.
	RevisionReachable(ctx context.Context, owner, repo, sha string) (bool, error)
}

// GitHubObjects is the production RevisionResolver. It uses the GitHub git
// data REST API: /git/commits/{sha} answers only for commit objects, and
// /git/tags/{sha} answers for annotated tag objects, which are peeled to
// the commit they point to.
type GitHubObjects struct {
	// APIBase defaults to https://api.github.com; tests point it at a local
	// server.
	APIBase string
	// Token, when set, authenticates API requests (rate limit only).
	Token string
	// Client is an optional base client; it is always wrapped by the
	// hardened fetch client (timeout, same-host redirects, no proxy).
	Client *http.Client

	// repos caches, per repository, the default branch and the tag commits
	// (set by NewGitHubObjects); without it every reachability check looks
	// them up again.
	repos *repoCache
}

type repoCache struct {
	mu sync.Mutex
	m  map[string]*repoFacts
}

type repoFacts struct {
	branchOnce sync.Once
	branch     string
	branchErr  error
	tagsOnce   sync.Once
	tags       map[string]bool
	tagsErr    error
}

// NewGitHubObjects returns a GitHubObjects that looks up each repository's
// default branch once.
func NewGitHubObjects(token string) GitHubObjects {
	return GitHubObjects{Token: token, repos: &repoCache{m: map[string]*repoFacts{}}}
}

// apiRetryDelay is the pause before a retry of a transient API failure.
var apiRetryDelay = 2 * time.Second

// maxAPIAttempts bounds the tries of one API request. Only a network error,
// HTTP 429 or a 5xx answer is retried; the last failure is returned, never
// turned into a result.
const maxAPIAttempts = 3

func (g GitHubObjects) get(ctx context.Context, u string) ([]byte, int, error) {
	return g.getLimited(ctx, u, maxAPIBytes)
}

func (g GitHubObjects) getLimited(ctx context.Context, u string, limit int) ([]byte, int, error) {
	var (
		body   []byte
		status int
		err    error
	)
	for attempt := 1; attempt <= maxAPIAttempts; attempt++ {
		body, status, err = g.getOnce(ctx, u, limit)
		transient := err != nil || status == http.StatusTooManyRequests || status >= 500
		if !transient || attempt == maxAPIAttempts || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			return body, status, err
		case <-time.After(time.Duration(attempt) * apiRetryDelay):
		}
	}
	return body, status, err
}

func (g GitHubObjects) getOnce(ctx context.Context, u string, limit int) ([]byte, int, error) {
	// The same hardened client the raw fetcher uses (SEC-D): no proxy
	// environment, a bounded timeout, and redirects only within the
	// original host and scheme, so the token never follows a redirect.
	client := newFetchClient(g.Client)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		request.Header.Set("Authorization", "Bearer "+g.Token)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > limit {
		return nil, response.StatusCode, fmt.Errorf("%s: response exceeds %d bytes", u, limit)
	}
	return body, response.StatusCode, nil
}

func (g GitHubObjects) endpoint(owner, repo, kind, sha string) string {
	return g.repoURL(owner, repo) + "/git/" + kind + "/" + sha
}

// RevisionReachable implements RevisionResolver. The commit belongs to the
// repository's history when it is the commit of one of its tags (releases
// are cited by their tag commit, which need not be on the default branch),
// or the tip of, or an ancestor of, the default branch: the compare API
// answers "identical" or "ahead" (the branch is ahead of the commit) for
// base=commit, head=default branch. "behind" (the commit is ahead of the
// branch) and "diverged" (not an ancestor), and 404/422 (the commit is
// unknown to the compare, as for a fork-only commit) mean not reachable;
// any other failure is an error, never a result. Tags and the default branch
// are looked up once per repository with NewGitHubObjects, so a commit costs
// at most one compare request.
func (g GitHubObjects) RevisionReachable(ctx context.Context, owner, repo, sha string) (bool, error) {
	if !revisionPattern.MatchString(sha) {
		return false, fmt.Errorf("revision %q is not a full 40-character lowercase SHA", sha)
	}
	tags, err := g.tagCommits(ctx, owner, repo)
	if err != nil {
		return false, err
	}
	if tags[sha] {
		return true, nil
	}
	branch, err := g.defaultBranch(ctx, owner, repo)
	if err != nil {
		return false, err
	}
	u := g.repoURL(owner, repo) + "/compare/" + sha + "..." + url.PathEscape(branch) + "?per_page=1"
	body, status, err := g.getLimited(ctx, u, maxCompareBytes)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return false, nil
	default:
		return false, fmt.Errorf("compare %s...%s: HTTP %d", sha, branch, status)
	}
	var doc struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, fmt.Errorf("compare %s...%s returned an unexpected body", sha, branch)
	}
	switch doc.Status {
	case "identical", "ahead":
		return true, nil
	case "behind", "diverged":
		return false, nil
	}
	return false, fmt.Errorf("compare %s...%s returned status %q", sha, branch, doc.Status)
}

func (g GitHubObjects) facts(owner, repo string) *repoFacts {
	if g.repos == nil {
		return &repoFacts{}
	}
	key := owner + "/" + repo
	g.repos.mu.Lock()
	defer g.repos.mu.Unlock()
	f := g.repos.m[key]
	if f == nil {
		f = &repoFacts{}
		g.repos.m[key] = f
	}
	return f
}

// tagCommits lists the (peeled) commits of the repository's tags, at most
// maxTagPages pages of 100.
func (g GitHubObjects) tagCommits(ctx context.Context, owner, repo string) (map[string]bool, error) {
	f := g.facts(owner, repo)
	f.tagsOnce.Do(func() {
		f.tags = map[string]bool{}
		for page := 1; page <= maxTagPages; page++ {
			body, status, err := g.get(ctx, fmt.Sprintf("%s/tags?per_page=100&page=%d", g.repoURL(owner, repo), page))
			if err != nil {
				f.tags, f.tagsErr = nil, err
				return
			}
			if status != http.StatusOK {
				f.tags, f.tagsErr = nil, fmt.Errorf("tag listing for %s/%s: HTTP %d", owner, repo, status)
				return
			}
			var list []struct {
				Commit struct {
					SHA string `json:"sha"`
				} `json:"commit"`
			}
			if json.Unmarshal(body, &list) != nil {
				f.tags, f.tagsErr = nil, fmt.Errorf("tag listing for %s/%s returned an unexpected body", owner, repo)
				return
			}
			for _, tag := range list {
				f.tags[tag.Commit.SHA] = true
			}
			if len(list) < 100 {
				return
			}
		}
	})
	return f.tags, f.tagsErr
}

func (g GitHubObjects) repoURL(owner, repo string) string {
	base := strings.TrimSuffix(g.APIBase, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	return base + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)
}

func (g GitHubObjects) defaultBranch(ctx context.Context, owner, repo string) (string, error) {
	f := g.facts(owner, repo)
	f.branchOnce.Do(func() { f.branch, f.branchErr = g.lookupDefaultBranch(ctx, owner, repo) })
	return f.branch, f.branchErr
}

func (g GitHubObjects) lookupDefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	body, status, err := g.get(ctx, g.repoURL(owner, repo))
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("repository lookup for %s/%s: HTTP %d", owner, repo, status)
	}
	var doc struct {
		DefaultBranch string `json:"default_branch"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.DefaultBranch == "" {
		return "", fmt.Errorf("repository lookup for %s/%s returned no default branch", owner, repo)
	}
	return doc.DefaultBranch, nil
}

// ResolveRevision implements RevisionResolver.
func (g GitHubObjects) ResolveRevision(ctx context.Context, owner, repo, sha string) (ObjectKind, error) {
	if !revisionPattern.MatchString(sha) {
		return ObjectKind{}, fmt.Errorf("revision %q is not a full 40-character lowercase SHA", sha)
	}
	body, status, err := g.get(ctx, g.endpoint(owner, repo, "commits", sha))
	if err != nil {
		return ObjectKind{}, err
	}
	if status == http.StatusOK {
		var doc struct {
			SHA string `json:"sha"`
		}
		if json.Unmarshal(body, &doc) != nil || doc.SHA != sha {
			return ObjectKind{}, fmt.Errorf("commit lookup for %s returned an unexpected body", sha)
		}
		return ObjectKind{Commit: true}, nil
	}
	if status != http.StatusNotFound && status != http.StatusUnprocessableEntity {
		return ObjectKind{}, fmt.Errorf("commit lookup for %s: HTTP %d", sha, status)
	}
	// Not a commit: see whether it is an annotated tag object.
	current := sha
	for depth := 0; depth < maxTagPeelDepth; depth++ {
		body, status, err = g.get(ctx, g.endpoint(owner, repo, "tags", current))
		if err != nil {
			return ObjectKind{}, err
		}
		if status != http.StatusOK {
			return ObjectKind{}, fmt.Errorf("revision %s is neither a commit nor a tag object in %s/%s (HTTP %d)", current, owner, repo, status)
		}
		var tag struct {
			SHA    string `json:"sha"`
			Object struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"object"`
		}
		if json.Unmarshal(body, &tag) != nil || tag.SHA != current || !revisionPattern.MatchString(tag.Object.SHA) {
			return ObjectKind{}, fmt.Errorf("tag lookup for %s returned an unexpected body", current)
		}
		switch tag.Object.Type {
		case "commit":
			return ObjectKind{PeeledCommit: tag.Object.SHA}, nil
		case "tag":
			current = tag.Object.SHA
		default:
			return ObjectKind{}, fmt.Errorf("tag object %s points to a %q, not a commit", current, tag.Object.Type)
		}
	}
	return ObjectKind{}, errors.New("tag object chain is too deep to peel")
}

// CitationFinding is one failed citation check.
type CitationFinding struct {
	RuleID   string `json:"ruleId"`
	SourceID string `json:"sourceId"`
	Check    string `json:"check"`
	Message  string `json:"message"`
	// PeeledCommit is the suggested replacement revision for a
	// revision-not-commit finding.
	PeeledCommit string `json:"peeledCommit,omitempty"`
	// ActualDigest is the recomputed whole-file sha256 for a digest mismatch,
	// or for a tag-object revision the digest at the peeled commit.
	ActualDigest string `json:"actualDigest,omitempty"`
}

// CitationReport is the result of verifying every cited source.
type CitationReport struct {
	Schema          string            `json:"schema"`
	Pass            bool              `json:"pass"`
	RulesChecked    int               `json:"rulesChecked"`
	RecordsChecked  int               `json:"recordsChecked"`
	SourcesChecked  int               `json:"sourcesChecked"`
	UniqueRevisions int               `json:"uniqueRevisions"`
	FailedRules     []string          `json:"failedRules"`
	Findings        []CitationFinding `json:"findings"`
}

// CitationVerifier checks that each source revision is a commit object and
// that the whole-file sha256 at that commit equals contentDigest. There is
// no bypass: every failure to establish a fact is a finding.
type CitationVerifier struct {
	Resolver RevisionResolver
	Fetcher  Fetcher
	// Concurrency bounds parallel sources; values below 1 mean 4.
	Concurrency int
	// CheckSpans selects the STRICT span rule for every source: endLine must
	// lie inside the file (endLine <= its line count) and the finding is
	// CheckCitationSpan. It is on for image-source tables. When false (rule
	// packs and the knowledge gate) the tolerant rule applies instead: a
	// span may end on the empty position after the final newline (the
	// convention of the cortex and thanos corpus sources, DECISIONS
	// 2026-10-08 CITE-VERIFY-2), but startLine <= the strict line count
	// always, and the finding is CheckCitationLineRange.
	CheckSpans bool
	// Timeout bounds one whole VerifyItems run (every request included);
	// zero means DefaultCitationTimeout. When it expires the run fails:
	// VerifyItems returns an error, never a partial pass.
	Timeout time.Duration

	mu      sync.Mutex
	kinds   map[string]*kindFlight
	reach   map[string]*reachFlight
	content map[string]*contentFlight
}

// DefaultCitationTimeout is the overall deadline of one citation run.
const DefaultCitationTimeout = 20 * time.Minute

type reachFlight struct {
	once      sync.Once
	reachable bool
	err       error
}

type kindFlight struct {
	once sync.Once
	kind ObjectKind
	err  error
}

type contentFlight struct {
	once  sync.Once
	facts fileFacts
	err   error
}

func (v *CitationVerifier) kind(ctx context.Context, owner, repo, sha string) (ObjectKind, error) {
	key := owner + "/" + repo + "@" + sha
	v.mu.Lock()
	if v.kinds == nil {
		v.kinds = map[string]*kindFlight{}
	}
	f := v.kinds[key]
	if f == nil {
		f = &kindFlight{}
		v.kinds[key] = f
	}
	v.mu.Unlock()
	f.once.Do(func() { f.kind, f.err = v.Resolver.ResolveRevision(ctx, owner, repo, sha) })
	return f.kind, f.err
}

// reachable caches RevisionReachable per commit, so a commit cited by many
// sources costs its REST calls once.
func (v *CitationVerifier) reachable(ctx context.Context, owner, repo, sha string) (bool, error) {
	key := owner + "/" + repo + "@" + sha
	v.mu.Lock()
	if v.reach == nil {
		v.reach = map[string]*reachFlight{}
	}
	f := v.reach[key]
	if f == nil {
		f = &reachFlight{}
		v.reach[key] = f
	}
	v.mu.Unlock()
	f.once.Do(func() { f.reachable, f.err = v.Resolver.RevisionReachable(ctx, owner, repo, sha) })
	return f.reachable, f.err
}

type fileFacts struct {
	digest string
	// lines is the strict line count; slots is lineSlots.
	lines, slots int
}

func (v *CitationVerifier) contentAt(ctx context.Context, rawURL string) (fileFacts, error) {
	v.mu.Lock()
	if v.content == nil {
		v.content = map[string]*contentFlight{}
	}
	f := v.content[rawURL]
	if f == nil {
		f = &contentFlight{}
		v.content[rawURL] = f
	}
	v.mu.Unlock()
	f.once.Do(func() {
		body, err := v.Fetcher.FetchRawBlob(ctx, rawURL)
		if err != nil {
			f.err = err
			return
		}
		f.facts = fileFacts{digest: digestOf(body), lines: countLines(body), slots: lineSlots(body)}
	})
	return f.facts, f.err
}

// lineSlots is how many line positions a file offers a citation: the
// newline-separated segments, so a file ending in a newline has one more
// position than it has lines. The corpus cites a whole file as 1 to that
// count (the convention of PrintSpanLines), so a span may END on the empty
// position after the final newline; a span past it never is, and a span
// must START on a real line (startLine <= countLines).
func lineSlots(content []byte) int {
	return bytes.Count(content, []byte("\n")) + 1
}

type citationTask struct {
	ruleID string
	source constraintengine.SourceEvidence
}

// CitationItem is one source-bearing record: a rule, a path policy, a line
// attestation or a distribution record. ID names it in findings.
type CitationItem struct {
	// Record is true for anything that is not a rule.
	Record  bool
	ID      string
	Sources []constraintengine.SourceEvidence
}

// Verify checks every source of every rule. rules are the raw "rule"
// objects of a pack (the pack entry's rule field).
func (v *CitationVerifier) Verify(ctx context.Context, rules []json.RawMessage) (CitationReport, error) {
	items, err := RuleCitationItems(rules)
	if err != nil {
		return CitationReport{}, err
	}
	return v.VerifyItems(ctx, items)
}

// RuleCitationItems decodes raw "rule" objects into citation items.
func RuleCitationItems(rules []json.RawMessage) ([]CitationItem, error) {
	items := make([]CitationItem, 0, len(rules))
	for i, raw := range rules {
		var body ruleBody
		if err := json.Unmarshal(raw, &body); err != nil || body.ID == "" {
			return nil, fmt.Errorf("rule %d: could not decode id and evidence: %v", i, err)
		}
		items = append(items, CitationItem{ID: body.ID, Sources: body.Evidence.Sources})
	}
	return items, nil
}

// VerifyItems checks every source of every item. An empty list, or a list
// without a single source, is not a pass.
func (v *CitationVerifier) VerifyItems(ctx context.Context, items []CitationItem) (CitationReport, error) {
	if v.Resolver == nil || v.Fetcher == nil {
		return CitationReport{}, errors.New("citation verification needs both a RevisionResolver and a Fetcher")
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = DefaultCitationTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	report := CitationReport{Schema: CitationReportSchema, FailedRules: []string{}, Findings: []CitationFinding{}}
	var noSources []CitationFinding
	var tasks []citationTask
	for _, item := range items {
		if item.ID == "" {
			return CitationReport{}, errors.New("a citation item has no id")
		}
		if item.Record {
			report.RecordsChecked++
		} else {
			report.RulesChecked++
		}
		if len(item.Sources) == 0 {
			noSources = append(noSources, CitationFinding{RuleID: item.ID, Check: CheckCitationNoSources, Message: "the item cites no source; an item without a source is not a pass"})
		}
		for _, source := range item.Sources {
			tasks = append(tasks, citationTask{ruleID: item.ID, source: source})
		}
	}
	report.SourcesChecked = len(tasks)
	revisions := map[string]struct{}{}
	results := make([][]CitationFinding, len(tasks))
	workers := v.Concurrency
	if workers < 1 {
		workers = 4
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = v.verifySource(ctx, tasks[i])
			}
		}()
	}
	for i := range tasks {
		next <- i
	}
	close(next)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return CitationReport{}, fmt.Errorf("citation verification did not finish within %s: %w", timeout, err)
	}
	for _, task := range tasks {
		revisions[task.source.Revision] = struct{}{}
	}
	report.UniqueRevisions = len(revisions)
	failed := map[string]struct{}{}
	results = append(results, noSources)
	for _, found := range results {
		for _, finding := range found {
			report.Findings = append(report.Findings, finding)
			failed[finding.RuleID] = struct{}{}
		}
	}
	for id := range failed {
		report.FailedRules = append(report.FailedRules, id)
	}
	sort.Strings(report.FailedRules)
	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.SourceID != b.SourceID {
			return a.SourceID < b.SourceID
		}
		return a.Check < b.Check
	})
	report.Pass = len(report.Findings) == 0 && report.SourcesChecked > 0
	return report, nil
}

func (v *CitationVerifier) verifySource(ctx context.Context, task citationTask) []CitationFinding {
	source := task.source
	fail := func(check, format string, args ...any) CitationFinding {
		return CitationFinding{RuleID: task.ruleID, SourceID: source.ID, Check: check, Message: fmt.Sprintf(format, args...)}
	}
	owner, repo, revision, ok := githubBlobURL(source.URL)
	if !ok || revision != source.Revision {
		return []CitationFinding{fail(CheckCitationURL, "source url %q is not a pinned github blob URL whose revision equals revision %q", source.URL, source.Revision)}
	}
	var findings []CitationFinding
	kind, err := v.kind(ctx, owner, repo, revision)
	switch {
	case err != nil:
		findings = append(findings, fail(CheckRevisionUnresolved, "revision %s of %s/%s could not be resolved to a commit object: %v", revision, owner, repo, err))
	case kind.PeeledCommit != "":
		finding := fail(CheckRevisionNotCommit, "revision %s is an annotated tag object, not a commit; use the peeled commit %s", revision, kind.PeeledCommit)
		finding.PeeledCommit = kind.PeeledCommit
		if peeledURL, ok := rawBlobURL(owner, repo, kind.PeeledCommit, source.URL); ok {
			// rawBlobURL kept the revision in the URL; rebuild it for the peeled commit.
			peeledURL = strings.Replace(peeledURL, "/"+revision+"/", "/"+kind.PeeledCommit+"/", 1)
			if facts, err := v.contentAt(ctx, peeledURL); err == nil {
				digest := facts.digest
				finding.ActualDigest = digest
				if digest == source.ContentDigest {
					finding.Message += "; contentDigest matches the file at the peeled commit"
				} else {
					finding.Message += "; contentDigest does NOT match the file at the peeled commit (" + digest + ")"
				}
			}
		}
		findings = append(findings, finding)
	case !kind.Commit:
		findings = append(findings, fail(CheckRevisionUnresolved, "revision %s of %s/%s is not a commit object", revision, owner, repo))
	}
	if err == nil && !kind.Commit {
		return findings // digest at a non-commit revision would be meaningless
	}
	if err != nil {
		return findings
	}
	rawURL, ok := rawBlobURL(owner, repo, revision, source.URL)
	if !ok {
		return append(findings, fail(CheckCitationURL, "source url %q could not be converted to a raw.githubusercontent.com URL", source.URL))
	}
	reachable, err := v.reachable(ctx, owner, repo, revision)
	switch {
	case err != nil:
		findings = append(findings, fail(CheckRevisionUnreachable, "could not establish that commit %s is a tag commit or in the default branch history of %s/%s: %v", revision, owner, repo, err))
	case !reachable:
		findings = append(findings, fail(CheckRevisionUnreachable, "commit %s is neither a tag commit nor in the default branch history of %s/%s (it may exist only in a fork)", revision, owner, repo))
	}
	facts, err := v.contentAt(ctx, rawURL)
	if err != nil {
		return append(findings, fail(CheckCitationFetch, "could not fetch %s: %v", rawURL, err))
	}
	digest, lines := facts.digest, facts.lines
	if digest != source.ContentDigest {
		finding := fail(CheckCitationDigest, "contentDigest is %s but the whole-file sha256 of %s at commit %s is %s", source.ContentDigest, rawURL, revision, digest)
		finding.ActualDigest = digest
		findings = append(findings, finding)
	}
	if v.CheckSpans {
		// Strict: endLine <= the line count, no tolerance.
		if source.StartLine < 1 || source.EndLine < source.StartLine || source.EndLine > lines {
			findings = append(findings, fail(CheckCitationSpan, "cited lines %d-%d are outside the %d-line file %s", source.StartLine, source.EndLine, lines, rawURL))
		}
	} else if source.StartLine < 1 || source.StartLine > source.EndLine || source.StartLine > lines || source.EndLine > facts.slots {
		findings = append(findings, fail(CheckCitationLineRange, "cited lines %d-%d are not inside %s at commit %s, which has %d lines (%d line positions)", source.StartLine, source.EndLine, rawURL, revision, lines, facts.slots))
	}
	return findings
}
