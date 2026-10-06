// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
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
)

// ObjectKind is what a source revision resolves to on the remote.
type ObjectKind struct {
	// Commit is true when the revision is itself a commit object.
	Commit bool
	// PeeledCommit is the commit a tag-object revision points to, when the
	// revision is an (annotated) tag object. Empty otherwise.
	PeeledCommit string
}

// RevisionResolver reports whether a revision SHA is a commit object.
// Implementations must return an error, never Commit=true, when the object
// cannot be established.
type RevisionResolver interface {
	ResolveRevision(ctx context.Context, owner, repo, sha string) (ObjectKind, error)
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
	// Client defaults to a client with a 60 second timeout.
	Client *http.Client
}

func (g GitHubObjects) get(ctx context.Context, u string) ([]byte, int, error) {
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
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
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAPIBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxAPIBytes {
		return nil, response.StatusCode, fmt.Errorf("%s: response exceeds %d bytes", u, maxAPIBytes)
	}
	return body, response.StatusCode, nil
}

func (g GitHubObjects) endpoint(owner, repo, kind, sha string) string {
	base := strings.TrimSuffix(g.APIBase, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	return base + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/git/" + kind + "/" + sha
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

	mu      sync.Mutex
	kinds   map[string]*kindFlight
	content map[string]*contentFlight
}

type kindFlight struct {
	once sync.Once
	kind ObjectKind
	err  error
}

type contentFlight struct {
	once   sync.Once
	digest string
	err    error
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

func (v *CitationVerifier) digestAt(ctx context.Context, rawURL string) (string, error) {
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
		f.digest = digestOf(body)
	})
	return f.digest, f.err
}

type citationTask struct {
	ruleID string
	source constraintengine.SourceEvidence
}

// Verify checks every source of every rule. rules are the raw "rule"
// objects of a pack (the pack entry's rule field).
func (v *CitationVerifier) Verify(ctx context.Context, rules []json.RawMessage) (CitationReport, error) {
	if v.Resolver == nil || v.Fetcher == nil {
		return CitationReport{}, errors.New("citation verification needs both a RevisionResolver and a Fetcher")
	}
	report := CitationReport{Schema: CitationReportSchema, FailedRules: []string{}, Findings: []CitationFinding{}}
	var tasks []citationTask
	for _, raw := range rules {
		var body ruleBody
		if err := json.Unmarshal(raw, &body); err != nil || body.ID == "" {
			return CitationReport{}, fmt.Errorf("rule %d: could not decode id and evidence: %v", report.RulesChecked, err)
		}
		report.RulesChecked++
		for _, source := range body.Evidence.Sources {
			tasks = append(tasks, citationTask{ruleID: body.ID, source: source})
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
	for _, task := range tasks {
		revisions[task.source.Revision] = struct{}{}
	}
	report.UniqueRevisions = len(revisions)
	failed := map[string]struct{}{}
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
			if digest, err := v.digestAt(ctx, peeledURL); err == nil {
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
	digest, err := v.digestAt(ctx, rawURL)
	if err != nil {
		return append(findings, fail(CheckCitationFetch, "could not fetch %s: %v", rawURL, err))
	}
	if digest != source.ContentDigest {
		finding := fail(CheckCitationDigest, "contentDigest is %s but the whole-file sha256 of %s at commit %s is %s", source.ContentDigest, rawURL, revision, digest)
		finding.ActualDigest = digest
		findings = append(findings, finding)
	}
	return findings
}
