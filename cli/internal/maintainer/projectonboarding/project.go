// SPDX-License-Identifier: AGPL-3.0-only

// Package projectonboarding creates bounded, public GitHub evidence snapshots.
// It never evaluates a project, approves a rule, or contacts an end-user system.
package projectonboarding

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const (
	RequestSchema     = "prufyx.io/public-project-onboarding-request/v1"
	SnapshotSchema    = "prufyx.io/public-project-onboarding-snapshot/v1"
	ReceiptSchema     = "prufyx.io/public-project-onboarding-sync-receipt/v1"
	Authority         = "DECLARED_PUBLIC_PROJECT_EVIDENCE_NOT_RULE_OR_RUNTIME_PROOF"
	maxRequest        = 64 << 10
	maxAPI            = 1 << 20
	maxReleaseListAPI = 4 << 20
	maxObject         = 4 << 20
	maxAggregate      = 32 << 20
	maxCorpusBytes    = 16 << 20
	maxRequests       = 108
	maxJSONDepth      = 32
	maxJSONTokens     = 1 << 16
)

var (
	ErrRejected    = errors.New("project onboarding rejected")
	ErrNoEligible  = errors.New("no eligible releases")
	ErrRateLimited = errors.New("github rate limited")
	ErrUnavailable = errors.New("repository unavailable")
	ErrNetwork     = errors.New("network failure")
	tagRE          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,95}){0,7}$`)
	pathRE         = regexp.MustCompile(`^(?:[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}/)*[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$`)
	objectRE       = regexp.MustCompile(`^sha256/[0-9a-f]{64}$`)
)

var snapshotLimitations = []string{
	"public GitHub observations and retained bytes are evidence candidates only; release bodies are mutable API observations",
	"no ownership, license determination, review, rule approval, compatibility, runtime behavior, signing, publication, or training authority follows",
}

var receiptLimitations = []string{
	"only fixed public GitHub API and raw immutable GitHub blob endpoints were queried",
	"a successful sync does not approve a source, project, rule, compatibility conclusion, or publication",
}

type Fetcher interface {
	Fetch(context.Context, string, string) ([]byte, int, error)
}
type FetchFunc func(context.Context, string, string) ([]byte, int, error)

func (f FetchFunc) Fetch(ctx context.Context, host, path string) ([]byte, int, error) {
	return f(ctx, host, path)
}

// FixedHTTPSFetcher is deliberately direct: no proxy, credentials, redirects,
// cookies, compression, endpoint override, or caller-controlled host.
type FixedHTTPSFetcher struct{}

func (FixedHTTPSFetcher) Fetch(ctx context.Context, host, path string) ([]byte, int, error) {
	if (host != "api.github.com" && host != "raw.githubusercontent.com") || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "#\\") || (host == "raw.githubusercontent.com" && strings.Contains(path, "?")) {
		return nil, 0, ErrRejected
	}
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"} {
		if os.Getenv(name) != "" {
			return nil, 0, ErrNetwork
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return nil, 0, ErrRejected
	}
	if host == "api.github.com" {
		req.Header.Set("Accept", "application/vnd.github+json")
	} else {
		req.Header.Set("Accept", "application/octet-stream")
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "prufyx-project-onboarding/1")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10, TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, ErrRejected
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxObject+1))
	if err != nil || len(data) > maxObject {
		return nil, 0, ErrRejected
	}
	return data, response.StatusCode, nil
}

type Options struct {
	Fetcher Fetcher
	Now     func() time.Time
}

type githubRelease struct {
	ID         int64           `json:"id"`
	Tag        string          `json:"tag_name"`
	Published  string          `json:"published_at"`
	Body       json.RawMessage `json:"body"`
	Draft      *bool           `json:"draft"`
	Prerelease *bool           `json:"prerelease"`
	body       string
}

func decodeReleaseList(raw []byte) ([]githubRelease, error) {
	var releases []githubRelease
	if decodeAPILimit(raw, maxReleaseListAPI, &releases) != nil || len(releases) > 30 {
		return nil, ErrRejected
	}
	for _, release := range releases {
		if release.Draft == nil || release.Prerelease == nil || len(release.Body) == 0 {
			return nil, ErrRejected
		}
	}
	for i := range releases {
		if bytes.Equal(releases[i].Body, []byte("null")) {
			continue
		}
		if json.Unmarshal(releases[i].Body, &releases[i].body) != nil {
			return nil, ErrRejected
		}
	}
	return releases, nil
}

func releaseBody(release githubRelease) string { return release.body }

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	if len(args) == 0 {
		return reject(stderr)
	}
	switch args[0] {
	case "help", "--help", "-h":
		_, _ = io.WriteString(stdout, "usage: prufyx-maintainer project <init|sync|verify|status|inspect|proposal> [options]\ninit --repository HTTPS_GITHUB_REPO --output NEW_REQUEST [--slug SLUG] [--release-limit 1..10] [--tag-prefix PREFIX] [--changelog-paths PATH,...]\nexact-tag init: init --repository HTTPS_GITHUB_REPO --exact-tag TAG [--exact-tag TAG ...] --license-anchor-tag TAG --output NEW_REQUEST [--slug SLUG] [--changelog-paths PATH,...]\nsync --manifest REQUEST --output-parent PRIVATE_DIR [--previous SNAPSHOT]\nverify --snapshot SNAPSHOT [--previous PRIOR_EXACT_TAG_SNAPSHOT]\nstatus|proposal --snapshot SNAPSHOT\ninspect --snapshot SNAPSHOT [--tag TAG] [--include-notes]\n")
		return 0
	case "init":
		return runInit(args[1:], stderr)
	case "sync":
		return runSync(ctx, args[1:], stdout, stderr, options)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "proposal":
		return runProposal(args[1:], stdout, stderr)
	default:
		return reject(stderr)
	}
}

func reject(stderr io.Writer) int { return rejectReason(stderr, "INVALID_INPUT_OR_INTEGRITY_FAILURE") }
func rejectReason(stderr io.Writer, reason string) int {
	_, _ = io.WriteString(stderr, "project: "+reason+"\n")
	return 2
}

func runInit(args []string, stderr io.Writer) int {
	if hasLongFlag(args, "--exact-tag") || hasLongFlag(args, "--license-anchor-tag") {
		return runExactTagInit(args, stderr)
	}
	flags := flag.NewFlagSet("project init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var repository, output, slug, prefix, license, pathsCSV string
	var limit int
	flags.StringVar(&repository, "repository", "", "canonical public GitHub repository")
	flags.StringVar(&output, "output", "", "new request file")
	flags.StringVar(&slug, "slug", "", "project slug")
	flags.IntVar(&limit, "release-limit", 5, "recent release limit")
	flags.StringVar(&prefix, "tag-prefix", "", "optional tag prefix")
	flags.StringVar(&pathsCSV, "changelog-paths", "", "comma-separated commit-pinned changelog candidate paths")
	flags.StringVar(&license, "license-disposition", "NOT_REVIEWED", "declared license disposition")
	if flags.Parse(args) != nil || flags.NArg() != 0 || output == "" || limit < 1 || limit > 10 || (license != "NOT_REVIEWED" && license != "DECLARED_UNKNOWN") {
		return reject(stderr)
	}
	repo, owner, name, err := repositoryParts(repository)
	if err != nil {
		return reject(stderr)
	}
	if slug == "" {
		slug = deriveSlug(owner, name)
	}
	if _, err = sourcecorpus.ValidateSlug(slug); err != nil || !validPrefix(prefix) {
		return reject(stderr)
	}
	paths := append(stringList(nil), defaultChangelogPaths...)
	if pathsCSV != "" {
		paths = stringList(strings.Split(pathsCSV, ","))
	}
	if len(paths) > 8 {
		return reject(stderr)
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !validChangelogPath(repo, p) || seen[p] {
			return reject(stderr)
		}
		seen[p] = true
	}
	prefixValue := any(prefix)
	if prefix == "" {
		prefixValue = nil
	}
	value := map[string]any{"schema": RequestSchema, "authority": Authority, "project": map[string]any{"slug": slug, "canonicalRepositoryURL": repo, "owner": owner, "repository": name}, "discovery": map[string]any{"releaseLimit": int64(limit), "tagPrefix": prefixValue, "changelogPaths": toAny(paths), "licenseDisposition": license}, "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}}
	raw, err := sourcecorpus.Canonical(value)
	if err != nil || writeNewPrivate(output, raw) != nil {
		return reject(stderr)
	}
	return 0
}

func hasLongFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || strings.HasPrefix(arg, name+"=") {
			return true
		}
	}
	return false
}

func deriveSlug(owner, name string) string {
	value := strings.ToLower(owner + "-" + name)
	value = strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			return character
		}
		return '-'
	}, value)
	value = strings.Trim(value, "-")
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	if len(value) > 119 {
		value = value[:119]
	}
	return value + "-" + strings.TrimPrefix(sourcecorpus.SHA([]byte(owner+"/"+name)), "sha256:")[:8]
}

type stringList []string

var defaultChangelogPaths = stringList{"CHANGELOG.md", "CHANGES.md", "CHANGES", "RELEASES.md", "docs/CHANGELOG.md"}

func toAny(items []string) []any {
	out := make([]any, len(items))
	for i := range items {
		out[i] = items[i]
	}
	return out
}
func validPrefix(value string) bool {
	return value == "" || (len(value) <= 64 && strings.HasSuffix(value, "/") && tagRE.MatchString(strings.TrimSuffix(value, "/"))) || (len(value) <= 64 && tagRE.MatchString(value))
}

func runSync(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := flag.NewFlagSet("project sync", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var manifest, parent, previous string
	flags.StringVar(&manifest, "manifest", "", "private request file")
	flags.StringVar(&parent, "output-parent", "", "private snapshot parent")
	flags.StringVar(&previous, "previous", "", "previous snapshot")
	if flags.Parse(args) != nil || flags.NArg() != 0 || manifest == "" || parent == "" {
		return reject(stderr)
	}
	raw, err := sourcecorpus.ReadPrivateFile(manifest, maxRequest)
	if err != nil {
		return reject(stderr)
	}
	request, err := parseRequest(raw)
	if err != nil {
		if exactRequest, exactErr := parseExactTagRequest(raw); exactErr == nil {
			return runExactTagSync(ctx, exactRequest, parent, previous, stdout, stderr, options)
		}
	}
	if err != nil || sourcecorpus.ValidatePrivateDirectoryPath(parent) != nil {
		return reject(stderr)
	}
	if options.Fetcher == nil {
		options.Fetcher = FixedHTTPSFetcher{}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	previousObjects := map[string][]byte{}
	var previousDigest any = nil
	var priorSnapshot map[string]any
	if previous != "" {
		priorSnapshot, previousObjects, err = VerifySnapshot(previous)
		if err != nil || priorSnapshot["schema"] != SnapshotSchema || priorSnapshot["repository"].(map[string]any)["canonicalRepositoryURL"] != request.repo {
			return reject(stderr)
		}
		previousDigest = digestMust(priorSnapshot)
	}
	snapshot, corpus, receipt, objects, err := Sync(ctx, request, priorSnapshot, previousObjects, previousDigest, options.Fetcher, options.Now)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoEligible):
			return rejectReason(stderr, "NO_ELIGIBLE_RELEASES")
		case errors.Is(err, ErrRateLimited):
			return rejectReason(stderr, "GITHUB_RATE_LIMITED")
		case errors.Is(err, ErrUnavailable):
			return rejectReason(stderr, "REPOSITORY_UNAVAILABLE")
		case errors.Is(err, ErrNetwork):
			return rejectReason(stderr, "NETWORK_FAILURE")
		default:
			return reject(stderr)
		}
	}
	if priorSnapshot != nil && comparePrevious(priorSnapshot, snapshot) != nil {
		return reject(stderr)
	}
	snapshotRaw, canonicalErr := sourcecorpus.Canonical(snapshot)
	if canonicalErr != nil {
		return reject(stderr)
	}
	finalDigest := sourcecorpus.SHA(snapshotRaw)
	destination := "snapshot-" + strings.TrimPrefix(finalDigest, "sha256:")
	if _, statErr := os.Stat(filepath.Join(parent, destination)); statErr == nil {
		if prior, _, verifyErr := VerifySnapshot(filepath.Join(parent, destination)); verifyErr == nil && digestMust(prior) == finalDigest {
			receipt["result"] = "UNCHANGED"
			receipt["snapshotDigest"] = finalDigest
			receipt["outputName"] = destination
			if emitJSON(stdout, receipt) != nil {
				return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
			}
			return 0
		}
		return reject(stderr)
	}
	receipt["snapshotDigest"] = finalDigest
	receipt["outputName"] = destination
	receiptRaw, canonicalErr := sourcecorpus.Canonical(receipt)
	if canonicalErr != nil {
		return reject(stderr)
	}
	var corpusRaw []byte
	if len(snapshot["sources"].([]any)) > 0 {
		corpusRaw, canonicalErr = sourcecorpus.Canonical(corpus)
		if canonicalErr != nil {
			return reject(stderr)
		}
	}
	if sourcecorpus.WriteProjectSnapshotTree(parent, destination, objects, snapshotRaw, corpusRaw, receiptRaw) != nil {
		return reject(stderr)
	}
	if emitJSON(stdout, receipt) != nil {
		return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
	}
	return 0
}

// comparePrevious checks only tags visible in both selected windows. Missing
// older tags are outside the current bounded window, never a deletion signal.
func comparePrevious(previous, next map[string]any) error {
	oldRepo, oldRepoOK := previous["repository"].(map[string]any)
	newRepo, newRepoOK := next["repository"].(map[string]any)
	oldReleases, oldReleasesOK := previous["releases"].([]any)
	newReleases, newReleasesOK := next["releases"].([]any)
	if !oldRepoOK || !newRepoOK || !oldReleasesOK || !newReleasesOK {
		return ErrRejected
	}
	if oldRepo["repositoryID"] != newRepo["repositoryID"] {
		return ErrRejected
	}
	oldByID := map[int64]map[string]any{}
	oldByTag := map[string]map[string]any{}
	for _, value := range oldReleases {
		release, ok := value.(map[string]any)
		id, idOK := release["releaseID"].(int64)
		if !ok || !idOK || oldByID[id] != nil || oldByTag[stringOf(release["tag"])] != nil {
			return ErrRejected
		}
		oldByID[id] = release
		oldByTag[stringOf(release["tag"])] = release
	}
	for _, value := range newReleases {
		release, ok := value.(map[string]any)
		id, idOK := release["releaseID"].(int64)
		if !ok || !idOK {
			return ErrRejected
		}
		if prior := oldByTag[stringOf(release["tag"])]; prior != nil && prior["commit"] != release["commit"] {
			return ErrRejected
		}
		prior := oldByID[id]
		if prior == nil {
			continue
		}
		if prior["tag"] != release["tag"] || prior["commit"] != release["commit"] {
			return ErrRejected
		}
		release["priorReleaseBodyDigest"] = prior["releaseBodyDigest"]
		if prior["releaseBodyDigest"] == release["releaseBodyDigest"] {
			release["releaseBodyState"] = "UNCHANGED"
		} else {
			release["releaseBodyState"] = "CHANGED"
		}
	}
	return nil
}

type request struct {
	repo, owner, name, slug, prefix, license string
	limit                                    int
	paths                                    []string
	digest                                   string
	document                                 map[string]any
}

func parseRequest(raw []byte) (request, error) {
	v, err := sourcecorpus.DecodeBounded(raw, maxRequest)
	if err != nil {
		return request{}, ErrRejected
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 5 || m["schema"] != RequestSchema || m["authority"] != Authority {
		return request{}, ErrRejected
	}
	project, ok := m["project"].(map[string]any)
	if !ok || len(project) != 4 {
		return request{}, ErrRejected
	}
	repo, owner, name, err := repositoryParts(stringOf(project["canonicalRepositoryURL"]))
	if err != nil || project["owner"] != owner || project["repository"] != name {
		return request{}, ErrRejected
	}
	slug, err := sourcecorpus.ValidateSlug(project["slug"])
	if err != nil {
		return request{}, ErrRejected
	}
	discovery, ok := m["discovery"].(map[string]any)
	if !ok || len(discovery) != 4 {
		return request{}, ErrRejected
	}
	n, ok := discovery["releaseLimit"].(int64)
	if !ok || n < 1 || n > 10 {
		return request{}, ErrRejected
	}
	prefix := ""
	if discovery["tagPrefix"] != nil {
		var prefixOK bool
		prefix, prefixOK = discovery["tagPrefix"].(string)
		if !prefixOK {
			return request{}, ErrRejected
		}
	}
	if !validPrefix(prefix) {
		return request{}, ErrRejected
	}
	license := stringOf(discovery["licenseDisposition"])
	if license != "NOT_REVIEWED" && license != "DECLARED_UNKNOWN" {
		return request{}, ErrRejected
	}
	rawPaths, ok := discovery["changelogPaths"].([]any)
	if !ok || len(rawPaths) < 1 || len(rawPaths) > 8 {
		return request{}, ErrRejected
	}
	paths := make([]string, 0, len(rawPaths))
	seen := map[string]bool{}
	for _, x := range rawPaths {
		p := stringOf(x)
		if !validChangelogPath(repo, p) || seen[p] {
			return request{}, ErrRejected
		}
		seen[p] = true
		paths = append(paths, p)
	}
	review, ok := m["review"].(map[string]any)
	if !ok || len(review) != 2 || review["state"] != "NOT_REVIEWED" || review["admissionState"] != "NOT_ADMITTED" {
		return request{}, ErrRejected
	}
	canonical, canonicalErr := sourcecorpus.Canonical(v)
	if canonicalErr != nil {
		return request{}, ErrRejected
	}
	return request{repo, owner, name, slug, prefix, license, int(n), paths, sourcecorpus.SHA(canonical), m}, nil
}
func stringOf(v any) string { s, _ := v.(string); return s }
func repositoryParts(value string) (string, string, string, error) {
	repo, err := sourcecorpus.ValidateRepository(value)
	if err != nil {
		return "", "", "", err
	}
	pieces := strings.Split(strings.TrimPrefix(repo, "https://github.com/"), "/")
	return repo, pieces[0], pieces[1], nil
}

func validChangelogPath(repository, path string) bool {
	if !pathRE.MatchString(path) {
		return false
	}
	const placeholderCommit = "0000000000000000000000000000000000000000"
	_, err := sourcecorpus.ValidateImmutableURL(repository+"/blob/"+placeholderCommit+"/"+path, repository, placeholderCommit)
	return err == nil
}

// Sync is exported for deterministic no-network tests through an injected Fetcher.
func Sync(ctx context.Context, r request, previousSnapshot map[string]any, prior map[string][]byte, previousDigest any, fetcher Fetcher, now func() time.Time) (map[string]any, map[string]any, map[string]any, map[string][]byte, error) {
	if fetcher == nil || now == nil {
		return nil, nil, nil, nil, ErrRejected
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	objects := map[string][]byte{}
	priorSources := map[string]map[string]any{}
	if previousSnapshot != nil {
		for _, value := range previousSnapshot["sources"].([]any) {
			source := value.(map[string]any)
			priorSources[stringOf(source["immutableURL"])] = source
		}
	}
	aggregate, sourceAggregate, requestCount := 0, 0, 0
	fetch := func(host, path string) ([]byte, int, error) {
		requestCount++
		if requestCount > maxRequests {
			return nil, 0, ErrRejected
		}
		return fetcher.Fetch(ctx, host, path)
	}
	add := func(data []byte) string {
		d := sourcecorpus.SHA(data)
		if old, ok := prior[d]; ok && bytes.Equal(old, data) {
			if _, exists := objects[d]; !exists {
				aggregate += len(old)
			}
			objects[d] = old
		} else {
			if _, exists := objects[d]; !exists {
				aggregate += len(data)
			}
			objects[d] = append([]byte(nil), data...)
		}
		return d
	}
	api := func(path string, limit int) ([]byte, string, error) {
		data, status, err := fetch("api.github.com", path)
		if err != nil {
			return nil, "", ErrNetwork
		}
		if status == 403 || status == 429 {
			return nil, "", ErrRateLimited
		}
		if status == 404 {
			return nil, "", ErrUnavailable
		}
		if status != 200 || len(data) == 0 || len(data) > limit {
			return nil, "", ErrRejected
		}
		d := add(data)
		if aggregate > maxAggregate {
			return nil, "", ErrRejected
		}
		return data, d, nil
	}
	repoRaw, repoDigest, err := api("/repos/"+r.owner+"/"+r.name, maxAPI)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var repoWire struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	}
	if decodeAPI(repoRaw, &repoWire) != nil || repoWire.ID < 1 || repoWire.FullName != r.owner+"/"+r.name || repoWire.HTMLURL != r.repo {
		return nil, nil, nil, nil, ErrRejected
	}
	releasesRaw, releasesDigest, err := api("/repos/"+r.owner+"/"+r.name+"/releases?per_page=30&page=1", maxReleaseListAPI)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	wireReleases, decodeErr := decodeReleaseList(releasesRaw)
	if decodeErr != nil {
		return nil, nil, nil, nil, ErrRejected
	}
	releases := []any{}
	sources := []any{}
	corpusRecords := []any{}
	seenReleaseIDs, seenReleaseTags, seenImmutable := map[int64]bool{}, map[string]bool{}, map[string]bool{}
	captured := now().UTC().Truncate(time.Second).Format(time.RFC3339)
	for _, rel := range wireReleases {
		if len(releases) >= r.limit {
			break
		}
		if *rel.Draft || *rel.Prerelease || rel.ID < 1 || !tagRE.MatchString(rel.Tag) || (r.prefix != "" && !strings.HasPrefix(rel.Tag, r.prefix)) || !validTimestamp(rel.Published) {
			continue
		}
		if seenReleaseIDs[rel.ID] || seenReleaseTags[rel.Tag] {
			return nil, nil, nil, nil, ErrRejected
		}
		seenReleaseIDs[rel.ID], seenReleaseTags[rel.Tag] = true, true
		refRaw, refDigest, refErr := api("/repos/"+r.owner+"/"+r.name+"/git/ref/tags/"+url.PathEscape(rel.Tag), maxAPI)
		if refErr != nil {
			return nil, nil, nil, nil, refErr
		}
		var ref struct {
			Ref    string                     `json:"ref"`
			Object struct{ Type, SHA string } `json:"object"`
		}
		if decodeAPI(refRaw, &ref) != nil || ref.Ref != "refs/tags/"+rel.Tag || (ref.Object.Type != "commit" && ref.Object.Type != "tag") || !commit(ref.Object.SHA) {
			return nil, nil, nil, nil, ErrRejected
		}
		annotatedObject := any(nil)
		annotatedSHA := any(nil)
		if ref.Object.Type == "tag" {
			outerSHA := ref.Object.SHA
			tagRaw, tagDigest, tagErr := api("/repos/"+r.owner+"/"+r.name+"/git/tags/"+ref.Object.SHA, maxAPI)
			if tagErr != nil {
				return nil, nil, nil, nil, tagErr
			}
			var tagWire struct {
				SHA    string `json:"sha"`
				Tag    string `json:"tag"`
				Object struct {
					Type string `json:"type"`
					SHA  string `json:"sha"`
				} `json:"object"`
			}
			if decodeAPI(tagRaw, &tagWire) != nil || tagWire.SHA != outerSHA || tagWire.Tag != rel.Tag || tagWire.Object.Type != "commit" || !commit(tagWire.Object.SHA) {
				return nil, nil, nil, nil, ErrRejected
			}
			ref.Object.SHA = tagWire.Object.SHA
			annotatedObject = "sha256/" + strings.TrimPrefix(tagDigest, "sha256:")
			annotatedSHA = outerSHA
		}
		entry := map[string]any{"releaseID": rel.ID, "tag": rel.Tag, "publishedAt": rel.Published, "releaseBodyDigest": sourcecorpus.SHA([]byte(releaseBody(rel))), "releaseListObject": "sha256/" + strings.TrimPrefix(releasesDigest, "sha256:"), "tagReferenceObject": "sha256/" + strings.TrimPrefix(refDigest, "sha256:"), "annotatedTagObject": annotatedObject, "annotatedTagSHA": annotatedSHA, "commit": ref.Object.SHA}
		releases = append(releases, entry)
		for _, p := range r.paths {
			immutable := r.repo + "/blob/" + ref.Object.SHA + "/" + p
			if seenImmutable[immutable] {
				break
			}
			body := []byte(nil)
			reused := false
			if old, exists := priorSources[immutable]; exists {
				if data, exists := prior[stringOf(old["fileDigest"])]; exists {
					body = data
					reused = true
				}
			}
			if !reused {
				status := 0
				var fetchErr error
				body, status, fetchErr = fetch("raw.githubusercontent.com", "/"+r.owner+"/"+r.name+"/"+ref.Object.SHA+"/"+p)
				if status == 404 && fetchErr == nil {
					continue
				}
				if fetchErr != nil {
					return nil, nil, nil, nil, ErrNetwork
				}
				if status == 403 || status == 429 {
					return nil, nil, nil, nil, ErrRateLimited
				}
				if status != 200 || len(body) < 1 || len(body) > maxObject {
					return nil, nil, nil, nil, ErrRejected
				}
			}
			span, spanErr := fullSpan(body)
			if spanErr != nil {
				return nil, nil, nil, nil, ErrRejected
			}
			d := add(body)
			if aggregate > maxAggregate {
				return nil, nil, nil, nil, ErrRejected
			}
			if !seenImmutable[immutable] {
				sourceAggregate += len(body)
			}
			if sourceAggregate > maxCorpusBytes {
				return nil, nil, nil, nil, ErrRejected
			}
			sourceID := onboardingSourceID(r, ref.Object.SHA, p)
			version := "reference_only"
			state := "FETCHED"
			if reused {
				state = "REUSED_VERIFIED_PRIOR"
			}
			source := map[string]any{"id": sourceID, "kind": "changelog", "version": version, "commit": ref.Object.SHA, "immutableURL": immutable, "fileDigest": d, "object": "sha256/" + strings.TrimPrefix(d, "sha256:"), "byteLength": int64(len(body)), "spans": []any{span}, "captureState": state}
			sources = append(sources, source)
			seenImmutable[immutable] = true
			corpusRecords = append(corpusRecords, corpusRecord(r, sourceID, version, ref.Object.SHA, immutable, d, len(body), span, captured))
			break
		}
	}
	if len(releases) == 0 {
		return nil, nil, nil, nil, ErrNoEligible
	}
	// License is public retained context only. It is deliberately absent from the
	// corpus adapter because v1 has no license source kind.
	latest := releases[0].(map[string]any)
	licenseObservation := any(nil)
	for _, p := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING"} {
		body, status, fetchErr := fetch("raw.githubusercontent.com", "/"+r.owner+"/"+r.name+"/"+latest["commit"].(string)+"/"+p)
		if fetchErr != nil {
			return nil, nil, nil, nil, ErrNetwork
		}
		if status == 404 {
			continue
		}
		if status == 403 || status == 429 {
			return nil, nil, nil, nil, ErrRateLimited
		}
		if status != 200 || len(body) < 1 || len(body) > maxObject {
			return nil, nil, nil, nil, ErrRejected
		}
		d := add(body)
		if aggregate > maxAggregate {
			return nil, nil, nil, nil, ErrRejected
		}
		licenseObservation = map[string]any{"kind": "license", "commit": latest["commit"], "immutableURL": r.repo + "/blob/" + latest["commit"].(string) + "/" + p, "fileDigest": d, "object": "sha256/" + strings.TrimPrefix(d, "sha256:"), "byteLength": int64(len(body)), "disposition": r.license}
		break
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].(map[string]any)["tag"].(string) < releases[j].(map[string]any)["tag"].(string)
	})
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].(map[string]any)["id"].(string) < sources[j].(map[string]any)["id"].(string)
	})
	sort.Slice(corpusRecords, func(i, j int) bool {
		return corpusRecords[i].(map[string]any)["id"].(string) < corpusRecords[j].(map[string]any)["id"].(string)
	})
	adapterState := "PRESENT"
	if len(sources) == 0 {
		adapterState = "OMITTED_NO_CHANGELOG_BYTES"
	}
	snapshot := map[string]any{"schema": SnapshotSchema, "authority": Authority, "request": r.document, "requestDigest": r.digest, "observedAt": captured, "repository": map[string]any{"canonicalRepositoryURL": r.repo, "repositoryID": repoWire.ID, "fullName": repoWire.FullName, "repositoryObject": "sha256/" + strings.TrimPrefix(repoDigest, "sha256:")}, "window": map[string]any{"selection": "FIRST_PAGE_RECENT_PUBLISHED_NON_PRERELEASE", "page": int64(1), "candidatePageSize": int64(30), "candidateReleaseCount": int64(len(wireReleases)), "pageMayBeTruncated": len(wireReleases) == 30, "releaseLimit": int64(r.limit), "priorAbsentState": "OUTSIDE_SELECTED_WINDOW"}, "releases": releases, "sources": sources, "corpusAdapterState": adapterState, "license": licenseObservation, "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}, "previousSnapshotDigest": previousDigest, "limitations": toAny(snapshotLimitations)}
	corpus := map[string]any{"schema": sourcecorpus.Schema, "revision": onboardingRevision(r), "authority": sourcecorpus.DeclaredAuthority, "records": corpusRecords}
	corpusRaw, _ := sourcecorpus.Canonical(corpus)
	corpusDigest := any(nil)
	if len(sources) > 0 {
		corpusDigest = sourcecorpus.SHA(corpusRaw)
	}
	receipt := map[string]any{"schema": ReceiptSchema, "result": "SYNCED", "authority": Authority, "requestDigest": r.digest, "repositoryID": repoWire.ID, "releaseCount": int64(len(releases)), "sourceCount": int64(len(sources)), "corpusAdapterState": adapterState, "sourceCorpusManifestDigest": corpusDigest, "reviewState": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED", "limitations": toAny(receiptLimitations)}
	return snapshot, corpus, receipt, objects, nil
}

func fullSpan(body []byte) (map[string]any, error) {
	lines := bytes.Count(body, []byte{'\n'})
	if lines+1 > sourcecorpus.MaxSourceLines {
		return nil, ErrRejected
	}
	if len(body) > 0 && body[len(body)-1] != '\n' {
		lines++
	}
	if lines < 1 {
		lines = 1
	}
	return map[string]any{"startLine": int64(1), "endLine": int64(lines), "spanDigest": sourcecorpus.SHA(bytes.TrimSuffix(body, []byte("\n")))}, nil
}
func corpusRecord(r request, id, version, commitValue, immutable, d string, length int, span map[string]any, captured string) map[string]any {
	return map[string]any{"id": id, "project": map[string]any{"slug": r.slug, "canonicalRepositoryURL": r.repo}, "source": map[string]any{"repositoryURL": r.repo, "sourceKind": "changelog", "version": version, "commit": commitValue, "immutableURL": immutable, "fileDigest": d, "byteLength": int64(length), "spans": []any{span}}, "capture": map[string]any{"capturedAt": captured, "object": "sha256/" + strings.TrimPrefix(d, "sha256:")}, "declarations": map[string]any{"packetDigest": nil, "ruleIDs": []any{}}}
}
func onboardingRevision(r request) string {
	return "project-onboarding-" + strings.TrimPrefix(sourcecorpus.SHA([]byte(r.repo)), "sha256:")[:24]
}
func onboardingSourceID(r request, commitValue, path string) string {
	repositoryPart := strings.TrimPrefix(sourcecorpus.SHA([]byte(r.repo)), "sha256:")[:16]
	pathPart := strings.TrimPrefix(sourcecorpus.SHA([]byte(path)), "sha256:")[:32]
	return "onboarding-changelog-" + repositoryPart + "-" + commitValue[:16] + "-" + pathPart
}
func normalizeVersion(value string) string {
	value = strings.TrimPrefix(value, "v")
	if regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`).MatchString(value) {
		return value
	}
	return "reference_only"
}
func validTimestamp(v string) bool {
	_, err := time.Parse(time.RFC3339, v)
	return err == nil && strings.HasSuffix(v, "Z")
}
func commit(v string) bool { return regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(v) }
func digestMust(value any) string {
	raw, _ := sourcecorpus.Canonical(value)
	return sourcecorpus.SHA(raw)
}

func decodeAPI(raw []byte, target any) error {
	return decodeAPILimit(raw, maxAPI, target)
}

// decodeAPILimit preserves the structural limits while allowing the one
// reviewed release-list endpoint to have its own retained-object byte bound.
func decodeAPILimit(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || !validJSONUnicodeEscapes(raw) {
		return ErrRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	tokens := 0
	if err := scanJSON(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrRejected
	}
	return json.Unmarshal(raw, target)
}

func validJSONUnicodeEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		value, ok := hexQuad(raw, i+1)
		if !ok {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value < 0xd800 || value > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, lowOK := hexQuad(raw, i+3)
		if !lowOK || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return !inString
}

func hexQuad(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, character := range raw[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
func scanJSON(decoder *json.Decoder, depth int, tokens *int) error {
	*tokens++
	if depth > maxJSONDepth || *tokens > maxJSONTokens {
		return ErrRejected
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrRejected
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return ErrRejected
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrRejected
			}
			seen[name] = true
			if err := scanJSON(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrRejected
		}
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrRejected
		}
	}
	return nil
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	if (len(args) != 2 && len(args) != 4) || args[0] != "--snapshot" || (len(args) == 4 && args[2] != "--previous") {
		return reject(stderr)
	}
	snapshot, _, err := VerifySnapshot(args[1])
	if err != nil {
		return reject(stderr)
	}
	if snapshot["schema"] == ExactTagSnapshotSchema {
		return runExactTagVerify(args, stdout, stderr)
	}
	if len(args) != 2 {
		return reject(stderr)
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-onboarding-verification/v1", "snapshotDigest": digestMust(snapshot), "verification": "VERIFIED_RETAINED_PUBLIC_PROJECT_EVIDENCE", "reviewState": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}) != nil {
		return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
	}
	return 0
}
func runStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--snapshot" {
		return reject(stderr)
	}
	snapshot, _, err := VerifySnapshot(args[1])
	if err != nil {
		return reject(stderr)
	}
	if snapshot["schema"] == ExactTagSnapshotSchema {
		return runExactTagStatus(args, stdout, stderr)
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-onboarding-status/v1", "snapshotDigest": digestMust(snapshot), "repository": publicRepository(snapshot), "releaseCount": int64(len(snapshot["releases"].([]any))), "sourceCount": int64(len(snapshot["sources"].([]any))), "freshness": "NOT_CHECKED_OFFLINE", "upstreamContinuity": "NOT_CHECKED_OFFLINE", "nonRevocation": "NOT_CHECKED_OFFLINE", "review": snapshot["review"]}) != nil {
		return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
	}
	return 0
}
func runInspect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("project inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var path, tag string
	var includeNotes bool
	flags.StringVar(&path, "snapshot", "", "snapshot")
	flags.StringVar(&tag, "tag", "", "tag")
	flags.BoolVar(&includeNotes, "include-notes", false, "include retained public release bodies")
	if flags.Parse(args) != nil || flags.NArg() != 0 || path == "" {
		return reject(stderr)
	}
	snapshot, objects, err := VerifySnapshot(path)
	if err != nil {
		return reject(stderr)
	}
	if snapshot["schema"] == ExactTagSnapshotSchema {
		return runExactTagInspect(path, tag, includeNotes, stdout, stderr)
	}
	releases := []any{}
	for _, r := range snapshot["releases"].([]any) {
		if tag == "" || r.(map[string]any)["tag"] == tag {
			releases = append(releases, r)
		}
	}
	if tag != "" && len(releases) == 0 {
		return reject(stderr)
	}
	notes := []any{}
	if includeNotes {
		for _, value := range releases {
			release := value.(map[string]any)
			object := "sha256:" + strings.TrimPrefix(stringOf(release["releaseListObject"]), "sha256/")
			var all []struct {
				ID   int64  `json:"id"`
				Body string `json:"body"`
			}
			if json.Unmarshal(objects[object], &all) != nil {
				return reject(stderr)
			}
			for _, item := range all {
				if item.ID == release["releaseID"] {
					notes = append(notes, map[string]any{"releaseID": item.ID, "tag": release["tag"], "body": item.Body})
					break
				}
			}
		}
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-onboarding-inspection/v1", "repository": snapshot["repository"], "releases": releases, "sources": snapshot["sources"], "releaseNotes": notes, "review": snapshot["review"]}) != nil {
		return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
	}
	return 0
}
func runProposal(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--snapshot" {
		return reject(stderr)
	}
	snapshot, _, err := VerifySnapshot(args[1])
	if err != nil {
		return reject(stderr)
	}
	if snapshot["schema"] == ExactTagSnapshotSchema {
		return runExactTagProposal(args, stdout, stderr)
	}
	releases := make([]any, 0, len(snapshot["releases"].([]any)))
	for _, item := range snapshot["releases"].([]any) {
		r := item.(map[string]any)
		release := map[string]any{"releaseID": r["releaseID"], "tag": r["tag"], "version": normalizeVersion(stringOf(r["tag"])), "publishedAt": r["publishedAt"], "commit": r["commit"], "releaseBodyDigest": r["releaseBodyDigest"], "releaseURL": snapshot["repository"].(map[string]any)["canonicalRepositoryURL"].(string) + "/releases/tag/" + url.PathEscape(stringOf(r["tag"]))}
		if prior, ok := r["priorReleaseBodyDigest"]; ok {
			release["priorReleaseBodyDigest"] = prior
			release["releaseBodyState"] = r["releaseBodyState"]
		}
		releases = append(releases, release)
	}
	sources := make([]any, 0, len(snapshot["sources"].([]any)))
	for _, item := range snapshot["sources"].([]any) {
		s := item.(map[string]any)
		sources = append(sources, map[string]any{"id": s["id"], "kind": s["kind"], "version": s["version"], "commit": s["commit"], "immutableURL": s["immutableURL"], "fileDigest": s["fileDigest"], "byteLength": s["byteLength"], "spans": s["spans"], "captureState": s["captureState"]})
	}
	var license any
	if retained, ok := snapshot["license"].(map[string]any); ok {
		license = map[string]any{"kind": retained["kind"], "commit": retained["commit"], "immutableURL": retained["immutableURL"], "fileDigest": retained["fileDigest"], "byteLength": retained["byteLength"], "disposition": retained["disposition"]}
	}
	if emitJSON(stdout, map[string]any{"schema": "prufyx.io/public-project-source-only-proposal/v1", "snapshotDigest": digestMust(snapshot), "observedAt": snapshot["observedAt"], "repository": publicRepository(snapshot), "window": snapshot["window"], "releases": releases, "sources": sources, "license": license, "request": "INDEPENDENT_REVIEW_REQUIRED", "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}, "limitations": []any{"references and digests only; raw objects are deliberately excluded", "this proposal does not approve ownership, a rule, compatibility, signing, or publication"}}) != nil {
		return rejectReason(stderr, "OUTPUT_WRITE_FAILURE")
	}
	return 0
}

func emitJSON(writer io.Writer, value any) error {
	raw, err := sourcecorpus.Canonical(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	written, err := writer.Write(raw)
	if err != nil {
		return err
	}
	if written != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}

func publicRepository(snapshot map[string]any) map[string]any {
	repository := snapshot["repository"].(map[string]any)
	return map[string]any{"canonicalRepositoryURL": repository["canonicalRepositoryURL"], "repositoryID": repository["repositoryID"], "fullName": repository["fullName"]}
}

// VerifySnapshot verifies the corpus adapter and the bounded snapshot shape.
func VerifySnapshot(directory string) (map[string]any, map[string][]byte, error) {
	raw, err := sourcecorpus.ReadPrivateTreeFile(directory, "PROJECT-ONBOARDING-SNAPSHOT.json", 256<<10)
	if err != nil {
		return nil, nil, ErrRejected
	}
	value, err := sourcecorpus.DecodeBounded(bytes.TrimSpace(raw), 256<<10)
	if err != nil {
		return nil, nil, ErrRejected
	}
	snapshot, ok := value.(map[string]any)
	if ok && snapshot["schema"] == ExactTagSnapshotSchema {
		return verifyExactTagSnapshot(directory, snapshot)
	}
	if !ok || snapshot["schema"] != SnapshotSchema || snapshot["authority"] != Authority {
		return nil, nil, ErrRejected
	}
	if !closedSnapshot(snapshot) {
		return nil, nil, ErrRejected
	}
	if sources, ok := snapshot["sources"].([]any); !ok {
		return nil, nil, ErrRejected
	} else if len(sources) > 0 {
		if _, err = sourcecorpus.VerifyPath(filepath.Join(directory, "SOURCE-CORPUS-MANIFEST.json"), filepath.Join(directory, "objects")); err != nil {
			return nil, nil, ErrRejected
		}
		if !adapterMatchesSnapshot(directory, snapshot) {
			return nil, nil, ErrRejected
		}
	} else if snapshot["corpusAdapterState"] != "OMITTED_NO_CHANGELOG_BYTES" {
		return nil, nil, ErrRejected
	}
	objects := map[string][]byte{}
	aggregate := 0
	read := func(name string) ([]byte, error) {
		if !objectRE.MatchString(name) {
			return nil, ErrRejected
		}
		digest := "sha256:" + strings.TrimPrefix(name, "sha256/")
		if cached, ok := objects[digest]; ok {
			return cached, nil
		}
		if len(objects) >= maxRequests {
			return nil, ErrRejected
		}
		b, e := sourcecorpus.ReadPrivateTreeFile(directory, "objects/"+name, maxObject)
		if e != nil || sourcecorpus.SHA(b) != digest || aggregate+len(b) > maxAggregate {
			return nil, ErrRejected
		}
		aggregate += len(b)
		objects[digest] = b
		return b, nil
	}
	repo, ok := snapshot["repository"].(map[string]any)
	if !ok {
		return nil, nil, ErrRejected
	}
	repoObject := stringOf(repo["repositoryObject"])
	b, e := read(repoObject)
	if e != nil {
		return nil, nil, e
	}
	var wire struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	}
	requestRaw, _ := sourcecorpus.Canonical(snapshot["request"])
	boundRequest, requestErr := parseRequest(requestRaw)
	if decodeAPI(b, &wire) != nil || requestErr != nil || wire.ID < 1 || wire.FullName != boundRequest.owner+"/"+boundRequest.name || wire.HTMLURL != boundRequest.repo || repo["repositoryID"] != wire.ID || repo["fullName"] != wire.FullName || repo["canonicalRepositoryURL"] != wire.HTMLURL {
		return nil, nil, ErrRejected
	}
	if err := verifyReleaseObservations(snapshot, boundRequest, read); err != nil {
		return nil, nil, ErrRejected
	}
	if err := verifySourcesAgainstSnapshot(snapshot, read); err != nil {
		return nil, nil, ErrRejected
	}
	if err := verifyLicense(snapshot, read); err != nil {
		return nil, nil, ErrRejected
	}
	receiptRaw, receiptErr := sourcecorpus.ReadPrivateTreeFile(directory, "SYNC-RECEIPT.json", maxRequest)
	if receiptErr != nil {
		return nil, nil, ErrRejected
	}
	receiptValue, receiptErr := sourcecorpus.DecodeBounded(bytes.TrimSpace(receiptRaw), maxRequest)
	receipt, receiptOK := receiptValue.(map[string]any)
	if receiptErr != nil || !receiptOK || !closedReceipt(directory, snapshot, receipt) {
		return nil, nil, ErrRejected
	}
	return snapshot, objects, nil
}

func closedReceipt(directory string, snapshot, receipt map[string]any) bool {
	if !exact(receipt, "schema", "result", "authority", "requestDigest", "repositoryID", "releaseCount", "sourceCount", "corpusAdapterState", "sourceCorpusManifestDigest", "reviewState", "admissionState", "limitations", "snapshotDigest", "outputName") {
		return false
	}
	digest := digestMust(snapshot)
	outputName := "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	if receipt["schema"] != ReceiptSchema || receipt["result"] != "SYNCED" || receipt["authority"] != Authority || receipt["requestDigest"] != snapshot["requestDigest"] || receipt["repositoryID"] != snapshot["repository"].(map[string]any)["repositoryID"] || receipt["releaseCount"] != int64(len(snapshot["releases"].([]any))) || receipt["sourceCount"] != int64(len(snapshot["sources"].([]any))) || receipt["corpusAdapterState"] != snapshot["corpusAdapterState"] || receipt["reviewState"] != "NOT_REVIEWED" || receipt["admissionState"] != "NOT_ADMITTED" || receipt["snapshotDigest"] != digest || receipt["outputName"] != outputName || filepath.Base(filepath.Clean(directory)) != outputName || !exactStrings(receipt["limitations"], receiptLimitations) {
		return false
	}
	if len(snapshot["sources"].([]any)) == 0 {
		return receipt["sourceCorpusManifestDigest"] == nil
	}
	raw, err := sourcecorpus.ReadPrivateTreeFile(directory, "SOURCE-CORPUS-MANIFEST.json", 256<<10)
	return err == nil && receipt["sourceCorpusManifestDigest"] == sourcecorpus.SHA(bytes.TrimSpace(raw))
}

func exact(object map[string]any, fields ...string) bool {
	if len(object) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return false
		}
	}
	return true
}
func nonnegative(value any) bool { n, ok := value.(int64); return ok && n >= 0 && n <= 30 }
func boolValue(value any) bool   { _, ok := value.(bool); return ok }
func exactStrings(value any, expected []string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for i := range expected {
		if items[i] != expected[i] {
			return false
		}
	}
	return true
}
func closedSnapshot(snapshot map[string]any) bool {
	if !exact(snapshot, "schema", "authority", "request", "requestDigest", "observedAt", "repository", "window", "releases", "sources", "corpusAdapterState", "license", "review", "previousSnapshotDigest", "limitations") {
		return false
	}
	requestRaw, requestErr := sourcecorpus.Canonical(snapshot["request"])
	boundRequest, boundErr := parseRequest(requestRaw)
	if requestErr != nil || boundErr != nil || snapshot["requestDigest"] != boundRequest.digest || !validTimestamp(stringOf(snapshot["observedAt"])) {
		return false
	}
	review, ok := snapshot["review"].(map[string]any)
	if !ok || !exact(review, "state", "admissionState") || review["state"] != "NOT_REVIEWED" || review["admissionState"] != "NOT_ADMITTED" {
		return false
	}
	repo, ok := snapshot["repository"].(map[string]any)
	if !ok || !exact(repo, "canonicalRepositoryURL", "repositoryID", "fullName", "repositoryObject") {
		return false
	}
	if _, _, _, err := repositoryParts(stringOf(repo["canonicalRepositoryURL"])); err != nil || repo["canonicalRepositoryURL"] != boundRequest.repo {
		return false
	}
	repositoryID, ok := repo["repositoryID"].(int64)
	if !ok || repositoryID < 1 || repo["fullName"] != boundRequest.owner+"/"+boundRequest.name || !objectRE.MatchString(stringOf(repo["repositoryObject"])) {
		return false
	}
	window, ok := snapshot["window"].(map[string]any)
	if !ok || !exact(window, "selection", "page", "candidatePageSize", "candidateReleaseCount", "pageMayBeTruncated", "releaseLimit", "priorAbsentState") || window["selection"] != "FIRST_PAGE_RECENT_PUBLISHED_NON_PRERELEASE" || window["page"] != int64(1) || window["candidatePageSize"] != int64(30) || window["priorAbsentState"] != "OUTSIDE_SELECTED_WINDOW" || window["releaseLimit"] != int64(boundRequest.limit) || !nonnegative(window["candidateReleaseCount"]) || !boolValue(window["pageMayBeTruncated"]) {
		return false
	}
	if snapshot["previousSnapshotDigest"] != nil {
		if _, err := sourcecorpus.ValidateSHA(snapshot["previousSnapshotDigest"]); err != nil {
			return false
		}
	}
	sources, sourcesOK := snapshot["sources"].([]any)
	releases, releasesOK := snapshot["releases"].([]any)
	if !sourcesOK || !releasesOK || len(releases) < 1 || len(releases) > boundRequest.limit {
		return false
	}
	wantAdapter := "PRESENT"
	if len(sources) == 0 {
		wantAdapter = "OMITTED_NO_CHANGELOG_BYTES"
	}
	return snapshot["corpusAdapterState"] == wantAdapter && exactStrings(snapshot["limitations"], snapshotLimitations)
}

func adapterMatchesSnapshot(directory string, snapshot map[string]any) bool {
	raw, err := sourcecorpus.ReadPrivateTreeFile(directory, "SOURCE-CORPUS-MANIFEST.json", 256<<10)
	if err != nil {
		return false
	}
	value, err := sourcecorpus.DecodeBounded(bytes.TrimSpace(raw), 256<<10)
	if err != nil {
		return false
	}
	manifest, ok := value.(map[string]any)
	if !ok {
		return false
	}
	records, ok := manifest["records"].([]any)
	if !ok || len(records) != len(snapshot["sources"].([]any)) {
		return false
	}
	byID := map[string]map[string]any{}
	for _, item := range records {
		record, ok := item.(map[string]any)
		if !ok {
			return false
		}
		id := stringOf(record["id"])
		if id == "" || byID[id] != nil {
			return false
		}
		byID[id] = record
	}
	requestRaw, _ := sourcecorpus.Canonical(snapshot["request"])
	request, requestErr := parseRequest(requestRaw)
	if requestErr != nil || manifest["revision"] != onboardingRevision(request) {
		return false
	}
	for _, item := range snapshot["sources"].([]any) {
		source, ok := item.(map[string]any)
		if !ok {
			return false
		}
		record := byID[stringOf(source["id"])]
		if record == nil {
			return false
		}
		rs, ok := record["source"].(map[string]any)
		project, projectOK := record["project"].(map[string]any)
		capture, captureOK := record["capture"].(map[string]any)
		declarations, declarationsOK := record["declarations"].(map[string]any)
		ruleIDs, ruleIDsOK := declarations["ruleIDs"].([]any)
		if !ok || !projectOK || !captureOK || !declarationsOK || !ruleIDsOK || !exact(declarations, "packetDigest", "ruleIDs") || declarations["packetDigest"] != nil || len(ruleIDs) != 0 || project["slug"] != request.slug || project["canonicalRepositoryURL"] != snapshot["repository"].(map[string]any)["canonicalRepositoryURL"] || rs["repositoryURL"] != snapshot["repository"].(map[string]any)["canonicalRepositoryURL"] || rs["sourceKind"] != "changelog" || rs["version"] != source["version"] || rs["commit"] != source["commit"] || rs["immutableURL"] != source["immutableURL"] || rs["fileDigest"] != source["fileDigest"] || rs["byteLength"] != source["byteLength"] || capture["object"] != source["object"] || capture["capturedAt"] != snapshot["observedAt"] {
			return false
		}
		a, _ := sourcecorpus.Canonical(rs["spans"])
		b, _ := sourcecorpus.Canonical(source["spans"])
		if !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

func verifyLicense(snapshot map[string]any, read func(string) ([]byte, error)) error {
	if snapshot["license"] == nil {
		return nil
	}
	license, ok := snapshot["license"].(map[string]any)
	if !ok || !exact(license, "kind", "commit", "immutableURL", "fileDigest", "object", "byteLength", "disposition") || license["kind"] != "license" || license["disposition"] != "NOT_REVIEWED" && license["disposition"] != "DECLARED_UNKNOWN" {
		return ErrRejected
	}
	requestRaw, _ := sourcecorpus.Canonical(snapshot["request"])
	request, requestErr := parseRequest(requestRaw)
	if requestErr != nil || license["disposition"] != request.license {
		return ErrRejected
	}
	repo := stringOf(snapshot["repository"].(map[string]any)["canonicalRepositoryURL"])
	commitValue := stringOf(license["commit"])
	selectedCommit, selectedErr := firstSelectedReleaseCommit(snapshot, request, read)
	immutable, err := sourcecorpus.ValidateImmutableURL(license["immutableURL"], repo, commitValue)
	if err != nil || selectedErr != nil || !commit(commitValue) || commitValue != selectedCommit || !hasFixedLicensePath(immutable, repo, commitValue) {
		return ErrRejected
	}
	data, err := read(stringOf(license["object"]))
	if err != nil || sourcecorpus.SHA(data) != license["fileDigest"] || license["byteLength"] != int64(len(data)) {
		return ErrRejected
	}
	return nil
}

func firstSelectedReleaseCommit(snapshot map[string]any, request request, read func(string) ([]byte, error)) (string, error) {
	releases := snapshot["releases"].([]any)
	byID := map[int64]string{}
	for _, item := range releases {
		release := item.(map[string]any)
		byID[release["releaseID"].(int64)] = stringOf(release["commit"])
	}
	listObject := stringOf(releases[0].(map[string]any)["releaseListObject"])
	raw, err := read(listObject)
	if err != nil {
		return "", ErrRejected
	}
	candidates, decodeErr := decodeReleaseList(raw)
	if decodeErr != nil {
		return "", ErrRejected
	}
	for _, candidate := range candidates {
		if *candidate.Draft || *candidate.Prerelease || candidate.ID < 1 || !tagRE.MatchString(candidate.Tag) || request.prefix != "" && !strings.HasPrefix(candidate.Tag, request.prefix) || !validTimestamp(candidate.Published) {
			continue
		}
		if commitValue := byID[candidate.ID]; commitValue != "" {
			return commitValue, nil
		}
		return "", ErrRejected
	}
	return "", ErrRejected
}

func hasFixedLicensePath(immutable, repo, commitValue string) bool {
	for _, path := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING"} {
		if immutable == repo+"/blob/"+commitValue+"/"+path {
			return true
		}
	}
	return false
}

func verifyReleaseObservations(snapshot map[string]any, request request, read func(string) ([]byte, error)) error {
	releases, ok := snapshot["releases"].([]any)
	if !ok || len(releases) < 1 || len(releases) > request.limit {
		return ErrRejected
	}
	byID := map[int64]map[string]any{}
	seenTags := map[string]bool{}
	listObject := ""
	lastTag := ""
	for _, value := range releases {
		release, ok := value.(map[string]any)
		if !ok || !exactRelease(release) {
			return ErrRejected
		}
		id, idOK := release["releaseID"].(int64)
		tag := stringOf(release["tag"])
		if !idOK || id < 1 || !tagRE.MatchString(tag) || request.prefix != "" && !strings.HasPrefix(tag, request.prefix) || !validTimestamp(stringOf(release["publishedAt"])) || !commit(stringOf(release["commit"])) || !validDigest(release["releaseBodyDigest"]) || !objectRE.MatchString(stringOf(release["releaseListObject"])) || !objectRE.MatchString(stringOf(release["tagReferenceObject"])) || byID[id] != nil || seenTags[tag] || lastTag != "" && tag <= lastTag {
			return ErrRejected
		}
		if listObject == "" {
			listObject = stringOf(release["releaseListObject"])
		} else if release["releaseListObject"] != listObject {
			return ErrRejected
		}
		if prior, exists := release["priorReleaseBodyDigest"]; exists {
			if snapshot["previousSnapshotDigest"] == nil || !validDigest(prior) || release["releaseBodyState"] == "UNCHANGED" && prior != release["releaseBodyDigest"] || release["releaseBodyState"] == "CHANGED" && prior == release["releaseBodyDigest"] {
				return ErrRejected
			}
		}
		byID[id], seenTags[tag], lastTag = release, true, tag
	}
	raw, err := read(listObject)
	if err != nil {
		return ErrRejected
	}
	apiReleases, decodeErr := decodeReleaseList(raw)
	if decodeErr != nil {
		return ErrRejected
	}
	window := snapshot["window"].(map[string]any)
	if window["candidateReleaseCount"] != int64(len(apiReleases)) || window["pageMayBeTruncated"] != (len(apiReleases) == 30) {
		return ErrRejected
	}
	expected := make([]map[string]any, 0, request.limit)
	selectedIDs, selectedTags := map[int64]bool{}, map[string]bool{}
	for _, candidate := range apiReleases {
		if len(expected) >= request.limit {
			break
		}
		if *candidate.Draft || *candidate.Prerelease || candidate.ID < 1 || !tagRE.MatchString(candidate.Tag) || request.prefix != "" && !strings.HasPrefix(candidate.Tag, request.prefix) || !validTimestamp(candidate.Published) {
			continue
		}
		if selectedIDs[candidate.ID] || selectedTags[candidate.Tag] {
			return ErrRejected
		}
		selectedIDs[candidate.ID], selectedTags[candidate.Tag] = true, true
		expected = append(expected, map[string]any{"releaseID": candidate.ID, "tag": candidate.Tag, "publishedAt": candidate.Published, "releaseBodyDigest": sourcecorpus.SHA([]byte(releaseBody(candidate)))})
	}
	sort.Slice(expected, func(i, j int) bool { return stringOf(expected[i]["tag"]) < stringOf(expected[j]["tag"]) })
	if len(expected) != len(releases) {
		return ErrRejected
	}
	for i, expectedRelease := range expected {
		release := releases[i].(map[string]any)
		if release["releaseID"] != expectedRelease["releaseID"] || release["tag"] != expectedRelease["tag"] || release["publishedAt"] != expectedRelease["publishedAt"] || release["releaseBodyDigest"] != expectedRelease["releaseBodyDigest"] {
			return ErrRejected
		}
		refRaw, err := read(stringOf(release["tagReferenceObject"]))
		if err != nil {
			return ErrRejected
		}
		var ref struct {
			Ref    string `json:"ref"`
			Object struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"object"`
		}
		if decodeAPI(refRaw, &ref) != nil || ref.Ref != "refs/tags/"+stringOf(release["tag"]) || (ref.Object.Type != "commit" && ref.Object.Type != "tag") || !commit(ref.Object.SHA) {
			return ErrRejected
		}
		resolved := ref.Object.SHA
		if ref.Object.Type == "tag" {
			tagObject, ok := release["annotatedTagObject"].(string)
			annotatedSHA, shaOK := release["annotatedTagSHA"].(string)
			if !ok || !shaOK || annotatedSHA != ref.Object.SHA || !objectRE.MatchString(tagObject) {
				return ErrRejected
			}
			tagRaw, tagErr := read(tagObject)
			if tagErr != nil {
				return ErrRejected
			}
			var tag struct {
				SHA    string `json:"sha"`
				Tag    string `json:"tag"`
				Object struct {
					Type string `json:"type"`
					SHA  string `json:"sha"`
				} `json:"object"`
			}
			if decodeAPI(tagRaw, &tag) != nil || tag.SHA != annotatedSHA || tag.Tag != release["tag"] || tag.Object.Type != "commit" || !commit(tag.Object.SHA) {
				return ErrRejected
			}
			resolved = tag.Object.SHA
		} else if release["annotatedTagObject"] != nil || release["annotatedTagSHA"] != nil {
			return ErrRejected
		}
		if release["commit"] != resolved {
			return ErrRejected
		}
	}
	return nil
}

func exactRelease(release map[string]any) bool {
	base := []string{"releaseID", "tag", "publishedAt", "releaseBodyDigest", "releaseListObject", "tagReferenceObject", "annotatedTagObject", "annotatedTagSHA", "commit"}
	if exact(release, base...) {
		return true
	}
	return exact(release, append(base, "priorReleaseBodyDigest", "releaseBodyState")...) && (release["releaseBodyState"] == "UNCHANGED" || release["releaseBodyState"] == "CHANGED")
}

func validDigest(value any) bool {
	_, err := sourcecorpus.ValidateSHA(value)
	return err == nil
}

func verifySourcesAgainstSnapshot(snapshot map[string]any, read func(string) ([]byte, error)) error {
	repository, ok := snapshot["repository"].(map[string]any)
	if !ok {
		return ErrRejected
	}
	repo := stringOf(repository["canonicalRepositoryURL"])
	requestRaw, _ := sourcecorpus.Canonical(snapshot["request"])
	request, requestErr := parseRequest(requestRaw)
	if requestErr != nil {
		return ErrRejected
	}
	releaseCommits := map[string]bool{}
	for _, value := range snapshot["releases"].([]any) {
		releaseCommits[stringOf(value.(map[string]any)["commit"])] = true
	}
	sources, ok := snapshot["sources"].([]any)
	if !ok {
		return ErrRejected
	}
	seenIDs, seenURLs := map[string]bool{}, map[string]bool{}
	lastID := ""
	for _, value := range sources {
		source, ok := value.(map[string]any)
		if !ok || !exact(source, "id", "kind", "version", "commit", "immutableURL", "fileDigest", "object", "byteLength", "spans", "captureState") || source["kind"] != "changelog" || source["version"] != "reference_only" || (source["captureState"] != "FETCHED" && source["captureState"] != "REUSED_VERIFIED_PRIOR") {
			return ErrRejected
		}
		if source["captureState"] == "REUSED_VERIFIED_PRIOR" && snapshot["previousSnapshotDigest"] == nil {
			return ErrRejected
		}
		id, immutable := stringOf(source["id"]), stringOf(source["immutableURL"])
		commitValue, digest := stringOf(source["commit"]), stringOf(source["fileDigest"])
		if !releaseCommits[commitValue] || !commit(commitValue) {
			return ErrRejected
		}
		path := ""
		for _, candidate := range request.paths {
			if immutable == repo+"/blob/"+commitValue+"/"+candidate {
				path = candidate
				break
			}
		}
		expectedID := onboardingSourceID(request, commitValue, path)
		if path == "" || id != expectedID || seenIDs[id] || seenURLs[immutable] || lastID != "" && id <= lastID {
			return ErrRejected
		}
		seenIDs[id], seenURLs[immutable], lastID = true, true, id
		if _, err := sourcecorpus.ValidateImmutableURL(source["immutableURL"], repo, commitValue); err != nil || !validDigest(source["fileDigest"]) || stringOf(source["object"]) != "sha256/"+strings.TrimPrefix(digest, "sha256:") {
			return ErrRejected
		}
		data, err := read(stringOf(source["object"]))
		if err != nil || sourcecorpus.SHA(data) != digest || source["byteLength"] != int64(len(data)) {
			return ErrRejected
		}
	}
	return nil
}

func writeNewPrivate(path string, data []byte) error {
	if path == "" || len(data) == 0 || len(data) > maxRequest {
		return ErrRejected
	}
	if sourcecorpus.WriteNewPrivateFile(path, append(data, '\n')) != nil {
		return ErrRejected
	}
	return nil
}
