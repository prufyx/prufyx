// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Release status values. "unknown" means the mirror has no authenticated
// release metadata for the repository; it is never inferred from tags.
const (
	ReleasesKnown   = "known"
	ReleasesStale   = "stale"
	ReleasesUnknown = "unknown"
)

// Release reasons recorded when status is not "known".
const (
	ReasonNoToken     = "no_token"
	ReasonRateLimited = "rate_limited"
	ReasonNotFound    = "not_found"
	ReasonError       = "error"
	ReasonUnsupported = "unsupported_host"
)

// Releases is the cached GitHub Releases metadata of one repository.
type Releases struct {
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	ETag      string    `json:"etag,omitempty"`
	FetchedAt string    `json:"fetchedAt,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
	Items     []Release `json:"items,omitempty"`
}

// Release is the subset of release metadata the pipeline needs.
type Release struct {
	ID              int64  `json:"id"`
	Tag             string `json:"tag"`
	Name            string `json:"name,omitempty"`
	Draft           bool   `json:"draft"`
	Prerelease      bool   `json:"prerelease"`
	TargetCommitish string `json:"targetCommitish,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
	PublishedAt     string `json:"publishedAt,omitempty"`
}

// ReleaseResult is the outcome of one release listing.
type ReleaseResult struct {
	NotModified bool
	ETag        string
	Items       []Release
	Truncated   bool
}

// ReleaseClient lists release metadata for a repository.
type ReleaseClient interface {
	List(ctx context.Context, repo Repo, etag string) (ReleaseResult, error)
}

var (
	// ErrRateLimited stops further release calls for the rest of the run.
	ErrRateLimited = errors.New("factory mirror: github api rate limited")
	// ErrReleasesNotFound is a 404 for the repository's releases.
	ErrReleasesNotFound = errors.New("factory mirror: releases not found")
)

// TokenSource supplies a GitHub bearer token (a personal/fine-grained token
// or a GitHub App installation token). Tokens are only ever sent to the
// GitHub API base URL and are never logged or stored.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed token, typically from GITHUB_TOKEN.
type StaticToken string

// Token implements TokenSource.
func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

// TokenSourceFromEnv selects a token source from the environment: a GitHub
// App when PRUFYX_GITHUB_APP_ID, PRUFYX_GITHUB_APP_INSTALLATION_ID and
// PRUFYX_GITHUB_APP_KEY_FILE are all set, otherwise GITHUB_TOKEN (or
// GH_TOKEN). It returns nil when no credential is configured.
func TokenSourceFromEnv(getenv func(string) string, now func() time.Time) (TokenSource, error) {
	return TokenSourceFromEnvBase(getenv, now, "")
}

// TokenSourceFromEnvBase is TokenSourceFromEnv with the GitHub API base URL
// a GitHub App exchanges its key at ("" is the public API). It exists so a
// test API base receives the app exchange instead of api.github.com.
func TokenSourceFromEnvBase(getenv func(string) string, now func() time.Time, apiBase string) (TokenSource, error) {
	appID, inst, keyFile := getenv("PRUFYX_GITHUB_APP_ID"), getenv("PRUFYX_GITHUB_APP_INSTALLATION_ID"), getenv("PRUFYX_GITHUB_APP_KEY_FILE")
	if appID != "" || inst != "" || keyFile != "" {
		if appID == "" || inst == "" || keyFile == "" {
			return nil, fmt.Errorf("%w: GitHub App configuration is incomplete", ErrInvalid)
		}
		pemBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("%w: GitHub App key: %v", ErrInvalid, err)
		}
		return NewAppTokenSource(appID, inst, pemBytes, apiBase, nil, now)
	}
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			return StaticToken(v), nil
		}
	}
	return nil, nil
}

// AppTokenSource exchanges a GitHub App private key for short-lived
// installation tokens. The key is a credential for reading public release
// metadata and opening pull requests; it is not a release or database
// signing key.
type AppTokenSource struct {
	appID, installation string
	key                 *rsa.PrivateKey
	baseURL             string
	client              *http.Client
	now                 func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewAppTokenSource builds an AppTokenSource. baseURL and client default to
// the public GitHub API; tests inject their own.
func NewAppTokenSource(appID, installation string, keyPEM []byte, baseURL string, client *http.Client, now func() time.Time) (*AppTokenSource, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: GitHub App key is not PEM", ErrInvalid)
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: GitHub App key is not RSA", ErrInvalid)
		}
		key = rk
	} else {
		return nil, fmt.Errorf("%w: GitHub App key unreadable", ErrInvalid)
	}
	if baseURL == "" {
		baseURL = defaultAPIBase
	}
	if client == nil {
		client = newAPIClient()
	}
	if now == nil {
		now = time.Now
	}
	return &AppTokenSource{appID: appID, installation: installation, key: key, baseURL: baseURL, client: client, now: now}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *AppTokenSource) jwt() (string, error) {
	now := a.now().Unix()
	header := b64([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"iat": now - 60, "exp": now + 9*60, "iss": a.appID})
	signing := header + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// Token implements TokenSource with an in-memory cache.
func (a *AppTokenSource) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && a.now().Add(5*time.Minute).Before(a.expires) {
		return a.token, nil
	}
	jwt, err := a.jwt()
	if err != nil {
		return "", err
	}
	endpoint := a.baseURL + "/app/installations/" + url.PathEscape(a.installation) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	setAPIHeaders(req)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github app token: transport: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github app token: status %d", resp.StatusCode)
	}
	var parsed struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Token == "" {
		return "", errors.New("github app token: malformed response")
	}
	exp, err := time.Parse(time.RFC3339, parsed.ExpiresAt)
	if err != nil {
		exp = a.now().Add(30 * time.Minute)
	}
	a.token, a.expires = parsed.Token, exp
	return a.token, nil
}

const defaultAPIBase = "https://api.github.com"

func setAPIHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "prufyx-factory-mirror/1")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

func newAPIClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, DisableCompression: true,
			MaxResponseHeaderBytes: 32 << 10,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// GitHubReleases lists releases through the GitHub REST API with ETag
// revalidation (a 304 does not consume rate limit).
//
// The ETag handed back to the caller is opaque: it carries the validator of
// every page that was read, one per line, and a later call revalidates every
// one of those pages. A change on any page (a release published, deleted,
// flipped from or to prerelease) therefore causes a fresh listing.
type GitHubReleases struct {
	Tokens TokenSource
	// BaseURL defaults to the public API; tests point it at a local server.
	BaseURL string
	Client  *http.Client
	// MaxPages bounds pagination (ReleasesPerPage releases per page);
	// default DefaultReleasePages. A
	// listing cut short by the bound is marked Truncated and must not be
	// used to derive release lines.
	MaxPages int
	// CompleteScan reads every page regardless of MaxPages (up to a hard
	// ceiling of absoluteMaxReleasePages pages).
	CompleteScan bool
}

const (
	// maxReleasePageBytes bounds one response page. Release notes make a
	// page large: at per_page=100 real pages reach 16.5 MB (dapr), which
	// this bound rejected, leaving the repository's releases unknown. At
	// ReleasesPerPage a page is a fifth of that, well inside the bound, and
	// the bound itself stays at 8 MiB.
	maxReleasePageBytes = 8 << 20
	// ReleasesPerPage is the page size requested from the releases API.
	ReleasesPerPage = 20
	// DefaultReleasePages is the default page bound: 100 pages of
	// ReleasesPerPage releases, i.e. the 2000 newest releases.
	DefaultReleasePages = 100
	// absoluteMaxReleasePages bounds even a complete scan.
	absoluteMaxReleasePages = 5000
	// etagLayout tags the validator string with the page size it was made
	// for, so validators from another page size are never replayed.
	etagLayout = "per_page=" + "20" // keep in step with ReleasesPerPage
)

// splitETags returns the per-page validators of an ETag string written by
// List. A string made for another page size yields none.
func splitETags(etag string) []string {
	lines := strings.Split(etag, "\n")
	if len(lines) < 2 || lines[0] != etagLayout {
		return nil
	}
	return lines[1:]
}

// List implements ReleaseClient. Only github.com repositories are supported.
func (g GitHubReleases) List(ctx context.Context, repo Repo, etag string) (ReleaseResult, error) {
	if repo.Host != DefaultHost {
		return ReleaseResult{}, fmt.Errorf("%w: releases are only read for %s", ErrInvalid, DefaultHost)
	}
	base := g.BaseURL
	if base == "" {
		base = defaultAPIBase
	}
	client := g.Client
	if client == nil {
		client = newAPIClient()
	}
	maxPages := g.MaxPages
	if maxPages <= 0 {
		maxPages = DefaultReleasePages
	}
	if g.CompleteScan {
		maxPages = absoluteMaxReleasePages
	}
	token, err := g.Tokens.Token(ctx)
	if err != nil {
		return ReleaseResult{}, err
	}
	pageURL := func(n int) string {
		return base + "/repos/" + url.PathEscape(repo.Owner) + "/" + url.PathEscape(repo.Name) + "/releases?per_page=" + strconv.Itoa(ReleasesPerPage) + "&page=" + strconv.Itoa(n)
	}

	// Revalidate every page we saw last time; only when all of them are
	// unchanged is the cached listing still good.
	if validators := splitETags(etag); len(validators) > 0 {
		unchanged := true
		for i, v := range validators {
			if v == "" {
				unchanged = false
				break
			}
			resp, err := g.fetchPage(ctx, client, base, pageURL(i+1), token, v)
			if err != nil {
				return ReleaseResult{}, err
			}
			if resp.status != http.StatusNotModified {
				unchanged = false
				break
			}
		}
		if unchanged {
			return ReleaseResult{NotModified: true, ETag: etag}, nil
		}
	}

	var result ReleaseResult
	var etags []string
	missingValidator := false
	seen := map[int64]bool{}
	next := pageURL(1)
	for page := 1; next != ""; page++ {
		resp, err := g.fetchPage(ctx, client, base, next, token, "")
		if err != nil {
			return ReleaseResult{}, err
		}
		if tag := resp.header.Get("ETag"); tag == "" || strings.ContainsAny(tag, "\r\n") {
			missingValidator = true
		} else {
			etags = append(etags, tag)
		}
		var raw []struct {
			ID              int64  `json:"id"`
			TagName         string `json:"tag_name"`
			Name            string `json:"name"`
			Draft           bool   `json:"draft"`
			Prerelease      bool   `json:"prerelease"`
			TargetCommitish string `json:"target_commitish"`
			CreatedAt       string `json:"created_at"`
			PublishedAt     string `json:"published_at"`
		}
		if err := json.Unmarshal(resp.body, &raw); err != nil {
			return ReleaseResult{}, errors.New("github releases: malformed response")
		}
		for _, r := range raw {
			// A release listed again because the list shifted between two
			// page requests is kept once.
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			result.Items = append(result.Items, Release{ID: r.ID, Tag: r.TagName, Name: r.Name, Draft: r.Draft, Prerelease: r.Prerelease, TargetCommitish: r.TargetCommitish, CreatedAt: r.CreatedAt, PublishedAt: r.PublishedAt})
		}
		next = nextLink(resp.header.Get("Link"))
		if next != "" && page >= maxPages {
			result.Truncated = true
			break
		}
	}
	if !missingValidator {
		result.ETag = etagLayout + "\n" + strings.Join(etags, "\n")
	}
	return result, nil
}

type pageResponse struct {
	status int
	header http.Header
	body   []byte
}

// fetchPage performs one GET. A 200 or (when a validator was sent) 304 is
// returned; everything else is mapped to an error.
func (g GitHubReleases) fetchPage(ctx context.Context, client *http.Client, base, target, token, validator string) (pageResponse, error) {
	if !strings.HasPrefix(target, base+"/") {
		return pageResponse{}, errors.New("github releases: pagination left the API host")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return pageResponse{}, err
	}
	setAPIHeaders(req)
	req.Header.Set("Authorization", "Bearer "+token)
	if validator != "" {
		req.Header.Set("If-None-Match", validator)
	}
	resp, err := client.Do(req)
	if err != nil {
		return pageResponse{}, fmt.Errorf("github releases: transport: %w", err)
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxReleasePageBytes+1))
	resp.Body.Close()
	if rerr != nil || len(body) > maxReleasePageBytes {
		return pageResponse{}, errors.New("github releases: unreadable or oversized response")
	}
	switch {
	case resp.StatusCode == http.StatusNotModified && validator != "":
		return pageResponse{status: resp.StatusCode, header: resp.Header}, nil
	case resp.StatusCode == http.StatusNotFound:
		return pageResponse{}, ErrReleasesNotFound
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""):
		return pageResponse{}, ErrRateLimited
	case resp.StatusCode != http.StatusOK:
		return pageResponse{}, fmt.Errorf("github releases: status %d", resp.StatusCode)
	}
	return pageResponse{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

// nextLink extracts rel="next" from a Link header.
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start, end := strings.Index(part, "<"), strings.Index(part, ">")
		if start == 0 && end > 1 {
			return part[1:end]
		}
	}
	return ""
}
