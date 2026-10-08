// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git object ids are SHA-1 by definition
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Limits on what the GitHub source accepts.
const (
	maxRawFileBytes = 64 << 20
	maxTreeBytes    = 32 << 20
	maxTagListBytes = 16 << 20
	// maxCachedBlobBytes bounds the files kept in the per-run blob cache;
	// larger files (the 4-6 MiB swagger.json) are not retained.
	maxCachedBlobBytes = 1 << 20
)

// GitHubStats counts what a GitHubSource asked GitHub for during a run.
type GitHubStats struct {
	// RESTCalls are api.github.com requests (they count against the rate
	// limit): commit lookups plus tree lookups, recursive or not.
	RESTCalls int64
	// CommitCalls and TreeCalls split RESTCalls; RecursiveTreeCalls is the
	// part of TreeCalls that used ?recursive=1.
	CommitCalls, TreeCalls, RecursiveTreeCalls int64
	// TruncatedFallbacks counts recursive listings GitHub truncated, which
	// were redone per directory for that tree only.
	TruncatedFallbacks int64
	// RawFetches and RawBytes are raw.githubusercontent.com requests and the
	// bytes they returned.
	RawFetches, RawBytes int64
	// RawCacheHits counts file reads answered from the per-run blob cache.
	RawCacheHits int64
	// APIRequests are the HTTP requests actually sent to api.github.com
	// (retries after a server error count; each one costs rate limit).
	// It is the number the budget is checked against.
	APIRequests int64
	// DiskTreeHits and DiskBlobHits are objects answered from the on-disk
	// cache (CacheDir) instead of the network.
	DiskTreeHits, DiskBlobHits int64
	// RateLimitRemaining is the last X-RateLimit-Remaining GitHub
	// reported, or -1 when none was seen.
	RateLimitRemaining int64
	// BudgetExhausted reports that a request was refused (or GitHub
	// refused it) because the REST budget ran out; Reason says which.
	BudgetExhausted bool
	BudgetReason    string
}

// ErrBudgetExhausted marks work that could not run because the GitHub REST
// budget (the caller's cap or GitHub's own rate limit) is used up. It is not
// a verdict about the data: a gate that meets it reports "could not run" and
// never passes.
var ErrBudgetExhausted = errors.New("GitHub REST budget exhausted")

// DefaultRESTReserve is how many requests of GitHub's own remaining count
// the gate leaves for the rest of the job.
const DefaultRESTReserve = 25

// GitHubSource fetches pinned upstream bytes straight from GitHub,
// independently of any mirror: directory listings from the git trees API
// (walking tree objects from the commit's root tree), file bytes from
// raw.githubusercontent.com by commit SHA, and tags with "git ls-remote".
// Every file it returns is checked against the git blob id its commit's
// tree records, so the bytes are exactly the ones the commit holds.
type GitHubSource struct {
	// APIBase and RawBase default to https://api.github.com and
	// https://raw.githubusercontent.com; tests point them at a local server.
	APIBase, RawBase string
	// Token, when set, authenticates API requests (rate limit only).
	Token string
	// Client defaults to an HTTP client with a 60 second timeout.
	Client *http.Client
	// LsRemote returns "git ls-remote --tags" output for a repository URL;
	// nil runs git.
	LsRemote func(ctx context.Context, repoURL string) ([]byte, error)
	// MaxRESTRequests caps the api.github.com requests of this source; 0
	// means no cap of our own (GitHub's rate limit still applies). A
	// request over the cap is not sent and fails with ErrBudgetExhausted.
	MaxRESTRequests int64
	// RESTReserve is the number of requests of GitHub's reported
	// remaining count that are never used; negative means none, 0 means
	// DefaultRESTReserve.
	RESTReserve int64
	// CacheDir, when set, keeps verified git trees and small blobs on disk
	// between runs. An entry is used only if it hashes to its own object id.
	CacheDir string

	mu        sync.Mutex
	roots     map[string]string              // repo NUL commit -> root tree id
	trees     map[string][]extract.TreeEntry // repo NUL tree id -> entries (names only)
	blobs     map[string][]byte              // repo NUL blob id -> verified bytes (small files)
	flights   map[string]*flight             // in-flight requests, by cache key
	noRecurse map[string]bool                // repo NUL tree id -> GitHub truncated its recursive listing

	nCommit, nTree, nRecursive, nTruncated, nRaw, nRawBytes, nRawHit atomic.Int64
	nAPI, nDiskTree, nDiskBlob                                       atomic.Int64

	remaining atomic.Int64 // last X-RateLimit-Remaining + 1; 0 means none seen
	exhausted atomic.Bool
	reasonMu  sync.Mutex
	reason    string
}

// flight is one request in progress; concurrent callers of the same key
// wait for it instead of repeating it.
type flight struct {
	done chan struct{}
	err  error
}

// once runs fn for key unless a call for key is running (then it waits) or
// done() already reports the result cached.
func (g *GitHubSource) once(key string, done func() bool, fn func() error) error {
	for {
		g.mu.Lock()
		if done() {
			g.mu.Unlock()
			return nil
		}
		if f, ok := g.flights[key]; ok {
			g.mu.Unlock()
			<-f.done
			if f.err != nil {
				return f.err
			}
			continue
		}
		f := &flight{done: make(chan struct{})}
		g.flights[key] = f
		g.mu.Unlock()
		f.err = fn()
		g.mu.Lock()
		delete(g.flights, key)
		g.mu.Unlock()
		close(f.done)
		return f.err
	}
}

// Stats returns the request counters of this source since it was created.
func (g *GitHubSource) Stats() GitHubStats {
	c, t, r := g.nCommit.Load(), g.nTree.Load(), g.nRecursive.Load()
	return GitHubStats{RESTCalls: c + t, CommitCalls: c, TreeCalls: t, RecursiveTreeCalls: r,
		TruncatedFallbacks: g.nTruncated.Load(), RawFetches: g.nRaw.Load(), RawBytes: g.nRawBytes.Load(), RawCacheHits: g.nRawHit.Load(),
		APIRequests: g.nAPI.Load(), DiskTreeHits: g.nDiskTree.Load(), DiskBlobHits: g.nDiskBlob.Load(),
		RateLimitRemaining: g.remaining.Load() - 1, BudgetExhausted: g.exhausted.Load(), BudgetReason: g.budgetReason()}
}

func (g *GitHubSource) budgetReason() string {
	g.reasonMu.Lock()
	defer g.reasonMu.Unlock()
	return g.reason
}

// exhaust records that the budget ran out and returns the error to give.
func (g *GitHubSource) exhaust(why string) error {
	g.reasonMu.Lock()
	if g.reason == "" {
		g.reason = why
	}
	why = g.reason
	g.reasonMu.Unlock()
	g.exhausted.Store(true)
	return fmt.Errorf("%w: %s", ErrBudgetExhausted, why)
}

// admitAPI decides, before an api.github.com request is sent, whether the
// budget still allows it.
func (g *GitHubSource) admitAPI() error {
	if g.exhausted.Load() {
		return fmt.Errorf("%w: %s", ErrBudgetExhausted, g.budgetReason())
	}
	if g.MaxRESTRequests > 0 && g.nAPI.Load() >= g.MaxRESTRequests {
		return g.exhaust(fmt.Sprintf("the cap of %d REST requests for this run is used up", g.MaxRESTRequests))
	}
	reserve := g.RESTReserve
	if reserve == 0 {
		reserve = DefaultRESTReserve
	}
	if reserve < 0 {
		reserve = 0
	}
	if rem := g.remaining.Load() - 1; g.remaining.Load() > 0 && rem <= reserve {
		return g.exhaust(fmt.Sprintf("GitHub reports %d requests left, %d are kept for the rest of the job", rem, reserve))
	}
	return nil
}

// noteRateLimit reads GitHub's rate limit headers from an API response.
func (g *GitHubSource) noteRateLimit(resp *http.Response) error {
	if v := resp.Header.Get("X-RateLimit-Remaining"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			g.remaining.Store(n + 1)
		}
	}
	// A refusal because of the rate limit: primary (remaining 0) or
	// secondary (Retry-After). Both are "could not run", not "not found".
	if resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode == http.StatusForbidden && (resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "")) {
		return g.exhaust(fmt.Sprintf("GitHub refused the request (HTTP %d, rate limit)", resp.StatusCode))
	}
	return nil
}

func (g *GitHubSource) init() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.roots == nil {
		g.roots, g.trees = map[string]string{}, map[string][]extract.TreeEntry{}
		g.blobs, g.flights, g.noRecurse = map[string][]byte{}, map[string]*flight{}, map[string]bool{}
	}
}

// httpTimeout bounds one whole request, body included.
var httpTimeout = 60 * time.Second

const maxHTTPRedirects = 3

// noProxyTransport is the default transport minus proxy environment lookup.
var noProxyTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return t
}()

// newHTTPClient returns the one HTTP client this package uses. It ignores
// proxy environment variables, applies httpTimeout, and follows redirects
// only within the original host and scheme (so the token never reaches
// another host and a request never drops from https to http).
func newHTTPClient(base *http.Client) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	} else {
		c.Transport = noProxyTransport
	}
	if c.Timeout <= 0 || c.Timeout > httpTimeout {
		c.Timeout = httpTimeout
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxHTTPRedirects {
			return fmt.Errorf("stopped after %d redirects", maxHTTPRedirects)
		}
		first := via[0].URL
		if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
			return fmt.Errorf("redirect to another host or scheme refused")
		}
		return nil
	}
	return &c
}

// checkHTTPURL refuses anything but https, except plain http to a loopback
// address (local test servers).
func checkHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("not a fetchable URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("only https URLs are fetched")
}

func (g *GitHubSource) client() *http.Client {
	return newHTTPClient(g.Client)
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return strings.TrimSuffix(v, "/")
}

func (g *GitHubSource) get(ctx context.Context, u string, api bool, limit int64) ([]byte, int, error) {
	if err := checkHTTPURL(u); err != nil {
		return nil, 0, err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if api {
			if err := g.admitAPI(); err != nil {
				return nil, 0, err
			}
			g.nAPI.Add(1)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, 0, err
		}
		if api {
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
			if g.Token != "" {
				req.Header.Set("Authorization", "Bearer "+g.Token)
			}
		}
		resp, err := g.client().Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
			resp.Body.Close()
			if api {
				if err := g.noteRateLimit(resp); err != nil {
					return nil, resp.StatusCode, err
				}
			}
			switch {
			case readErr != nil:
				lastErr = readErr
			case int64(len(body)) > limit:
				return nil, resp.StatusCode, fmt.Errorf("%s: response exceeds %d bytes", u, limit)
			case resp.StatusCode >= 500:
				lastErr = fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
			default:
				return body, resp.StatusCode, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	return nil, 0, lastErr
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// rootTree returns the root tree id of a commit.
func (g *GitHubSource) rootTree(ctx context.Context, repo extract.RepoRef, commit string) (string, error) {
	if !extract.IsCommitSHA(commit) {
		return "", fmt.Errorf("commit must be a full 40-character SHA")
	}
	g.init()
	key := repo.Key + "\x00" + commit
	g.mu.Lock()
	id, ok := g.roots[key]
	g.mu.Unlock()
	if ok {
		return id, nil
	}
	err := g.once("c\x00"+key, func() bool { _, ok := g.roots[key]; return ok }, func() error {
		owner, name := repo.OwnerName()
		u := orDefault(g.APIBase, "https://api.github.com") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/git/commits/" + commit
		g.nCommit.Add(1)
		body, status, err := g.get(ctx, u, true, 1<<20)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("commit %s of %s: HTTP %d", commit, repo.Key, status)
		}
		var doc struct {
			SHA  string `json:"sha"`
			Tree struct {
				SHA string `json:"sha"`
			} `json:"tree"`
		}
		if err := json.Unmarshal(body, &doc); err != nil || doc.SHA != commit || !extract.IsCommitSHA(doc.Tree.SHA) {
			return fmt.Errorf("commit %s of %s: unexpected response", commit, repo.Key)
		}
		g.mu.Lock()
		g.roots[key] = doc.Tree.SHA
		g.mu.Unlock()
		return nil
	})
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	id = g.roots[key]
	g.mu.Unlock()
	return id, nil
}

// tree returns the entries (names only) of one tree object. With recursive
// set it asks GitHub for the whole subtree in one call and caches the
// listing of every directory below it by tree id, so later lookups of any
// of them (in this commit or any other commit sharing the tree) cost
// nothing. A truncated recursive listing is not used: that tree alone is
// then read one directory at a time.
func (g *GitHubSource) tree(ctx context.Context, repo extract.RepoRef, id string, recursive bool) ([]extract.TreeEntry, error) {
	g.init()
	key := repo.Key + "\x00" + id
	lookup := func() ([]extract.TreeEntry, bool) {
		g.mu.Lock()
		defer g.mu.Unlock()
		e, ok := g.trees[key]
		return e, ok
	}
	if cached, ok := lookup(); ok {
		return cached, nil
	}
	if entries, ok := g.diskLoadTree(id); ok {
		g.mu.Lock()
		g.trees[key] = entries
		g.mu.Unlock()
		g.nDiskTree.Add(1)
		return entries, nil
	}
	g.mu.Lock()
	skip := g.noRecurse[key]
	g.mu.Unlock()
	if recursive && !skip {
		err := g.once("r\x00"+key, func() bool { _, ok := g.trees[key]; return ok }, func() error {
			return g.fetchTree(ctx, repo, id, true)
		})
		if err == nil {
			if cached, ok := lookup(); ok {
				return cached, nil
			}
		} else if !errors.Is(err, errTruncated) {
			return nil, err
		}
	}
	if err := g.once("t\x00"+key, func() bool { _, ok := g.trees[key]; return ok }, func() error {
		return g.fetchTree(ctx, repo, id, false)
	}); err != nil {
		return nil, err
	}
	cached, _ := lookup()
	return cached, nil
}

var errTruncated = errors.New("listing truncated")

// gitOrder sorts tree entries the way git does: by name, a directory as if
// its name ended in "/".
func gitOrder(entries []extract.TreeEntry) {
	k := func(e extract.TreeEntry) string {
		if e.Type == "tree" {
			return e.Path + "/"
		}
		return e.Path
	}
	sort.SliceStable(entries, func(i, j int) bool { return k(entries[i]) < k(entries[j]) })
}

func (g *GitHubSource) fetchTree(ctx context.Context, repo extract.RepoRef, id string, recursive bool) error {
	key := repo.Key + "\x00" + id
	owner, name := repo.OwnerName()
	u := orDefault(g.APIBase, "https://api.github.com") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/git/trees/" + id
	g.nTree.Add(1)
	if recursive {
		u += "?recursive=1"
		g.nRecursive.Add(1)
	}
	body, status, err := g.get(ctx, u, true, maxTreeBytes)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("tree %s of %s: HTTP %d", id, repo.Key, status)
	}
	var doc struct {
		SHA       string `json:"sha"`
		Truncated bool   `json:"truncated"`
		Tree      []struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.SHA != id {
		return fmt.Errorf("tree %s of %s: unexpected response", id, repo.Key)
	}
	if doc.Truncated {
		if recursive {
			g.nTruncated.Add(1)
			g.mu.Lock()
			g.noRecurse[key] = true
			g.mu.Unlock()
			return errTruncated
		}
		return fmt.Errorf("tree %s of %s: listing truncated", id, repo.Key)
	}
	// dirs maps a directory path below this tree ("" is the tree itself) to
	// its tree id and its entries.
	dirIDs := map[string]string{"": id}
	children := map[string][]extract.TreeEntry{"": {}}
	for _, e := range doc.Tree {
		dir, base := "", e.Path
		if i := strings.LastIndex(e.Path, "/"); i >= 0 {
			if !recursive {
				return fmt.Errorf("tree %s of %s: invalid entry %q", id, repo.Key, e.Path)
			}
			dir, base = e.Path[:i], e.Path[i+1:]
		}
		if base == "" || !extract.IsCommitSHA(e.SHA) {
			return fmt.Errorf("tree %s of %s: invalid entry %q", id, repo.Key, e.Path)
		}
		if _, ok := dirIDs[dir]; !ok && dir != "" {
			return fmt.Errorf("tree %s of %s: entry %q before its directory", id, repo.Key, e.Path)
		}
		children[dir] = append(children[dir], extract.TreeEntry{Mode: e.Mode, Type: e.Type, SHA: e.SHA, Path: base})
		if recursive && e.Type == "tree" {
			dirIDs[e.Path] = e.SHA
			if _, ok := children[e.Path]; !ok {
				children[e.Path] = []extract.TreeEntry{}
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for dir, did := range dirIDs {
		list := children[dir]
		if recursive {
			gitOrder(list)
		}
		g.trees[repo.Key+"\x00"+did] = list
		g.diskStoreTree(did, list)
	}
	return nil
}

// dirTree walks from the commit's root tree to dir and returns its tree id.
func (g *GitHubSource) dirTree(ctx context.Context, repo extract.RepoRef, commit, dir string) (string, error) {
	id, err := g.rootTree(ctx, repo, commit)
	if err != nil {
		return "", err
	}
	if dir == "" {
		return id, nil
	}
	if strings.HasPrefix(dir, "/") || path.Clean(dir) != dir || strings.HasPrefix(dir, "..") {
		return "", fmt.Errorf("invalid path %q", dir)
	}
	for _, part := range strings.Split(dir, "/") {
		entries, err := g.tree(ctx, repo, id, false)
		if err != nil {
			return "", err
		}
		found := false
		for _, e := range entries {
			if e.Path == part {
				if e.Type != "tree" {
					return "", fmt.Errorf("%s is not a directory", dir)
				}
				id, found = e.SHA, true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("%w: %s", extract.ErrNotFound, dir)
		}
	}
	return id, nil
}

// List implements extract.PinnedReader. A listing of a directory fetches
// that directory's whole subtree in one call (the repository root is read
// one level only: for a large repository its subtree is always truncated).
func (g *GitHubSource) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	return g.list(context.Background(), repo, commit, dir, dir != "")
}

func (g *GitHubSource) list(ctx context.Context, repo extract.RepoRef, commit, dir string, recursive bool) ([]extract.TreeEntry, error) {
	id, err := g.dirTree(ctx, repo, commit, dir)
	if err != nil {
		return nil, err
	}
	entries, err := g.tree(ctx, repo, id, recursive)
	if err != nil {
		return nil, err
	}
	out := make([]extract.TreeEntry, len(entries))
	for i, e := range entries {
		e.Path = path.Join(dir, e.Path)
		out[i] = e
	}
	return out, nil
}

// Read implements extract.PinnedReader. The path must be a regular file in
// the commit's tree, and the fetched bytes must hash to its blob id. Small
// verified files are kept for the run, so a blob shared by several commits
// is fetched once.
func (g *GitHubSource) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.HasPrefix(p, "..") {
		return nil, fmt.Errorf("invalid path %q", p)
	}
	ctx := context.Background()
	dir, base := path.Dir(p), path.Base(p)
	if dir == "." {
		dir = ""
	}
	// The parent is read one level only unless a recursive listing above
	// it is already cached: a lone file must not pull in a whole subtree.
	entries, err := g.list(ctx, repo, commit, dir, false)
	if err != nil {
		return nil, err
	}
	var blob string
	for _, e := range entries {
		if path.Base(e.Path) == base {
			if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
				return nil, fmt.Errorf("%s is not a regular file", p)
			}
			blob = e.SHA
		}
	}
	if blob == "" {
		return nil, fmt.Errorf("%w: %s", extract.ErrNotFound, p)
	}
	bkey := repo.Key + "\x00" + blob
	g.mu.Lock()
	cached, hit := g.blobs[bkey]
	g.mu.Unlock()
	if !hit {
		if b, ok := g.diskLoadBlob(blob); ok {
			g.mu.Lock()
			g.blobs[bkey] = b
			g.mu.Unlock()
			g.nDiskBlob.Add(1)
			cached, hit = b, true
		}
	}
	if hit {
		g.nRawHit.Add(1)
		return append([]byte(nil), cached...), nil
	}
	var body []byte
	err = g.once("b\x00"+bkey, func() bool { cached, hit = g.blobs[bkey]; return hit }, func() error {
		owner, name := repo.OwnerName()
		u := orDefault(g.RawBase, "https://raw.githubusercontent.com") + "/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/" + commit + "/" + escapePath(p)
		g.nRaw.Add(1)
		b, status, err := g.get(ctx, u, false, maxRawFileBytes)
		if err != nil {
			return err
		}
		g.nRawBytes.Add(int64(len(b)))
		if status != http.StatusOK {
			return fmt.Errorf("%s@%s:%s: HTTP %d", repo.Key, commit, p, status)
		}
		if got := gitBlobID(b); got != blob {
			return fmt.Errorf("%s@%s:%s: fetched bytes hash to blob %s, the commit records %s", repo.Key, commit, p, got, blob)
		}
		body = b
		if len(b) <= maxCachedBlobBytes {
			g.mu.Lock()
			g.blobs[bkey] = b
			g.mu.Unlock()
			g.diskStoreBlob(blob, b)
			body = append([]byte(nil), b...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if body == nil { // another caller fetched it
		g.mu.Lock()
		cached, hit = g.blobs[bkey]
		g.mu.Unlock()
		if hit {
			g.nRawHit.Add(1)
			return append([]byte(nil), cached...), nil
		}
		return g.Read(repo, commit, p)
	}
	return body, nil
}

func gitBlobID(data []byte) string {
	h := sha1.New() //nolint:gosec // git object ids are SHA-1 by definition
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Tags implements extract.TagSource from "git ls-remote --tags": an
// annotated tag resolves to the commit it peels to.
func (g *GitHubSource) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	lsRemote := g.LsRemote
	if lsRemote == nil {
		lsRemote = gitLsRemote
	}
	raw, err := lsRemote(context.Background(), "https://"+repo.Key)
	if err != nil {
		return nil, fmt.Errorf("list tags of %s: %w", repo.Key, err)
	}
	return parseLsRemoteTags(raw)
}

func gitLsRemote(ctx context.Context, repoURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--tags", "--", repoURL)
	cmd.Env = append(cmd.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git ls-remote: %v: %s", err, strings.TrimSpace(errOut.String()))
	}
	if out.Len() > maxTagListBytes {
		return nil, errors.New("git ls-remote: output too large")
	}
	return out.Bytes(), nil
}

// parseLsRemoteTags reads "git ls-remote --tags" output. A peeled line
// ("refs/tags/X^{}") overrides the tag object id with the commit.
func parseLsRemoteTags(raw []byte) ([]extract.Tag, error) {
	direct, peeled := map[string]string{}, map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		sha, ref, ok := strings.Cut(line, "\t")
		if !ok || !extract.IsCommitSHA(sha) || !strings.HasPrefix(ref, "refs/tags/") {
			return nil, fmt.Errorf("unexpected ls-remote line %q", line)
		}
		name := strings.TrimPrefix(ref, "refs/tags/")
		if strings.HasSuffix(name, "^{}") {
			peeled[strings.TrimSuffix(name, "^{}")] = sha
		} else {
			direct[name] = sha
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := make([]extract.Tag, 0, len(direct))
	for name, sha := range direct {
		if p, ok := peeled[name]; ok {
			sha = p
		}
		out = append(out, extract.Tag{Name: name, Commit: sha})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
