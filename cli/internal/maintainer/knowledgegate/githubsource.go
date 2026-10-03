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
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Limits on what the GitHub source accepts.
const (
	maxRawFileBytes = 64 << 20
	maxTreeBytes    = 32 << 20
	maxTagListBytes = 16 << 20
)

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

	mu    sync.Mutex
	roots map[string]string            // repo NUL commit -> root tree id
	trees map[string][]extract.TreeEntry // repo NUL tree id -> entries (names only)
}

func (g *GitHubSource) init() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.roots == nil {
		g.roots, g.trees = map[string]string{}, map[string][]extract.TreeEntry{}
	}
}

func (g *GitHubSource) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return strings.TrimSuffix(v, "/")
}

func (g *GitHubSource) get(ctx context.Context, u string, api bool, limit int64) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
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
	owner, name := repo.OwnerName()
	u := orDefault(g.APIBase, "https://api.github.com") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/git/commits/" + commit
	body, status, err := g.get(ctx, u, true, 1<<20)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("commit %s of %s: HTTP %d", commit, repo.Key, status)
	}
	var doc struct {
		SHA  string `json:"sha"`
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.SHA != commit || !extract.IsCommitSHA(doc.Tree.SHA) {
		return "", fmt.Errorf("commit %s of %s: unexpected response", commit, repo.Key)
	}
	g.mu.Lock()
	g.roots[key] = doc.Tree.SHA
	g.mu.Unlock()
	return doc.Tree.SHA, nil
}

// tree returns the entries (names only) of one tree object.
func (g *GitHubSource) tree(ctx context.Context, repo extract.RepoRef, id string) ([]extract.TreeEntry, error) {
	g.init()
	key := repo.Key + "\x00" + id
	g.mu.Lock()
	cached, ok := g.trees[key]
	g.mu.Unlock()
	if ok {
		return cached, nil
	}
	owner, name := repo.OwnerName()
	u := orDefault(g.APIBase, "https://api.github.com") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/git/trees/" + id
	body, status, err := g.get(ctx, u, true, maxTreeBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("tree %s of %s: HTTP %d", id, repo.Key, status)
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
		return nil, fmt.Errorf("tree %s of %s: unexpected response", id, repo.Key)
	}
	if doc.Truncated {
		return nil, fmt.Errorf("tree %s of %s: listing truncated", id, repo.Key)
	}
	entries := make([]extract.TreeEntry, 0, len(doc.Tree))
	for _, e := range doc.Tree {
		if e.Path == "" || strings.Contains(e.Path, "/") || !extract.IsCommitSHA(e.SHA) {
			return nil, fmt.Errorf("tree %s of %s: invalid entry %q", id, repo.Key, e.Path)
		}
		entries = append(entries, extract.TreeEntry{Mode: e.Mode, Type: e.Type, SHA: e.SHA, Path: e.Path})
	}
	g.mu.Lock()
	g.trees[key] = entries
	g.mu.Unlock()
	return entries, nil
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
		entries, err := g.tree(ctx, repo, id)
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

// List implements extract.PinnedReader.
func (g *GitHubSource) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	ctx := context.Background()
	id, err := g.dirTree(ctx, repo, commit, dir)
	if err != nil {
		return nil, err
	}
	entries, err := g.tree(ctx, repo, id)
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
// the commit's tree, and the fetched bytes must hash to its blob id.
func (g *GitHubSource) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.HasPrefix(p, "..") {
		return nil, fmt.Errorf("invalid path %q", p)
	}
	ctx := context.Background()
	dir, base := path.Dir(p), path.Base(p)
	if dir == "." {
		dir = ""
	}
	entries, err := g.List(repo, commit, dir)
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
	owner, name := repo.OwnerName()
	u := orDefault(g.RawBase, "https://raw.githubusercontent.com") + "/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/" + commit + "/" + escapePath(p)
	body, status, err := g.get(ctx, u, false, maxRawFileBytes)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s@%s:%s: HTTP %d", repo.Key, commit, p, status)
	}
	if got := gitBlobID(body); got != blob {
		return nil, fmt.Errorf("%s@%s:%s: fetched bytes hash to blob %s, the commit records %s", repo.Key, commit, p, got, blob)
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
