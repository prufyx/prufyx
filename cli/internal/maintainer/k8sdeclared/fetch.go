// SPDX-License-Identifier: AGPL-3.0-only

package k8sdeclared

import (
	"crypto/sha1" // #nosec G505 -- git blob object ids are SHA-1; used to check, not to authenticate
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	apiBase      = "https://api.github.com"
	maxBodyBytes = 4 << 20
)

// APIFetcher reads the public GitHub API: tag ref, tag object, contents at a
// commit. It stores no credential: GITHUB_TOKEN from the environment is used
// for the request when set, never written anywhere. CacheDir, when set, keeps
// raw response bodies so a later run (or a second host) reuses them; a cached
// body is digested exactly like a fresh one.
type APIFetcher struct {
	Client   *http.Client
	Token    string
	CacheDir string
}

func (a *APIFetcher) get(u string) ([]byte, int, error) {
	if !strings.HasPrefix(u, apiBase+"/repos/") {
		return nil, 0, fmt.Errorf("refusing non-API URL")
	}
	var cache string
	if a.CacheDir != "" {
		cache = filepath.Join(a.CacheDir, sha256Hex([]byte(u))+".json")
		if raw, err := os.ReadFile(cache); err == nil {
			return raw, 200, nil
		}
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "prufyx-maintainer-k8s-declared")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		return nil, 0, fmt.Errorf("response unreadable or too large")
	}
	if resp.StatusCode == http.StatusOK && cache != "" {
		if err := os.MkdirAll(a.CacheDir, 0o700); err != nil {
			return nil, 0, err
		}
		if err := os.WriteFile(cache, raw, 0o600); err != nil {
			return nil, 0, err
		}
	}
	return raw, resp.StatusCode, nil
}

type gitObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
}

// ResolveTag binds (repo, tag) to a commit: the exact tag ref, then, for an
// annotated tag, the tag object. Both response digests are returned.
func (a *APIFetcher) ResolveTag(repo, tag string) (Resolution, error) {
	if !repoRE.MatchString(repo) || !tagRE.MatchString(tag) {
		return Resolution{}, fmt.Errorf("invalid repo or tag")
	}
	raw, code, err := a.get(fmt.Sprintf("%s/repos/%s/git/ref/tags/%s", apiBase, repo, url.PathEscape(tag)))
	if err != nil || code != http.StatusOK {
		return Resolution{}, fmt.Errorf("tag ref not resolved (status %d): %v", code, err)
	}
	var ref struct {
		Ref    string    `json:"ref"`
		Object gitObject `json:"object"`
	}
	if err := json.Unmarshal(raw, &ref); err != nil || ref.Ref != "refs/tags/"+tag || !hex40RE.MatchString(ref.Object.SHA) {
		return Resolution{}, fmt.Errorf("tag ref response is not the exact tag")
	}
	res := Resolution{TagRefResponseSHA256: sha256Hex(raw)}
	switch ref.Object.Type {
	case "commit":
		res.Commit = ref.Object.SHA
	case "tag":
		raw2, code, err := a.get(fmt.Sprintf("%s/repos/%s/git/tags/%s", apiBase, repo, ref.Object.SHA))
		if err != nil || code != http.StatusOK {
			return Resolution{}, fmt.Errorf("tag object not resolved (status %d): %v", code, err)
		}
		var t struct {
			SHA    string    `json:"sha"`
			Tag    string    `json:"tag"`
			Object gitObject `json:"object"`
		}
		if err := json.Unmarshal(raw2, &t); err != nil || t.SHA != ref.Object.SHA || t.Tag != tag || t.Object.Type != "commit" || !hex40RE.MatchString(t.Object.SHA) {
			return Resolution{}, fmt.Errorf("tag object does not name a commit")
		}
		res.Commit, res.TagObjectSHA, res.TagObjectResponseSHA256 = t.Object.SHA, t.SHA, sha256Hex(raw2)
	default:
		return Resolution{}, fmt.Errorf("tag ref points at %q", ref.Object.Type)
	}
	return res, nil
}

// ReadFile reads one file at a commit and checks that its git blob id
// matches the bytes.
func (a *APIFetcher) ReadFile(repo, path, commit string) (File, error) {
	if !repoRE.MatchString(repo) || !pathRE.MatchString(path) || !hex40RE.MatchString(commit) {
		return File{}, fmt.Errorf("invalid repo, path or commit")
	}
	raw, code, err := a.get(fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", apiBase, repo, path, commit))
	if err != nil {
		return File{}, err
	}
	if code == http.StatusNotFound {
		return File{}, ErrNotFound
	}
	if code != http.StatusOK {
		return File{}, fmt.Errorf("contents not read (status %d)", code)
	}
	var c struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
		SHA      string `json:"sha"`
		Path     string `json:"path"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return File{}, errors.New("contents response malformed")
	}
	if c.Type != "file" || c.Encoding != "base64" || c.Path != path || !hex40RE.MatchString(c.SHA) {
		return File{}, fmt.Errorf("contents response is not the requested file")
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(c.Content, "\n", ""))
	if err != nil || len(data) != c.Size {
		return File{}, fmt.Errorf("contents body does not match its size")
	}
	h := sha1.New() // #nosec G401
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	if hex.EncodeToString(h.Sum(nil)) != c.SHA {
		return File{}, fmt.Errorf("contents body does not match its blob id")
	}
	return File{BlobSHA: c.SHA, Data: data, ContentsResponseSHA256: sha256Hex(raw)}, nil
}
