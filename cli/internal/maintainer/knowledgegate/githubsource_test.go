// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"crypto/sha1" //nolint:gosec // test tree ids only
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// fakeGitHub serves a fixture tree the way GitHub's git API and
// raw.githubusercontent.com serve a repository: commits, tree objects by id
// and raw files by commit and path. Tree ids are synthetic; blob ids are
// the real git ids of the bytes.
type fakeGitHub struct {
	fixture  extract.FixtureReader
	mu       sync.Mutex
	trees    map[string][2]string // tree id -> commit, dir
	tamper   map[string][]byte    // path -> bytes served instead
	truncate bool
	requests int
}

func newFakeGitHub(root string) *fakeGitHub {
	return &fakeGitHub{fixture: extract.FixtureReader{Root: root}, trees: map[string][2]string{}, tamper: map[string][]byte{}}
}

func fakeTreeID(commit, dir string) string {
	sum := sha1.Sum([]byte("tree\x00" + commit + "\x00" + dir)) //nolint:gosec // test ids only
	return hex.EncodeToString(sum[:])
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 6 && parts[0] == "repos" && parts[3] == "git" && parts[4] == "commits":
		repo, _ := extract.ParseRepo("github.com/" + parts[1] + "/" + parts[2])
		commit := parts[5]
		if _, err := f.fixture.List(repo, commit, ""); err != nil {
			http.NotFound(w, r)
			return
		}
		id := fakeTreeID(commit, "")
		f.mu.Lock()
		f.trees[id] = [2]string{commit, ""}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": commit, "tree": map[string]string{"sha": id}})
	case len(parts) == 6 && parts[0] == "repos" && parts[3] == "git" && parts[4] == "trees":
		repo, _ := extract.ParseRepo("github.com/" + parts[1] + "/" + parts[2])
		f.mu.Lock()
		loc, ok := f.trees[parts[5]]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		entries, err := f.fixture.List(repo, loc[0], loc[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var out []map[string]string
		for _, e := range entries {
			sha := e.SHA
			if e.Type == "tree" {
				sha = fakeTreeID(loc[0], e.Path)
				f.mu.Lock()
				f.trees[sha] = [2]string{loc[0], e.Path}
				f.mu.Unlock()
			}
			out = append(out, map[string]string{"path": path.Base(e.Path), "mode": e.Mode, "type": e.Type, "sha": sha})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sha": parts[5], "tree": out, "truncated": f.truncate})
	case len(parts) >= 5 && parts[0] == "raw":
		repo, _ := extract.ParseRepo("github.com/" + parts[1] + "/" + parts[2])
		p := strings.Join(parts[4:], "/")
		if b, ok := f.tamper[p]; ok {
			_, _ = w.Write(b)
			return
		}
		data, err := f.fixture.Read(repo, parts[3], p)
		if errors.Is(err, extract.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

// lsRemoteFrom renders a fixture's tags.json as "git ls-remote --tags"
// output, with every tag annotated (the peeled line names the commit).
func lsRemoteFrom(t *testing.T, root string) func(context.Context, string) ([]byte, error) {
	return func(_ context.Context, repoURL string) ([]byte, error) {
		raw, err := os.ReadFile(filepath.Join(root, strings.TrimPrefix(repoURL, "https://"), "tags.json"))
		if err != nil {
			return nil, err
		}
		var tags map[string]string
		if err := json.Unmarshal(raw, &tags); err != nil {
			return nil, err
		}
		names := make([]string, 0, len(tags))
		for n := range tags {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			obj := sha1.Sum([]byte("tag " + n)) //nolint:gosec // test ids only
			fmt.Fprintf(&b, "%s\trefs/tags/%s\n%s\trefs/tags/%s^{}\n", hex.EncodeToString(obj[:]), n, tags[n], n)
		}
		return []byte(b.String()), nil
	}
}

func githubSourceFor(t *testing.T, fake *fakeGitHub) *GitHubSource {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return &GitHubSource{APIBase: srv.URL, RawBase: srv.URL + "/raw", LsRemote: lsRemoteFrom(t, servedFixture)}
}

// The gate re-derives mechanical rules from bytes it fetches itself over
// the GitHub API and raw file endpoints, exactly as from a fixture tree.
func TestGateRederivesFromGitHub(t *testing.T) {
	base, head, _ := mechanicalTrees(t, nil)
	fake := newFakeGitHub(servedFixture)
	r := runGate(t, Options{Base: base, Head: head, Source: githubSourceFor(t, fake), Concurrency: 4})
	requirePass(t, r)
	if fake.requests == 0 {
		t.Fatal("no upstream request was made")
	}
}

// Bytes that do not hash to the blob id the commit's tree records are
// refused, so a re-derivation can never run on altered upstream bytes.
func TestGitHubSourceRefusesAlteredBytes(t *testing.T) {
	fake := newFakeGitHub(servedFixture)
	src := githubSourceFor(t, fake)
	repo, _ := extract.ParseRepo("github.com/kubernetes/kubernetes")
	tags, err := src.Tags(repo)
	if err != nil || len(tags) == 0 {
		t.Fatalf("tags: %v %v", tags, err)
	}
	commit := tags[0].Commit
	entries, err := src.List(repo, commit, "")
	if err != nil {
		t.Fatal(err)
	}
	var file string
	var walk func(dir string)
	walk = func(dir string) {
		es, err := src.List(repo, commit, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if file != "" {
				return
			}
			if e.Type == "blob" {
				file = e.Path
			} else {
				walk(e.Path)
			}
		}
	}
	_ = entries
	walk("")
	if file == "" {
		t.Fatal("no file in the fixture")
	}
	if _, err := src.Read(repo, commit, file); err != nil {
		t.Fatalf("read: %v", err)
	}
	fake.tamper[file] = []byte("altered\n")
	fresh := githubSourceFor(t, fake)
	if _, err := fresh.Read(repo, commit, file); err == nil || !strings.Contains(err.Error(), "hash to blob") {
		t.Fatalf("altered bytes accepted: %v", err)
	}
	if _, err := fresh.Read(repo, commit, "no/such/file.go"); !errors.Is(err, extract.ErrNotFound) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := fresh.Read(repo, "v1.0.0", file); err == nil {
		t.Fatal("a tag name was accepted as a commit")
	}
	fake.truncate = true
	if _, err := githubSourceFor(t, fake).List(repo, commit, ""); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated listing accepted: %v", err)
	}
}

func TestParseLsRemoteTags(t *testing.T) {
	a, c1, c2 := strings.Repeat("a", 40), strings.Repeat("1", 40), strings.Repeat("2", 40)
	raw := a + "\trefs/tags/v1.0.0\n" + c1 + "\trefs/tags/v1.0.0^{}\n" + c2 + "\trefs/tags/v1.1.0\n"
	tags, err := parseLsRemoteTags([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0] != (extract.Tag{Name: "v1.0.0", Commit: c1}) || tags[1] != (extract.Tag{Name: "v1.1.0", Commit: c2}) {
		t.Fatalf("tags %v", tags)
	}
	for _, bad := range []string{"xyz\trefs/tags/v1\n", a + "\trefs/heads/main\n", a + " refs/tags/v1\n"} {
		if _, err := parseLsRemoteTags([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
