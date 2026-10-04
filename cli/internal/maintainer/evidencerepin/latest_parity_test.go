// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// latestFixture is a recorded (reduced) release and tag listing of one
// repository, in the order the GitHub API lists it.
type latestFixture struct {
	Repo             string `json:"repo"`
	ExpectTag        string `json:"expectTag"`
	ExpectResolution string `json:"expectResolution"`
	Releases         []struct {
		ID         int64  `json:"id"`
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	} `json:"releases"`
	Tags []string `json:"tags"`
}

func loadLatestFixtures(t *testing.T) map[string]latestFixture {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "latest", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no latest-release fixtures: %v", err)
	}
	out := map[string]latestFixture{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f latestFixture
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[strings.TrimSuffix(filepath.Base(p), ".json")] = f
	}
	return out
}

func fixtureSHA(tag string) string {
	sum := sha1.Sum([]byte(tag))
	return hex.EncodeToString(sum[:])
}

// httpFixtureFetcher serves a fixture as api.github.com would, paged.
type httpFixtureFetcher struct {
	f     latestFixture
	calls []string
}

func (h *httpFixtureFetcher) Fetch(_ context.Context, path string) ([]byte, int, error) {
	h.calls = append(h.calls, path)
	p, rawQuery, _ := strings.Cut(path, "?")
	q, _ := url.ParseQuery(rawQuery)
	per, _ := strconv.Atoi(q.Get("per_page"))
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	window := func(n int) (int, int) {
		lo := (page - 1) * per
		if lo > n {
			lo = n
		}
		hi := lo + per
		if hi > n {
			hi = n
		}
		return lo, hi
	}
	switch {
	case strings.HasSuffix(p, "/releases"):
		lo, hi := window(len(h.f.Releases))
		raw, _ := json.Marshal(append([]struct {
			ID         int64  `json:"id"`
			TagName    string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}{}, h.f.Releases[lo:hi]...))
		return raw, 200, nil
	case strings.HasSuffix(p, "/tags"):
		lo, hi := window(len(h.f.Tags))
		out := []map[string]string{}
		for _, n := range h.f.Tags[lo:hi] {
			out = append(out, map[string]string{"name": n})
		}
		raw, _ := json.Marshal(out)
		return raw, 200, nil
	case strings.Contains(p, "/git/ref/tags/"):
		tag, _ := url.PathUnescape(p[strings.Index(p, "/git/ref/tags/")+len("/git/ref/tags/"):])
		raw, _ := json.Marshal(map[string]any{"object": map[string]string{"sha": fixtureSHA(tag), "type": "commit"}})
		return raw, 200, nil
	}
	return nil, 404, nil
}

// fixtureMirror is a MirrorSource holding a fixture the way the factory
// mirror stores it: releases ordered by id, newest first.
type fixtureMirror struct{ f latestFixture }

func (m fixtureMirror) Tags(_, _ string) (map[string]string, error) {
	out := map[string]string{}
	for _, r := range m.f.Releases {
		out[r.TagName] = fixtureSHA(r.TagName)
	}
	for _, tag := range m.f.Tags {
		out[tag] = fixtureSHA(tag)
	}
	return out, nil
}

func (m fixtureMirror) Releases(_, _ string) (MirrorReleases, error) {
	items := make([]MirrorRelease, 0, len(m.f.Releases))
	for _, r := range m.f.Releases {
		items = append(items, MirrorRelease{ID: r.ID, Tag: r.TagName, Draft: r.Draft, Prerelease: r.Prerelease})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ID > items[j].ID })
	return MirrorReleases{Items: items}, nil
}

func (fixtureMirror) Read(_, _, _, _ string) ([]byte, error) { return nil, ErrMirrorBlobNotLocal }
func (fixtureMirror) RepoStatus(_, _ string) (MirrorRepoStatus, error) {
	return MirrorRepoStatus{}, nil
}
func (fixtureMirror) Index() MirrorIndex { return MirrorIndex{} }

// The mirror and the HTTP repin pick the same latest release or tag for
// every recorded repository (istio, containerd: a backport published later
// than the newest line; golang/go: no releases, tags in no useful order),
// and that choice does not depend on the order the source lists them in.
func TestLatestReleaseParityMirrorAndHTTP(t *testing.T) {
	for name, fx := range loadLatestFixtures(t) {
		owner, repo, _ := strings.Cut(fx.Repo, "/")
		reversed := fx
		reversed.Releases = nil
		for i := len(fx.Releases) - 1; i >= 0; i-- {
			reversed.Releases = append(reversed.Releases, fx.Releases[i])
		}
		reversed.Tags = nil
		for i := len(fx.Tags) - 1; i >= 0; i-- {
			reversed.Tags = append(reversed.Tags, fx.Tags[i])
		}
		for variant, f := range map[string]latestFixture{"api order": fx, "reversed": reversed} {
			httpTag, httpCommit, httpRes, err := ResolveCurrentCommit(context.Background(), &httpFixtureFetcher{f: f}, owner, repo)
			if err != nil {
				t.Fatalf("%s/%s http: %v", name, variant, err)
			}
			mirrorFetcher := newMirrorAPIFetcher(fixtureMirror{f: f}, mirrorNotes{})
			mTag, mCommit, mRes, err := ResolveCurrentCommit(context.Background(), mirrorFetcher, owner, repo)
			if err != nil {
				t.Fatalf("%s/%s mirror: %v", name, variant, err)
			}
			if httpTag != mTag || httpCommit != mCommit || httpRes != mRes {
				t.Fatalf("%s/%s: http picks %s (%s, %q) but the mirror picks %s (%s, %q)", name, variant, httpTag, httpCommit, httpRes, mTag, mCommit, mRes)
			}
			if httpTag != fx.ExpectTag || httpRes != fx.ExpectResolution || httpCommit != fixtureSHA(fx.ExpectTag) {
				t.Fatalf("%s/%s: got %s (%q), want %s (%q)", name, variant, httpTag, httpRes, fx.ExpectTag, fx.ExpectResolution)
			}
		}
	}
}

// The HTTP repin reads release pages of releasePageSize, never the 100 that
// made real pages exceed the response bound.
func TestLatestReleaseHTTPUsesSmallPages(t *testing.T) {
	for name, fx := range loadLatestFixtures(t) {
		owner, repo, _ := strings.Cut(fx.Repo, "/")
		h := &httpFixtureFetcher{f: fx}
		if _, _, _, err := ResolveCurrentCommit(context.Background(), h, owner, repo); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range h.calls {
			if strings.Contains(c, "/releases?") && !strings.Contains(c, "per_page="+strconv.Itoa(releasePageSize)+"&") {
				t.Fatalf("%s: unexpected release page request %s", name, c)
			}
		}
	}
}

// A list longer than one page is read to its end.
func TestLatestReleaseReadsEveryPage(t *testing.T) {
	var fx latestFixture
	fx.Repo = "acme/long"
	for i := 1; i <= 3*releasePageSize+5; i++ {
		fx.Releases = append(fx.Releases, struct {
			ID         int64  `json:"id"`
			TagName    string `json:"tag_name"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}{int64(1000 - i), "v1." + strconv.Itoa(i) + ".0", false, false})
	}
	// The highest version is the oldest entry on the last page.
	fx.Releases[len(fx.Releases)-1].TagName = "v7.0.0"
	tag, _, _, err := ResolveCurrentCommit(context.Background(), &httpFixtureFetcher{f: fx}, "acme", "long")
	if err != nil || tag != "v7.0.0" {
		t.Fatalf("tag=%q err=%v", tag, err)
	}
	mTag, _, _, err := ResolveCurrentCommit(context.Background(), newMirrorAPIFetcher(fixtureMirror{f: fx}, mirrorNotes{}), "acme", "long")
	if err != nil || mTag != "v7.0.0" {
		t.Fatalf("mirror tag=%q err=%v", mTag, err)
	}
}
