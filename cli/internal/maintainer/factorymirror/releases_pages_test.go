// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// bigReleasesServer serves a repository whose release notes make a page of
// 100 releases larger than maxReleasePageBytes (as for dapr, nats-server and
// containerd) and a page of ReleasesPerPage releases small. shift, when set,
// inserts a new release at the top after the first page was served, so the
// listing moves between two page requests.
type bigReleasesServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	total    int
	notes    string
	perPages []int
	maxBody  int
	inm      []string
	shift    bool
	served1  bool
}

func newBigReleasesServer(t *testing.T, total int) *bigReleasesServer {
	t.Helper()
	b := &bigReleasesServer{total: total, notes: strings.Repeat("release note line\n", 6000)} // ~108 KB
	b.srv = httptest.NewServer(http.HandlerFunc(b.serve))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *bigReleasesServer) release(i int) map[string]any {
	return map[string]any{"id": 100000 - i, "tag_name": "v1." + strconv.Itoa(1000-i) + ".0", "body": b.notes}
}

func (b *bigReleasesServer) serve(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if per < 1 || per > 100 {
		per = 30
	}
	if page < 1 {
		page = 1
	}
	b.perPages = append(b.perPages, per)
	b.inm = append(b.inm, r.Header.Get("If-None-Match"))
	offset := 0
	if b.shift && b.served1 && page > 1 {
		offset = 1 // one release was published after page 1 was read
	}
	var out []map[string]any
	for i := (page-1)*per - offset; i < page*per-offset && i < b.total; i++ {
		if i >= 0 {
			out = append(out, b.release(i))
		}
	}
	if out == nil {
		out = []map[string]any{}
	}
	body, _ := json.Marshal(out)
	if len(body) > b.maxBody {
		b.maxBody = len(body)
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:6]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	if page*per < b.total {
		w.Header().Set("Link", `<`+b.srv.URL+`/repos/acme/widget/releases?per_page=`+strconv.Itoa(per)+`&page=`+strconv.Itoa(page+1)+`>; rel="next"`)
	}
	b.served1 = true
	_, _ = w.Write(body)
}

// A repository whose pages would exceed the response bound at 100 per page
// is read completely at ReleasesPerPage, with every page inside the bound.
func TestGitHubReleasesLargePagesStayInsideTheBound(t *testing.T) {
	big := newBigReleasesServer(t, 100)
	// The old page size would have been rejected: prove the fixture is
	// large enough to have mattered.
	if probe := (len(big.notes) + 100) * 100; probe <= maxReleasePageBytes {
		t.Fatalf("fixture too small to model a large page: %d bytes", probe)
	}
	c := GitHubReleases{Tokens: StaticToken("t"), BaseURL: big.srv.URL}
	res, err := c.List(context.Background(), mustRepo(t, "acme/widget"), "")
	if err != nil || res.Truncated || len(res.Items) != 100 {
		t.Fatalf("items=%d truncated=%v err=%v", len(res.Items), res.Truncated, err)
	}
	for _, p := range big.perPages {
		if p != ReleasesPerPage {
			t.Fatalf("requested per_page=%d, want %d", p, ReleasesPerPage)
		}
	}
	if big.maxBody >= maxReleasePageBytes {
		t.Fatalf("largest page %d bytes is not below the bound", big.maxBody)
	}
	if len(big.perPages) != 100/ReleasesPerPage {
		t.Fatalf("expected %d page requests, got %d", 100/ReleasesPerPage, len(big.perPages))
	}
	// Pagination is deterministic: the same listing twice is the same
	// listing, in the same order, with the same validator.
	again, err := c.List(context.Background(), mustRepo(t, "acme/widget"), "")
	if err != nil || again.ETag != res.ETag || len(again.Items) != len(res.Items) {
		t.Fatalf("second listing differs: %v", err)
	}
	for i := range res.Items {
		if res.Items[i] != again.Items[i] {
			t.Fatalf("item %d differs", i)
		}
	}
}

// The per-page bound is still enforced: a page over 8 MiB is an error.
func TestGitHubReleasesPageOverTheBoundIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"tag_name":"v1","body":"` + strings.Repeat("x", maxReleasePageBytes) + `"}]`))
	}))
	defer srv.Close()
	c := GitHubReleases{Tokens: StaticToken("t"), BaseURL: srv.URL}
	if _, err := c.List(context.Background(), mustRepo(t, "acme/widget"), ""); err == nil {
		t.Fatal("an oversized page must fail")
	}
}

// Unchanged pages cost one conditional request each and no body.
func TestGitHubReleasesRevalidatesLargeListing(t *testing.T) {
	big := newBigReleasesServer(t, 60)
	c := GitHubReleases{Tokens: StaticToken("t"), BaseURL: big.srv.URL}
	repo := mustRepo(t, "acme/widget")
	res, err := c.List(context.Background(), repo, "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.List(context.Background(), repo, res.ETag)
	if err != nil || !again.NotModified || again.ETag != res.ETag {
		t.Fatalf("%+v %v", again, err)
	}
}

// Validators written for another page size are never replayed: their pages
// do not line up with the current ones.
func TestGitHubReleasesIgnoresValidatorsOfAnotherPageSize(t *testing.T) {
	big := newBigReleasesServer(t, 40)
	c := GitHubReleases{Tokens: StaticToken("t"), BaseURL: big.srv.URL}
	res, err := c.List(context.Background(), mustRepo(t, "acme/widget"), `"aaa"`+"\n"+`"bbb"`)
	if err != nil || res.NotModified || len(res.Items) != 40 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, v := range big.inm {
		if v != "" {
			t.Fatalf("a foreign validator was replayed: %q", v)
		}
	}
	if !strings.HasPrefix(res.ETag, etagLayout+"\n") {
		t.Fatalf("ETag has no layout line: %q", res.ETag)
	}
}

// A release listed on two pages because the listing moved between the page
// requests is kept once.
func TestGitHubReleasesDeduplicatesAcrossShiftedPages(t *testing.T) {
	big := newBigReleasesServer(t, 45)
	big.shift = true
	c := GitHubReleases{Tokens: StaticToken("t"), BaseURL: big.srv.URL}
	res, err := c.List(context.Background(), mustRepo(t, "acme/widget"), "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, it := range res.Items {
		if seen[it.ID] {
			t.Fatalf("release %d listed twice", it.ID)
		}
		seen[it.ID] = true
	}
	if len(res.Items) != 45 {
		t.Fatalf("items = %d", len(res.Items))
	}
}

// A `null` page is a malformed answer, not an empty release list.
func TestGitHubReleasesNullPageIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("null")) }))
	defer srv.Close()
	c := GitHubReleases{Tokens: StaticToken("t"), BaseURL: srv.URL}
	if _, err := c.List(context.Background(), mustRepo(t, "acme/widget"), ""); err == nil {
		t.Fatal("null page must be an error")
	}
}
