// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// In release-line mode every repository's release list is read once for
// both the latest release and the release lines.
func TestReleaseListIsFetchedOncePerRepositoryPerRun(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	f.blob("v1.25.3", "doc.md", "x")
	c := f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1)
	for _, mode := range []string{BaselineModeReleaseLine, BaselineModeLatest} {
		f.api.calls = nil
		w := f.run(t, mode, c)
		if mode == BaselineModeReleaseLine && w.Citations[0].Baseline != BaselineReleaseLine {
			t.Fatalf("expected a line baseline: %+v", w.Citations[0])
		}
		counts := map[string]int{}
		for _, call := range f.api.calls {
			if strings.Contains(call, "/releases?") {
				counts[call]++
			}
		}
		if len(counts) == 0 {
			t.Fatalf("%s: no release list request seen", mode)
		}
		for call, n := range counts {
			if n != 1 {
				t.Fatalf("%s: %s requested %d times, want exactly once", mode, call, n)
			}
		}
	}
}

// Several repositories each cost one list read, whatever the mode.
func TestReleaseListRequestsScaleWithRepositoriesNotCitations(t *testing.T) {
	f := newLineFixture(standardTags, nil, "v1.26.0")
	f.blob("v1.25.0", "doc.md", "x")
	f.blob("v1.25.0", "other.md", "y")
	cs := []Citation{
		f.citation("proj-v1-25-0-doc", "v1.25.0", "doc.md", "x", 1, 1),
		f.citation("proj-v1-25-0-other", "v1.25.0", "other.md", "y", 1, 1),
	}
	f.api.calls = nil
	f.run(t, BaselineModeReleaseLine, cs...)
	pages := 0
	for _, call := range f.api.calls {
		if strings.Contains(call, "/releases?") {
			pages++
		}
	}
	if pages != 2 { // one page of releases, one empty page ending the scan
		t.Fatalf("release list requests = %d, want 2: %v", pages, f.api.calls)
	}
}

func ambiguityFixture(releases string) *fakeAPIFetcher {
	return &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/example/website/releases?per_page=" + strconv.Itoa(releasePageSize) + "&page=1": {[]byte(releases), 200},
		"/repos/example/website/releases?per_page=" + strconv.Itoa(releasePageSize) + "&page=2": {[]byte(`[]`), 200},
		"/repos/example/website/tags?per_page=100&page=1":                                       {[]byte(`[{"name":"v9.9.9"}]`), 200},
	}}
}

func TestAmbiguousLatestIsPendingWithTheReasonAndSkipsTheTagsFallback(t *testing.T) {
	for name, releases := range map[string]string{
		"other prefix":   `[{"id":3,"tag_name":"helm-chart-5.0.0"},{"id":2,"tag_name":"v1.30.0"}]`,
		"calendar newer": `[{"id":3,"tag_name":"2025.1.0"},{"id":2,"tag_name":"v3.2.1"}]`,
	} {
		api := ambiguityFixture(releases)
		wl, err := BuildWorklist(context.Background(), noBaselineCitations(), nil, 0, newState(), api, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := wl.Citations[0]
		if got.Class != ClassPending || !strings.Contains(got.Detail, "PENDING_AMBIGUOUS_LATEST") || !strings.Contains(got.Detail, "human") {
			t.Fatalf("%s: %+v", name, got)
		}
		if wl.Repos[0].Status != repoPendingAmbiguous || wl.Repos[0].CurrentCommit != "" {
			t.Fatalf("%s: %+v", name, wl.Repos[0])
		}
		for _, call := range api.calls {
			if strings.Contains(call, "/tags") {
				t.Fatalf("%s: ambiguous releases must not fall back to tags: %v", name, api.calls)
			}
		}
	}
}

func TestTruncatedReleaseListIsRecordedOnTheRepository(t *testing.T) {
	f := newLineFixture([]string{"v1.26.0", "v1.25.0"}, nil, "v1.26.0")
	f.truncatedPages()
	f.blob("v1.25.0", "doc.md", "x")
	w := f.run(t, BaselineModeLatest, f.citation("s-v1-25-0", "v1.25.0", "doc.md", "x", 1, 1))
	if len(w.Repos) != 1 || !w.Repos[0].ReleaseListTruncated {
		t.Fatalf("truncation must be recorded: %+v", w.Repos)
	}
	g := newLineFixture([]string{"v1.26.0", "v1.25.0"}, nil, "v1.26.0")
	g.blob("v1.25.0", "doc.md", "x")
	w = g.run(t, BaselineModeLatest, g.citation("s-v1-25-0", "v1.25.0", "doc.md", "x", 1, 1))
	if w.Repos[0].ReleaseListTruncated {
		t.Fatalf("a complete list must not be marked: %+v", w.Repos[0])
	}
}

// A release listed on two pages because the list shifted between requests
// is read once.
func TestFetchAllReleasesDeduplicatesShiftedPages(t *testing.T) {
	api := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/o/r/releases?per_page=20&page=1": {[]byte(`[{"id":1,"tag_name":"v1.0.0"},{"id":2,"tag_name":"v1.1.0"}]`), 200},
		"/repos/o/r/releases?per_page=20&page=2": {[]byte(`[{"id":2,"tag_name":"v1.1.0"},{"id":3,"tag_name":"v1.2.0"}]`), 200},
		"/repos/o/r/releases?per_page=20&page=3": {[]byte(`[]`), 200},
	}}
	list, err := fetchAllReleases(context.Background(), api, "o", "r")
	if err != nil || len(list.entries) != 3 || !list.complete {
		t.Fatalf("%+v %v", list, err)
	}
}

// `null` as a page body is an error for releases and tags alike.
func TestNullPagesAreErrors(t *testing.T) {
	api := &fakeAPIFetcher{responses: map[string]struct {
		body   []byte
		status int
	}{
		"/repos/o/r/releases?per_page=20&page=1": {[]byte(`null`), 200},
		"/repos/o/r/tags?per_page=100&page=1":    {[]byte(`null`), 200},
	}}
	if _, err := fetchAllReleases(context.Background(), api, "o", "r"); err == nil {
		t.Fatal("null release page must be an error")
	}
	if _, _, err := latestTag(context.Background(), api, "o", "r"); err == nil {
		t.Fatal("null tags page must be an error")
	}
}

type endlessTags struct{ pages int }

func (e *endlessTags) Fetch(_ context.Context, path string) ([]byte, int, error) {
	e.pages++
	if !strings.Contains(path, "/tags?") {
		return nil, 404, nil
	}
	_, page, _ := strings.Cut(path, "&page=")
	n, _ := strconv.Atoi(page)
	return []byte(fmt.Sprintf(`[{"name":"v1.%d.0"}]`, n)), 200, nil
}

// A tags list that never ends is cut at maxTagPages and not trusted.
func TestTagsListIsBounded(t *testing.T) {
	api := &endlessTags{}
	_, _, err := latestTag(context.Background(), api, "o", "r")
	if err == nil || !errors.Is(err, errRejected) {
		t.Fatalf("err = %v", err)
	}
	if api.pages != maxTagPages {
		t.Fatalf("read %d tag pages, want the bound %d", api.pages, maxTagPages)
	}
}
