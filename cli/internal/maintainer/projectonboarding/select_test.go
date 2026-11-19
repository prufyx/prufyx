// SPDX-License-Identifier: AGPL-3.0-only

package projectonboarding

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// listFetcher serves tags in the given GitHub list order, honouring per_page
// and page like the real endpoint.
func listFetcher(tags []string) Fetcher {
	return FetchFunc(func(_ context.Context, host, path string) ([]byte, int, error) {
		if host != "api.github.com" {
			return nil, 404, nil
		}
		if path == "/repos/acme/sample" {
			return []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample"}`), 200, nil
		}
		if strings.HasPrefix(path, "/repos/acme/sample/git/ref/tags/") {
			tag := strings.TrimPrefix(path, "/repos/acme/sample/git/ref/tags/")
			return []byte(`{"ref":"refs/tags/` + tag + `","object":{"type":"commit","sha":"` + testCommit + `"}}`), 200, nil
		}
		if !strings.HasPrefix(path, "/repos/acme/sample/releases?") {
			return nil, 404, nil
		}
		query, _ := url.ParseQuery(strings.TrimPrefix(path, "/repos/acme/sample/releases?"))
		perPage, _ := strconv.Atoi(query.Get("per_page"))
		page, _ := strconv.Atoi(query.Get("page"))
		if perPage < 1 || page < 1 {
			return nil, 404, nil
		}
		start := (page - 1) * perPage
		end := start + perPage
		if start > len(tags) {
			start = len(tags)
		}
		if end > len(tags) {
			end = len(tags)
		}
		items := []string{}
		for i := start; i < end; i++ {
			items = append(items, `{"id":`+strconv.Itoa(i+1000)+`,"tag_name":"`+tags[i]+`","published_at":"2026-09-12T10:00:00Z","body":"n","draft":false,"prerelease":false}`)
		}
		return []byte("[" + strings.Join(items, ",") + "]"), 200, nil
	})
}

// syncTags runs a full sync with the given list and release limit, verifies
// the retained snapshot offline and returns the selected tags in file order.
func syncTags(t *testing.T, tags []string, limit int64) ([]string, map[string]any, string, int) {
	t.Helper()
	doc := testRequest(t).document
	doc["discovery"].(map[string]any)["releaseLimit"] = limit
	raw, _ := sourcecorpus.Canonical(doc)
	requestPath := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(requestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "snapshots")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"sync", "--manifest", requestPath, "--output-parent", parent}, &stdout, &stderr, Options{Fetcher: listFetcher(tags), Now: func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }})
	if code != 0 {
		return nil, nil, stderr.String(), code
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatalf("snapshots: %d", len(entries))
	}
	snapshot, _, err := VerifySnapshot(filepath.Join(parent, entries[0].Name()))
	if err != nil {
		t.Fatalf("offline verify: %v", err)
	}
	selected := []string{}
	for _, release := range snapshot["releases"].([]any) {
		selected = append(selected, release.(map[string]any)["tag"].(string))
	}
	return selected, snapshot, "", 0
}

func TestWindowBackportsDoNotDisplaceNewestLine(t *testing.T) {
	selected, snapshot, stderr, code := syncTags(t, []string{"v1.8.5", "v1.8.4", "v1.9.1", "v1.8.3", "v1.9.0"}, 2)
	if code != 0 {
		t.Fatalf("code=%d %s", code, stderr)
	}
	if strings.Join(selected, ",") != "v1.9.0,v1.9.1" {
		t.Fatalf("selected=%v", selected)
	}
	if snapshot["license"] != nil {
		t.Fatalf("unexpected license %v", snapshot["license"])
	}
}

func TestWindowIncludesNewestOnSecondPage(t *testing.T) {
	tags := []string{}
	for i := 0; i < 100; i++ {
		tags = append(tags, "v1.0."+strconv.Itoa(i))
	}
	tags = append(tags, "v2.0.0", "v1.0.200")
	selected, snapshot, stderr, code := syncTags(t, tags, 2)
	if code != 0 {
		t.Fatalf("code=%d %s", code, stderr)
	}
	if strings.Join(selected, ",") != "v1.0.200,v2.0.0" {
		t.Fatalf("selected=%v", selected)
	}
	if snapshot["window"].(map[string]any)["candidateReleaseCount"] != int64(102) {
		t.Fatalf("window=%v", snapshot["window"])
	}
}

func TestWindowSkipsNonSemverTagsAndRecordsCount(t *testing.T) {
	selected, snapshot, stderr, code := syncTags(t, []string{"nightly", "release-1.2", "v1.1.0", "v1.0.0-rc.1", "v1.0.0"}, 3)
	if code != 0 {
		t.Fatalf("code=%d %s", code, stderr)
	}
	if strings.Join(selected, ",") != "v1.0.0,v1.0.0-rc.1,v1.1.0" {
		t.Fatalf("selected=%v", selected)
	}
	if snapshot["window"].(map[string]any)["nonSemverSkippedCount"] != int64(2) {
		t.Fatalf("window=%v", snapshot["window"])
	}
}

func TestWindowCapReachedWithoutEnoughVersionsFailsClearly(t *testing.T) {
	tags := []string{"v1.0.0"}
	for i := 0; i < 999; i++ {
		tags = append(tags, "nightly-"+strconv.Itoa(i))
	}
	_, _, stderr, code := syncTags(t, tags, 2)
	if code == 0 || !strings.Contains(stderr, "RELEASE_LIST_CAP_REACHED") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestWindowCapReachedWithEnoughVersionsIsMarkedTruncated(t *testing.T) {
	tags := []string{}
	for i := 0; i < 1000; i++ {
		tags = append(tags, "v1.0."+strconv.Itoa(i))
	}
	selected, snapshot, stderr, code := syncTags(t, tags, 2)
	if code != 0 {
		t.Fatalf("code=%d %s", code, stderr)
	}
	if strings.Join(selected, ",") != "v1.0.998,v1.0.999" || snapshot["window"].(map[string]any)["pageMayBeTruncated"] != true {
		t.Fatalf("selected=%v window=%v", selected, snapshot["window"])
	}
}

func TestParseVersionOrdering(t *testing.T) {
	order := []string{"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-alpha.beta", "v1.0.0-beta", "v1.0.0-beta.2", "v1.0.0-beta.11", "v1.0.0-rc.1", "v1.0.0", "v1.0.1", "v1.10.0", "v2.0.0"}
	for i := 1; i < len(order); i++ {
		a, okA := parseVersion(order[i-1], "")
		b, okB := parseVersion(order[i], "")
		if !okA || !okB || compareVersion(a, b) >= 0 || compareVersion(b, a) <= 0 {
			t.Fatalf("%s !< %s", order[i-1], order[i])
		}
	}
	for _, bad := range []string{"", "v1", "v1.2", "1.2.x", "v01.2.3", "v1.2.3-", "v1.2.3-01", "release-1.2.3", "v1.2.3.4", "v1234567890.0.0"} {
		if _, ok := parseVersion(bad, ""); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
	if v, ok := parseVersion("kueue-v1.2.3", "kueue-"); !ok || v.core != [3]uint64{1, 2, 3} {
		t.Fatalf("prefix parse %v %v", v, ok)
	}
}
