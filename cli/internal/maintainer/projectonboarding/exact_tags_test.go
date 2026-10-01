// SPDX-License-Identifier: AGPL-3.0-only

package projectonboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

func exactFixture(t *testing.T) (exactTagRequest, Fetcher, *strings.Builder) {
	t.Helper()
	v := map[string]any{"schema": ExactTagRequestSchema, "authority": Authority, "project": map[string]any{"slug": "sample", "canonicalRepositoryURL": "https://github.com/acme/sample", "owner": "acme", "repository": "sample"}, "discovery": map[string]any{"mode": "EXPLICIT_GIT_TAGS", "exactTags": []any{"v1.0.0", "v2.0.0"}, "licenseAnchorTag": "v2.0.0", "changelogPaths": []any{"CHANGELOG.md"}, "licenseDisposition": "NOT_REVIEWED"}, "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}}
	raw, _ := sourcecorpus.Canonical(v)
	r, err := parseExactTagRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	seen := &strings.Builder{}
	f := FetchFunc(func(_ context.Context, host, path string) ([]byte, int, error) {
		seen.WriteString(host + path + "\n")
		switch path {
		case "/repos/acme/sample":
			return []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample"}`), 200, nil
		case "/repos/acme/sample/git/ref/tags/v1.0.0":
			return []byte(`{"ref":"refs/tags/v1.0.0","object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`), 200, nil
		case "/repos/acme/sample/git/ref/tags/v2.0.0":
			return []byte(`{"ref":"refs/tags/v2.0.0","object":{"type":"tag","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`), 200, nil
		case "/repos/acme/sample/git/ref/tags/v3.0.0":
			return []byte(`{"ref":"refs/tags/v3.0.0","object":{"type":"commit","sha":"dddddddddddddddddddddddddddddddddddddddd"}}`), 200, nil
		case "/repos/acme/sample/git/tags/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":
			return []byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tag":"v2.0.0","object":{"type":"commit","sha":"cccccccccccccccccccccccccccccccccccccccc"}}`), 200, nil
		}
		return nil, 404, nil
	})
	return r, f, seen
}

func TestExactTags_RequestIsClosedAndAnchorIsSelected(t *testing.T) {
	r, _, _ := exactFixture(t)
	if r.digest == "" || len(r.tags) != 2 || r.anchor != "v2.0.0" {
		t.Fatalf("valid request did not round trip: %#v", r)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown": func(m map[string]any) { m["unknown"] = true },
		"duplicate-tag": func(m map[string]any) {
			m["discovery"].(map[string]any)["exactTags"] = []any{"v1.0.0", "v1.0.0"}
		},
		"missing-anchor": func(m map[string]any) {
			m["discovery"].(map[string]any)["licenseAnchorTag"] = "v9.0.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := cloneExactMap(t, r.document)
			mutate(value)
			raw, err := sourcecorpus.Canonical(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = parseExactTagRequest(raw); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	duplicate := bytes.Replace([]byte(`{"schema":"prufyx.io/public-project-onboarding-request/v2","authority":"DECLARED_PUBLIC_PROJECT_EVIDENCE_NOT_RULE_OR_RUNTIME_PROOF","project":{},"discovery":{},"review":{}}`), []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1)
	if _, err := parseExactTagRequest(duplicate); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
}

func TestExactTags_SyncVerifyAndRenderWithoutReleases(t *testing.T) {
	r, fetch, seen := exactFixture(t)
	snapshot, receipt, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, func() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	delete(snapshot, "corpusRecords")
	receipt["sourceCorpusManifestDigest"] = nil
	if strings.Contains(seen.String(), "/releases") || strings.Contains(seen.String(), "/tags?") {
		t.Fatalf("tag discovery used: %s", seen.String())
	}
	raw, _ := sourcecorpus.Canonical(snapshot)
	digest := sourcecorpus.SHA(raw)
	name := "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	receipt["snapshotDigest"], receipt["outputName"] = digest, name
	rr, _ := sourcecorpus.Canonical(receipt)
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sourcecorpus.WriteProjectSnapshotTree(parent, name, objects, raw, nil, rr); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, name)
	if _, _, err := VerifySnapshot(path); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"verify", "--snapshot", path}, {"status", "--snapshot", path}, {"inspect", "--snapshot", path, "--tag", "v2.0.0"}, {"proposal", "--snapshot", path}} {
		var out, errout bytes.Buffer
		if code := Run(context.Background(), args, &out, &errout, Options{}); code != 0 {
			t.Fatalf("%v: %d %s", args, code, errout.String())
		}
		if strings.Contains(out.String(), "releaseID") || strings.Contains(out.String(), "publishedAt") || strings.Contains(out.String(), "releaseURL") {
			t.Fatalf("fabricated release field: %s", out.String())
		}
	}
	var out, errout bytes.Buffer
	if Run(context.Background(), []string{"inspect", "--snapshot", path, "--include-notes"}, &out, &errout, Options{}) == 0 {
		t.Fatal("notes accepted")
	}
}

func TestExactTags_ChangedSharedBindingRejects(t *testing.T) {
	r, fetch, _ := exactFixture(t)
	first, _, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	moved := FetchFunc(func(ctx context.Context, h, p string) ([]byte, int, error) {
		b, s, e := fetch.Fetch(ctx, h, p)
		if strings.HasSuffix(p, "/v1.0.0") {
			return []byte(`{"ref":"refs/tags/v1.0.0","object":{"type":"commit","sha":"dddddddddddddddddddddddddddddddddddddddd"}}`), 200, nil
		}
		return b, s, e
	})
	if _, _, _, err = syncExactTags(context.Background(), r, first, objects, moved, time.Now); err == nil {
		t.Fatal("moved shared tag accepted")
	}
}

func TestExactTags_ChangedSharedReferenceKindRejectsEvenWithSameCommit(t *testing.T) {
	r, fetch, _ := exactFixture(t)
	prior, _, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	moved := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if strings.HasSuffix(path, "/git/ref/tags/v1.0.0") {
			return []byte(`{"ref":"refs/tags/v1.0.0","object":{"type":"tag","sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}`), 200, nil
		}
		if strings.HasSuffix(path, "/git/tags/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") {
			return []byte(`{"sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","tag":"v1.0.0","object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`), 200, nil
		}
		return fetch.Fetch(ctx, host, path)
	})
	if _, _, _, err = syncExactTags(context.Background(), r, prior, objects, moved, time.Now); err == nil {
		t.Fatal("direct-to-annotated replacement with same commit accepted")
	}
}

func TestExactTags_CapturesSourceAndAnchorLicenseIntoCorpus(t *testing.T) {
	r, base, _ := exactFixture(t)
	fetched := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" {
			if strings.HasSuffix(path, "/CHANGELOG.md") {
				return []byte("# changes\n"), 200, nil
			}
			if strings.HasSuffix(path, "/LICENSE") {
				return []byte("MIT\n"), 200, nil
			}
			return nil, 404, nil
		}
		return base.Fetch(ctx, host, path)
	})
	s, receipt, objects, err := syncExactTags(context.Background(), r, nil, nil, fetched, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(s["sources"].([]any)) != 2 || s["license"] == nil || s["corpusAdapterState"] != "PRESENT" {
		t.Fatalf("missing capture: %#v", s)
	}
	records := s["corpusRecords"]
	corpus := map[string]any{"schema": sourcecorpus.Schema, "revision": onboardingRevision(request{repo: r.repo}), "authority": sourcecorpus.DeclaredAuthority, "records": records}
	corpusRaw, _ := sourcecorpus.Canonical(corpus)
	delete(s, "corpusRecords")
	raw, _ := sourcecorpus.Canonical(s)
	digest := sourcecorpus.SHA(raw)
	name := "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	receipt["snapshotDigest"], receipt["outputName"], receipt["sourceCorpusManifestDigest"] = digest, name, sourcecorpus.SHA(corpusRaw)
	rr, _ := sourcecorpus.Canonical(receipt)
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sourcecorpus.WriteProjectSnapshotTree(parent, name, objects, raw, corpusRaw, rr); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, name)
	if _, err := sourcecorpus.VerifyPath(filepath.Join(path, "SOURCE-CORPUS-MANIFEST.json"), filepath.Join(path, "objects")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifySnapshot(path); err != nil {
		t.Fatal(err)
	}
}

func TestExactTags_LineagePartitionsAddOmitAndReorder(t *testing.T) {
	r, fetch, _ := exactFixture(t)
	old, _, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		tags []string
		want []string
	}{{"same", []string{"v1.0.0", "v2.0.0"}, []string{"v1.0.0", "v2.0.0"}}, {"reorder", []string{"v2.0.0", "v1.0.0"}, []string{"v1.0.0", "v2.0.0"}}, {"omit", []string{"v1.0.0"}, []string{"v1.0.0"}}} {
		t.Run(tc.name, func(t *testing.T) {
			next := r
			next.tags = tc.tags
			next.anchor = tc.tags[0]
			s, _, _, e := syncExactTags(context.Background(), next, old, objects, fetch, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			l := s["lineage"].(map[string]any)
			if got := l["sharedTags"].([]any); len(got) != len(tc.want) {
				t.Fatalf("partition %#v", l)
			}
			if tc.name == "omit" && l["omittedState"] != "NOT_REOBSERVED_NOT_REVALIDATED" {
				t.Fatal(l)
			}
		})
	}
}

func TestExactTags_ClosedLineageRejectsMalformedCurrentOnlyClaims(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	base := map[string]any{"previousSnapshotDigest": digest, "sharedTags": []any{"v1"}, "newlySelectedTags": []any{"v2"}, "omittedPriorTags": []any{"v0"}, "sharedBindingState": "REOBSERVED_UNCHANGED", "omittedState": "NOT_REOBSERVED_NOT_REVALIDATED", "scope": "IMMEDIATE_PREVIOUS_SELECTION_SHARED_TAG_BINDINGS_ONLY"}
	obs := []any{map[string]any{"tag": "v1"}, map[string]any{"tag": "v2"}}
	if !validExactTagLineage(base, []string{"v1", "v2"}, obs) {
		t.Fatal("valid lineage rejected")
	}
	for name, mutate := range map[string]func(map[string]any){
		"duplicate":       func(m map[string]any) { m["sharedTags"] = []any{"v1", "v1"} },
		"unsorted":        func(m map[string]any) { m["sharedTags"] = []any{"v2", "v1"}; m["newlySelectedTags"] = []any{} },
		"overlap":         func(m map[string]any) { m["newlySelectedTags"] = []any{"v1", "v2"} },
		"missing":         func(m map[string]any) { m["newlySelectedTags"] = []any{} },
		"unknown":         func(m map[string]any) { m["extra"] = true },
		"bad-digest":      func(m map[string]any) { m["previousSnapshotDigest"] = "no" },
		"bad-state":       func(m map[string]any) { m["sharedBindingState"] = "CHANGED" },
		"omitted-current": func(m map[string]any) { m["omittedPriorTags"] = []any{"v1"} },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := sourcecorpus.Canonical(base)
			v, _ := sourcecorpus.DecodeBounded(raw, 4096)
			m := v.(map[string]any)
			mutate(m)
			if validExactTagLineage(m, []string{"v1", "v2"}, obs) {
				t.Fatal("malformed lineage accepted")
			}
		})
	}
	lineage := func(shared, newer, omitted []any) map[string]any {
		return map[string]any{"previousSnapshotDigest": digest, "sharedTags": shared, "newlySelectedTags": newer, "omittedPriorTags": omitted, "sharedBindingState": "REOBSERVED_UNCHANGED", "omittedState": "NOT_REOBSERVED_NOT_REVALIDATED", "scope": "IMMEDIATE_PREVIOUS_SELECTION_SHARED_TAG_BINDINGS_ONLY"}
	}
	for _, test := range []struct {
		name       string
		value      map[string]any
		tags       []string
		observed   []any
		wantAccept bool
	}{
		{"prior-zero", lineage([]any{}, []any{"v1"}, []any{}), []string{"v1"}, []any{map[string]any{"tag": "v1"}}, false},
		{"prior-one", lineage([]any{"v1"}, []any{}, []any{}), []string{"v1"}, []any{map[string]any{"tag": "v1"}}, true},
		{"prior-ten", lineage([]any{"z"}, []any{}, []any{"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"}), []string{"z"}, []any{map[string]any{"tag": "z"}}, true},
		{"prior-eleven", lineage([]any{"z"}, []any{}, []any{"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"}), []string{"z"}, []any{map[string]any{"tag": "z"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validExactTagLineage(test.value, test.tags, test.observed); got != test.wantAccept {
				t.Fatalf("accepted=%t, want %t", got, test.wantAccept)
			}
		})
	}
}

func TestExactTags_PreviousNumericRepositoryIdentityRejects(t *testing.T) {
	r, fetch, _ := exactFixture(t)
	prior, _, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prior["repository"].(map[string]any)["repositoryID"] = int64(99)
	if _, _, _, err = syncExactTags(context.Background(), r, prior, objects, fetch, time.Now); err == nil {
		t.Fatal("wrong prior repository identity accepted")
	}
}

func TestExactTags_AddAndOmitPartition(t *testing.T) {
	r, fetch, _ := exactFixture(t)
	prior, _, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	next := r
	next.tags = []string{"v2.0.0", "v3.0.0"}
	next.anchor = "v3.0.0"
	s, _, _, err := syncExactTags(context.Background(), next, prior, objects, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l := s["lineage"].(map[string]any)
	for field, want := range map[string][]any{"sharedTags": {"v2.0.0"}, "newlySelectedTags": {"v3.0.0"}, "omittedPriorTags": {"v1.0.0"}} {
		got := l[field].([]any)
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("%s=%#v", field, got)
		}
	}
}

type exactPublicFixture struct {
	repositoryID int64
	requests     []string
}

func (fixture *exactPublicFixture) fetch(_ context.Context, host, path string) ([]byte, int, error) {
	fixture.requests = append(fixture.requests, host+path)
	if host == "api.github.com" {
		switch path {
		case "/repos/acme/sample":
			return []byte(fmt.Sprintf(`{"id":%d,"full_name":"acme/sample","html_url":"https://github.com/acme/sample"}`, fixture.repositoryID)), 200, nil
		case "/repos/acme/sample/git/ref/tags/v1.0.0":
			return []byte(`{"ref":"refs/tags/v1.0.0","object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`), 200, nil
		case "/repos/acme/sample/git/ref/tags/v2.0.0":
			return []byte(`{"ref":"refs/tags/v2.0.0","object":{"type":"tag","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`), 200, nil
		case "/repos/acme/sample/git/tags/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":
			return []byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tag":"v2.0.0","object":{"type":"commit","sha":"cccccccccccccccccccccccccccccccccccccccc"}}`), 200, nil
		case "/repos/acme/sample/git/ref/tags/v3.0.0":
			return []byte(`{"ref":"refs/tags/v3.0.0","object":{"type":"commit","sha":"dddddddddddddddddddddddddddddddddddddddd"}}`), 200, nil
		}
	}
	if host == "raw.githubusercontent.com" {
		switch path {
		case "/acme/sample/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/CHANGELOG.md":
			return nil, 404, nil
		case "/acme/sample/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/CHANGES.md":
			return []byte("# v1\nfirst retained source\n"), 200, nil
		case "/acme/sample/cccccccccccccccccccccccccccccccccccccccc/CHANGELOG.md":
			return []byte("# v2\nsecond retained source\n"), 200, nil
		case "/acme/sample/dddddddddddddddddddddddddddddddddddddddd/CHANGELOG.md":
			return nil, 404, nil
		case "/acme/sample/dddddddddddddddddddddddddddddddddddddddd/CHANGES.md":
			return []byte("# v3\nthird retained source\n"), 200, nil
		case "/acme/sample/cccccccccccccccccccccccccccccccccccccccc/LICENSE",
			"/acme/sample/dddddddddddddddddddddddddddddddddddddddd/LICENSE":
			return []byte("MIT License\n"), 200, nil
		}
	}
	return nil, 404, nil
}

func runExactPublicSnapshot(t *testing.T, parent, requestName string, tags []string, anchor, previous string, fixture *exactPublicFixture) string {
	t.Helper()
	requestPath := filepath.Join(parent, requestName)
	args := []string{"init", "--repository", "https://github.com/acme/sample", "--output", requestPath, "--changelog-paths", "CHANGELOG.md,CHANGES.md", "--license-anchor-tag", anchor}
	for _, tag := range tags {
		args = append(args, "--exact-tag", tag)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), args, &out, &errOut, Options{}); code != 0 {
		t.Fatalf("init code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	args = []string{"sync", "--manifest", requestPath, "--output-parent", parent}
	if previous != "" {
		args = append(args, "--previous", previous)
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), args, &out, &errOut, Options{Fetcher: FetchFunc(fixture.fetch), Now: func() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }}); code != 0 {
		t.Fatalf("sync code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var receipt struct {
		OutputName string `json:"outputName"`
	}
	if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.OutputName == "" {
		t.Fatalf("invalid sync receipt %q", out.String())
	}
	return filepath.Join(parent, receipt.OutputName)
}

func TestExactTags_PublicRunPipelineAndTwoSnapshotReplay(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := &exactPublicFixture{repositoryID: 7}
	prior := runExactPublicSnapshot(t, parent, "request-one.json", []string{"v1.0.0", "v2.0.0"}, "v2.0.0", "", fixture)
	current := runExactPublicSnapshot(t, parent, "request-two.json", []string{"v2.0.0", "v3.0.0"}, "v3.0.0", prior, fixture)

	commands := []struct {
		name string
		args []string
		want []string
	}{
		{"verify-initial", []string{"verify", "--snapshot", prior}, []string{"NO_PREVIOUS_SNAPSHOT", "NOT_REVIEWED", "NOT_ADMITTED"}},
		{"verify-current", []string{"verify", "--snapshot", current}, []string{"CONTINUITY_NOT_REPLAYED_PREVIOUS_NOT_SUPPLIED", "NOT_REVIEWED", "NOT_ADMITTED"}},
		{"verify-replay", []string{"verify", "--snapshot", current, "--previous", prior}, []string{"CONTINUITY_REPLAYED_VERIFIED", "NOT_REVIEWED", "NOT_ADMITTED"}},
		{"status", []string{"status", "--snapshot", current}, []string{`"sourceCount":2`, "CONTINUITY_NOT_REPLAYED_PREVIOUS_NOT_SUPPLIED"}},
		{"inspect", []string{"inspect", "--snapshot", current, "--tag", "v3.0.0"}, []string{"/CHANGES.md", `"license"`, `"lineage"`}},
		{"proposal", []string{"proposal", "--snapshot", current}, []string{"INDEPENDENT_REVIEW_REQUIRED", "/CHANGES.md", `"license"`, "NOT_REVIEWED", "NOT_ADMITTED"}},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(context.Background(), command.args, &stdout, &stderr, Options{}); code != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			for _, want := range command.want {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("missing %q in %s", want, stdout.String())
				}
			}
			for _, forbidden := range []string{"releaseID", "releaseURL", "publishedAt", "first retained source", "second retained source", "third retained source", parent} {
				if strings.Contains(stdout.String(), forbidden) {
					t.Fatalf("unexpected %q in %s", forbidden, stdout.String())
				}
			}
		})
	}
	joined := strings.Join(fixture.requests, "\n")
	if strings.Contains(joined, "/releases") || strings.Contains(joined, "/tags?") {
		t.Fatalf("implicit discovery used: %s", joined)
	}
	if strings.Count(joined, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/CHANGELOG.md") != 1 || strings.Count(joined, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/CHANGES.md") != 1 || strings.Contains(joined, "/cccccccccccccccccccccccccccccccccccccccc/CHANGES.md") {
		t.Fatalf("first matching changelog path not preserved: %s", joined)
	}
	t.Run("wrong-prior-digest", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"verify", "--snapshot", current, "--previous", current}, &stdout, &stderr, Options{}); code == 0 {
			t.Fatal("wrong prior digest accepted")
		}
	})
	t.Run("wrong-numeric-repository", func(t *testing.T) {
		otherParent := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(otherParent, 0o700); err != nil {
			t.Fatal(err)
		}
		other := runExactPublicSnapshot(t, otherParent, "request.json", []string{"v1.0.0", "v2.0.0"}, "v2.0.0", "", &exactPublicFixture{repositoryID: 8})
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"verify", "--snapshot", current, "--previous", other}, &stdout, &stderr, Options{}); code == 0 {
			t.Fatal("different numeric repository identity accepted")
		}
	})
	t.Run("changed-non-selection", func(t *testing.T) {
		requestPath := filepath.Join(parent, "request-changed.json")
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", requestPath, "--changelog-paths", "CHANGELOG.md,CHANGES.md", "--license-disposition", "DECLARED_UNKNOWN", "--license-anchor-tag", "v3.0.0", "--exact-tag", "v2.0.0", "--exact-tag", "v3.0.0"}, &stdout, &stderr, Options{}); code != 0 {
			t.Fatalf("init changed request: %d %s", code, stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run(context.Background(), []string{"sync", "--manifest", requestPath, "--output-parent", parent, "--previous", prior}, &stdout, &stderr, Options{Fetcher: FetchFunc(fixture.fetch), Now: time.Now}); code == 0 {
			t.Fatal("changed non-selection declaration accepted")
		}
	})
	t.Run("changed-shared-tuple", func(t *testing.T) {
		moved := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			if path == "/repos/acme/sample/git/ref/tags/v2.0.0" {
				return []byte(`{"ref":"refs/tags/v2.0.0","object":{"type":"tag","sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}`), 200, nil
			}
			if path == "/repos/acme/sample/git/tags/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
				return []byte(`{"sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","tag":"v2.0.0","object":{"type":"commit","sha":"cccccccccccccccccccccccccccccccccccccccc"}}`), 200, nil
			}
			return fixture.fetch(ctx, host, path)
		})
		var stdout, stderr bytes.Buffer
		if code := Run(context.Background(), []string{"sync", "--manifest", filepath.Join(parent, "request-two.json"), "--output-parent", parent, "--previous", prior}, &stdout, &stderr, Options{Fetcher: moved, Now: time.Now}); code == 0 {
			t.Fatal("changed shared annotated identity accepted")
		}
	})
}

func materializeExactSnapshot(t *testing.T, snapshot, receipt map[string]any, objects map[string][]byte) string {
	t.Helper()
	var corpusRaw []byte
	if len(snapshot["sources"].([]any)) > 0 {
		corpus := map[string]any{"schema": sourcecorpus.Schema, "revision": onboardingRevision(request{repo: snapshot["repository"].(map[string]any)["canonicalRepositoryURL"].(string)}), "authority": sourcecorpus.DeclaredAuthority, "records": snapshot["corpusRecords"]}
		var err error
		corpusRaw, err = sourcecorpus.Canonical(corpus)
		if err != nil {
			t.Fatal(err)
		}
		receipt["sourceCorpusManifestDigest"] = sourcecorpus.SHA(corpusRaw)
	}
	delete(snapshot, "corpusRecords")
	snapshotRaw, err := sourcecorpus.Canonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sourcecorpus.SHA(snapshotRaw)
	name := "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	receipt["snapshotDigest"], receipt["outputName"] = digest, name
	receiptRaw, err := sourcecorpus.Canonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err = os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = sourcecorpus.WriteProjectSnapshotTree(parent, name, objects, snapshotRaw, corpusRaw, receiptRaw); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, name)
}

func cloneExactMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := sourcecorpus.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := sourcecorpus.DecodeBounded(raw, int64(len(raw)+1))
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func TestExactTags_VerifierRejectsCrossArtifactMismatch(t *testing.T) {
	r, base, _ := exactFixture(t)
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" {
			if strings.HasSuffix(path, "/CHANGELOG.md") {
				return []byte("# changes\n"), 200, nil
			}
			if strings.HasSuffix(path, "/LICENSE") {
				return []byte("MIT\n"), 200, nil
			}
			return nil, 404, nil
		}
		return base.Fetch(ctx, host, path)
	})
	baseSnapshot, baseReceipt, baseObjects, err := syncExactTags(context.Background(), r, nil, nil, fetch, func() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any, map[string][]byte)
	}{
		{"source-corpus-binding", func(s, _ map[string]any, _ map[string][]byte) {
			s["sources"].([]any)[0].(map[string]any)["byteLength"] = int64(999)
		}},
		{"malformed-source-element", func(s, _ map[string]any, _ map[string][]byte) { s["sources"].([]any)[0] = "not-an-object" }},
		{"second-source-for-same-commit", func(s, _ map[string]any, _ map[string][]byte) {
			first := s["sources"].([]any)[0].(map[string]any)
			second := s["sources"].([]any)[1].(map[string]any)
			second["commit"] = first["commit"]
			second["immutableURL"] = strings.Replace(second["immutableURL"].(string), "cccccccccccccccccccccccccccccccccccccccc", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1)
		}},
		{"license-anchor", func(s, _ map[string]any, _ map[string][]byte) {
			s["license"].(map[string]any)["commit"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
		{"observed-at", func(s, _ map[string]any, _ map[string][]byte) { s["observedAt"] = "not-a-time" }},
		{"review", func(s, _ map[string]any, _ map[string][]byte) { s["review"].(map[string]any)["state"] = "REVIEWED" }},
		{"limitations", func(s, _ map[string]any, _ map[string][]byte) { s["limitations"].([]any)[0] = "changed" }},
		{"receipt", func(_ map[string]any, receipt map[string]any, _ map[string][]byte) {
			receipt["repositoryID"] = int64(9)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := cloneExactMap(t, baseSnapshot)
			receipt := cloneExactMap(t, baseReceipt)
			objects := make(map[string][]byte, len(baseObjects))
			for key, value := range baseObjects {
				objects[key] = append([]byte(nil), value...)
			}
			test.mutate(snapshot, receipt, objects)
			path := materializeExactSnapshot(t, snapshot, receipt, objects)
			if _, _, err := VerifySnapshot(path); err == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
	t.Run("object-digest", func(t *testing.T) {
		snapshot := cloneExactMap(t, baseSnapshot)
		receipt := cloneExactMap(t, baseReceipt)
		objects := make(map[string][]byte, len(baseObjects))
		for key, value := range baseObjects {
			objects[key] = append([]byte(nil), value...)
		}
		path := materializeExactSnapshot(t, snapshot, receipt, objects)
		name := stringOf(snapshot["repository"].(map[string]any)["repositoryObject"])
		if err := os.WriteFile(filepath.Join(path, "objects", name), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifySnapshot(path); err == nil {
			t.Fatal("wrong object bytes accepted")
		}
	})
}

func TestExactTags_ReceiptFieldsAreExact(t *testing.T) {
	r, base, _ := exactFixture(t)
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" {
			if strings.HasSuffix(path, "/CHANGELOG.md") {
				return []byte("# changes\n"), 200, nil
			}
			if strings.HasSuffix(path, "/LICENSE") {
				return []byte("MIT\n"), 200, nil
			}
			return nil, 404, nil
		}
		return base.Fetch(ctx, host, path)
	})
	baseSnapshot, baseReceipt, baseObjects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema", "result", "authority", "requestDigest", "repositoryID", "tagCount", "sourceCount", "corpusAdapterState", "sourceCorpusManifestDigest", "reviewState", "admissionState", "lineage", "limitations", "snapshotDigest", "outputName"} {
		t.Run(field, func(t *testing.T) {
			path := materializeExactSnapshot(t, cloneExactMap(t, baseSnapshot), cloneExactMap(t, baseReceipt), baseObjects)
			receiptPath := filepath.Join(path, "SYNC-RECEIPT.json")
			raw, err := os.ReadFile(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := sourcecorpus.DecodeBounded(bytes.TrimSpace(raw), maxRequest)
			if err != nil {
				t.Fatal(err)
			}
			receipt := decoded.(map[string]any)
			receipt[field] = false
			raw, err = sourcecorpus.Canonical(receipt)
			if err != nil || os.WriteFile(receiptPath, append(raw, '\n'), 0o600) != nil {
				t.Fatal("could not write benign receipt mutation")
			}
			if _, _, err := VerifySnapshot(path); err == nil {
				t.Fatal("altered receipt field accepted")
			}
		})
	}
}

func TestExactTags_VerifierObjectBounds(t *testing.T) {
	r, base, _ := exactFixture(t)
	snapshot, receipt, objects, err := syncExactTags(context.Background(), r, nil, nil, base, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("api-one-mib", func(t *testing.T) {
		s := cloneExactMap(t, snapshot)
		rc := cloneExactMap(t, receipt)
		copied := cloneObjects(objects)
		body := []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample","padding":"` + strings.Repeat("x", maxAPI) + `"}`)
		digest := sourcecorpus.SHA(body)
		copied[digest] = body
		s["repository"].(map[string]any)["repositoryObject"] = "sha256/" + strings.TrimPrefix(digest, "sha256:")
		if _, _, err := VerifySnapshot(materializeExactSnapshot(t, s, rc, copied)); err == nil {
			t.Fatal("API object over 1 MiB accepted")
		}
	})
	t.Run("raw-four-mib", func(t *testing.T) {
		withSources, withReceipt, withObjects, err := syncExactTags(context.Background(), r, nil, nil, FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			if host == "raw.githubusercontent.com" && strings.HasSuffix(path, "/CHANGELOG.md") {
				return []byte("source\n"), 200, nil
			}
			return base.Fetch(ctx, host, path)
		}), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		path := materializeExactSnapshot(t, withSources, withReceipt, withObjects)
		object := stringOf(withSources["sources"].([]any)[0].(map[string]any)["object"])
		if err := os.WriteFile(filepath.Join(path, "objects", object), bytes.Repeat([]byte("x"), maxObject+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifySnapshot(path); err == nil {
			t.Fatal("raw object over 4 MiB accepted")
		}
	})
	t.Run("aggregate-thirty-two-mib", func(t *testing.T) {
		request := r
		request.tags = make([]string, 10)
		for i := range request.tags {
			request.tags[i] = "v" + strconv.Itoa(i+1)
		}
		request.anchor = request.tags[9]
		generated := generatedExactFetcher(10, 810<<10, maxObject)
		fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			if host == "raw.githubusercontent.com" && strings.HasSuffix(path, "/CHANGELOG.md") {
				for i := 5; i <= 10; i++ {
					if strings.Contains(path, "/"+fmt.Sprintf("%040x", i+100)+"/") {
						return nil, 404, nil
					}
				}
			}
			return generated.Fetch(ctx, host, path)
		})
		s, rc, retained, err := syncExactTags(context.Background(), request, nil, nil, fetch, time.Now)
		if err != nil {
			t.Fatalf("below-limit fixture: %v", err)
		}
		observation := s["tagObservations"].([]any)[0].(map[string]any)
		outer := stringOf(observation["refTargetSHA"])
		body := []byte(fmt.Sprintf(`{"ref":"refs/tags/v1","object":{"type":"tag","sha":"%s"},"padding":"%s"}`, outer, strings.Repeat("z", 1015<<10)))
		if len(body) > maxAPI {
			t.Fatalf("replacement API fixture exceeds per-object cap: %d", len(body))
		}
		digest := sourcecorpus.SHA(body)
		retained[digest] = body
		observation["tagReferenceObject"] = "sha256/" + strings.TrimPrefix(digest, "sha256:")
		if _, _, err := VerifySnapshot(materializeExactSnapshot(t, s, rc, retained)); err == nil {
			t.Fatal("verified object aggregate over 32 MiB accepted")
		}
	})
}

func cloneObjects(objects map[string][]byte) map[string][]byte {
	copy := make(map[string][]byte, len(objects))
	for digest, value := range objects {
		copy[digest] = append([]byte(nil), value...)
	}
	return copy
}

func TestExactTags_V1VerifyRejectsPreviousAndExactSelectorsRejectPresence(t *testing.T) {
	var helpOut, helpErr bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, &helpOut, &helpErr, Options{}); code != 0 || !strings.Contains(helpOut.String(), "--exact-tag TAG") || !strings.Contains(helpOut.String(), "--previous PRIOR_EXACT_TAG_SNAPSHOT") || helpErr.Len() != 0 {
		t.Fatalf("incomplete exact-tag help code=%d stdout=%q stderr=%q", code, helpOut.String(), helpErr.String())
	}
	snapshot, corpus, receipt, objects := releaseOnlyFixture(t)
	path := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"verify", "--snapshot", path, "--previous", "ignored"}, &out, &errOut, Options{}); code == 0 {
		t.Fatal("v1 accepted v2-only previous argument")
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	base := []string{"init", "--repository", "https://github.com/acme/sample", "--exact-tag", "v1.0.0", "--output", filepath.Join(parent, "request.json")}
	for _, extra := range [][]string{{"--license-anchor-tag", "v1.0.0", "--tag-prefix="}, {"--license-anchor-tag", "v1.0.0", "--release-limit=0"}, {"--license-anchor-tag", "v1.0.0", "-tag-prefix="}, {"--license-anchor-tag", "v1.0.0", "-release-limit=0"}, nil, {"--license-anchor-tag", "missing"}} {
		args := append(append([]string(nil), base...), extra...)
		out.Reset()
		errOut.Reset()
		if code := Run(context.Background(), args, &out, &errOut, Options{}); code == 0 {
			t.Fatalf("unsupported selector accepted: %v", extra)
		}
	}
}

func TestExactTags_V1SyncRejectsV2PreviousBeforeFetch(t *testing.T) {
	r, fetch, _ := exactFixture(t)
	snapshot, receipt, objects, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	previous := materializeExactSnapshot(t, snapshot, receipt, objects)
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(parent, "release-request.json")
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", requestPath}, &stdout, &stderr, Options{}); code != 0 {
		t.Fatalf("v1 init code=%d stderr=%q", code, stderr.String())
	}
	calls := 0
	guard := FetchFunc(func(context.Context, string, string) ([]byte, int, error) {
		calls++
		return nil, 500, nil
	})
	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), []string{"sync", "--manifest", requestPath, "--output-parent", parent, "--previous", previous}, &stdout, &stderr, Options{Fetcher: guard, Now: time.Now}); code == 0 {
		t.Fatal("v1 sync accepted v2 previous snapshot")
	}
	if calls != 0 {
		t.Fatalf("schema mismatch fetched %d times", calls)
	}
}

func TestExactTags_ProducerBounds(t *testing.T) {
	r, base, _ := exactFixture(t)
	t.Run("request", func(t *testing.T) {
		if _, err := parseExactTagRequest(bytes.Repeat([]byte(" "), maxRequest+1)); err == nil {
			t.Fatal("oversized request accepted")
		}
	})
	t.Run("api", func(t *testing.T) {
		fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			if host == "api.github.com" && path == "/repos/acme/sample" {
				return bytes.Repeat([]byte("x"), maxAPI+1), 200, nil
			}
			return base.Fetch(ctx, host, path)
		})
		if _, _, _, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now); err == nil {
			t.Fatal("oversized API response accepted")
		}
	})
	t.Run("raw", func(t *testing.T) {
		fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			if host == "raw.githubusercontent.com" && strings.HasSuffix(path, "/CHANGELOG.md") {
				return bytes.Repeat([]byte("x"), maxObject+1), 200, nil
			}
			return base.Fetch(ctx, host, path)
		})
		if _, _, _, err := syncExactTags(context.Background(), r, nil, nil, fetch, time.Now); err == nil {
			t.Fatal("oversized raw response accepted")
		}
	})
	t.Run("source-aggregate", func(t *testing.T) {
		request := r
		request.tags = []string{"v1", "v2", "v3", "v4", "v5"}
		request.anchor = "v5"
		rawCalls := 0
		generated := generatedExactFetcher(5, 0, maxObject)
		fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			body, status, err := generated.Fetch(ctx, host, path)
			if host == "raw.githubusercontent.com" && status == 200 {
				rawCalls++
			}
			return body, status, err
		})
		if _, _, _, err := syncExactTags(context.Background(), request, nil, nil, fetch, time.Now); err == nil {
			t.Fatal("source aggregate over 16 MiB accepted")
		}
		if rawCalls != 5 {
			t.Fatalf("source aggregate failed at call %d, want 5", rawCalls)
		}
	})
	t.Run("all-objects-aggregate", func(t *testing.T) {
		request := r
		request.tags = make([]string, 10)
		for i := range request.tags {
			request.tags[i] = "v" + strconv.Itoa(i+1)
		}
		request.anchor = request.tags[len(request.tags)-1]
		rawCalls := 0
		generated := generatedExactFetcher(10, 850<<10, maxObject)
		fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
			body, status, err := generated.Fetch(ctx, host, path)
			if host == "raw.githubusercontent.com" && status == 200 {
				rawCalls++
			}
			return body, status, err
		})
		if _, _, _, err := syncExactTags(context.Background(), request, nil, nil, fetch, time.Now); err == nil {
			t.Fatal("object aggregate over 32 MiB accepted")
		}
		if rawCalls != 4 {
			t.Fatalf("object aggregate failed at raw call %d, want 4", rawCalls)
		}
	})
	t.Run("request-count", func(t *testing.T) {
		request := r
		request.tags = make([]string, 10)
		for i := range request.tags {
			request.tags[i] = "v" + strconv.Itoa(i+1)
		}
		request.anchor = request.tags[9]
		request.paths = []string{"A", "B", "C", "D", "E", "F", "G", "H"}
		calls := 0
		fetch := FetchFunc(func(_ context.Context, host, path string) ([]byte, int, error) {
			calls++
			if host == "api.github.com" && path == "/repos/acme/sample" {
				return []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample"}`), 200, nil
			}
			if host == "api.github.com" && strings.Contains(path, "/git/ref/tags/") {
				tag := path[strings.LastIndex(path, "/")+1:]
				sha := fmt.Sprintf("%040x", calls)
				return []byte(fmt.Sprintf(`{"ref":"refs/tags/%s","object":{"type":"tag","sha":"%s"}}`, tag, sha)), 200, nil
			}
			if host == "api.github.com" && strings.Contains(path, "/git/tags/") {
				outer := path[strings.LastIndex(path, "/")+1:]
				tagIndex := (calls - 2) / 2
				return []byte(fmt.Sprintf(`{"sha":"%s","tag":"v%d","object":{"type":"commit","sha":"%040x"}}`, outer, tagIndex+1, tagIndex+100)), 200, nil
			}
			return nil, 404, nil
		})
		if _, _, _, err := syncExactTags(context.Background(), request, nil, nil, fetch, time.Now); err != nil {
			t.Fatal(err)
		}
		if calls != 107 {
			t.Fatalf("calls=%d, want 107", calls)
		}
	})
}

func generatedExactFetcher(tagCount, apiPadding, sourceSize int) Fetcher {
	return FetchFunc(func(_ context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && path == "/repos/acme/sample" {
			return []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample"}`), 200, nil
		}
		if host == "api.github.com" && strings.Contains(path, "/git/ref/tags/") {
			tag := path[strings.LastIndex(path, "/")+1:]
			i, _ := strconv.Atoi(strings.TrimPrefix(tag, "v"))
			outer := fmt.Sprintf("%040x", i)
			padding := strings.Repeat("x", apiPadding)
			return []byte(fmt.Sprintf(`{"ref":"refs/tags/%s","object":{"type":"tag","sha":"%s"},"padding":"%s"}`, tag, outer, padding)), 200, nil
		}
		if host == "api.github.com" && strings.Contains(path, "/git/tags/") {
			outer := path[strings.LastIndex(path, "/")+1:]
			i, _ := strconv.ParseInt(outer, 16, 64)
			padding := strings.Repeat("y", apiPadding)
			return []byte(fmt.Sprintf(`{"sha":"%s","tag":"v%d","object":{"type":"commit","sha":"%040x"},"padding":"%s"}`, outer, i, i+100, padding)), 200, nil
		}
		if host == "raw.githubusercontent.com" && strings.HasSuffix(path, "/CHANGELOG.md") {
			body := bytes.Repeat([]byte("x"), sourceSize)
			if len(body) > 0 {
				body[0] = path[len(path)-len("/CHANGELOG.md")-1]
			}
			return body, 200, nil
		}
		return nil, 404, nil
	})
}
