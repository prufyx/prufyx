// SPDX-License-Identifier: AGPL-3.0-only

package projectonboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const testCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testRequest(t *testing.T) request {
	t.Helper()
	v := map[string]any{"schema": RequestSchema, "authority": Authority, "project": map[string]any{"slug": "sample", "canonicalRepositoryURL": "https://github.com/acme/sample", "owner": "acme", "repository": "sample"}, "discovery": map[string]any{"releaseLimit": int64(2), "tagPrefix": nil, "changelogPaths": []any{"CHANGELOG.md"}, "licenseDisposition": "NOT_REVIEWED"}, "review": map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"}}
	raw, _ := sourcecorpus.Canonical(v)
	r, err := parseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testFetcher(t *testing.T) Fetcher {
	t.Helper()
	return FetchFunc(func(_ context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" {
			switch path {
			case "/repos/acme/sample":
				return []byte(`{"id":7,"full_name":"acme/sample","html_url":"https://github.com/acme/sample","unexpected":"retained"}`), 200, nil
			case "/repos/acme/sample/releases?per_page=30&page=1":
				return []byte(`[{"id":9,"tag_name":"v1.2.3","published_at":"2026-09-12T10:00:00Z","body":"public notes","draft":false,"prerelease":false}]`), 200, nil
			case "/repos/acme/sample/git/ref/tags/v1.2.3":
				return []byte(`{"ref":"refs/tags/v1.2.3","object":{"type":"commit","sha":"` + testCommit + `"}}`), 200, nil
			}
		}
		if host == "raw.githubusercontent.com" && path == "/acme/sample/"+testCommit+"/CHANGELOG.md" {
			return []byte("# 1.2.3\nChanges\n"), 200, nil
		}
		return nil, 404, nil
	})
}

func writeSnapshotFixture(t *testing.T, snapshot, corpus, receipt map[string]any, objects map[string][]byte, directoryName string) string {
	t.Helper()
	snapshotRaw, err := sourcecorpus.Canonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sourcecorpus.SHA(snapshotRaw)
	if directoryName == "" {
		directoryName = "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	}
	receipt["snapshotDigest"] = digest
	receipt["outputName"] = "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	receiptRaw, err := sourcecorpus.Canonical(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var corpusRaw []byte
	if len(snapshot["sources"].([]any)) > 0 {
		corpusRaw, err = sourcecorpus.Canonical(corpus)
		if err != nil {
			t.Fatal(err)
		}
		receipt["sourceCorpusManifestDigest"] = sourcecorpus.SHA(corpusRaw)
		receiptRaw, err = sourcecorpus.Canonical(receipt)
		if err != nil {
			t.Fatal(err)
		}
	}
	parent := filepath.Join(t.TempDir(), "snapshots")
	if err = os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = sourcecorpus.WriteProjectSnapshotTree(parent, directoryName, objects, snapshotRaw, corpusRaw, receiptRaw); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, directoryName)
}

func releaseOnlyFixture(t *testing.T) (map[string]any, map[string]any, map[string]any, map[string][]byte) {
	t.Helper()
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" {
			return nil, 404, nil
		}
		return testFetcher(t).Fetch(ctx, host, path)
	})
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), testRequest(t), nil, nil, nil, fetch, func() time.Time { return time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, corpus, receipt, objects
}

func TestProject_SyncVerifyInspect_CommitPinnedCorpus(t *testing.T) {
	r := testRequest(t)
	now := func() time.Time { return time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC) }
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), r, nil, nil, nil, testFetcher(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot["sources"].([]any)) != 1 || snapshot["corpusAdapterState"] != "PRESENT" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	snapshotRaw, _ := sourcecorpus.Canonical(snapshot)
	digest := sourcecorpus.SHA(snapshotRaw)
	receipt["snapshotDigest"] = digest
	receipt["outputName"] = "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	corpusRaw, _ := sourcecorpus.Canonical(corpus)
	receiptRaw, _ := sourcecorpus.Canonical(receipt)
	parent := filepath.Join(t.TempDir(), "snapshots")
	if err = os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := receipt["outputName"].(string)
	if err = sourcecorpus.WriteProjectSnapshotTree(parent, dir, objects, snapshotRaw, corpusRaw, receiptRaw); err != nil {
		t.Fatal(err)
	}
	if _, err = sourcecorpus.VerifyPath(filepath.Join(parent, dir, "SOURCE-CORPUS-MANIFEST.json"), filepath.Join(parent, dir, "objects")); err != nil {
		t.Fatalf("corpus: %v raw=%s", err, corpusRaw)
	}
	verified, _, err := VerifySnapshot(filepath.Join(parent, dir))
	if err != nil {
		t.Fatal(err)
	}
	if verified["repository"].(map[string]any)["repositoryID"] != int64(7) {
		t.Fatalf("repo mismatch: %#v", verified)
	}
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"inspect", "--snapshot", filepath.Join(parent, dir), "--tag", "v1.2.3"}, &out, &errOut, Options{}); code != 0 || !strings.Contains(out.String(), "v1.2.3") {
		t.Fatalf("inspect code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	if code := Run(context.Background(), []string{"inspect", "--snapshot", filepath.Join(parent, dir), "--tag", "missing"}, &out, &errOut, Options{}); code == 0 {
		t.Fatal("unknown tag accepted")
	}
}

func TestDecodeReleaseListEndpointBound(t *testing.T) {
	body := strings.Repeat("x", 100000)
	items := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		id, tag, draft := i+100, "v9.9."+strconv.Itoa(i), "true"
		if i == 0 {
			id, tag, draft = 9, "v1.2.3", "false"
		}
		items = append(items, `{"id":`+strconv.Itoa(id)+`,"tag_name":"`+tag+`","published_at":"2026-09-12T10:00:00Z","body":"`+body+`","draft":`+draft+`,"prerelease":false}`)
	}
	valid := []byte("[" + strings.Join(items, ",") + "]")
	if len(valid) <= maxAPI || len(valid) > maxReleaseListAPI {
		t.Fatalf("fixture bounds: %d", len(valid))
	}
	if _, err := decodeReleaseList(valid); err != nil {
		t.Fatalf("release list within endpoint bound: %v", err)
	}
	tooLarge := append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), maxReleaseListAPI-len(valid)+1)...)
	if _, err := decodeReleaseList(tooLarge); err == nil {
		t.Fatal("release list over endpoint bound accepted")
	}
	var repository map[string]any
	if err := decodeAPI(valid, &repository); err == nil {
		t.Fatal("non-release API accepted within release-only 2MiB range")
	}
}

func TestProjectRunSyncRetainsAndVerifiesLargeReleaseList(t *testing.T) {
	body := strings.Repeat("x", 100000)
	items := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		id, tag, draft := i+100, "v9.9."+strconv.Itoa(i), "true"
		if i == 0 {
			id, tag, draft = 9, "v1.2.3", "false"
		}
		items = append(items, `{"id":`+strconv.Itoa(id)+`,"tag_name":"`+tag+`","published_at":"2026-09-12T10:00:00Z","body":"`+body+`","draft":`+draft+`,"prerelease":false}`)
	}
	list := []byte("[" + strings.Join(items, ",") + "]")
	if len(list) <= maxAPI || len(list) > maxReleaseListAPI {
		t.Fatalf("fixture bounds: %d", len(list))
	}
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && path == "/repos/acme/sample/releases?per_page=30&page=1" {
			return list, 200, nil
		}
		return testFetcher(t).Fetch(ctx, host, path)
	})
	request := filepath.Join(t.TempDir(), "request.json")
	raw, _ := sourcecorpus.Canonical(testRequest(t).document)
	if err := os.WriteFile(request, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "snapshots")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"sync", "--manifest", request, "--output-parent", parent}, &stdout, &stderr, Options{Fetcher: fetch, Now: func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }})
	if code != 0 {
		t.Fatalf("sync code=%d stderr=%q", code, stderr.String())
	}
	var receipt map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifySnapshot(filepath.Join(parent, receipt["outputName"].(string))); err != nil {
		t.Fatalf("offline verify: %v", err)
	}
}

func TestProject_ParseRequest_RejectsDuplicateAndEmptyPrefixIsNull(t *testing.T) {
	r := testRequest(t)
	if r.prefix != "" {
		t.Fatalf("prefix=%q", r.prefix)
	}
	if _, err := parseRequest([]byte(`{"schema":"x","schema":"y"}`)); err == nil {
		t.Fatal("duplicate JSON accepted")
	}
}

func TestProject_Sync_AnnotatedTagDereferences(t *testing.T) {
	r := testRequest(t)
	fetch := testFetcher(t).(FetchFunc)
	annotated := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && path == "/repos/acme/sample/git/ref/tags/v1.2.3" {
			return []byte(`{"ref":"refs/tags/v1.2.3","object":{"type":"tag","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`), 200, nil
		}
		if host == "api.github.com" && path == "/repos/acme/sample/git/tags/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			return []byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tag":"v1.2.3","object":{"type":"commit","sha":"` + testCommit + `"}}`), 200, nil
		}
		return fetch(ctx, host, path)
	})
	snapshot, _, _, _, err := Sync(context.Background(), r, nil, nil, nil, annotated, time.Now)
	if err != nil || snapshot["releases"].([]any)[0].(map[string]any)["annotatedTagObject"] == nil {
		t.Fatalf("annotated sync err=%v snapshot=%#v", err, snapshot)
	}
}

func TestProject_Sync_ReusesPriorImmutableChangelogAndDetectsRetag(t *testing.T) {
	r := testRequest(t)
	first, _, _, objects, err := Sync(context.Background(), r, nil, nil, nil, testFetcher(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	rawCalls := 0
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" {
			if strings.HasSuffix(path, "CHANGELOG.md") {
				return nil, 500, nil
			}
			rawCalls++
			return nil, 404, nil
		}
		return testFetcher(t).Fetch(ctx, host, path)
	})
	second, _, _, _, err := Sync(context.Background(), r, first, objects, digestMust(first), fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if rawCalls != 6 || second["sources"].([]any)[0].(map[string]any)["captureState"] != "REUSED_VERIFIED_PRIOR" {
		t.Fatalf("rawCalls=%d source=%#v", rawCalls, second["sources"])
	}
	retag := map[string]any{"repository": first["repository"], "releases": []any{map[string]any{"tag": "v1.2.3", "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "releaseBodyDigest": "sha256:old"}}}
	if comparePrevious(retag, second) == nil {
		t.Fatal("moved reobserved tag accepted")
	}
}

func TestProject_Sync_ReleaseOnlySnapshotOmitsCorpusAdapter(t *testing.T) {
	r := testRequest(t)
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" {
			return nil, 404, nil
		}
		return testFetcher(t).Fetch(ctx, host, path)
	})
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), r, nil, nil, nil, fetch, time.Now)
	if err != nil || len(snapshot["sources"].([]any)) != 0 || snapshot["corpusAdapterState"] != "OMITTED_NO_CHANGELOG_BYTES" {
		t.Fatalf("err=%v snapshot=%#v", err, snapshot)
	}
	snapshotRaw, _ := sourcecorpus.Canonical(snapshot)
	digest := sourcecorpus.SHA(snapshotRaw)
	receipt["snapshotDigest"] = digest
	receipt["outputName"] = "snapshot-" + strings.TrimPrefix(digest, "sha256:")
	receiptRaw, _ := sourcecorpus.Canonical(receipt)
	parent := filepath.Join(t.TempDir(), "snapshots")
	if err = os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = sourcecorpus.WriteProjectSnapshotTree(parent, receipt["outputName"].(string), objects, snapshotRaw, nil, receiptRaw); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifySnapshot(filepath.Join(parent, receipt["outputName"].(string))); err != nil {
		t.Fatal(err)
	}
	_ = corpus
}

func TestProject_Init_IsOfflineAndWritesStrictRequest(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "request.json")
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", output}, io.Discard, &stderr, Options{}); code != 0 {
		t.Fatalf("init=%d stderr=%q", code, stderr.String())
	}
	raw, err := sourcecorpus.ReadPrivateFile(output, maxRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseRequest(raw); err != nil {
		t.Fatal(err)
	}
}

func TestProject_ReleaseWireIsDocumentedSnakeCase(t *testing.T) {
	var r struct {
		Full      string `json:"full_name"`
		Published string `json:"published_at"`
	}
	if err := json.Unmarshal([]byte(`{"full_name":"a/b","published_at":"2026-09-12T00:00:00Z"}`), &r); err != nil || r.Full != "a/b" {
		t.Fatal("fixture guard failed")
	}
}

func TestProject_Init_BareRelativeOutputInPrivateCWD(t *testing.T) {
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(private); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	var stderr bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", "project-request.json"}, io.Discard, &stderr, Options{}); code != 0 {
		t.Fatalf("init=%d stderr=%q", code, stderr.String())
	}
	raw, err := sourcecorpus.ReadPrivateFile("project-request.json", maxRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseRequest(raw); err != nil {
		t.Fatal(err)
	}
}

func TestProject_PreviousUsesStableReleaseIdentity(t *testing.T) {
	previous := map[string]any{"repository": map[string]any{"repositoryID": int64(7)}, "releases": []any{map[string]any{"releaseID": int64(9), "tag": "v1.2.3", "commit": testCommit, "releaseBodyDigest": sourcecorpus.SHA([]byte("old"))}}}
	nextRelease := map[string]any{"releaseID": int64(9), "tag": "v1.2.3", "commit": testCommit, "releaseBodyDigest": sourcecorpus.SHA([]byte("new"))}
	next := map[string]any{"repository": map[string]any{"repositoryID": int64(7)}, "releases": []any{nextRelease}}
	if err := comparePrevious(previous, next); err != nil || nextRelease["releaseBodyState"] != "CHANGED" {
		t.Fatalf("body lineage rejected: %v %#v", err, nextRelease)
	}
	nextRelease["tag"] = "v1.2.4"
	if comparePrevious(previous, next) == nil {
		t.Fatal("stable release ID rename accepted")
	}
	nextRelease["releaseID"] = int64(10)
	nextRelease["tag"] = "v1.2.3"
	nextRelease["commit"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if comparePrevious(previous, next) == nil {
		t.Fatal("reused tag moved to another commit accepted")
	}
}

func TestProject_SyncRejectsMismatchedRefAndAnnotatedIdentity(t *testing.T) {
	base := testFetcher(t)
	wrongRef := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && strings.Contains(path, "/git/ref/tags/") {
			return []byte(`{"ref":"refs/tags/other","object":{"type":"commit","sha":"` + testCommit + `"}}`), 200, nil
		}
		return base.Fetch(ctx, host, path)
	})
	if _, _, _, _, err := Sync(context.Background(), testRequest(t), nil, nil, nil, wrongRef, time.Now); err == nil {
		t.Fatal("mismatched ref identity accepted")
	}
	wrongAnnotated := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && strings.Contains(path, "/git/ref/tags/") {
			return []byte(`{"ref":"refs/tags/v1.2.3","object":{"type":"tag","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`), 200, nil
		}
		if host == "api.github.com" && strings.Contains(path, "/git/tags/") {
			return []byte(`{"sha":"cccccccccccccccccccccccccccccccccccccccc","tag":"v1.2.3","object":{"type":"commit","sha":"` + testCommit + `"}}`), 200, nil
		}
		return base.Fetch(ctx, host, path)
	})
	if _, _, _, _, err := Sync(context.Background(), testRequest(t), nil, nil, nil, wrongAnnotated, time.Now); err == nil {
		t.Fatal("mismatched annotated tag identity accepted")
	}
}

func TestProject_VerifyClosesReceiptAndBindsDirectoryName(t *testing.T) {
	snapshot, corpus, receipt, objects := releaseOnlyFixture(t)
	receipt["reviewState"] = "APPROVED"
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	if _, _, err := VerifySnapshot(directory); err == nil {
		t.Fatal("tampered receipt accepted")
	}
	snapshot, corpus, receipt, objects = releaseOnlyFixture(t)
	wrongName := "snapshot-" + strings.Repeat("0", 64)
	directory = writeSnapshotFixture(t, snapshot, corpus, receipt, objects, wrongName)
	if _, _, err := VerifySnapshot(directory); err == nil {
		t.Fatal("copied snapshot under wrong digest name accepted")
	}
}

func TestProject_VerifyRejectsOmittedSelectedRelease(t *testing.T) {
	r := testRequest(t)
	base := testFetcher(t)
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && strings.Contains(path, "/releases?") {
			return []byte(`[{"id":9,"tag_name":"v1.2.3","published_at":"2026-09-12T10:00:00Z","body":"one","draft":false,"prerelease":false},{"id":10,"tag_name":"v1.2.4","published_at":"2026-09-11T10:00:00Z","body":"two","draft":false,"prerelease":false}]`), 200, nil
		}
		if host == "api.github.com" && strings.HasSuffix(path, "/git/ref/tags/v1.2.4") {
			return []byte(`{"ref":"refs/tags/v1.2.4","object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`), 200, nil
		}
		if host == "raw.githubusercontent.com" {
			return nil, 404, nil
		}
		return base.Fetch(ctx, host, path)
	})
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), r, nil, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot["releases"] = snapshot["releases"].([]any)[:1]
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	if _, _, err = VerifySnapshot(directory); err == nil {
		t.Fatal("snapshot omitting an eligible selected release accepted")
	}
}

func TestProject_ProposalIsPublicAndCarriesObservationTime(t *testing.T) {
	snapshot, corpus, receipt, objects := releaseOnlyFixture(t)
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"proposal", "--snapshot", directory}, &out, &stderr, Options{}); code != 0 {
		t.Fatalf("proposal=%d stderr=%q", code, stderr.String())
	}
	value, err := sourcecorpus.DecodeBounded(bytes.TrimSpace(out.Bytes()), maxRequest)
	if err != nil {
		t.Fatal(err)
	}
	proposal := value.(map[string]any)
	if proposal["observedAt"] != snapshot["observedAt"] {
		t.Fatalf("observedAt mismatch: %#v", proposal)
	}
	release := proposal["releases"].([]any)[0].(map[string]any)
	if release["releaseURL"] != "https://github.com/acme/sample/releases/tag/v1.2.3" || release["tagReferenceURL"] != nil {
		t.Fatalf("incorrect release projection: %#v", release)
	}
	assertNoLocalObjectKeys(t, proposal)
}

func assertNoLocalObjectKeys(t *testing.T, value any) {
	t.Helper()
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if key == "object" || strings.HasSuffix(key, "Object") {
				t.Fatalf("private locator key %q emitted", key)
			}
			assertNoLocalObjectKeys(t, child)
		}
	case []any:
		for _, child := range item {
			assertNoLocalObjectKeys(t, child)
		}
	}
}

func TestProject_LicenseTransportFailureIsNotAbsence(t *testing.T) {
	base := testFetcher(t)
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" && strings.HasSuffix(path, "/CHANGELOG.md") {
			return nil, 404, nil
		}
		if host == "raw.githubusercontent.com" {
			return nil, 0, errors.New("transport")
		}
		return base.Fetch(ctx, host, path)
	})
	if _, _, _, _, err := Sync(context.Background(), testRequest(t), nil, nil, nil, fetch, time.Now); !errors.Is(err, ErrNetwork) {
		t.Fatalf("license transport error=%v", err)
	}
}

func TestProject_LicenseIsBoundToFirstSelectedRelease(t *testing.T) {
	base := testFetcher(t)
	secondCommit := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "api.github.com" && strings.Contains(path, "/releases?") {
			return []byte(`[{"id":9,"tag_name":"v1.2.3","published_at":"2026-09-12T10:00:00Z","body":"one","draft":false,"prerelease":false},{"id":10,"tag_name":"v1.2.4","published_at":"2026-09-11T10:00:00Z","body":"two","draft":false,"prerelease":false}]`), 200, nil
		}
		if host == "api.github.com" && strings.HasSuffix(path, "/git/ref/tags/v1.2.4") {
			return []byte(`{"ref":"refs/tags/v1.2.4","object":{"type":"commit","sha":"` + secondCommit + `"}}`), 200, nil
		}
		if host == "raw.githubusercontent.com" && path == "/acme/sample/"+testCommit+"/LICENSE" {
			return []byte("first license"), 200, nil
		}
		if host == "raw.githubusercontent.com" {
			return nil, 404, nil
		}
		return base.Fetch(ctx, host, path)
	})
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), testRequest(t), nil, nil, nil, fetch, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("second license")
	digest := sourcecorpus.SHA(body)
	objects[digest] = body
	snapshot["license"] = map[string]any{"kind": "license", "commit": secondCommit, "immutableURL": "https://github.com/acme/sample/blob/" + secondCommit + "/LICENSE", "fileDigest": digest, "object": "sha256/" + strings.TrimPrefix(digest, "sha256:"), "byteLength": int64(len(body)), "disposition": "NOT_REVIEWED"}
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	if _, _, err = VerifySnapshot(directory); err == nil {
		t.Fatal("license from non-latest selected release accepted")
	}
}

func TestProject_StatusStatesOfflineLimits(t *testing.T) {
	snapshot, corpus, receipt, objects := releaseOnlyFixture(t)
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"status", "--snapshot", directory}, &out, io.Discard, Options{}); code != 0 {
		t.Fatalf("status=%d", code)
	}
	for _, field := range []string{"freshness", "upstreamContinuity", "nonRevocation"} {
		if !strings.Contains(out.String(), `"`+field+`":"NOT_CHECKED_OFFLINE"`) {
			t.Fatalf("missing %s: %s", field, out.String())
		}
	}
}

func TestProject_DecodeAPIAcceptsUnicodeAndRejectsUnpairedSurrogates(t *testing.T) {
	valid := [][]byte{
		[]byte(`{"body":"\ud83d\ude00"}`),
		[]byte(`{"body":"😀"}`),
		[]byte(`{"body":"literal \\ud800 text"}`),
	}
	for _, raw := range valid {
		var value map[string]any
		if err := decodeAPI(raw, &value); err != nil {
			t.Fatalf("valid Unicode rejected: %s: %v", raw, err)
		}
	}
	for _, raw := range [][]byte{[]byte(`{"body":"\ud800"}`), []byte(`{"body":"\udc00"}`), []byte(`{"body":"\ud800\u0041"}`)} {
		var value map[string]any
		if err := decodeAPI(raw, &value); err == nil {
			t.Fatalf("unpaired surrogate accepted: %s", raw)
		}
	}
}

func TestProject_ReleaseListRequiresBooleanFlagsAndObservedBody(t *testing.T) {
	prefix := `[{"id":9,"tag_name":"v1","published_at":"2026-09-12T10:00:00Z",`
	for _, suffix := range []string{
		`"body":"x","prerelease":false}]`,
		`"body":"x","draft":null,"prerelease":false}]`,
		`"body":"x","draft":"false","prerelease":false}]`,
		`"body":"x","draft":false}]`,
		`"body":"x","draft":false,"prerelease":null}]`,
		`"draft":false,"prerelease":false}]`,
	} {
		if _, err := decodeReleaseList([]byte(prefix + suffix)); err == nil {
			t.Fatalf("invalid release flags/body accepted: %s", suffix)
		}
	}
	for _, body := range []string{"null", `""`} {
		releases, err := decodeReleaseList([]byte(prefix + `"body":` + body + `,"draft":false,"prerelease":false}]`))
		if err != nil || len(releases) != 1 || releaseBody(releases[0]) != "" {
			t.Fatalf("valid empty body rejected: body=%s releases=%#v err=%v", body, releases, err)
		}
	}
}

func TestProject_SyncRejectsChangelogBeyondSharedLineCap(t *testing.T) {
	base := testFetcher(t)
	fetch := FetchFunc(func(ctx context.Context, host, path string) ([]byte, int, error) {
		if host == "raw.githubusercontent.com" && strings.HasSuffix(path, "/CHANGELOG.md") {
			return bytes.Repeat([]byte{'\n'}, sourcecorpus.MaxSourceLines), 200, nil
		}
		return base.Fetch(ctx, host, path)
	})
	if _, _, _, _, err := Sync(context.Background(), testRequest(t), nil, nil, nil, fetch, time.Now); err == nil {
		t.Fatal("producer accepted changelog beyond verifier line cap")
	}
}

func TestProject_RequestPathMatchesImmutableURLBound(t *testing.T) {
	repository := "https://github.com/acme/sample"
	const placeholderCommit = "0000000000000000000000000000000000000000"
	maximum := 512 - len(repository+"/blob/"+placeholderCommit+"/")
	makePath := func(length int) string {
		parts := []string{}
		for length > 0 {
			partLength := length
			if partLength > 128 {
				partLength = 128
			}
			parts = append(parts, strings.Repeat("a", partLength))
			length -= partLength
			if length > 0 {
				length--
			}
		}
		return strings.Join(parts, "/")
	}
	accepted := makePath(maximum)
	tooLong := makePath(maximum + 1)
	if len(accepted) != maximum || !validChangelogPath(repository, accepted) {
		t.Fatalf("maximum path rejected: length=%d maximum=%d", len(accepted), maximum)
	}
	if validChangelogPath(repository, tooLong) {
		t.Fatalf("path beyond immutable URL bound accepted: length=%d", len(tooLong))
	}
	r := testRequest(t)
	discovery := r.document["discovery"].(map[string]any)
	discovery["changelogPaths"] = []any{tooLong}
	raw, _ := sourcecorpus.Canonical(r.document)
	if _, err := parseRequest(raw); err == nil {
		t.Fatal("request parser accepted overlong immutable path")
	}
}

func TestProject_MaxLengthSlugProducesVerifiableCorpus(t *testing.T) {
	r := testRequest(t)
	project := r.document["project"].(map[string]any)
	project["slug"] = strings.Repeat("a", 128)
	raw, _ := sourcecorpus.Canonical(r.document)
	r, err := parseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), r, nil, nil, nil, testFetcher(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	if _, _, err = VerifySnapshot(directory); err != nil {
		t.Fatalf("max slug generated invalid snapshot: %v", err)
	}
}

func TestProject_AdapterRejectsRuleDeclarationsAndWrongRevision(t *testing.T) {
	for _, mutation := range []string{"declarations", "revision"} {
		t.Run(mutation, func(t *testing.T) {
			snapshot, corpus, receipt, objects, err := Sync(context.Background(), testRequest(t), nil, nil, nil, testFetcher(t), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "revision" {
				corpus["revision"] = "attacker-revision"
			} else {
				record := corpus["records"].([]any)[0].(map[string]any)
				record["declarations"] = map[string]any{"packetDigest": nil, "ruleIDs": []any{"approved-rule"}}
			}
			directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
			if _, _, err = VerifySnapshot(directory); err == nil {
				t.Fatalf("tampered adapter %s accepted", mutation)
			}
		})
	}
}

func TestProject_StandaloneSnapshotCannotClaimLineage(t *testing.T) {
	snapshot, corpus, receipt, objects := releaseOnlyFixture(t)
	release := snapshot["releases"].([]any)[0].(map[string]any)
	release["priorReleaseBodyDigest"] = release["releaseBodyDigest"]
	release["releaseBodyState"] = "UNCHANGED"
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	if _, _, err := VerifySnapshot(directory); err == nil {
		t.Fatal("standalone snapshot lineage accepted")
	}
}

func TestProject_InitialSnapshotCannotClaimReusedSource(t *testing.T) {
	snapshot, corpus, receipt, objects, err := Sync(context.Background(), testRequest(t), nil, nil, nil, testFetcher(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot["sources"].([]any)[0].(map[string]any)["captureState"] = "REUSED_VERIFIED_PRIOR"
	directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
	if _, _, err = VerifySnapshot(directory); err == nil {
		t.Fatal("initial snapshot impossible source reuse accepted")
	}
}

func TestProject_VerifyMalformedClosedShapesNeverPanics(t *testing.T) {
	for _, field := range []string{"request", "repository", "releases"} {
		t.Run(field, func(t *testing.T) {
			snapshot, corpus, receipt, objects := releaseOnlyFixture(t)
			switch field {
			case "request":
				snapshot[field] = "invalid"
			case "repository":
				snapshot[field] = "invalid"
			case "releases":
				snapshot[field] = []any{"invalid"}
			}
			directory := writeSnapshotFixture(t, snapshot, corpus, receipt, objects, "")
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("VerifySnapshot panicked for %s: %v", field, recovered)
				}
			}()
			if _, _, err := VerifySnapshot(directory); err == nil {
				t.Fatalf("malformed %s accepted", field)
			}
		})
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return len(data) - 1, nil
}

func TestProject_OutputWriteFailureIsReportedAndSnapshotRemains(t *testing.T) {
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(private, "request.json")
	if code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", manifest}, io.Discard, io.Discard, Options{}); code != 0 {
		t.Fatalf("init=%d", code)
	}
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"sync", "--manifest", manifest, "--output-parent", private}, shortWriter{}, &stderr, Options{Fetcher: testFetcher(t), Now: time.Now})
	if code == 0 || !strings.Contains(stderr.String(), "OUTPUT_WRITE_FAILURE") {
		t.Fatalf("sync code=%d stderr=%q", code, stderr.String())
	}
	matches, err := filepath.Glob(filepath.Join(private, "snapshot-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("persisted snapshots=%v err=%v", matches, err)
	}
	if _, _, err = VerifySnapshot(matches[0]); err != nil {
		t.Fatalf("persisted snapshot invalid after output failure: %v", err)
	}
}
