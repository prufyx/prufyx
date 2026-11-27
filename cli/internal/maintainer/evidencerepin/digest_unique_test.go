// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// A baseline equal to the pinned commit proves nothing about the recorded
// contentDigest: the pinned file has to be read and hashed.
func TestClassifyNoNewReleaseNeedsTheRecordedDigest(t *testing.T) {
	body := []byte("a\nb\nc")
	path := "/argoproj/argo-cd/" + commitA + "/VERSION"
	citation := Citation{Owner: "argoproj", Repo: "argo-cd", Path: "VERSION", OldCommit: commitA, OldDigest: sourcecorpus.SHA(body), StartLine: 1, EndLine: 1}
	for _, tc := range []struct {
		name    string
		fetcher fakeBlobFetcher
		want    string
	}{
		{"match", fakeBlobFetcher{path: {Kind: "HTTP_200", StatusCode: 200, Body: body}}, ClassNoNewRelease},
		{"other bytes", fakeBlobFetcher{path: {Kind: "HTTP_200", StatusCode: 200, Body: []byte("x")}}, ClassCorpusDigestMismatch},
		{"not found", fakeBlobFetcher{}, ClassCorpusDigestMismatch},
		{"server error", fakeBlobFetcher{path: {Kind: "HTTP_STATUS", StatusCode: 500}}, ClassPending},
		{"transport error", fakeBlobFetcher{path: sourcecapture.FetchResult{Kind: "TRANSPORT_ERROR"}}, ClassPending},
	} {
		if got := Classify(context.Background(), citation, commitA, tc.fetcher); got.Class != tc.want {
			t.Errorf("%s: got %s (%s), want %s", tc.name, got.Class, got.Detail, tc.want)
		}
	}
}

// A span that reads the same at the same line numbers is only proven intact
// when its bytes occur exactly once in both files.
func TestClassifySpanInPlaceNeedsExactlyOneOccurrence(t *testing.T) {
	for _, tc := range []struct {
		name, old, new string
		start, end     int
	}{
		// The cited first block changed and an identical block slid into its lines.
		{"twice in old, cited copy gone", "k: v\nn: 1\nsep\nk: v\nn: 1", "sep\nsep\nsep\nk: v\nn: 1", 4, 5},
		{"copy added", "head\nk: v\nn: 1", "head\nk: v\nn: 1\nk: v\nn: 1", 2, 3},
		{"copy removed", "head\nk: v\nn: 1\nk: v\nn: 1", "head\nk: v\nn: 1\ntail", 2, 3},
		{"copy inside a longer line", "head\nk: v\ntail", "head\nk: v\nzk: vz", 2, 2},
		{"blank span", "a\n\nb", "a\n\nc", 2, 2},
	} {
		if class, _, _ := classifySpan([]byte(tc.old), tc.start, tc.end, []byte(tc.new)); class != ClassContentChanged {
			t.Errorf("%s: got %s, want %s", tc.name, class, ClassContentChanged)
		}
	}
}

// Results classified before the digest and occurrence checks existed are
// recomputed, never resumed.
func TestLoadStateDiscardsEarlierResults(t *testing.T) {
	for _, schema := range []string{"prufyx.io/evidence-repin-state/v1", "prufyx.io/evidence-repin-state/v2"} {
		path := filepath.Join(t.TempDir(), "state.json")
		raw := `{"schema":"` + schema + `","repos":{},"results":{"k":{"class":"NO_NEW_RELEASE"}}}`
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		state, err := LoadState(path)
		if err != nil {
			t.Fatalf("%s: %v", schema, err)
		}
		if len(state.Results) != 0 || state.Schema != StateSchema || StateSchema == schema {
			t.Errorf("%s: resumed %d results under %s", schema, len(state.Results), state.Schema)
		}
	}
}
