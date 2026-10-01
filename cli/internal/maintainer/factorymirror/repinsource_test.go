// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

func TestUsableReleasesAcceptsTruncatedButNotUnknown(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.opts.Releases = &fakeReleases{results: map[string]ReleaseResult{k1: {ETag: "e", Truncated: true, Items: []Release{{ID: 1, Tag: "v1"}}}}}
	e.run()
	r, _ := OpenReader(e.state)
	if rel, err := r.UsableReleases(k1); err != nil || !rel.Truncated || len(rel.Items) != 1 {
		t.Fatalf("a truncated list still has its newest entries: %+v %v", rel, err)
	}
	if _, err := r.CompleteReleases(k1); !errors.Is(err, ErrReleasesIncomplete) {
		t.Fatalf("truncated list accepted as complete: %v", err)
	}

	e2 := newEnv(t, k1)
	e2.remote[k1].commit("one", map[string]string{"a": "1"})
	e2.run()
	r2, _ := OpenReader(e2.state)
	if _, err := r2.UsableReleases(k1); !errors.Is(err, ErrReleasesIncomplete) {
		t.Fatalf("unknown releases accepted: %v", err)
	}
}

func TestReaderRepoStatusAndIndexInfo(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.opts.Releases = &fakeReleases{results: map[string]ReleaseResult{k1: {ETag: "e", Items: []Release{{ID: 1, Tag: "v1"}}}}}
	e.run()
	r, _ := OpenReader(e.state)
	st, err := r.RepoStatus(k1)
	if err != nil || st.Status != "ok" || st.LastCheckedAt == "" || st.LastFetchedAt == "" || st.ReleasesFetchedAt == "" {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := r.RepoStatus("github.com/acme/nothing"); !errors.Is(err, ErrRepoNotMirrored) {
		t.Fatalf("%v", err)
	}
	updated, digest := r.IndexInfo()
	if updated == "" || digest == "" {
		t.Fatalf("index identity missing: %q %q", updated, digest)
	}
	e.run()
	r2, _ := OpenReader(e.state)
	if _, digest2 := r2.IndexInfo(); digest2 == "" {
		t.Fatal("digest lost")
	}
}

func TestRepinSourceMapsReaderErrors(t *testing.T) {
	e := newEnv(t, k1)
	c1 := e.remote[k1].commit("one", map[string]string{"a": "1"})
	e.remote[k1].tag("v1", false)
	e.run() // refs only: no blobs requested
	src, err := OpenRepinSource(e.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Read("acme", "widget", c1, "a"); !errors.Is(err, evidencerepin.ErrMirrorBlobNotLocal) {
		t.Fatalf("an unmaterialized file must map to ErrMirrorBlobNotLocal: %v", err)
	}
	if _, err := src.Read("acme", "widget", "1234567890123456789012345678901234567890", "a"); !errors.Is(err, evidencerepin.ErrMirrorCommitUnknown) {
		t.Fatalf("%v", err)
	}
	if _, err := src.Read("acme", "nothing", c1, "a"); !errors.Is(err, evidencerepin.ErrMirrorNotMirrored) {
		t.Fatalf("%v", err)
	}
	if _, err := src.Releases("acme", "widget"); !errors.Is(err, evidencerepin.ErrMirrorReleasesUnusable) {
		t.Fatalf("unknown releases must be unusable: %v", err)
	}
	tags, err := src.Tags("acme", "widget")
	if err != nil || tags["v1"] != c1 {
		t.Fatalf("%v %v", tags, err)
	}
	// A moved tag freezes the repository for every read.
	e.remote[k1].commit("two", map[string]string{"a": "2"})
	e.remote[k1].tag("v1", false)
	e.run()
	src, _ = OpenRepinSource(e.state)
	if _, err := src.Tags("acme", "widget"); !errors.Is(err, evidencerepin.ErrMirrorFrozen) {
		t.Fatalf("%v", err)
	}
	if _, err := src.Read("acme", "widget", c1, "a"); !errors.Is(err, evidencerepin.ErrMirrorFrozen) {
		t.Fatalf("a frozen repository must not be read: %v", err)
	}
	if _, err := src.Releases("acme", "widget"); !errors.Is(err, evidencerepin.ErrMirrorFrozen) {
		t.Fatalf("%v", err)
	}
}
