// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
)

// The gate's source serves a pinned archive, counts the request against its
// budget, and fails closed when the budget is used up.
func TestGitHubSourceArchiveBudget(t *testing.T) {
	body := []byte("archive bytes")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write(body) }))
	defer srv.Close()
	var _ crdversions.ArchiveSource = &GitHubSource{}
	g := &GitHubSource{MaxRESTRequests: 2}
	for i := 0; i < 2; i++ {
		got, err := g.Archive(context.Background(), srv.URL+"/a.tgz", digest)
		if err != nil || string(got) != string(body) {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	if _, err := g.Archive(context.Background(), srv.URL+"/a.tgz", digest); !errors.Is(err, ErrBudgetExhausted) || hits.Load() != 2 {
		t.Fatalf("over the cap: %v after %d requests", err, hits.Load())
	}
	if !g.Stats().BudgetExhausted || g.Stats().APIRequests != 2 {
		t.Fatalf("stats %+v", g.Stats())
	}
	// A fetch whose bytes do not verify is refused.
	h := &GitHubSource{}
	if _, err := h.Archive(context.Background(), srv.URL+"/a.tgz", "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("wrong bytes were returned")
	}
}

// Only a source that can fetch archives is given to a crd.version-removal
// extractor.
func TestUseArchives(t *testing.T) {
	tg, ok := crdversions.TargetFor("kyverno")
	if !ok {
		t.Fatal("no kyverno target")
	}
	crd := crdversions.New(tg)
	if useArchives(crd, extract.FixtureReader{Root: t.TempDir()}) || crd.HasArchives() {
		t.Fatal("a source without archives was given")
	}
	if !useArchives(crd, &GitHubSource{}) || !crd.HasArchives() {
		t.Fatal("the GitHub source was not given")
	}
	if spec, ok := extractcli.Catalog()[k8sservedapis.ID]; !ok || useArchives(spec.New(1), &GitHubSource{}) {
		t.Fatal("an extractor of another kind was given a source")
	}
}
